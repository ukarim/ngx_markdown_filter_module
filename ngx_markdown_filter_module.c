#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <cmark.h>


// pointers to next handlers

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;

static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


// location conf

typedef struct {
    ngx_flag_t enable;
} ngx_markdown_filter_conf_t;


// request context

typedef struct {
    cmark_parser *parser;
} ngx_markdown_filter_ctx_t;


static void *ngx_markdown_filter_create_conf(ngx_conf_t *cf);

static char *ngx_markdown_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_markdown_header_filter(ngx_http_request_t *r);

static ngx_int_t ngx_markdown_body_filter(ngx_http_request_t *r, ngx_chain_t *chain);

static ngx_int_t ngx_markdown_filter_init(ngx_conf_t *cf);

static void cmark_parser_cleanup(void *parser);


/* module directives */

static ngx_command_t ngx_markdown_filter_commands[] = {

    { ngx_string("markdown_filter"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_markdown_filter_conf_t, enable),
      NULL },

      ngx_null_command
};


/* module context */

static ngx_http_module_t  ngx_markdown_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_markdown_filter_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    // TODO create conf functions
    ngx_markdown_filter_create_conf,       /* create location configuration */
    ngx_markdown_filter_merge_conf         /* merge location configuration */
};


/* module itself */

ngx_module_t ngx_markdown_filter_module = {
    NGX_MODULE_V1,
    &ngx_markdown_filter_module_ctx,       /* module context */
    ngx_markdown_filter_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *ngx_markdown_filter_create_conf(ngx_conf_t *cf)
{
    ngx_markdown_filter_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_markdown_filter_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->enable = NGX_CONF_UNSET;
    return conf;
}

static char *ngx_markdown_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_markdown_filter_conf_t *prev = parent;
    ngx_markdown_filter_conf_t *conf = child;
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    return NGX_CONF_OK;
}


static ngx_int_t ngx_markdown_filter_init(ngx_conf_t *cf)
{

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_markdown_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_markdown_body_filter;

    return NGX_OK;
}


static void cmark_parser_cleanup(void *data)
{
    cmark_parser *parser = data;
    cmark_parser_free(parser);
}


static ngx_int_t ngx_markdown_header_filter(ngx_http_request_t *r)
{
    ngx_markdown_filter_conf_t *lc = ngx_http_get_module_loc_conf(r, ngx_markdown_filter_module);
    if (lc->enable && r->headers_out.status == NGX_HTTP_OK) {
        ngx_markdown_filter_ctx_t *ctx = ngx_pcalloc(r->pool, sizeof(ngx_markdown_filter_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        cmark_parser *parser = cmark_parser_new(CMARK_OPT_DEFAULT);
        if (parser == NULL) {
            return NGX_ERROR;
        }
        ctx->parser = parser;

        ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            cmark_parser_cleanup(parser);
            return NGX_ERROR;
        }
        cln->handler = cmark_parser_cleanup;
        cln->data = parser;

        ngx_http_set_ctx(r, ctx, ngx_markdown_filter_module);

        ngx_str_t mime = ngx_string("text/html");
        r->headers_out.content_type = mime;
        r->main_filter_need_in_memory = 1;
        ngx_http_clear_content_length(r);
    }
    return ngx_http_next_header_filter(r);
}


static ngx_int_t ngx_markdown_body_filter(ngx_http_request_t *r, ngx_chain_t *chain)
{
    if (chain == NULL) {
        return ngx_http_next_body_filter(r, chain);
    }

    if (r->headers_out.status != NGX_HTTP_OK) {
        return ngx_http_next_body_filter(r, chain);
    }

    ngx_markdown_filter_conf_t *lc = ngx_http_get_module_loc_conf(r, ngx_markdown_filter_module);
    if (!(lc->enable)) {
        return ngx_http_next_body_filter(r, chain);
    }

    ngx_markdown_filter_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_markdown_filter_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    cmark_parser *parser = ctx->parser;
    if (parser == NULL) {
        return NGX_ERROR;
    }

    int last = 0;
    for (ngx_chain_t *cl = chain; cl; cl = cl->next) {
        ngx_buf_t *buf = cl->buf;

        cmark_parser_feed(parser, (char *)(buf->pos), ngx_buf_size(buf));

        if (buf->last_buf) {
            last = 1;
        }
    }
    if (last) {
        cmark_node *root = cmark_parser_finish(parser);
        char *html = cmark_render_html(root, CMARK_OPT_DEFAULT);
        cmark_node_free(root); // remove document tree

        if (html == NULL) {
            return NGX_ERROR;
        }

        ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            ngx_free(html);
            return NGX_ERROR;
        }

        cln->handler = ngx_free;
        cln->data = html;

        ngx_buf_t *html_buf = ngx_calloc_buf(r->pool);
        html_buf->pos = (u_char *) html;
        html_buf->last = html_buf->pos + (strlen(html) - 1);
        html_buf->memory = 1;
        html_buf->last_buf = 1;
        html_buf->last_in_chain = 1;

        ngx_chain_t *html_chain = ngx_alloc_chain_link(r->pool);
        if (html_chain == NULL) {
            return NGX_ERROR;
        }

        html_chain->next = NULL;
        html_chain->buf = html_buf;

        return ngx_http_next_body_filter(r, html_chain);
    }

    return NGX_OK;
}
