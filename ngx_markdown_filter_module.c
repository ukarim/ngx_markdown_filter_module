#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifdef WITH_CMARK_GFM
    #include <cmark-gfm.h>
    #include <cmark-gfm-extension_api.h>
    #include <cmark-gfm-core-extensions.h>
#else
    #include <cmark.h>
#endif


// pointers to next handlers

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;

static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


// location conf

typedef struct {
    ngx_flag_t enable;
    u_char *header;
    u_char *footer;
    ngx_int_t header_len;
    ngx_int_t footer_len;
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

static char *ngx_conf_set_template(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* module directives */

static ngx_command_t ngx_markdown_filter_commands[] = {

    { ngx_string("markdown_filter"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_markdown_filter_conf_t, enable),
      NULL },

    { ngx_string("markdown_template"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_template,
      NGX_HTTP_LOC_CONF_OFFSET,
      0, // unused
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


static char *ngx_conf_set_template(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    ngx_str_t filename = value[1];
    ngx_markdown_filter_conf_t *markdown_conf = (ngx_markdown_filter_conf_t *) conf;

    // TODO read template file from provided filename and parse it

    ngx_fd_t fd = ngx_open_file(filename.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "cannot open template file %s", filename.data);
        return NGX_CONF_ERROR;
    }

    ngx_file_info_t fi;
    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR){
        ngx_close_file(fd);
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "cannot get stats for template file %s", filename.data);
        return NGX_CONF_ERROR;
    }

    u_char *template = ngx_calloc(fi.st_size + 1, cf->log);
    if (template == NULL) {
        ngx_close_file(fd);
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "cannot allocate memory for template content");
        return NGX_CONF_ERROR;
    }

    ngx_file_t file;
    file.fd = fd;
    file.info = fi;
    file.log = cf->log;

    ngx_int_t n = ngx_read_file(&file, template, fi.st_size, 0);
    template[fi.st_size] = '\0';

    ngx_close_file(fd);

    for (ngx_int_t i = 0; i < n; i++) {
        if (template[i] == '{' && template[i+1] == '{') {
            template[i] = '\0';
            markdown_conf->header = template;
            markdown_conf->header_len = ngx_strlen(template);
            continue;
        }
        if (template[i] == '}' && template[i+1] == '}') {
            markdown_conf->footer = template + (i+2); // Note!! pointer arithmetic
            markdown_conf->footer_len = ngx_strlen(markdown_conf->footer);
            break;
        }
    }

    return NGX_CONF_OK;
}


static void *ngx_markdown_filter_create_conf(ngx_conf_t *cf)
{
    ngx_markdown_filter_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_markdown_filter_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->enable = NGX_CONF_UNSET;
    conf->header = NGX_CONF_UNSET_PTR;
    conf->footer = NGX_CONF_UNSET_PTR;
    conf->header_len = NGX_CONF_UNSET;
    conf->footer_len = NGX_CONF_UNSET;
    return conf;
}


static char *ngx_markdown_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_markdown_filter_conf_t *prev = parent;
    ngx_markdown_filter_conf_t *conf = child;
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_ptr_value(conf->header, prev->header, NULL);
    ngx_conf_merge_ptr_value(conf->footer, prev->footer, NULL);
    ngx_conf_merge_value(conf->header_len, prev->header_len, 0);
    ngx_conf_merge_value(conf->footer_len, prev->footer_len, 0);
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

#ifdef WITH_CMARK_GFM
        cmark_gfm_core_extensions_ensure_registered();
        cmark_syntax_extension *ext = cmark_find_syntax_extension("table");
        if (ext != NULL) {
            cmark_parser_attach_syntax_extension(parser, ext);
        }
#endif

        ctx->parser = parser;

        ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            cmark_parser_cleanup(parser);
            return NGX_ERROR;
        }
        cln->handler = cmark_parser_cleanup;
        cln->data = parser;

        ngx_http_set_ctx(r, ctx, ngx_markdown_filter_module);

        ngx_str_t mime = ngx_string("text/html;charset=utf-8");
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

        buf->pos = buf->last;
        buf->flush = 0;

        if (buf->last_buf) {
            last = 1;
        }
    }
    if (last) {
        cmark_node *root = cmark_parser_finish(parser);

#ifdef WITH_CMARK_GFM
        char *html = cmark_render_html(root, CMARK_OPT_DEFAULT, NULL);
#else
        char *html = cmark_render_html(root, CMARK_OPT_DEFAULT);
#endif

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

        ngx_chain_t *out_chain = NULL;

        // add header

        if (lc->header != NULL) {
            out_chain = ngx_alloc_chain_link(r->pool);
            if (out_chain == NULL) {
                return NGX_ERROR;
            }
            ngx_buf_t *header_buf = ngx_calloc_buf(r->pool);
            if (header_buf == NULL) {
                return NGX_ERROR;
            }
            header_buf->pos = lc->header;
            header_buf->last = header_buf->pos + lc->header_len;
            header_buf->memory = 1; // Set readonly flag, and do not create copy of lc->header
            header_buf->last_buf = 0;
            header_buf->last_in_chain = 0;

            out_chain->buf = header_buf;
            out_chain->next = NULL;
        }

        int footer_missing = lc->footer == NULL ? 1 : 0;

        // add markdown content

        ngx_chain_t *content_chain = ngx_alloc_chain_link(r->pool);
        if (content_chain == NULL) {
            return NGX_ERROR;
        }

        ngx_buf_t *content_buf = ngx_calloc_buf(r->pool);
        if (content_buf == NULL) {
            return NGX_ERROR;
        }
        content_buf->pos = (u_char *) html;
        content_buf->last = content_buf->pos + strlen(html);
        content_buf->memory = 1;
        content_buf->last_buf = footer_missing;
        content_buf->last_in_chain = footer_missing;

        content_chain->buf = content_buf;
        content_chain->next = NULL;

        if (out_chain == NULL) {
            out_chain = content_chain;
        } else {
            out_chain->next = content_chain;
        }

        // add footer

        if (!footer_missing) {
            ngx_chain_t *footer_chain = ngx_alloc_chain_link(r->pool);
            if (footer_chain == NULL) {
                return NGX_ERROR;
            }
            ngx_buf_t *footer_buf = ngx_calloc_buf(r->pool);
            if (footer_buf == NULL) {
                return NGX_ERROR;
            }
            footer_buf->pos = lc->footer;
            footer_buf->last = footer_buf->pos + lc->footer_len;
            footer_buf->memory = 1; // Set readonly flag, and do not create copy of lc->footer
            footer_buf->last_buf = 1;
            footer_buf->last_in_chain = 1;

            footer_chain->buf = footer_buf;
            footer_chain->next = NULL;

            content_chain->next = footer_chain;
        }

        return ngx_http_next_body_filter(r, out_chain);
    }

    return NGX_OK;
}
