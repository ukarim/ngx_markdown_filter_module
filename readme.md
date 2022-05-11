# ngx_markdown_filter_module

Nginx module that converts markdown files to html.

### Usage

```
location ~* \.md {
    markdown_filter on;
}
```

### Dependencies

* https://github.com/commonmark/cmark
