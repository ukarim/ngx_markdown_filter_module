## ngx_markdown_filter_module

The `ngx_markdown_filter_module` module is a filter that transforms markdown files to html format.

This module utilizes the [cmark](https://github.com/commonmark/cmark) library.

### Example configuration

```
location ~ \.md {
    markdown_filter on;
}
```

This works on proxy locations as well.

### Directives

```
Syntax:  markdown_filter on;

Default: markdown_filter off;

Context: location
```
