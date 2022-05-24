## ngx_markdown_filter_module

The `ngx_markdown_filter_module` module is a filter that transforms markdown files to html format.

This module utilizes the [cmark](https://github.com/commonmark/cmark) library.

### Example configuration

```
location ~ \.md {
    markdown_filter on;
    markdown_template html/template.html;
}
```

This works on proxy locations as well.

### Directives

```
Syntax:  markdown_filter on;
Context: location
```

```
Syntax:  markdown_template html/template.html;
Context: location
```

### Build

1. Clone this repo

2. Install `cmark` lib with development headers

```
dnf install cmark-devel
```

3. Download nginx archive from http://nginx.org/en/download.html and extract it

4. Run `configure` script from nginx sources and build nginx

```
./configure --add-module=/path/to/ngx_markdown_filter_module
```

```
make
```

5. Apply markdown directives to nginx conf and run it
