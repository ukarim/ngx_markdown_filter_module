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

3. Download [nginx src archive](http://nginx.org/en/download.html) and unpack it

4. Run `configure` script (see nginx src) and build nginx

```
> ./configure --add-module=/path/to/ngx_markdown_filter_module
> make
```

5. Apply markdown directives to nginx conf and run it

### Build with cmark-gfm (tables support)

Original cmark library doesn't support tables. But there is [cmark-gfm](https://github.com/github/cmark-gfm)
fork with table extension, supported by Github.

1. Clone this repo

2. Rename `config_gfm` to `config`

2. Install `cmark-gfm` lib

3. Download [nginx src archive](http://nginx.org/en/download.html) and unpack it

4. Run `configure` script (see nginx src) and build nginx

```
> ./configure --add-module=/path/to/ngx_markdown_filter_module --with-cc-opt=-DWITH_CMARK_GFM=1
> make
```

5. Apply markdown directives to nginx conf and run it
