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
Syntax:  markdown_filter on|off;
Context: location
```

```
Syntax:  markdown_template html/template.html;
Context: location
```

```
# enable `unsafe` mode for cmark
Syntax:  markdown_unsafe on|off;
Context: location;
```

```
# enable `tagfilter` extension for cmark-gfm
Syntax:  markdown_gfm_tagfilter on|off;
Context: location;
```

```
# enable `tasklist` extension for cmark-gfm
Syntax:  markdown_gfm_tasklist on|off;
Context: location;
```

```
# enable `strikethrough` extension for cmark-gfm
Syntax:  markdown_gfm_strikethrough on|off;
Context: location;
```

```
# enable `autolink` extension for cmark-gfm
Syntax: markdown_gfm_autolink on|off;
Context: location;
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

3. Install `cmark-gfm` lib

4. Download [nginx src archive](http://nginx.org/en/download.html) and unpack it

5. Run `configure` script (see nginx src) and build nginx

```
> ./configure --add-module=/path/to/ngx_markdown_filter_module
> make
```

6. Apply markdown directives to nginx conf and run it
