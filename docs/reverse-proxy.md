# Reverse Proxy Setup

Octoka needs to be combined with a reverse proxy (like nginx) to dispatch requests to Opencast and octoka accordingly.
The basic logic for incoming requests looks like this:

- For static file requests (i.e. starts with `/static`):
  - Can octoka authorize the request (i.e. it has a valid JWT)? If yes: serve file
  - If no: can Opencast authorize the request? If yes: serve file
  - If no: reply "403 Forbidden"
- For all other requests: simply forward request to Opencast

However, there are many different ways to make this happen.

> **Note**: this document uses nginx as example. Configs shown here are not complete and just show the general idea!

## Recommended setup

The simplest setup without notable disadvantages has nginx simply `proxy_pass` the request to octoka, which internally forwards it to OC if necessary.

### File serving by octoka

Relevant octoka config:
- `opencast.downloads_path` set correctly (e.g. `/mnt/opencast/downloads`)
- `opencast.host` set correctly (default: `localhost:8080`)
- `opencast.use_as_fallback = true` (this is the default)
- `http.on_allow = "file"` (this is the default)

Relevant nginx config:

```
location /static/ {
    proxy_set_header Host $http_host;
    proxy_pass http://127.0.0.1:4050; # octoka
}

location / {
    proxy_set_header Host $http_host;
    proxy_pass http://host.docker.internal:8080; # Opencast
}
```

### File serving by nginx

While octoka has a powerful and fast file-server built-in, it of course does not quite match the performance and feature-set of nginx.
To use the latter for file serving, set `http.on_allow = "x-accel-redirect:/protected"` in octoka and add the following block to the nginx config:

```
location /protected {
    internal;
    alias /mnt/opencast/downloads; # Adjust!
}
```

Octoka then replies with either 403 or an `X-Accel-Redirect`.
That header is then interpreted by nginx which serves the file.

<br>

---

<br>

## Other setups

These other setups are not necessarily bad, but tend to require a bit more configuration.
They are listed here mostly for completeness and to show what's possible, should you require a specialized setup.
In the following the `location / { ... }` block is omitted, as it's the same for all setups.

Like the recommended solutions, most of these other solutions come in two variants: built-in file serving by octoka/Opencast and file serving by nginx.
As above, to make nginx serve the files you need to use `X-Accel-Redirect`: configure it in octoka and Opencast and add the additional nginx block.
Only the `auth_request` method does not have these two variants, as it always lets nginx serve the files.

### Option "`auth_request`"

- `opencast.host` set correctly (default: `localhost:8080`)
- `opencast.use_as_fallback = true` (this is the default)
- `http.on_allow = "empty"`

```
location /static/ {
    auth_request /octoka;
    alias /mnt/opencast/downloads/;
}

location /octoka {
    internal;
    proxy_set_header Host $http_host;
    proxy_pass http://127.0.0.1:4050$request_uri;
}
```

Instead of using `use_as_fallback`, you can implement the fallback inside `location /` with the tricks below, but at that point it's getting really involved and I can't think of a reason to go down that route.

### Option "`error_page`"

- `opencast.use_as_fallback = false`

```
location /static {
    error_page 403 = @oc_static_files;
    proxy_intercept_errors on;
    proxy_pass http://127.0.0.1:4050; # octoka
}

location @oc_static_files {
    proxy_set_header Host $http_host;
    proxy_pass http://127.0.0.1:8080; # Opencast
}
```

This can use built-in file serving or nginx file server via `X-Accel-Redirect`.

### Fallback via `X-Accel-Redirect`

This is needlesly complicated compared with other methods...

- `http.on_deny = "x-accel-redirect:/static-opencast-fallback"`

```
# Try Octoka first. If it cannot allow, it will X-Accel-Redirect to ...
location /static/ {
    proxy_set_header Host $http_host;
    proxy_pass http://127.0.0.1:4050;
}

# ... here! And now we just forward the request to Opencast.
location /static-opencast-fallback {
    internal;
    proxy_set_header Host $http_host;
    # Strip internal path prefix
    rewrite ^/static-opencast-fallback/(.*)$ $1 break;
    proxy_pass http://127.0.0.1:8080;
}
```

This can use built-in file serving or nginx file server via `X-Accel-Redirect`.
