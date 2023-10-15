# Varnish Caching + OAuth2 proxy

A varnish cache behind an OAuth2 proxy written in Python.

```
             ┌────────────┐   ┌─────────────┐   ┌───────────┐
             │  auth      │   │  cache      │   │  nginx    │
 request ───►│  :80       ├──►│  :8080      ├──►│  :8081    │
             │  (Python)  │   │  (varnish)  │   │           │
             └─────┬──────┘   └─────────────┘   └───────────┘
                   │
                   │          ┌─────────────┐
   gets jwks to    │          │  oidc       │
   validate token  └─────────►│  :8082      │
                              │  (idSrv)    │
                              └─────────────┘

```

## Getting Started

``` bash
$ docker compose build; docker compose up -d
$ token=$(curl http://localhost:8082/connect/token -d 'grant_type=client_credentials&client_id=cache.client&client_secret=secret&scope=cache' | jq .access_token -r)
$ curl http://localhost/big --header "Authorization: Bearer $token" -o /dev/null
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 1000M  100 1000M    0     0  96.1M      0  0:00:10  0:00:10 --:--:-- 96.3M

# Curl again, speed is quicker as Varnish has cached the previous request
$ curl http://localhost/big --header "Authorization: Bearer $token" -o /dev/null
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 1000M  100 1000M    0     0   621M      0  0:00:01  0:00:01 --:--:--  622M
```

## Why did you write your own Python proxy?

I couldn't find a simple proxy that supported JWT validation.

## Components

### Auth

Auth is a simple python HTTP server that proxies `GET` requests to the `cache` service and expects a valid JWT token signed by the `oidc` service.

It does not check whether the JWT contains the correct claims at the moment. That can be trivially added as it is supported by the underlying `PyJWT` library.

### Cache

Cache is a service running varnish with a very simple config, specifying `fetch` as the backend and allowing requests containing the `Authorization` header to be cached. The TTL of the objects is specified in the `Cache-Control` header returned by the `fetch` service.

It uses the `file` storage backend, specified on the command line in `compose.yaml`.

To see more information, you can run `varnishstat` and `varnishlog` in the container.

### Fetch

Fetch is a nginx service that contains 2 files: `/small` and `/big`. It simulates auth by verifying that the `Authorization` header is set, but does not validate the header value. Requests are rate-limited to 10 MB/s, to demonstrate cache hits on subsequent requests.

### OIDC

Oidc is a service running IdentityServer that issues tokens for the `auth` service.
