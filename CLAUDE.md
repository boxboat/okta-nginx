# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an Okta-based authentication proxy built with Go and NGINX. It protects upstream servers using Okta's OpenID Connect Authorization Code flow. The system consists of:

1. **Go authentication server** (`server.go`) - Handles Okta OAuth2/OIDC authentication flow via Unix socket
2. **NGINX reverse proxy** - Routes requests, validates authentication, and proxies to upstream servers
3. **Docker-based deployment** - Multi-stage build with Go compilation and NGINX runtime

## Architecture

### Authentication Flow

1. NGINX receives request and validates JWT cookie/bearer token via auth subrequest to `/auth/validate`
2. Go server (`server.go`) communicates with NGINX via Unix socket at `/var/run/auth.sock`
3. Unauthenticated requests redirect to Okta login with state parameter preserving original URL
4. After Okta authentication, callback handler at `LOGIN_REDIRECT_URL` exchanges auth code for JWT
5. JWT access token stored in HTTP-only cookie and validated on subsequent requests
6. Optional JavaScript injection provides transparent token refresh before expiration

### Key Components

- **validateCookieHandler** (server.go:216): Main auth validation endpoint, supports both cookie and bearer token auth, executes claim validation templates, sets custom headers from claims
- **callbackHandler** (server.go:328): Processes OAuth2 callback, exchanges code for JWT, validates cookie domain against state URL
- **refreshCheckHandler** (server.go:433): Checks token expiration, triggers refresh if <5 minutes remaining
- **generate.sh**: Generates NGINX config from environment variables, supports multiple server configurations with `_N` suffix pattern
- **run.sh**: Container entrypoint that starts both okta-nginx and nginx processes, monitors both for failures

### CORS Handling

The proxy properly handles CORS preflight (OPTIONS) requests to prevent authentication blocking:

- **Protected locations** (proxy-pass-protected.conf): OPTIONS requests are handled BEFORE auth_request, returning 204 with appropriate CORS headers
- **CORS headers mirror the Origin**: Uses `$http_origin` variable to echo back the requesting origin with `Access-Control-Allow-Credentials: true`
- **Actual responses include CORS headers**: All proxied responses include CORS headers using `add_header ... always` directive
- **No authentication for OPTIONS**: OPTIONS preflight requests bypass JWT validation entirely, as required by CORS specification

### NGINX Configuration

Configuration is dynamically generated from templates in `stage/etc/nginx/templates/` based on environment variables. The system supports:
- Multiple protected/unprotected location blocks per server
- Multiple server configurations (SERVER_NAME_2, LISTEN_2, etc.)
- Custom headers populated from JWT claims using Go templates
- Claim validation using Go templates with sprig functions

## Development Commands

### Build and Run Locally

```bash
# Build Docker image
./docker-build.sh

# Configure environment (copy and edit vars-example.env to vars.env)
cp vars-example.env vars.env
# Edit vars.env with your Okta credentials

# Run container
./docker-run.sh
```

### Build for Production

```bash
# Build and push to ECR (requires AWS credentials)
make build push
```

### Build Go Binary Directly

```bash
go build
```

## Configuration

Required environment variables (see vars-example.env):
- `CLIENT_ID`, `CLIENT_SECRET` - From Okta application
- `ISSUER` - Authorization server URL (e.g., `https://xxx.oktapreview.com/oauth2/default`)
- `AUDIENCE` - Usually `api://default`
- `LOGIN_REDIRECT_URL` - Callback URL (e.g., `http://localhost:8080/sso/authorization-code/callback`)
- `PROXY_PASS` - Upstream server to protect

Optional but important:
- `VALIDATE_CLAIMS_TEMPLATE` - Go template for claim validation (returns "true" or "1" for authorized)
- `PROXY_SET_HEADER_NAMES`/`PROXY_SET_HEADER_VALUES` - Custom headers from claims (comma-separated)
- `INJECT_REFRESH_JS` - Defaults to "true", set "false" to disable auto-refresh

## Key Files

- `server.go` - Main Go application handling authentication
- `stage/usr/local/bin/run.sh` - Container entrypoint
- `stage/usr/local/bin/generate.sh` - NGINX config generator
- `stage/etc/nginx/templates/` - NGINX configuration templates
- `Dockerfile` - Multi-stage build (Go compile + NGINX runtime)

## Notes

- The Go server uses the `okta-jwt-verifier-golang` library for JWT validation
- Template caching is used for claim validation and header value templates to improve performance
- The system validates that redirect URLs match the configured cookie domain to prevent open redirects
- Bearer token authentication is supported via `Authorization: Bearer <token>` header as an alternative to cookies
- X-Forwarded-Proto and X-Forwarded-Host headers are used to construct redirect URLs when behind a proxy
