# okta-nginx

This repository builds a Docker Image that protects an upstream server using [Okta's OpenID Connect](https://developer.okta.com/docs/api/resources/oidc) `Authorization Code` flow

## Prerequisites

- [Okta Developer](https://developer.okta.com/) account
- An Open ID Connect application supporting the `Authorization Code` flow

## Environment Variables

### Required

- `PROXY_PASS` - The upstream to proxy authenticated requests to.  Should include scheme, host, and port e.g. `http://localhost:8080`
- `CLIENT_ID` - The Client ID can be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console
- `CLIENT_SECRET` - The Client Secret be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console
- `ISSUER` - Issuer is the URL of the authorization server that will perform authentication. All Developer Accounts have a 'default' authorization server. The issuer is a combination of your Org URL (found in the upper right of the console home page) and /oauth2/default. For example, `https://xxxxx.oktapreview.com/oauth2/default`
- `AUDIENCE` - The Audience can be found on the 'Settings' tab of the Authorization Server.  The 'default' authorization server uses the audience `api://default`
- `LOGIN_REDIRECT_URL` - The Login Redirect URL can be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console

### Optional

- `COOKIE_DOMAIN` - Defaults to current domain only.  Set in order to allow use on subdomains.
- `COOKIE_NAME` - Defaults to `okta-jwt`. The name of the cookie that holds the Authorization Token
- `INJECT_REFRESH_JS` - Defaults to `true`.  Set to `false` to disable injection of JavaScript that transparently refreshes Access Tokens when they are close to expiring
- `LISTEN` - Defaults to `80`.  Specify another port to change the listening port number.  See [nginx listen](http://nginx.org/en/docs/http/ngx_http_core_module.html#listen) for options, such as TLS and unix sockets
- `REQUEST_TIMEOUT` - Defaults to `5`.  Timeout for calling the Okta `token` endpoint to retrieve an Authorization Token
- `SERVER_NAME` - Defaults to `_`.  See [nginx server_name](http://nginx.org/en/docs/http/ngx_http_core_module.html#server_name) for options.
- `SSO_PATH` - Defaults to `/sso/`. Path for SSO error and refresh endpoints.  Should include leading and trailing slash
- `USE_PROXY_PASS` - Defaults to `true`.  Set to `false` to use configuration in `server` block instead.
- `VALIDATE_CLAIMS_TEMPLATE` - Default is disabled. Go template to execute against claims, must return `true` or `1`.  [sprig](http://masterminds.github.io/sprig/) functions are available.  Example: `{{if or (has "default" .groups) (has "admin" .groups)}}true{{else}}false{{end}}`

## Authenticated Headers Passed to Upstream Server

- `X-Forwarded-User` - Contains the forwarded user's username.  Comes from the `sub` assertion in the Auth Token.

## Install From Source

1.  Build container `./docker-build.sh`
2.  Set environment variables in vars.env to match your deployment
3.  Run container `./docker-run.sh`

## Customize NGINX Configuration

### Adding Configuration to the `http` block

Any files added to `/etc/nginx/conf.d` will be included in the `http` block.

### Adding Configuration to the `server` block

Any content in the file `/etc/nginx/includes/default-server.conf` will be included in the default `server` block.

## Multiple Servers

Multiple servers are supported by incrementing a number starting with 2 to select environment variables.

- Server 2
    - `LISTEN_2`: required
    - `SERVER_NAME_2`: required
    - `PROXY_PASS_2`: required unless `USE_PROXY_PASS_2` is `false`
    - `USE_PROXY_PASS_2`: optional
    - `VALIDATE_CLAIMS_TEMPLATE_2`: optional
    - optionally add configuration to `/etc/nginx/includes/default-server.2.conf`
- Server N
    - `LISTEN_N`: required
    - `SERVER_NAME_N`: required
    - `PROXY_PASS_N`: required unless `USE_PROXY_PASS_N` is `false`
    - `USE_PROXY_PASS_N`: optional
    - `VALIDATE_CLAIMS_TEMPLATE_N`: optional
    - optionally add configuration to `/etc/nginx/includes/default-server.N.conf`

Multiple servers all use the same Okta Authorization Server and the same `LOGIN_REDIRECT_URL`.  Multiple servers should either be on the same host with different ports, or on subdomains are all valid for `COOKIE_DOMAIN`.
