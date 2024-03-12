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
- `LOGIN_REDIRECT_URL` - Must be on the 'General' tab of the Web application that you created earlier in the Okta Developer Console.  Path should be `/sso/authorization-code/callback`, or `${SSO_PATH}/authorization-code/callback` if `SSO_PATH` is set.

### Optional

- `AUTH_SCOPE` - Defaults to `openid profile`. Okta token auth scopes - note if you override this `openid` is necessary for authentication requests.
- `APP_POST_LOGIN_URL` - After authentication is complete, redirect to an application-specific URL.  The `state` query parameter will hold the original URL.
- `COOKIE_DOMAIN` - Defaults to current domain only.  Set in order to allow use on subdomains.
- `COOKIE_NAME` - Defaults to `okta-jwt`. The name of the cookie that holds the Identity Token
- `INJECT_REFRESH_JS` - Defaults to `true`.  Set to `false` to disable injection of JavaScript that transparently refreshes Identity Tokens when they are close to expiring
- `ENDPOINT_AUTHORIZE` - Defaults to `${ISSUER}/v1/authorize`.  Alternate endpoint to redirect to for authorization.
- `ENDPOINT_LOGOUT` - Defaults to `${ISSUER}/v1/logout`.  Alternate endpoint to redirect to for logout.
- `ENDPOINT_TOKEN` - Defaults to `${ISSUER}/v1/token`.  Alternate endpoint to retrieve token from.
- `LISTEN` - Defaults to `80`.  Specify another port to change the listening port number.  See [nginx listen](http://nginx.org/en/docs/http/ngx_http_core_module.html#listen) for options, such as TLS and unix sockets
- `LOCATIONS_PROTECTED` - Defaults to `/`.  Comma separated list of [location](http://nginx.org/en/docs/http/ngx_http_core_module.html#location) blocks to protect before passing to `PROXY_PASS`.
- `LOCATIONS_UNPROTECTED` - Defaults is disabled.  Comma separated list of [location](http://nginx.org/en/docs/http/ngx_http_core_module.html#location) blocks that will not be protected and passed to `PROXY_PASS`.
- `LOGOUT_REDIRECT_URL` - Defaults is app origin URL.  URL to redirect to after logging out, can be relative or absolute.  Logout path is `/sso/logout`, or `${SSO_PATH}/logout` if `SSO_PATH` is set.
- `PROXY_SET_HEADER_NAMES` - Default is none.  Comma separated list of headers to add that will be passed upstream.  Must be accompanied by `PROXY_SET_HEADER_VALUES`.
- `PROXY_SET_HEADER_VALUES` - Default is none.  Comma separated list of values to associate with `PROXY_SET_HEADER_NAMES`.  Values are Go templates that execute against claims, for example `{{.groups}}`.
- `REQUEST_TIMEOUT` - Defaults to `30`.  Timeout for calling the Okta Endpoints
- `SERVER_NAME` - Defaults to `_`.  See [nginx server_name](http://nginx.org/en/docs/http/ngx_http_core_module.html#server_name) for options.
- `SSO_PATH` - Defaults to `/sso/`. Path for SSO error and refresh endpoints.  Should include leading and trailing slash
- `UPDATE_SCRIPT` - Default is none.  If desired, set to the full path of an executable shell script that updates the configuration.  One parameter will be passed to the script, it will be `true` on the first update and `false` on subsequent updates.
- `UPDATE_PERIOD_SECONDS` - Defaults to `60`.  If `UPDATE_SCRIPT` is defined, it will be called at startup, then every `UPDATE_PERIOD_SECONDS` to refresh the configuration.
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
    - `PROXY_PASS_2`: required
    - `LOGIN_REDIRECT_URL_2` required
    - `APP_POST_LOGIN_URL_2` optional
    - `COOKIE_DOMAIN_2` optional
    - `COOKIE_NAME_2` optional
    - `LOCATIONS_PROTECTED_2`: optional
    - `LOCATIONS_UNPROTECTED_2`: optional
    - `LOGOUT_REDIRECT_URL_2`: optional
    - `PROXY_SET_HEADER_NAMES_2`: optional
    - `PROXY_SET_HEADER_VALUES_2`: optional
    - `VALIDATE_CLAIMS_TEMPLATE_2`: optional
    - optionally add configuration to `/etc/nginx/includes/default-server.2.conf`
- Server N
    - `LISTEN_N`: required
    - `SERVER_NAME_N`: required
    - `PROXY_PASS_N`: required
    - `LOGIN_REDIRECT_URL_N` required
    - `APP_POST_LOGIN_URL_N` optional
    - `COOKIE_DOMAIN_N` optional
    - `COOKIE_NAME_N` optional
    - `LOCATIONS_PROTECTED_N`: optional
    - `LOCATIONS_UNPROTECTED_N`: optional
    - `LOGOUT_REDIRECT_URL_N`: optional
    - `PROXY_SET_HEADER_NAMES_N`: optional
    - `PROXY_SET_HEADER_VALUES_N`: optional
    - `VALIDATE_CLAIMS_TEMPLATE_N`: optional
    - optionally add configuration to `/etc/nginx/includes/default-server.N.conf`
