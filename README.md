# okta-nginx

This repository builds a Docker Image that protects an upstream server using [Okta's OpenID Connect](https://developer.okta.com/docs/api/resources/oidc) `Authorization Code` flow

## Prerequisites

- [Okta Developer](https://developer.okta.com/) account
- An Open ID Connect application supporting the `Authorization Code` flow

## Environment Variables

### Required

- `UPSTREAM_ORIGIN` - The upstream origin to proxy authenticated requests to.  Should include scheme, host, and port e.g. `http://localhost:8080`
- `CLIENT_ID` - The Client ID can be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console
- `CLIENT_SECRET` - The Client Secret be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console
- `ISSUER` - Issuer is the URL of the authorization server that will perform authentication. All Developer Accounts have a 'default' authorization server. The issuer is a combination of your Org URL (found in the upper right of the console home page) and /oauth2/default. For example, `https://xxxxx.oktapreview.com/oauth2/default`
- `LOGIN_REDIRECT_URL` - The Login Redirect URL can be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console

### Optional

- `COOKIE_NAME` - Defaults to `okta-jwt`. The name of the cookie that holds the Authorization Token
- `INJECT_REFRESH_JS` - Defaults to `true`.  Set to `false` to disable injection of JavaScript that transparently refreshes Access Tokens when they are close to expiring
- `REQUEST_TIMEOUT` - Defaults to `5`.  Timeout for calling the Okta `token` endpoint to retrieve an Authorization Token

## Authenticated Headers Passed to Upstream Server

- `X-Forwarded-User` - Contains the forwarded user's username.  Comes from the `sub` assertion in the Auth Token.

## Install From Source

1.  Build container `./docker-build.sh`
2.  Set environment variables in vars.env to match your deployment
3.  Run container `./docker-run.sh`
