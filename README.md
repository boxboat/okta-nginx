# okta-nginx
NGINX Docker image with Okta OIDC JWT Verification

This image includes a authentication proxy nginx module for authenticating with the Okta Authentication API.

## Environment Variables

  -  CLIENT_ID - The Client ID can be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console.
  - CLIENT_SECRET - The Client Secret be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console
  - ISSUER - Issuer is the URL of the authorization server that will perform authentication. All Developer Accounts have a 'default' authorization server. The issuer is a combination of your Org URL (found in the upper right of the console home page) and /oauth2/default. For example, https://dev-1234.oktapreview.com/oauth2/default.
  - LOGIN_REDIRECT_URL - The Login Redirect URL can be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console.



## Instalation from source

1.  Build container `./docker-build.sh`
2.  Set environment variables in vars.env to match your deployment
3.  Run container `./docker-run.sh`

##  Change default service

Modify `./stage/etc/nginx/include/templates/default.conf`
to point to your service
```
    location / {
        proxy_pass http://www.example.com
    }
```

The proxy config can also be mounted into the container at `/etc/nginx/templates/default.conf`  esure you copy paste the authentication portion from this repo
