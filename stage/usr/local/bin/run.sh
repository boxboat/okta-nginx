#!/bin/sh

extract_scheme () {
    echo "$1" | sed -r 's|^(https?)://.*$|\1|ig'
}

extract_host () {
    echo "$1" | sed -r 's|^https?://([^/]+).*$|\1|ig'
}

extract_origin () {
    echo "$1" | sed -r 's|^(https?://[^/]+)(/.*)$|\1|ig'
}

extract_path () {
    echo "$1" | sed -r 's|^https?://[^/]+([^\?]+).*$|\1|ig'
}

ensure_path () {
    echo "/$1/" | sed -r 's:(^//|//$):/:ig'
}

# start okta-nginx
okta-nginx &
okta_verify_pid=$!

okta_verify_started="false"
for i in $(seq 0 50); do
    if [ -S "/var/run/auth.sock" ]; then
        okta_verify_started="true"
        break
    fi
    sleep 0.1
done

if [ "$okta_verify_started" = "false" ]; then
    echo "okta-nginx failed to start" >&2
    exit 1
fi
echo "okta-nginx started"

# set SSO path
if [ -z "$SSO_PATH" ]; then
    export SSO_PATH="/sso/"
fi
export SSO_PATH=$(ensure_path "$SSO_PATH")

# stamp out redirect-js.conf template
if [ "$INJECT_REFRESH_JS" != "false" ]; then
    app_origin=$(extract_origin "$LOGIN_REDIRECT_URL")
    export REFRESH_JS=$(/var/okta-nginx/refresh-minify.sh "$app_origin" "$SSO_PATH")
    envsubst '${REFRESH_JS}' \
            < /etc/nginx/templates/refresh-js.conf \
            > /etc/nginx/includes/refresh-js.conf
fi

# stamp out default.conf template
if [ -z "$PROXY_PASS" ]; then
    export PROXY_PASS="http://unix:/var/run/example-server.sock"
    cp /etc/nginx/templates/example-server.conf /etc/nginx/conf.d/
fi
export APP_REDIRECT_PATH=$(extract_path "$LOGIN_REDIRECT_URL")
envsubst '${APP_REDIRECT_PATH},${PROXY_PASS},${SSO_PATH}' \
        < /etc/nginx/templates/default.conf \
        > /etc/nginx/conf.d/default.conf

# start nginx
nginx -g 'daemon off;' &
nginx_pid=$!
echo "nginx started"

# monitor
while true; do
    if ! kill -0 "$okta_verify_pid"; then
        echo "okta-nginx has died" >&2
        exit 1
    fi
    if ! kill -0 "$nginx_pid"; then
        echo "nginx has died" >&2
        exit 1
    fi
    sleep 0.1
done
