#!/bin/sh

extract_host () {
    echo "$1" | sed -r 's|(https?://[^/]+)(/.*)|\1|g'
}

extract_path () {
    echo "$1" | sed -r 's|(https?://[^/]+)(/.*)|\2|g'
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

# set upstream server
if [ -z "$UPSTREAM_SERVER" ]; then
    export UPSTREAM_SERVER="unix:/var/run/default-server.sock"
    cp /etc/nginx/templates/default-server.conf /etc/nginx/conf.d/
fi
if [ ! -f "/etc/nginx/conf.d/upstream-server.conf" ]; then
    envsubst '${UPSTREAM_SERVER}' \
        < /etc/nginx/templates/upstream-server.conf \
        > /etc/nginx/conf.d/upstream-server.conf
fi

# stamp out redirect-js.conf template
if [ "$INJECT_REFRESH_JS" != "false" ]; then
    app_origin=$(extract_host "$LOGIN_REDIRECT_URL")
    export REFRESH_JS=$(/var/okta-nginx/refresh-minify.sh "$app_origin")
    envsubst '${REFRESH_JS}' \
            < /etc/nginx/templates/refresh-js.conf \
            > /etc/nginx/includes/refresh-js.conf
fi

# stamp out default.conf template
export APP_REDIRECT_PATH=$(extract_path "$LOGIN_REDIRECT_URL")
envsubst '${APP_REDIRECT_PATH}' \
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
