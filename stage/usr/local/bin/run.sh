#!/bin/sh

# stamp out nginx template
if [ -z "$UPSTREAM" ]; then
    export UPSTREAM="http://localhost:8080"
fi
envsubst '${UPSTREAM}' \
    < /etc/nginx/templates/default.conf \
    > /etc/nginx/conf.d/default.conf

# start okta-verify
okta-verify &
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
    echo "okta-verify failed to start" >&2
    exit 1
fi
echo "okta-verify started"

# start nginx
nginx -g 'daemon off;' &
nginx_pid=$!
echo "nginx started"

# monitor
while true; do
    if ! kill -0 "$okta_verify_pid"; then
        echo "okta-verify has died" >&2
        exit 1
    fi
    if ! kill -0 "$nginx_pid"; then
        echo "nginx has died" >&2
        exit 1
    fi
    sleep 0.1
done
