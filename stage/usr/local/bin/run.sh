#!/bin/sh

# start okta-nginx
okta-nginx &
okta_nginx_pid=$!

okta_nginx_started="false"
for i in $(seq 0 50); do
    if [ -S "/var/run/auth.sock" ]; then
        okta_nginx_started="true"
        break
    fi
    sleep 0.1
done

if [ "$okta_nginx_started" = "false" ]; then
    echo "okta-nginx failed to start" >&2
    exit 1
fi
echo "okta-nginx started"

generate.sh

# start nginx
nginx -g 'daemon off;' &
nginx_pid=$!
echo "nginx started"

stop_signal () {
    exit 0
}

exit_signal () {
    kill "$okta_nginx_pid" "$nginx_pid" >/dev/null 2>&1
    wait "$okta_nginx_pid" "$nginx_pid"
}

trap stop_signal SIGINT SIGTERM
trap exit_signal EXIT

# monitor
while true; do
    if ! kill -0 "$okta_nginx_pid" >/dev/null 2>&1; then
        echo "okta-nginx has died" >&2
        exit 1
    fi
    if ! kill -0 "$nginx_pid" >/dev/null 2>&1; then
        echo "nginx has died" >&2
        exit 1
    fi
    sleep 0.1
done
