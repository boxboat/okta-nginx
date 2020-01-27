#!/bin/sh

cd $(dirname $0)
set -e

# set UPDATE_PERIOD_SECONDS
if [ -z "$UPDATE_PERIOD_SECONDS" ]; then
    export UPDATE_PERIOD_SECONDS="60"
fi

# variables
update=$(if [ -n "$UPDATE_SCRIPT" ]; then echo "true"; else echo "false"; fi)
update_pid=""

# run update script and start okta-nginx
if [ "$update" = "true" ]; then
    (
        . "$UPDATE_SCRIPT" "true"
        exec okta-nginx
    ) &
    okta_nginx_pid=$!
else
    generate.sh
    okta-nginx &
    okta_nginx_pid=$!
fi

okta_nginx_started="false"
for i in $(seq 0 50); do
    if [ -S "/var/run/auth.sock" ]; then
        okta_nginx_started="true"
        break
    elif ! kill -0 "$okta_nginx_pid" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

if [ "$okta_nginx_started" = "false" ]; then
    echo "okta-nginx failed to start" >&2
    exit 1
fi
echo "okta-nginx started"

# start nginx
nginx -g 'daemon off;' &
nginx_pid=$!
echo "nginx started"

stop_signal () {
    exit 0
}

exit_signal () {
    kill $okta_nginx_pid $nginx_pid $update_pid >/dev/null 2>&1
    wait $okta_nginx_pid $nginx_pid $update_pid
}

trap stop_signal SIGINT SIGTERM
trap exit_signal EXIT

# monitor
start=$(date +%s)
while true; do
    now=$(date +%s)
    if [ "$update" = "true" ]; then
        if [ -n "$update_pid" ] && ! kill -0 "$update_pid" >/dev/null 2>&1; then
            update_pid=""
        fi
        if [ -z "$update_pid" ] && [ $((now-start)) -gt "$UPDATE_PERIOD_SECONDS" ]; then
            "$UPDATE_SCRIPT" "false" &
            update_pid=$!
            start=$(date +%s)
        fi
    fi
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
