#!/bin/sh

extract_path () {
    echo "$1" | sed -r 's|^https?://[^/]+([^\?]+).*$|\1|ig'
}

ensure_path () {
    echo "/$1/" | sed -r 's:(^//|//$):/:ig'
}

to_lower () {
    echo "$1" | tr '[:upper:]' '[:lower:]'
}

alpha_numeric_underscore () {
    echo "$1" | sed -r 's/[^a-z0-9_]/_/ig'
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

# set SSO_PATH
if [ -z "$SSO_PATH" ]; then
    export SSO_PATH="/sso/"
fi
export SSO_PATH=$(ensure_path "$SSO_PATH")
# set APP_REDIRECT_PATH
export APP_REDIRECT_PATH=$(extract_path "$LOGIN_REDIRECT_URL")

# iterate through server configurations
env_var_suffix=""
env_vars="LISTEN LOCATIONS_PROTECTED LOCATIONS_UNPROTECTED PROXY_PASS PROXY_SET_HEADER_NAMES PROXY_SET_HEADER_VALUES SERVER_NAME VALIDATE_CLAIMS_TEMPLATE"
export SERVER_SUFFIX=""
i=1
while : ; do

    for env_var in $env_vars; do
        if eval [ ! -z "\${${env_var}${env_var_suffix}+x}" ]; then
            eval export $env_var=\$${env_var}${env_var_suffix}
        else
            eval unset $env_var
        fi
    done

    if [ ! -z "$SERVER_SUFFIX" \
        -a -z "${LISTEN}" \
        -a -z "${SERVER_NAME}" \
    ]; then
        break
    fi
    
    # set LISTEN
    if [ -z "${LISTEN+x}" ]; then
        export LISTEN="80";
    fi
    # set SERVER_NAME
    if [ -z "${SERVER_NAME+x}" ]; then
        export SERVER_NAME="_";
    fi
    # set PROXY_PASS
    rm -f /var/run/example-server.sock
    if [ -z "${PROXY_PASS+x}" \
        -a ! -f /etc/nginx/includes/default-server.conf \
        -a ! -f /etc/nginx/includes/proxy-pass.conf \
    ]; then
        export PROXY_PASS="http://unix:/var/run/example-server.sock"
        cp /etc/nginx/templates/example-server.conf /etc/nginx/conf.d/
    fi
    # set LOCATIONS_PROTECTED
    if [ -z "${LOCATIONS_PROTECTED+x}" ]; then
        export LOCATIONS_PROTECTED="/"
    fi

    touch "/etc/nginx/includes/default-server${SERVER_SUFFIX}.conf"
    touch "/etc/nginx/includes/proxy-pass-protected${SERVER_SUFFIX}.conf"
    touch "/etc/nginx/includes/proxy-pass-unprotected${SERVER_SUFFIX}.conf"

    IFS=','
    for location in $LOCATIONS_PROTECTED; do
        export LOCATION="$location"
        envsubst '${LOCATION},${PROXY_PASS}' \
            < /etc/nginx/templates/proxy-pass-protected.conf \
            >> "/etc/nginx/includes/proxy-pass-protected${SERVER_SUFFIX}.conf"
    done
    for location in $LOCATIONS_UNPROTECTED; do
        export LOCATION="$location"
        envsubst '${LOCATION},${PROXY_PASS}' \
            < /etc/nginx/templates/proxy-pass-unprotected.conf \
            >> "/etc/nginx/includes/proxy-pass-unprotected${SERVER_SUFFIX}.conf"
    done
    unset IFS

    if [ ! -z "${PROXY_SET_HEADER_NAMES+x}" \
        -a ! -z "${PROXY_SET_HEADER_VALUES+x}" ]; then
        IFS=','
        for header_name in ${PROXY_SET_HEADER_NAMES}; do
            auth_request_var=$(alpha_numeric_underscore $(to_lower $header_name))
            line="auth_request_set \$auth_request_${auth_request_var} \$upstream_http_${auth_request_var};"
            sed -i "/^}\$/i $line" "/etc/nginx/includes/proxy-pass-protected${SERVER_SUFFIX}.conf"
            line="proxy_set_header ${header_name} \$auth_request_${auth_request_var};"
            sed -i "/^}\$/i $line" "/etc/nginx/includes/proxy-pass-protected${SERVER_SUFFIX}.conf"
        done
        unset IFS
    fi

    # stamp out default.conf template
    envsubst '${APP_REDIRECT_PATH},${LISTEN},${PROXY_SET_HEADER_NAMES},${PROXY_SET_HEADER_VALUES},${SERVER_NAME},${SERVER_SUFFIX},${SSO_PATH},${VALIDATE_CLAIMS_TEMPLATE}' \
        < /etc/nginx/templates/default.conf \
        > "/etc/nginx/conf.d/default${SERVER_SUFFIX}.conf"

    i=$((i+1))
    env_var_suffix="_$i"
    export SERVER_SUFFIX=".$i"
done

# stamp out redirect-js.conf template
if [ "$INJECT_REFRESH_JS" != "false" ]; then
    export REFRESH_JS=$(/var/okta-nginx/refresh-minify.sh "$SSO_PATH")
    envsubst '${REFRESH_JS}' \
            < /etc/nginx/templates/refresh-js.conf \
            > /etc/nginx/includes/refresh-js.conf
fi

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
