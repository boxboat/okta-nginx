#!/bin/bash

cd $(dirname $0)

if [ -f "vars.env" ]; then
    set +a
    . ./vars.env
    set -a
fi

docker run \
    --rm \
    -e "CLIENT_ID=$CLIENT_ID" \
    -e "CLIENT_SECRET=$CLIENT_SECRET" \
    -e "ISSUER=$ISSUER" \
    -e "LOGIN_REDIRECT_URL=$LOGIN_REDIRECT_URL" \
    -p "8080:80" \
    boxboat/okta-nginx
