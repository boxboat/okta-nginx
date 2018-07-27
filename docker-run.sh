#!/bin/bash

cd $(dirname $0)

docker run \
    --rm \
    -p "8080:80" \
    boxboat/okta-nginx
