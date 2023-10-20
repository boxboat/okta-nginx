#!/bin/bash

cd $(dirname $0)

docker build --platform linux/amd64 -t boxboat/okta-nginx .