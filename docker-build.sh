#!/bin/bash

cd $(dirname $0)

docker build -t boxboat/okta-nginx .