#!/bin/sh

cd $(dirname $0)
set -e

if [ -z "$BOXOPS_PROXY_SETTINGS_URL" ]; then
    echo "BOXOPS_PROXY_SETTINGS_URL must be set" >&2
    exit 1
fi

if [ -z "$BOXOPS_TEAM_PROXY_KEY" ]; then
    echo "BOXOPS_TEAM_PROXY_KEY must be set" >&2
    exit 1
fi


curl -fSsLo "proxy-settings.json" \
    -H "Authorization: Bearer ${BOXOPS_TEAM_PROXY_KEY}" \
    "$BOXOPS_PROXY_SETTINGS_URL"

if [ "$1" = "false" ]; then
    md5_sum=$(md5sum proxy-settings.json | cut -d' ' -f1)
    md5_sum_last=$(md5sum proxy-settings.last.json | cut -d' ' -f1)
    if [ "$md5_sum" = "$md5_sum_last" ]; then
        exit 0
    fi
fi

rm -f \
    "/etc/nginx/conf.d/default*.conf" \
    "/etc/nginx/conf.d/boxops-*.conf" \
    "/etc/nginx/includes/default-server*.conf"

jq -r ".environmentVariables" "proxy-settings.json" > vars.env
set -a
. ./vars.env
set +a

IFS=$';'
for jq_file in $JQ_FILES; do
    part_file=$(echo "$jq_file" | cut -d'=' -f1)
    part_jq=$(echo "$jq_file" | cut -d'=' -f2)
    mkdir -p $(dirname "$part_file")
    jq -r "$part_jq" "proxy-settings.json" > "$part_file"
done
unset IFS

./generate.sh
if [ "$1" = "false" ]; then
    nginx -s reload
fi

mv "proxy-settings.json" "proxy-settings.last.json"
