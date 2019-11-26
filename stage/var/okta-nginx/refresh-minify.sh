#!/bin/sh
# argument $1: application origin
# argument $2: SSO path

cd $(dirname $0)

echo '<script type="text/javascript">'$(\
    sed -r 's/console\.log\([^\)]+\);?//g' refresh.js \
    | sed -r 's|///.*||g' \
    | sed ':a;N;$!ba;s/\n/ /g' \
    | sed -r 's/\s+/ /g' \
    | sed -r "s|/sso/|${1}|g" \
    | sed -r "s/'/\\\'/g"
)'</script>'
