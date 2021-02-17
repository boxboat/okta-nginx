FROM golang:1.16.0-alpine3.13 AS build

ENV CGO_ENABLED=0

RUN apk add --no-cache \
        git

COPY / /root/okta-nginx

RUN cd /root/okta-nginx/ \
    && go build


FROM nginx:1.18.0-alpine

RUN apk add --no-cache \
        ca-certificates \
        curl \
        jq

COPY --from=build /root/okta-nginx/okta-nginx /usr/local/bin/okta-nginx

COPY stage/ /

CMD ["run.sh"]
