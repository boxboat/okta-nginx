FROM golang:1.23.4-alpine3.21 AS build

ENV CGO_ENABLED=0

RUN apk add --no-cache \
        git

COPY / /root/okta-nginx

RUN cd /root/okta-nginx/ \
    && go build


FROM nginx:1.26.2-alpine

RUN apk add --no-cache \
        ca-certificates \
        curl \
        jq

COPY --from=build /root/okta-nginx/okta-nginx /usr/local/bin/okta-nginx

COPY stage/ /

CMD ["run.sh"]
