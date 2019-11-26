FROM golang:1.12.4-alpine3.9 AS build

ENV CGO_ENABLED=0

RUN apk add --no-cache \
        git

COPY / /root/okta-nginx

RUN cd /root/okta-nginx/ \
    && go build


FROM nginx:1.14.0-alpine

RUN apk add --no-cache \
        ca-certificates

COPY --from=build /root/okta-nginx/okta-nginx /usr/local/bin/okta-nginx

COPY stage/ /

CMD ["run.sh"]
