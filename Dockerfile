FROM --platform=linux/amd64 cgr.dev/chainguard/wolfi-base@sha256:077b746426fe23fdca2edbc270a5695c6c03ad26b8e8006fcb2d8e0a7740cc28 as build

ENV CGO_ENABLED=0

RUN apk add --no-cache \
        git go-1.21

COPY / /root/okta-nginx

RUN cd /root/okta-nginx/ \
    && go build


FROM --platform=linux/amd64 cgr.dev/chainguard/wolfi-base@sha256:077b746426fe23fdca2edbc270a5695c6c03ad26b8e8006fcb2d8e0a7740cc28

RUN apk add --no-cache \
        ca-certificates \
        curl \
        jq \ 
        nginx

COPY --from=build /root/okta-nginx/okta-nginx /usr/local/bin/okta-nginx

COPY stage/ /

CMD ["run.sh"]
