FROM cgr.dev/chainguard/go@sha256:0de8c7f5835e3f14a87b543a88263f98f20651b0530072cb1ab41ce9d523bb86 as build

ENV CGO_ENABLED=0

COPY / /root/okta-nginx

RUN cd /root/okta-nginx/ \
    && go build

FROM cgr.dev/chainguard/nginx@sha256:fd16202667e3c93737f49755973be5e83d3c41d09000ea5040ab9af0da8a1ad5

COPY --from=build /root/okta-nginx/okta-nginx /usr/local/bin/okta-nginx

COPY stage/ /

CMD ["run.sh"]
