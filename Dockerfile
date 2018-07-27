FROM golang:alpine3.7 AS build

COPY *.go /go/src/github.com/boxboat/okta-nginx/

RUN cd /go/src/github.com/boxboat/okta-nginx/ \
    && go get \
    && go build


FROM nginx:alpine

COPY --from=build /go/src/github.com/boxboat/okta-nginx/okta-nginx /usr/local/bin/okta-nginx

COPY stage/ /

CMD ["run.sh"]