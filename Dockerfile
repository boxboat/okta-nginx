FROM golang:alpine3.7 AS build

COPY *.go /go/src/github.com/boxboat/okta-verify/

RUN cd /go/src/github.com/boxboat/okta-verify/ \
    && go get \
    && go build


FROM nginx:alpine

COPY --from=build /go/src/github.com/boxboat/okta-verify/okta-verify /usr/local/bin/okta-verify

COPY stage/ /

CMD ["run.sh"]