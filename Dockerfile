FROM golang:alpine

RUN apk add --no-cache git ca-certificates

WORKDIR /go/src/github.com/orkunkaraduman/nyx
COPY * ./

RUN go-wrapper download
RUN go-wrapper install

WORKDIR /app
RUN cp -a /go/bin/nyx ./

ENTRYPOINT ["./nyx"]
