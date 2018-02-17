FROM golang:alpine

RUN apk add --no-cache git ca-certificates

WORKDIR /go/src/github.com/orkunkaraduman/nyx
COPY * ./

RUN go-wrapper download
RUN go-wrapper install

WORKDIR /app
COPY nyx.conf ./
COPY server.crt.pem ./
COPY server.key.pem ./
COPY mitm.crt.pem ./
COPY mitm.key.pem ./
ONBUILD COPY nyx.conf ./
ONBUILD COPY server.crt.pem ./
ONBUILD COPY server.key.pem ./
ONBUILD COPY mitm.crt.pem ./
ONBUILD COPY mitm.key.pem ./

ENTRYPOINT ["nyx"]
