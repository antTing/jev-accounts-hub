FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/jevproxy ./cmd/jevproxy

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/jevproxy /usr/local/bin/jevproxy
VOLUME /data
ENV JEVPROXY_DATA_DIR=/data
ENV JEVPROXY_LISTEN=:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/jevproxy"]
