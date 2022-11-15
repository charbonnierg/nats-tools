FROM alpine:latest as certs

RUN apk add ca-certificates

FROM scratch

COPY --from=certs /etc/ssl /etc/ssl
COPY --from=nats:2.9.3 /nats-server /nats-server

ENTRYPOINT ["/nats-server"]
