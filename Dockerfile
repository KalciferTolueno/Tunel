# ---- Builder ----
FROM golang:1.24-alpine AS builder
ENV GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /tunels ./cmd/tunels

# ---- Runtime ----
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /tunels /usr/local/bin/tunels
COPY docker-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

RUN adduser -D -u 1000 tunel
USER tunel

VOLUME /certs

EXPOSE 9000/tcp
EXPOSE 3478/udp
EXPOSE 9001/tcp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]