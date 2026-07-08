# ---- Builder ----
FROM golang:1.24-alpine AS builder

# Use local toolchain (avoid auto-downloading go1.26 from go.mod)
ENV GOTOOLCHAIN=local

WORKDIR /src

# Dependencies first (cached layer)
COPY go.mod go.sum ./
RUN go mod download

# Source code
COPY . .

# Build only tunels (no CGO, no Fyne, no wintun — server-only)
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /tunels ./cmd/tunels

# ---- Runtime ----
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /tunels /usr/local/bin/tunels

# Non-root user
RUN adduser -D -u 1000 tunel
USER tunel

VOLUME /certs

EXPOSE 9000/tcp
EXPOSE 3478/udp
EXPOSE 9001/tcp

ENTRYPOINT ["tunels"]
CMD ["--bind", ":9000",
     "--cert", "/certs/server.crt",
     "--key",  "/certs/server.key",
     "--vpn",
     "--stun-bind", ":3478",
     "--dashboard-bind", ":9001",
     "--log-level", "info"]