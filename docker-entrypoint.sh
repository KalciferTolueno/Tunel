#!/bin/sh
set -e

if [ -z "$TUNEL_TOKEN" ]; then
  echo "ERROR: TUNEL_TOKEN environment variable is required"
  exit 1
fi

CERT="${TUNEL_CERT:-/certs/server.crt}"
KEY="${TUNEL_KEY:-/certs/server.key}"
ALLOWED_PORTS="${TUNEL_ALLOWED_PORTS:-25565,19132,2456,7777,8080}"
BIND="${TUNEL_BIND:-:9000}"
VPN="${TUNEL_VPN:-true}"
STUN_BIND="${TUNEL_STUN_BIND:-:3478}"
DASHBOARD_BIND="${TUNEL_DASHBOARD_BIND:-:9001}"
LOG_LEVEL="${TUNEL_LOG_LEVEL:-info}"

ARGS="--bind $BIND --token $TUNEL_TOKEN --allowed-ports $ALLOWED_PORTS --stun-bind $STUN_BIND --dashboard-bind $DASHBOARD_BIND --log-level $LOG_LEVEL"

if [ "$VPN" = "true" ]; then
  ARGS="$ARGS --vpn"
fi

# TLS (disabled by default)
if [ "${TUNEL_TLS:-false}" = "true" ]; then
  if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    mkdir -p /certs
    openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" \
      -days 3650 -nodes -subj "/CN=tunel-server" 2>/dev/null
    echo "Self-signed TLS cert generated."
  fi
  ARGS="$ARGS --tls --cert $CERT --key $KEY"
else
  echo "TLS disabled (plain TCP). Set TUNEL_TLS=true to enable."
fi

echo "tunels starting with: $ARGS"
exec tunels $ARGS