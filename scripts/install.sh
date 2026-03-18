#!/bin/bash

# Floki RTP Relay - Installation Script

set -e

# Resolve repo root regardless of where the script is called from
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BINARY_DST="/usr/local/bin/floki"
CONF_DIR="/etc/floki"
CONF_SRC="$REPO_ROOT/configs/floki.conf"
CONF_DST="$CONF_DIR/floki.conf"
SERVICE_SRC="$REPO_ROOT/deploy/floki.service"
SERVICE_DST="/etc/systemd/system/floki.service"

echo "================================================"
echo "  Floki RTP Relay - Installation"
echo "================================================"
echo ""

# Must run as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: this script must be run as root."
    exit 1
fi

# Go is required to build
if ! command -v go &>/dev/null; then
    echo "Error: Go is not installed. Please install Go 1.23 or higher."
    echo "  https://golang.org/doc/install"
    exit 1
fi

# iptables must be available
if ! command -v iptables &>/dev/null; then
    echo "Error: iptables not found. Please install iptables before proceeding."
    exit 1
fi

echo "[1/5] Building binary..."
CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o "$REPO_ROOT/floki" "$REPO_ROOT/src"
echo "      OK"

echo "[2/5] Installing binary to $BINARY_DST..."
cp "$REPO_ROOT/floki" "$BINARY_DST"
chmod +x "$BINARY_DST"
echo "      OK"

echo "[3/5] Creating configuration directory $CONF_DIR..."
mkdir -p "$CONF_DIR"
if [ ! -f "$CONF_DST" ]; then
    cp "$CONF_SRC" "$CONF_DST"
    echo "      Configuration installed at $CONF_DST"
    echo "      >>> Edit this file to match your network setup before starting the service!"
else
    echo "      Configuration already exists — skipping (no overwrite)"
fi

echo "[4/5] Installing systemd service..."
cp "$SERVICE_SRC" "$SERVICE_DST"
systemctl daemon-reload
echo "      OK"

echo "[5/5] Enabling service to start on boot..."
systemctl enable floki
echo "      OK"

echo ""
echo "================================================"
echo "  Installation complete!"
echo "================================================"
echo ""
echo "Next steps:"
echo ""
echo "  1. Review and adjust the configuration:"
echo "       nano $CONF_DST"
echo ""
echo "  2. Start the service:"
echo "       systemctl start floki"
echo ""
echo "  3. Check status:"
echo "       systemctl status floki"
echo "       journalctl -u floki -f"
echo ""
echo "Endpoints (default ports):"
echo "  UDP  - NG Protocol : 2223"
echo "  HTTP - Management  : 2224"
echo "    curl http://localhost:2224/status"
echo "    curl http://localhost:2224/metrics"
echo ""
