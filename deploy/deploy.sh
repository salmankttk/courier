#!/bin/sh
# Build Courier for the server and install or upgrade it there.
# Usage: deploy/deploy.sh user@host
set -eu
HOST=${1:?usage: deploy/deploy.sh user@host}
cd "$(dirname "$0")/.."

mkdir -p dist
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/courier .
scp -q dist/courier deploy/courier.service "$HOST:/tmp/"

ssh "$HOST" sh -s <<'EOF'
set -eu
id courier >/dev/null 2>&1 || sudo useradd -r -U -d /srv/courier -s /usr/sbin/nologin courier
sudo install -d -o courier -g courier -m 750 /srv/courier
sudo install -d -m 755 /etc/courier
[ -f /etc/courier/env ] || printf 'COURIER_ADMINS=\nCOURIER_FLAGS=\n' | sudo tee /etc/courier/env >/dev/null
sudo install -m 755 /tmp/courier /usr/local/bin/courier
sudo install -m 644 /tmp/courier.service /etc/systemd/system/courier.service
rm /tmp/courier /tmp/courier.service
sudo systemctl daemon-reload
sudo systemctl enable courier >/dev/null 2>&1
sudo systemctl restart courier
echo "deployed: $(systemctl is-active courier)"
EOF
