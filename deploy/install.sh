#!/bin/bash
# instaleaza vpn-server ca serviciu systemd, fara root la rulare
#   sudo deploy/install.sh <cale_binar> <cale_server.toml>
#
# - user de sistem `vpn-totp` (fara shell, fara home)
# - binar in /usr/local/bin, config in /etc/vpn-totp/server.toml (600, al userului vpn-totp)
# - serviciul porneste la boot

set -euo pipefail

BIN=${1:?cale catre vpn-server (ex target/release/vpn-server)}
CFG=${2:?cale catre server.toml}

[ "$(id -u)" -eq 0 ] || { echo "ruleaza ca root"; exit 1; }

id vpn-totp > /dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin vpn-totp

install -m 755 -o root -g root "$BIN" /usr/local/bin/vpn-server
# directorul accesibil doar userului serviciului: cheia privata si secretul TOTP
install -d -m 700 -o vpn-totp -g vpn-totp /etc/vpn-totp
install -m 600 -o vpn-totp -g vpn-totp "$CFG" /etc/vpn-totp/server.toml

install -m 644 -o root -g root "$(dirname "$0")/vpn-server.service" /etc/systemd/system/vpn-server.service
systemctl daemon-reload
systemctl enable --now vpn-server

systemctl --no-pager status vpn-server | head -n 5
echo
echo "izolare (cu cat mai mic, cu atat mai bine):"
systemd-analyze security vpn-server | tail -n 1
