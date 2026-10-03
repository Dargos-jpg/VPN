#!/bin/bash
# server VPN de dezvoltare in WSL, pentru testat clientul / interfata de pe windows
#   sudo BIN=<dir binare linux> scripts/dev-wsl-server.sh start <dir_iesire>
#   sudo scripts/dev-wsl-server.sh stop
#
# genereaza chei + secret TOTP noi la fiecare start; in <dir_iesire> scrie client.toml
# (cu IP-ul WSL-ului vazut de windows) si secret (pentru scripts/totp.py)
# tunel separat de cel din netns-test: vpndev0, 10.9.0.0/24, port 51902

set -euo pipefail
BIN=${BIN:-target/debug}
WORK=/tmp/vpn-dev
PORT=51902
field() { sed -n "s/^$1 = \"\(.*\)\"$/\1/p"; }

case "${1:-}" in
stop)
    pkill -f "$WORK/server.toml" && echo "server oprit" || echo "serverul nu rula"
    exit 0
    ;;
start) ;;
*)
    echo "folosire: $0 start <dir_iesire> | stop"
    exit 1
    ;;
esac

OUT=${2:?director pentru client.toml}
[ "$(id -u)" -eq 0 ] || { echo "ruleaza ca root (TUN)"; exit 1; }
pkill -f "$WORK/server.toml" 2> /dev/null || true

rm -rf "$WORK" && mkdir -p "$WORK" "$OUT"
"$BIN/vpn-server" keygen > "$WORK/srv.keys"
"$BIN/vpn-client" keygen > "$WORK/cli.keys"
SECRET=$("$BIN/vpn-server" enroll --account dev | field totp_secret)
IP=$(ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1)

cat > "$WORK/server.toml" <<EOF
listen = "0.0.0.0:$PORT"
private_key = "$(field private_key < "$WORK/srv.keys")"
public_key = "$(field public_key < "$WORK/srv.keys")"
client_public_key = "$(field public_key < "$WORK/cli.keys")"
totp_secret = "$SECRET"
tun_name = "vpndev0"
tun_address = "10.9.0.1"
client_tunnel_ip = "10.9.0.2"
EOF
chmod 600 "$WORK/server.toml"

cat > "$OUT/client.toml" <<EOF
# generat de scripts/dev-wsl-server.sh - chei de test, regenerate la fiecare start
server = "$IP:$PORT"
private_key = "$(field private_key < "$WORK/cli.keys")"
public_key = "$(field public_key < "$WORK/cli.keys")"
server_public_key = "$(field public_key < "$WORK/srv.keys")"
tun_name = "vpndev"
tunnel_address = "10.9.0.2"
EOF
echo "$SECRET" > "$OUT/secret"

nohup "$BIN/vpn-server" run --config "$WORK/server.toml" > "$WORK/server.log" 2>&1 &
sleep 1
cat "$WORK/server.log"
echo "server de dezvoltare: $IP:$PORT (log: $WORK/server.log)"
