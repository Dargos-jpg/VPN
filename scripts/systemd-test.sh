#!/bin/bash
# testeaza instalarea ca serviciu systemd: serverul ruleaza ca user fara privilegii,
# doar cu CAP_NET_ADMIN, si tunelul functioneaza. la final sterge tot ce a instalat.
#
#   sudo scripts/systemd-test.sh [director_binare]      implicit: target/debug
#
# serverul ruleaza in namespace-ul principal (ca pe un VM real), clientul intr-un netns
# legat prin veth (192.168.101.1 <-> 192.168.101.2)

set -u

BIN=$(realpath "${1:-target/debug}")
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
CLI=vpn-sd-cli
PORT=51901
FAILS=0
CLI_PID=""

ok()   { echo "  [OK]   $*"; }
fail() { echo "  [FAIL] $*"; FAILS=$((FAILS + 1)); }

cleanup() {
    [ -n "$CLI_PID" ] && kill "$CLI_PID" 2>/dev/null
    systemctl disable --now vpn-server > /dev/null 2>&1
    rm -f /etc/systemd/system/vpn-server.service /usr/local/bin/vpn-server
    rm -rf /etc/vpn-totp
    systemctl daemon-reload
    userdel vpn-totp 2>/dev/null
    ip link del veth-sd-host 2>/dev/null
    ip netns del "$CLI" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

totp_now() {
    python3 - "$1" <<'EOF'
import base64, hashlib, hmac, struct, sys, time
s = sys.argv[1]
key = base64.b32decode(s + "=" * (-len(s) % 8))
h = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
o = h[19] & 15
print("%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000))
EOF
}

field() { sed -n "s/^$1 = \"\(.*\)\"$/\1/p"; }

wait_for() {
    local i
    for ((i = 0; i < $3 * 10; i++)); do
        grep -q "$2" "$1" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

[ "$(id -u)" -eq 0 ] || { echo "ruleaza ca root"; exit 1; }
[ -d /run/systemd/system ] || { echo "systemd nu ruleaza pe aceasta masina"; exit 1; }
if systemctl list-unit-files vpn-server.service > /dev/null 2>&1 && [ -f /etc/systemd/system/vpn-server.service ]; then
    echo "vpn-server.service e deja instalat, testul l-ar sterge - opresc"
    exit 1
fi

echo "== retea de test"
ip netns add "$CLI"
ip link add veth-sd-host type veth peer name veth-sd-cli
ip link set veth-sd-cli netns "$CLI"
ip addr add 192.168.101.1/24 dev veth-sd-host
ip link set veth-sd-host up
ip -n "$CLI" addr add 192.168.101.2/24 dev veth-sd-cli
ip -n "$CLI" link set veth-sd-cli up
ip -n "$CLI" link set lo up

echo "== chei si config"
"$BIN/vpn-server" keygen > "$WORK/srv.keys"
"$BIN/vpn-client" keygen > "$WORK/cli.keys"
SECRET=$("$BIN/vpn-server" enroll --account test | field totp_secret)

cat > "$WORK/server.toml" <<EOF
listen = "192.168.101.1:$PORT"
private_key = "$(field private_key < "$WORK/srv.keys")"
public_key = "$(field public_key < "$WORK/srv.keys")"
client_public_key = "$(field public_key < "$WORK/cli.keys")"
totp_secret = "$SECRET"
tun_name = "vpnsd0"
tun_address = "10.8.0.1"
client_tunnel_ip = "10.8.0.2"
EOF

cat > "$WORK/client.toml" <<EOF
server = "192.168.101.1:$PORT"
private_key = "$(field private_key < "$WORK/cli.keys")"
public_key = "$(field public_key < "$WORK/cli.keys")"
server_public_key = "$(field public_key < "$WORK/srv.keys")"
tunnel_address = "10.8.0.2"
EOF
chmod 600 "$WORK/client.toml"

echo "== 1. instalare serviciu"
if "$ROOT/deploy/install.sh" "$BIN/vpn-server" "$WORK/server.toml" > "$WORK/install.log" 2>&1; then
    ok "install.sh a rulat"
else
    fail "install.sh: $(tail -n 5 "$WORK/install.log")"
fi
sleep 1
systemctl is-active --quiet vpn-server && ok "serviciul e activ" || fail "serviciul nu e activ: $(journalctl -u vpn-server --no-pager -n 5)"

echo "== 2. fara root"
PID=$(systemctl show -p MainPID --value vpn-server)
USER_NAME=$(ps -o user= -p "$PID" 2>/dev/null | tr -d ' ')
[ "$USER_NAME" = "vpn-totp" ] && ok "procesul ruleaza ca $USER_NAME" || fail "procesul ruleaza ca '$USER_NAME'"
CAPS=$(grep CapEff "/proc/$PID/status" | awk '{print $2}')
# CAP_NET_ADMIN = bitul 12 => 0x1000
[ "$CAPS" = "0000000000001000" ] && ok "capabilitati efective: doar CAP_NET_ADMIN" || fail "capabilitati efective: $CAPS"
PERMS=$(stat -c "%a %U" /etc/vpn-totp/server.toml)
[ "$PERMS" = "600 vpn-totp" ] && ok "config 600, al userului vpn-totp" || fail "config: $PERMS"
ip link show vpnsd0 > /dev/null 2>&1 && ok "interfata TUN creata fara root" || fail "interfata TUN lipseste"

echo "== 3. tunel prin serviciu"
mkfifo "$WORK/codes"
exec 3<> "$WORK/codes"
ip netns exec "$CLI" "$BIN/vpn-client" connect --config "$WORK/client.toml" < "$WORK/codes" > "$WORK/client.log" 2>&1 &
CLI_PID=$!
totp_now "$SECRET" >&3
wait_for "$WORK/client.log" "conectat la" 5 && ok "handshake reusit" || fail "handshake: $(cat "$WORK/client.log")"
ip netns exec "$CLI" ping -c 3 -W 2 -q 10.8.0.1 > /dev/null && ok "ping prin tunel" || fail "ping prin tunel"
exec 3>&-

echo "== 4. scor de izolare systemd"
SCORE=$(systemd-analyze security vpn-server 2>/dev/null | tail -n 1)
echo "  $SCORE"

echo
echo "== log serviciu"
journalctl -u vpn-server --no-pager -o cat | sed 's/^/  /'
echo
if [ "$FAILS" -eq 0 ]; then
    echo "TOATE TESTELE AU TRECUT"
else
    echo "$FAILS TESTE ESUATE"
fi
exit "$FAILS"
