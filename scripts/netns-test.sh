#!/bin/bash
# test cap-coada pe linux, fara VM-uri: server si client in doua network namespace-uri
# legate printr-o pereche veth (192.168.100.1 <-> 192.168.100.2)
#
# rulare (root, pentru netns si TUN):
#   sudo scripts/netns-test.sh [director_binare]      implicit: target/debug

set -u

BIN=$(realpath "${1:-target/debug}")
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
SRV=vpn-test-srv
CLI=vpn-test-cli
INET=vpn-test-inet
PORT=51900
PIDS=()
FAILS=0

ok()   { echo "  [OK]   $*"; }
fail() { echo "  [FAIL] $*"; FAILS=$((FAILS + 1)); }

cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    ip netns del "$SRV" 2>/dev/null
    ip netns del "$CLI" 2>/dev/null
    ip netns del "$INET" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

# cod TOTP curent din secretul base32 (RFC 6238, acelasi algoritm ca in proto/src/totp.rs)
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

# asteapta pana apare un text in fisier, max $3 secunde
wait_for() {
    local i
    for ((i = 0; i < $3 * 10; i++)); do
        grep -q "$2" "$1" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

start_server() {
    ip netns exec "$SRV" "$BIN/vpn-server" run --config "$WORK/server.toml" >> "$WORK/server.log" 2>&1 &
    SRV_PID=$!
    PIDS+=("$SRV_PID")
    wait_for "$WORK/server.log" "ascult pe" 5
}

[ "$(id -u)" -eq 0 ] || { echo "ruleaza ca root"; exit 1; }
[ -x "$BIN/vpn-server" ] && [ -x "$BIN/vpn-client" ] || { echo "lipsesc binarele din $BIN"; exit 1; }

echo "== retea de test"
ip netns add "$SRV"
ip netns add "$CLI"
ip link add veth-srv type veth peer name veth-cli
ip link set veth-srv netns "$SRV"
ip link set veth-cli netns "$CLI"
ip -n "$SRV" addr add 192.168.100.1/24 dev veth-srv
ip -n "$CLI" addr add 192.168.100.2/24 dev veth-cli
for ns in "$SRV" "$CLI"; do
    ip -n "$ns" link set lo up
done
ip -n "$SRV" link set veth-srv up
ip -n "$CLI" link set veth-cli up

echo "== chei si secret TOTP"
"$BIN/vpn-server" keygen > "$WORK/srv.keys"
"$BIN/vpn-client" keygen > "$WORK/cli.keys"
SECRET=$("$BIN/vpn-server" enroll --account test | field totp_secret)

# timeout-uri scurte ca testele de keepalive/reconectare sa dureze secunde, nu minute
cat > "$WORK/server.toml" <<EOF
listen = "192.168.100.1:$PORT"
private_key = "$(field private_key < "$WORK/srv.keys")"
public_key = "$(field public_key < "$WORK/srv.keys")"
client_public_key = "$(field public_key < "$WORK/cli.keys")"
totp_secret = "$SECRET"
tun_address = "10.8.0.1"
client_tunnel_ip = "10.8.0.2"
session_idle_secs = 8
listen_tcp = "192.168.100.1:$PORT"
EOF

cat > "$WORK/client.toml" <<EOF
server = "192.168.100.1:$PORT"
private_key = "$(field private_key < "$WORK/cli.keys")"
public_key = "$(field public_key < "$WORK/cli.keys")"
server_public_key = "$(field public_key < "$WORK/srv.keys")"
tunnel_address = "10.8.0.2"
keepalive_secs = 2
dead_peer_secs = 6
rekey_secs = 3
EOF

echo "== 0. permisiuni config"
# configurile contin chei private: serverul refuza sa porneasca daca le pot citi altii
chmod 644 "$WORK/server.toml"
if ip netns exec "$SRV" "$BIN/vpn-server" run --config "$WORK/server.toml" > "$WORK/perm.log" 2>&1; then
    fail "serverul a pornit cu config citibil de oricine"
else
    grep -q "chmod 600" "$WORK/perm.log" && ok "config cu permisiuni 644 refuzat" || fail "eroare neasteptata: $(cat "$WORK/perm.log")"
fi
chmod 600 "$WORK/server.toml" "$WORK/client.toml"

echo "== pornire server"
start_server

# captura pe cablu pentru testul de confidentialitate, daca exista tcpdump
if command -v tcpdump > /dev/null; then
    ip netns exec "$SRV" tcpdump -i veth-srv -w "$WORK/wire.pcap" -U udp > /dev/null 2>&1 &
    PIDS+=($!)
    sleep 1
fi

echo "== 1. cod TOTP gresit"
GOOD=$(totp_now "$SECRET")
BAD=$([ "$GOOD" = "000000" ] && echo 000001 || echo 000000)
if echo "$BAD" | ip netns exec "$CLI" "$BIN/vpn-client" connect --config "$WORK/client.toml" > "$WORK/bad.log" 2>&1; then
    fail "clientul s-a conectat cu cod gresit"
else
    ok "conectare refuzata ($(tail -n 1 "$WORK/bad.log"))"
fi
if ip -n "$CLI" link show vpn0 > /dev/null 2>&1; then
    fail "interfata vpn0 a ramas creata dupa esec"
else
    ok "nicio interfata TUN creata"
fi
grep -q "handshake respins" "$WORK/server.log" && ok "serverul a respins handshake-ul in tacere" || fail "serverul nu a logat respingerea"

echo "== 2. cod TOTP corect"
# codurile ajung la client printr-un fifo tinut deschis, ca sa putem trimite altul la reconectare
mkfifo "$WORK/codes"
exec 3<> "$WORK/codes"
ip netns exec "$CLI" "$BIN/vpn-client" connect --config "$WORK/client.toml" < "$WORK/codes" > "$WORK/client.log" 2>&1 &
CLI_PID=$!
PIDS+=("$CLI_PID")
totp_now "$SECRET" >&3
wait_for "$WORK/client.log" "conectat la" 5 && ok "handshake reusit" || fail "handshake esuat: $(cat "$WORK/client.log")"

ip netns exec "$CLI" ping -c 3 -W 2 -q 10.8.0.1 > /dev/null && ok "ping client -> server prin tunel" || fail "ping client -> server"
ip netns exec "$SRV" ping -c 3 -W 2 -q 10.8.0.2 > /dev/null && ok "ping server -> client prin tunel" || fail "ping server -> client"

echo "== 3. MTU"
# 1392 date + 8 icmp + 20 ip = 1420, fara fragmentare
ip netns exec "$CLI" ping -c 2 -W 2 -q -s 1392 -M do 10.8.0.1 > /dev/null && ok "pachet de 1420 bytes trece" || fail "pachet de 1420 bytes"

echo "== 4. anti-spoofing"
ip -n "$CLI" addr add 10.8.0.99/32 dev vpn0
if ip netns exec "$CLI" ping -c 2 -W 1 -q -I 10.8.0.99 10.8.0.1 > /dev/null 2>&1; then
    fail "pachet cu sursa falsa acceptat"
else
    ok "pachet cu sursa 10.8.0.99 nu a trecut"
fi
grep -q "sursa 10.8.0.99 " "$WORK/server.log" && ok "serverul a logat sursa falsa" || fail "serverul nu a logat sursa falsa"
ip -n "$CLI" addr del 10.8.0.99/32 dev vpn0

echo "== 5. doar IPv4 prin tunel"
# clientul nu trebuie sa trimita IPv6 link-local generat de OS (BUG-006)
if grep -q "sursa fe80:" "$WORK/server.log"; then
    fail "clientul a trimis IPv6 prin tunel"
else
    ok "niciun pachet IPv6 trimis prin tunel"
fi

echo "== 6. confidentialitate pe cablu"
if [ -f "$WORK/wire.pcap" ]; then
    # payload recognoscibil trimis prin tunel; nu trebuie sa apara in captura
    ip netns exec "$CLI" ping -c 2 -W 2 -q -p 5345435245545f5450 10.8.0.1 > /dev/null
    sleep 1
    # o captura goala ar trece testul degeaba
    if [ "$(stat -c %s "$WORK/wire.pcap")" -lt 1000 ]; then
        fail "captura de pe cablu e goala, testul nu e concludent"
    elif grep -q "SECRET_TP" "$WORK/wire.pcap"; then
        fail "payload vizibil in clar pe cablu"
    else
        ok "payload-ul nu apare in clar pe cablu"
    fi
else
    echo "  [SKIP] tcpdump nu e instalat"
fi

echo "== 7. rekey fara pierderi"
# rekey la 3s; ping continuu ~9s => cel putin 2 schimbari de chei in timpul lui
BEFORE=$(grep -c "chei reinnoite" "$WORK/server.log")
LOSS=$(ip netns exec "$CLI" ping -c 30 -i 0.3 -W 1 -q 10.8.0.1 | sed -n 's/.* \([0-9.]*\)% packet loss.*/\1/p')
AFTER=$(grep -c "chei reinnoite" "$WORK/server.log")
REKEYS=$((AFTER - BEFORE))
[ "$REKEYS" -ge 2 ] && ok "$REKEYS rekey-uri in timpul ping-ului, fara cod TOTP" || fail "doar $REKEYS rekey-uri"
[ "$LOSS" = "0" ] && ok "0% pachete pierdute la schimbarea cheilor" || fail "$LOSS% pachete pierdute"

echo "== 8. keepalive"
# 8s fara trafic > dead_peer_secs (6s): sesiunea supravietuieste doar daca serverul raspunde la keepalive
sleep 8
if grep -q "sesiune pierduta" "$WORK/client.log"; then
    fail "sesiunea s-a pierdut desi serverul e pornit"
else
    ok "sesiunea traieste fara trafic, doar cu keepalive"
fi

echo "== 9. restart server + reconectare"
kill "$SRV_PID"
wait "$SRV_PID" 2>/dev/null
start_server
if wait_for "$WORK/client.log" "sesiune pierduta" 15; then
    ok "clientul a detectat pierderea sesiunii"
else
    fail "clientul nu a detectat restartul serverului"
fi
totp_now "$SECRET" >&3
wait_for "$WORK/client.log" "reconectat" 8 && ok "reconectare cu cod TOTP nou" || fail "reconectare esuata: $(tail -n 3 "$WORK/client.log")"
ip netns exec "$CLI" ping -c 3 -W 2 -q 10.8.0.1 > /dev/null && ok "ping prin tunel dupa reconectare" || fail "ping dupa reconectare"

echo "== 10. timeout sesiune pe server"
kill "$CLI_PID"
wait "$CLI_PID" 2>/dev/null
if wait_for "$WORK/server.log" "inchisa: inactiva" 15; then
    ok "serverul a inchis sesiunea inactiva"
else
    fail "serverul nu a inchis sesiunea"
fi
exec 3>&-

echo "== 11. protectie DoS la handshake"
# msg1 falsificate trimise direct din python: (a) fara mac1 valid (scanner care nu stie cheia
# publica a serverului), (b) cu mac1 valid dar mesaj noise fals (atacator care stie cheia publica)
flood() {
    ip netns exec "$CLI" python3 - "$1" "$2" "$(field public_key < "$WORK/srv.keys")" "$PORT" <<'EOF'
import base64, hashlib, os, socket, struct, sys
count, valid_mac, server_pub, port = int(sys.argv[1]), sys.argv[2] == "1", base64.b64decode(sys.argv[3]), int(sys.argv[4])
key = hashlib.blake2s(b"vpn-totp mac1 v1" + server_pub).digest()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(count):
    body = bytes([1, 0, 0, 0]) + struct.pack(">I", i) + os.urandom(104)
    mac = hashlib.blake2s(body, key=key, digest_size=16).digest() if valid_mac else os.urandom(16)
    s.sendto(body + mac, ("192.168.100.1", port))
EOF
}
REJ_BEFORE=$(grep -c "handshake respins" "$WORK/server.log")
flood 200 0
flood 100 1
sleep 1
REJ_AFTER=$(grep -c "handshake respins" "$WORK/server.log")
PROCESSED=$((REJ_AFTER - REJ_BEFORE))
# PER_IP_BURST = 5: doar atatea ajung la DH, restul sunt oprite de limita de rata
[ "$PROCESSED" -ge 1 ] && [ "$PROCESSED" -le 5 ] && ok "din 300 de msg1 false, doar $PROCESSED au ajuns la DH" || fail "$PROCESSED msg1 false au ajuns la DH"
if wait_for "$WORK/server.log" "aruncate inainte de DH" 15; then
    BAD=$(sed -n 's/.*DH: \([0-9]*\) cu mac1.*/\1/p' "$WORK/server.log" | awk '{s += $1} END {print s + 0}')
    LIMITED=$(sed -n 's/.*invalid, \([0-9]*\) peste.*/\1/p' "$WORK/server.log" | awk '{s += $1} END {print s + 0}')
    [ "$BAD" -eq 200 ] && ok "200 msg1 fara mac1 valid oprite cu un singur BLAKE2s" || fail "mac1 invalid: $BAD din 200"
    [ "$LIMITED" -ge 95 ] && ok "$LIMITED msg1 cu mac1 valid oprite de limita de rata" || fail "limitate: $LIMITED"
else
    fail "serverul nu a raportat handshake-urile aruncate"
fi

echo "== 12. full tunnel + NAT pe server"
# al treilea namespace = "internet" (198.51.100.2), legat doar de server. clientul nu are
# nicio ruta catre el: ajunge acolo doar prin tunel + NAT-ul serverului
ip netns add "$INET"
ip link add veth-inet type veth peer name veth-world
ip link set veth-inet netns "$SRV"
ip link set veth-world netns "$INET"
ip -n "$SRV" addr add 198.51.100.1/24 dev veth-inet
ip -n "$INET" addr add 198.51.100.2/24 dev veth-world
ip -n "$SRV" link set veth-inet up
ip -n "$INET" link set veth-world up
ip -n "$INET" link set lo up
if ip netns exec "$SRV" bash "$ROOT/deploy/full-tunnel-nat.sh" veth-inet > "$WORK/nat.log" 2>&1; then
    ok "forwarding + NAT configurat pe server"
else
    fail "full-tunnel-nat.sh: $(cat "$WORK/nat.log")"
fi
ip netns exec "$CLI" ping -c 1 -W 1 -q 198.51.100.2 > /dev/null 2>&1 && fail "internetul simulat accesibil fara tunel" || ok "fara tunel, 198.51.100.2 nu e accesibil"

sed 's/^dead_peer_secs.*/dead_peer_secs = 30/' "$WORK/client.toml" > "$WORK/client-full.toml"
echo 'mode = "full"' >> "$WORK/client-full.toml"
chmod 600 "$WORK/client-full.toml"
exec 4<> "$WORK/codes"
ip netns exec "$CLI" "$BIN/vpn-client" connect --config "$WORK/client-full.toml" < "$WORK/codes" > "$WORK/client-full.log" 2>&1 &
FULL_PID=$!
PIDS+=("$FULL_PID")
totp_now "$SECRET" >&4
wait_for "$WORK/client-full.log" "full tunnel" 8 && ok "conectat in full tunnel" || fail "full tunnel: $(cat "$WORK/client-full.log")"

ROUTES=$(ip -n "$CLI" route)
echo "$ROUTES" | grep -q "^0.0.0.0/1 dev vpn0" && echo "$ROUTES" | grep -q "^128.0.0.0/1 dev vpn0" \
    && ok "rutele 0.0.0.0/1 + 128.0.0.0/1 prin vpn0" || fail "rute lipsa: $ROUTES"
echo "$ROUTES" | grep -q "^192.168.100.1 dev veth-cli" && ok "ruta catre server pe drumul vechi (fara bucla)" || fail "ruta catre server lipsa"

ip netns exec "$CLI" tcpdump -i veth-cli -w "$WORK/cli-wire.pcap" -U icmp > /dev/null 2>&1 &
TD1=$!
ip netns exec "$INET" tcpdump -i veth-world -n -l icmp > "$WORK/inet.txt" 2> /dev/null &
TD2=$!
PIDS+=("$TD1" "$TD2")
sleep 1
ip netns exec "$CLI" ping -c 3 -W 2 -q 198.51.100.2 > /dev/null && ok "client -> internet prin tunel + NAT" || fail "ping catre internetul simulat"
sleep 1
kill "$TD1" "$TD2" 2> /dev/null
wait "$TD1" "$TD2" 2> /dev/null
grep -q "198.51.100.1 > 198.51.100.2: ICMP echo request" "$WORK/inet.txt" \
    && ok "internetul vede adresa serverului (NAT), nu 10.8.0.2" || fail "sursa vazuta de internet: $(head -n 2 "$WORK/inet.txt")"
CLEAR=$(tcpdump -r "$WORK/cli-wire.pcap" 2> /dev/null | wc -l)
[ "$CLEAR" -eq 0 ] && ok "niciun ICMP in clar pe cablul clientului" || fail "$CLEAR pachete ICMP in clar pe cablul clientului"

# SIGTERM (kill) trebuie sa stearga rutele adaugate
kill "$FULL_PID"
wait "$FULL_PID" 2> /dev/null
exec 4>&-
if ip -n "$CLI" route | grep -q "^192.168.100.1 dev veth-cli"; then
    fail "ruta catre server a ramas dupa oprire"
else
    ok "rutele sterse la oprire (SIGTERM)"
fi

echo "== 13. transport TCP (UDP blocat)"
# UDP spre server blocat complet: clientul trebuie sa mearga doar pe TCP
ip netns exec "$SRV" nft -f - <<EOF
table inet vpn_test_block {
    chain input {
        type filter hook input priority 0;
        udp dport $PORT drop
    }
}
EOF
sed 's/^dead_peer_secs.*/dead_peer_secs = 30/' "$WORK/client.toml" > "$WORK/client-tcp.toml"
echo 'transport = "tcp"' >> "$WORK/client-tcp.toml"
chmod 600 "$WORK/client-tcp.toml"
exec 5<> "$WORK/codes"
ip netns exec "$CLI" "$BIN/vpn-client" connect --config "$WORK/client-tcp.toml" < "$WORK/codes" > "$WORK/client-tcp.log" 2>&1 &
TCP_PID=$!
PIDS+=("$TCP_PID")
totp_now "$SECRET" >&5
wait_for "$WORK/client-tcp.log" "(Tcp)" 8 && ok "conectat prin TCP" || fail "conectare TCP: $(cat "$WORK/client-tcp.log")"
ip netns exec "$CLI" ping -c 3 -W 2 -q 10.8.0.1 > /dev/null && ok "ping prin tunel peste TCP" || fail "ping peste TCP"
BEFORE=$(grep -c "chei reinnoite cu .* (tcp)" "$WORK/server.log")
sleep 7
AFTER=$(grep -c "chei reinnoite cu .* (tcp)" "$WORK/server.log")
[ $((AFTER - BEFORE)) -ge 1 ] && ok "rekey peste TCP ($((AFTER - BEFORE)) in 7s)" || fail "niciun rekey peste TCP"
ip netns exec "$CLI" ping -c 2 -W 2 -q 10.8.0.1 > /dev/null && ok "ping dupa rekey peste TCP" || fail "ping dupa rekey peste TCP"

# o conexiune TCP care nu incepe cu un msg1 cu mac1 valid e inchisa imediat
CLOSED=$(ip netns exec "$CLI" python3 - "$PORT" <<'EOF'
import socket, sys
s = socket.create_connection(("192.168.100.1", int(sys.argv[1])), timeout=3)
s.sendall(b"\x00\x05hello")
try:
    print("inchisa" if s.recv(16) == b"" else "deschisa")
except socket.timeout:
    print("deschisa")
EOF
)
[ "$CLOSED" = "inchisa" ] && ok "conexiune TCP cu date aleatoare inchisa de server" || fail "conexiunea TCP cu date aleatoare: $CLOSED"
kill "$TCP_PID"
wait "$TCP_PID" 2> /dev/null
exec 5>&-
ip netns exec "$SRV" nft delete table inet vpn_test_block

echo "== 14. daemon + ctl (separarea privilegiilor)"
SOCK="$WORK/ctl.sock"
ctl() { ip netns exec "$CLI" "$BIN/vpn-client" ctl --endpoint "$SOCK" "$@"; }
ip netns exec "$CLI" "$BIN/vpn-client" daemon --config "$WORK/client.toml" --endpoint "$SOCK" > "$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
PIDS+=("$DAEMON_PID")
wait_for "$WORK/daemon.log" "astept comenzi" 5 && ok "daemon pornit" || fail "daemon: $(cat "$WORK/daemon.log")"
[ "$(stat -c %a "$SOCK")" = "660" ] && ok "socket de control cu permisiuni 660" || fail "permisiuni socket: $(stat -c %a "$SOCK")"

# un user fara drepturi nu poate controla daemon-ul (binarul copiat unde il poate executa)
cp "$BIN/vpn-client" "$WORK/ctl-bin" && chmod 755 "$WORK" "$WORK/ctl-bin"
if ip netns exec "$CLI" runuser -u nobody -- "$WORK/ctl-bin" ctl --endpoint "$SOCK" status > /dev/null 2>&1; then
    fail "userul nobody a putut folosi socket-ul de control"
else
    ok "userul nobody nu are acces la daemon"
fi

ctl status | grep -q '"state": "disconnected"' && ok "ctl status: disconnected" || fail "ctl status: $(ctl status)"
ctl connect 12345 > /dev/null 2>&1 && fail "cod cu 5 cifre acceptat" || ok "cod cu format gresit refuzat de daemon"
BAD=$([ "$(totp_now "$SECRET")" = "000000" ] && echo 000001 || echo 000000)
OUT=$(ctl connect "$BAD" 2>&1) && fail "conectat cu cod gresit" || ok "cod gresit: ${OUT##*: }"
ip -n "$CLI" link show vpn0 > /dev/null 2>&1 && fail "vpn0 creat dupa cod gresit" || ok "nicio interfata dupa codul gresit"

ctl connect "$(totp_now "$SECRET")" | grep -q "conectat la" && ok "ctl connect: conectat" || fail "ctl connect esuat"
ip netns exec "$CLI" ping -c 3 -W 2 -q 10.8.0.1 > /dev/null && ok "ping prin tunelul daemon-ului" || fail "ping prin daemon"
STATUS=$(ctl status)
echo "$STATUS" | grep -q '"state": "connected"' && echo "$STATUS" | grep -qE '"tx_bytes": [1-9]' \
    && ok "ctl status: connected, cu trafic numarat" || fail "ctl status: $STATUS"

# server restartat => daemon-ul ajunge in need_code, un cod nou il reconecteaza (TUN ramane)
kill "$SRV_PID"
wait "$SRV_PID" 2> /dev/null
start_server
for _ in $(seq 1 150); do
    ctl status | grep -q '"state": "need_code"' && break
    sleep 0.1
done
ctl status | grep -q '"state": "need_code"' && ok "daemon: sesiune pierduta => need_code" || fail "daemon nu a ajuns in need_code"
ip -n "$CLI" link show vpn0 > /dev/null 2>&1 && ok "interfata TUN pastrata in need_code" || fail "vpn0 disparut in need_code"
ctl connect "$(totp_now "$SECRET")" | grep -q "conectat la" && ok "reconectat din need_code" || fail "reconectare din need_code"
ip netns exec "$CLI" ping -c 2 -W 2 -q 10.8.0.1 > /dev/null && ok "ping dupa reconectarea daemon-ului" || fail "ping dupa reconectare"

ctl disconnect | grep -q deconectat && ok "ctl disconnect" || fail "ctl disconnect"
ip -n "$CLI" link show vpn0 > /dev/null 2>&1 && fail "vpn0 a ramas dupa disconnect" || ok "interfata stearsa la disconnect"
kill "$DAEMON_PID"
wait "$DAEMON_PID" 2> /dev/null
[ -e "$SOCK" ] && fail "socket-ul a ramas dupa oprirea daemon-ului" || ok "socket sters la oprirea daemon-ului"

echo
echo "== log server"
sed 's/^/  /' "$WORK/server.log"
echo "== log client"
sed 's/^/  /' "$WORK/client.log"
echo
if [ "$FAILS" -eq 0 ]; then
    echo "TOATE TESTELE AU TRECUT"
else
    echo "$FAILS TESTE ESUATE"
fi
exit "$FAILS"
