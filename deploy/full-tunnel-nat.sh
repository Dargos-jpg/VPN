#!/bin/bash
# configurarea serverului pentru clientii in full tunnel: forwarding + NAT (nftables)
#   sudo deploy/full-tunnel-nat.sh <interfata_iesire> [subretea_tunel]     ex: enp0s6 10.8.0.0/24
#   sudo deploy/full-tunnel-nat.sh --remove
#
# serverul VPN ruleaza fara root, deci nu isi poate face singur configurarea asta.
# pentru masini cu UFW (VM-urile din oci-terraform-ansible) se foloseste rolul ansible,
# nu acest script - UFW are propria politica de forwarding (vezi DEPLOY.md)
#
# ce face:
# - net.ipv4.ip_forward = 1: kernelul trimite mai departe pachetele venite din vpn0
# - masquerade: pachetele 10.8.0.x pleaca spre internet cu adresa serverului, raspunsurile
#   sunt traduse inapoi (fara asta internetul n-ar sti cum sa raspunda la 10.8.0.x)
# - forward doar vpn0 -> iesire si raspunsurile inapoi; restul de forwarding blocat

set -euo pipefail

TABLE=vpn_totp

if [ "${1:-}" = "--remove" ]; then
    nft delete table ip "$TABLE" 2> /dev/null && echo "tabela $TABLE stearsa" || echo "tabela $TABLE nu exista"
    exit 0
fi

OUT=${1:?interfata de iesire spre internet (ex: enp0s6, eth0)}
SUBNET=${2:-10.8.0.0/24}
TUN=${TUN:-vpn0}

[ "$(id -u)" -eq 0 ] || { echo "ruleaza ca root"; exit 1; }

sysctl -q -w net.ipv4.ip_forward=1

nft -f - <<EOF
table ip $TABLE
delete table ip $TABLE
table ip $TABLE {
    chain forward {
        type filter hook forward priority 0; policy accept;
        iifname "$TUN" ip saddr != $SUBNET drop
        iifname "$TUN" oifname "$OUT" accept
        iifname "$OUT" oifname "$TUN" ct state established,related accept
        iifname "$TUN" drop
        oifname "$TUN" drop
    }
    chain postrouting {
        type nat hook postrouting priority 100;
        ip saddr $SUBNET oifname "$OUT" masquerade
    }
}
EOF

echo "forwarding + NAT activ: $SUBNET ($TUN) -> $OUT"
echo "persistent dupa reboot: net.ipv4.ip_forward=1 in /etc/sysctl.d/ si tabela in /etc/nftables.conf"
