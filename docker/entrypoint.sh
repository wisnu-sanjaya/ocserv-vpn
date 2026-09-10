#!/bin/bash
set -e

: "${HOSTNAME:?HOSTNAME env var is required}"
: "${LISTEN_PORT:=443}"
: "${DNS_SERVERS:=1.1.1.1}"
: "${CLIENTNET:=192.168.248.0}"
: "${CLIENTNETMASK:=255.255.255.0}"
: "${TUNNEL_ROUTES:=default}"
: "${COOKIE_TIMEOUT:=60}"

export LISTEN_PORT CLIENTNET CLIENTNETMASK COOKIE_TIMEOUT HOSTNAME

mkdir -p /config

envsubst < /templates/ocserv.conf.template > /config/ocserv.conf
envsubst < /templates/sso.conf.template > /config/sso.conf
envsubst < /templates/sp-metadata.xml.template > /config/sp-metadata.xml

# DNS_SERVERS and TUNNEL_ROUTES may contain multiple comma-separated
# values; ocserv.conf requires one "dns = X" / "route = X" line per
# value, so split and append them here.
IFS=',' read -ra DNS_ARR <<< "$DNS_SERVERS"
for d in "${DNS_ARR[@]}"; do
    d="${d#"${d%%[![:space:]]*}"}"
    d="${d%"${d##*[![:space:]]}"}"
    echo "dns = $d" >> /config/ocserv.conf
done

if [ "$TUNNEL_ROUTES" != "default" ]; then
    IFS=',' read -ra ROUTE_ARR <<< "$TUNNEL_ROUTES"
    for r in "${ROUTE_ARR[@]}"; do
        r="${r#"${r%%[![:space:]]*}"}"
        r="${r%"${r##*[![:space:]]}"}"
        echo "route = $r" >> /config/ocserv.conf
    done
fi

if [ -n "${DEFAULT_DOMAIN:-}" ]; then
    echo "default-domain = $DEFAULT_DOMAIN" >> /config/ocserv.conf
fi

if [ -n "${SPLIT_DNS_DOMAINS:-}" ]; then
    IFS=',' read -ra SPLITDNS_ARR <<< "$SPLIT_DNS_DOMAINS"
    for sd in "${SPLITDNS_ARR[@]}"; do
        sd="${sd#"${sd%%[![:space:]]*}"}"
        sd="${sd%"${sd##*[![:space:]]}"}"
        echo "split-dns = $sd" >> /config/ocserv.conf
    done
fi

# Enable IP forwarding and set up NAT so VPN client traffic can reach
# the outside network through this container's egress interface.
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

netmask_to_cidr() {
    local mask=$1 bits=0
    IFS=. read -r o1 o2 o3 o4 <<< "$mask"
    for octet in "$o1" "$o2" "$o3" "$o4"; do
        case "$octet" in
            255) bits=$((bits+8));;
            254) bits=$((bits+7));;
            252) bits=$((bits+6));;
            248) bits=$((bits+5));;
            240) bits=$((bits+4));;
            224) bits=$((bits+3));;
            192) bits=$((bits+2));;
            128) bits=$((bits+1));;
            0) bits=$((bits+0));;
        esac
    done
    echo "$bits"
}

EGRESS_IF=$(ip route | awk '/^default/ {print $5; exit}')
if [ -n "$EGRESS_IF" ]; then
    CIDR_BITS=$(netmask_to_cidr "$CLIENTNETMASK")
    CLIENT_SUBNET="${CLIENTNET}/${CIDR_BITS}"
    iptables -t nat -A POSTROUTING -s "$CLIENT_SUBNET" -o "$EGRESS_IF" -j MASQUERADE || true
    echo "NAT: MASQUERADE ${CLIENT_SUBNET} -> ${EGRESS_IF}"
fi

echo "=== Generated /config/ocserv.conf ==="
cat /config/ocserv.conf
echo "=========================================="

exec /usr/sbin/ocserv -c /config/ocserv.conf -f
