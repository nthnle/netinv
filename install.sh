#!/usr/bin/env bash
# netinv installer for Raspberry Pi OS / Debian. Run: sudo ./install.sh
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"

IFACE="${IFACE:-$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')}"
GATEWAY="${GATEWAY:-$(ip -4 route show default | awk '{print $3; exit}')}"
PI_CIDR="$(ip -4 -o addr show dev "$IFACE" | awk '{print $4}' | head -1)"
PI_IP="${PI_CIDR%/*}"
SUBNET="$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "$PI_CIDR" 2>/dev/null || true)"
UPSTREAM1="${UPSTREAM1:-1.1.1.1}"
UPSTREAM2="${UPSTREAM2:-9.9.9.9}"
PORT="${PORT:-8080}"
# Optional: where to POST a line of text when a new device joins, e.g. https://ntfy.sh/<a-topic-you-pick>
NOTIFY_URL="${NOTIFY_URL:-}"
BLOCK_DIR=/var/lib/netinv-dns
BLOCK_FILE="$BLOCK_DIR/blocked.conf"
[[ -n "$IFACE" && -n "$GATEWAY" && -n "$PI_IP" && -n "$SUBNET" ]] || { echo "Could not detect interface/gateway. Set IFACE= and GATEWAY=." >&2; exit 1; }
echo "Interface $IFACE, Pi address $PI_IP, network $SUBNET, router $GATEWAY"

# Something else already answering DNS here (Pi-hole, AdGuard Home, systemd-resolved)?
if ss -lnu 2>/dev/null | awk '{print $4}' | grep -qE '(^|:)53$' && ! systemctl is-active -q dnsmasq; then
  echo "Port 53 is already in use by another service. Stop it first, or point netinv at that" >&2
  echo "service's query log instead of installing dnsmasq." >&2
  exit 1
fi

apt-get update -qq
apt-get install -y -qq dnsmasq arp-scan dnsutils avahi-utils python3

id netinv &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin netinv
install -d -o netinv -g netinv -m 750 /var/lib/netinv
install -d -o root -g netinv -m 750 /var/log/netinv
install -d /opt/netinv
install -m 644 "$SRC/netinv.py" "$SRC/dashboard.html" /opt/netinv/
# The block list lives outside /var/lib/netinv so dnsmasq (another user) can read it.
install -d -o netinv -g netinv -m 755 "$BLOCK_DIR"
[[ -f "$BLOCK_FILE" ]] || install -o netinv -g netinv -m 644 /dev/null "$BLOCK_FILE"

# dnsmasq keeps the owner it finds; group netinv lets the collector read the log.
DNSMASQ_USER="$(getent passwd dnsmasq >/dev/null && echo dnsmasq || echo nobody)"
touch /var/log/netinv/dnsmasq.log
chown "$DNSMASQ_USER":netinv /var/log/netinv/dnsmasq.log
chmod 640 /var/log/netinv/dnsmasq.log

cat > /etc/dnsmasq.d/netinv.conf <<EOF
# Managed by netinv. DNS forwarder with per-client query logging. No DHCP.
port=53
bogus-priv
no-resolv
server=$UPSTREAM1
server=$UPSTREAM2
# bare hostnames, common local domains and reverse lookups stay with the router
server=//$GATEWAY
server=/lan/home/$GATEWAY
rev-server=$SUBNET,$GATEWAY
# sites blocked from the dashboard; re-read on SIGHUP (netinv-blocklist.path)
servers-file=$BLOCK_FILE
cache-size=10000
log-queries=extra
log-facility=/var/log/netinv/dnsmasq.log
log-async=50
EOF

cat > /etc/logrotate.d/netinv <<EOF
/var/log/netinv/dnsmasq.log {
    daily
    rotate 3
    missingok
    notifempty
    compress
    delaycompress
    create 640 $DNSMASQ_USER netinv
    postrotate
        pkill -USR2 -x dnsmasq || true
    endscript
}
EOF

cat > /etc/systemd/system/netinv.service <<EOF
[Unit]
Description=netinv - home network inventory and DNS activity
After=network-online.target dnsmasq.service
Wants=network-online.target

[Service]
User=netinv
Group=netinv
ExecStart=/usr/bin/python3 /opt/netinv/netinv.py --iface $IFACE --gateway $GATEWAY --port $PORT --block-file $BLOCK_FILE${NOTIFY_URL:+ --notify-url $NOTIFY_URL}
Restart=on-failure
RestartSec=5
# raw sockets for arp-scan, nothing else
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/netinv $BLOCK_DIR
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# netinv runs unprivileged and cannot signal dnsmasq. systemd watches the block list
# and tells dnsmasq to re-read it (SIGHUP also drops its cache, so blocks apply at once).
cat > /etc/systemd/system/netinv-blocklist.path <<EOF
[Unit]
Description=netinv - watch the DNS block list

[Path]
PathChanged=$BLOCK_FILE

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/netinv-blocklist.service <<EOF
[Unit]
Description=netinv - make dnsmasq re-read the block list

[Service]
Type=oneshot
ExecStart=/usr/bin/pkill -HUP -x dnsmasq
EOF

dnsmasq --test
systemctl daemon-reload
systemctl enable -q dnsmasq netinv netinv-blocklist.path
systemctl restart dnsmasq netinv netinv-blocklist.path

cat <<EOF

Installed. Dashboard: http://$PI_IP:$PORT

The inventory is already filling in. For the DNS side, two steps on your router:
  1. Reserve $PI_IP for this Pi (DHCP reservation / static lease).
  2. In the router's DHCP (LAN) settings, set the DNS server to $PI_IP only.
     Devices pick it up as their leases renew; reconnect Wi-Fi to speed that up.

Test from another machine:  dig example.com @$PI_IP
EOF
