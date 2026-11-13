#!/usr/bin/env bash
# netinv installer for Raspberry Pi OS / Debian. Run: sudo ./install.sh
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"

# Options given on an earlier run are remembered, so an update needs none of them repeated.
# Anything set on the command line this time wins. Only what was actually given is kept:
# what the installer worked out for itself is worked out afresh each time.
CONF="${NETINV_CONF:-/etc/netinv/install.conf}"
if [[ -f "$CONF" ]]; then
  while IFS='=' read -r key value; do
    case "$key" in
      IFACE|GATEWAY|UPSTREAM1|UPSTREAM2|PORT|NOTIFY_URL|ENCRYPTED_DNS)
        if [[ -z "${!key:-}" ]]; then printf -v "$key" '%s' "$value"; fi ;;
    esac
  done < "$CONF"
fi
GIVEN=""
for key in IFACE GATEWAY UPSTREAM1 UPSTREAM2 PORT NOTIFY_URL ENCRYPTED_DNS; do
  if [[ -n "${!key:-}" ]]; then GIVEN+="$key=${!key}"$'\n'; fi
done

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
HOSTS_FILE="$BLOCK_DIR/blocklist.hosts"
# Optional: ENCRYPTED_DNS=1 sends lookups to the internet encrypted (DNS-over-HTTPS via dnscrypt-proxy),
# so your internet provider cannot read them.
ENCRYPTED_DNS="${ENCRYPTED_DNS:-0}"
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
install -d -m 755 "$(dirname "$CONF")"
(umask 077; printf '%s' "$GIVEN" > "$CONF")
install -m 644 "$SRC/netinv.py" "$SRC/deco.py" "$SRC/dashboard.html" /opt/netinv/
# The block list lives outside /var/lib/netinv so dnsmasq (another user) can read it.
install -d -o netinv -g netinv -m 755 "$BLOCK_DIR"
[[ -f "$BLOCK_FILE" ]] || install -o netinv -g netinv -m 644 /dev/null "$BLOCK_FILE"
[[ -f "$HOSTS_FILE" ]] || install -o netinv -g netinv -m 644 /dev/null "$HOSTS_FILE"

UPSTREAM_LINES="server=$UPSTREAM1
server=$UPSTREAM2"
if [[ "$ENCRYPTED_DNS" == 1 ]]; then
  # Debian's dnscrypt-proxy package listens on 127.0.2.1:53. Only switch to it once it demonstrably answers.
  apt-get install -y -qq dnscrypt-proxy || true
  systemctl enable -q --now dnscrypt-proxy.socket dnscrypt-proxy.service 2>/dev/null || true
  sleep 3
  if dig +short +time=3 +tries=2 example.com @127.0.2.1 2>/dev/null | grep -q '^[0-9]'; then
    UPSTREAM_LINES="server=127.0.2.1"
    echo "Encrypted upstream DNS is on (dnscrypt-proxy)."
  else
    echo "WARNING: dnscrypt-proxy did not answer on 127.0.2.1, so lookups stay unencrypted ($UPSTREAM1, $UPSTREAM2)." >&2
  fi
fi

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
$UPSTREAM_LINES
# bare hostnames, common local domains and reverse lookups stay with the router
server=//$GATEWAY
server=/lan/home/$GATEWAY
rev-server=$SUBNET,$GATEWAY
# sites blocked from the dashboard; re-read on SIGHUP (netinv-blocklist.path)
servers-file=$BLOCK_FILE
# ready-made block lists switched on in the dashboard: every listed name answers 0.0.0.0
addn-hosts=$HOSTS_FILE
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
ExecStart=/usr/bin/python3 /opt/netinv/netinv.py --iface $IFACE --gateway $GATEWAY --port $PORT --block-file $BLOCK_FILE --block-hosts $HOSTS_FILE${NOTIFY_URL:+ --notify-url $NOTIFY_URL}
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

# netinv runs unprivileged and cannot signal dnsmasq. systemd watches the two block files
# and tells dnsmasq to re-read them (SIGHUP also drops its cache, so blocks apply at once).
cat > /etc/systemd/system/netinv-blocklist.path <<EOF
[Unit]
Description=netinv - watch the DNS block list

[Path]
PathChanged=$BLOCK_FILE
PathChanged=$HOSTS_FILE

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
