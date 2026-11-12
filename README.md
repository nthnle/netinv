# netinv

Home network inventory and DNS activity, on a Raspberry Pi.

- **Inventory**: ARP sweep of the LAN every 60 s. Each device gets a row keyed by MAC with IP, vendor, hostname, first/last seen, a label you set, and a "new" flag until you review it.
- **Traffic (DNS level)**: the Pi runs dnsmasq as the network's DNS forwarder with query logging. netinv follows that log and attributes every lookup to a device.
- **Dashboard**: `http://<pi-ip>:8080`. Devices, per-device domains over 24h/7d/30d, network-wide top domains, domains first seen in the last 24h, "which devices looked up X", and a live tail.

One Python file, standard library only, one SQLite database.

## Install

On the Pi (Raspberry Pi OS / Debian, wired Ethernet preferred):

```
git clone <this repo> && cd netinv
sudo ./install.sh
```

The installer detects the interface and router; override with `IFACE=`, `GATEWAY=`, `UPSTREAM1=`, `UPSTREAM2=`, `PORT=`. Then, on the router:

1. Give the Pi a DHCP reservation so its address never changes.
2. Set the DHCP-advertised DNS server to the Pi's address, and only that.

The inventory works before step 2. DNS data appears as devices renew their leases.

## What it will not see

- **Encrypted or hard-coded DNS.** Browsers with DNS-over-HTTPS on, iCloud Private Relay, and devices that ignore DHCP DNS (some Google/Chromecast and smart TV gear uses 8.8.8.8) bypass the Pi. A device that is online with zero lookups is the tell.
- **IPv6 DNS from the router.** If your ISP gives you IPv6, the router may advertise its own v6 resolver alongside the Pi. Turn off the router's IPv6 DNS advertisement (RDNSS / DHCPv6 DNS) if it has that setting.
- **Volume.** DNS shows who talks to what, not how many bytes. That needs flow data from the router, which consumer routers do not export.
- **Routers that lock the DNS setting.** Some ISP-managed mesh systems do not let you change DHCP DNS. The workaround is disabling the router's DHCP and letting dnsmasq on the Pi do DHCP too.

## Things to know

- **The Pi becomes a dependency.** If it is off, name resolution stops for the whole house. Adding a second DNS server on the router avoids that but lets devices skip the log at will. Pick one.
- **Private MAC addresses.** Phones use a different randomized MAC per network, and some rotate it. Those are tagged "private MAC"; a rotating one shows up as a new device each time.
- **Offline is approximate.** Sleeping phones often ignore ARP, so "online" means "answered a sweep in the last 5 minutes".
- **No login on the dashboard.** Anyone on the LAN can read it. It rejects cross-site writes and unexpected Host headers, but if you have a guest network that can reach the Pi, firewall port 8080 or run with `--bind 127.0.0.1` behind a reverse proxy. If you reach it by a custom name, add `--allow-host name`.
- **Storage.** Lookups are stored as hourly counts per device and domain, kept 30 days (`--retention-days`). The raw dnsmasq log rotates daily and keeps 3 days.

## Operate

```
systemctl status netinv dnsmasq
journalctl -u netinv -f
sqlite3 /var/lib/netinv/netinv.db 'select mac, ip, vendor, label from devices'
```

Files: `/opt/netinv` (code), `/var/lib/netinv/netinv.db` (data), `/var/log/netinv/dnsmasq.log` (raw queries), `/etc/dnsmasq.d/netinv.conf`, `/etc/systemd/system/netinv.service`.

Uninstall: `sudo systemctl disable --now netinv dnsmasq`, set the router's DNS back, then remove the files above.
