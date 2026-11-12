#!/usr/bin/env python3
"""netinv - home network inventory + DNS activity for a Raspberry Pi.

Three threads, one SQLite file, standard library only:
  scanner : ARP-sweeps the LAN (arp-scan) and keeps a device inventory
  tailer  : follows the dnsmasq query log and attributes lookups to devices
  web     : serves the dashboard and a small JSON API
"""
import argparse
import collections
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(
  mac TEXT PRIMARY KEY, ip TEXT, ip6 TEXT, vendor TEXT, hostname TEXT,
  label TEXT DEFAULT '', known INTEGER DEFAULT 0, randomized INTEGER DEFAULT 0,
  first_seen INTEGER, last_seen INTEGER, host_checked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS dns_hourly(
  dev TEXT, domain TEXT, base TEXT, hour INTEGER, count INTEGER,
  PRIMARY KEY(dev, domain, hour)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS dns_hour ON dns_hourly(hour);
CREATE INDEX IF NOT EXISTS dns_base ON dns_hourly(base);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""

ARP_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s*(.*)$")
NEIGH6_RE = re.compile(r"^(\S+)\s+(?:dev\s+\S+\s+)?lladdr\s+([0-9a-f:]{17})", re.I)
QUERY_RE = re.compile(
    r"^(\w{3})\s+(\d+)\s+(\d\d:\d\d:\d\d)\s+dnsmasq\[\d+\]:\s+(?:\d+\s+\S+\s+)?"
    r"query\[([\w-]+)\]\s+(\S+)\s+from\s+(\S+)")
SECOND_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu", "or", "ne", "go"}


def base_domain(name):
    """Rough registrable domain (no public-suffix list on purpose: zero deps)."""
    p = name.split(".")
    if len(p) <= 2:
        return name
    if len(p[-1]) == 2 and p[-2] in SECOND_LEVEL:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def is_randomized(mac):
    """Locally-administered bit set => private/randomized MAC (phones, etc.)."""
    return int(int(mac[:2], 16) & 2 > 0)


def run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


class App:
    def __init__(self, a):
        self.a = a
        self.lock = threading.Lock()
        self.db = sqlite3.connect(a.db, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("PRAGMA journal_mode=WAL;" + SCHEMA)
        self.ipmap = {}
        for r in self.q("SELECT mac, ip, ip6 FROM devices"):
            for ip in (r["ip"], r["ip6"]):
                if ip:
                    self.ipmap[ip] = r["mac"]
        self.live = collections.deque(maxlen=300)
        self.last_scan = 0

    # ---- db helpers -------------------------------------------------------
    def q(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def x(self, sql, args=(), many=False):
        with self.lock:
            (self.db.executemany if many else self.db.execute)(sql, args)
            self.db.commit()

    def meta(self, k, v=None):
        if v is None:
            r = self.q("SELECT v FROM meta WHERE k=?", (k,))
            return r[0]["v"] if r else None
        self.x("INSERT INTO meta VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))

    # ---- inventory --------------------------------------------------------
    def scan_cmd(self):
        if self.a.scan_cmd:
            return shlex.split(self.a.scan_cmd)
        cmd = ["arp-scan", "--localnet", "--retry=2"]
        if self.a.iface:
            cmd.append("--interface=" + self.a.iface)
        return cmd

    def scan_once(self):
        now = int(time.time())
        found = {}
        for line in run(self.scan_cmd(), timeout=120).splitlines():
            m = ARP_RE.match(line.strip())
            if not m:
                continue
            ip, mac, vendor = m.group(1), m.group(2).lower(), m.group(3)
            vendor = re.sub(r"\(DUP: \d+\)", "", vendor).strip()
            if vendor.startswith("(Unknown"):
                vendor = ""
            found.setdefault(mac, (ip, vendor))
        if self.a.iface:  # arp-scan never lists the machine it runs on
            try:
                with open(f"/sys/class/net/{self.a.iface}/address") as f:
                    mymac = f.read().strip().lower()
                m = re.search(r"inet (\S+?)/", run(["ip", "-4", "-o", "addr", "show", "dev", self.a.iface]))
                if m:
                    found.setdefault(mymac, (m.group(1), "this Pi (netinv)"))
            except OSError:
                pass
        for mac, (ip, vendor) in found.items():
            self.x("""INSERT INTO devices(mac, ip, vendor, randomized, first_seen, last_seen)
                      VALUES(?,?,?,?,?,?) ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip,
                      last_seen=excluded.last_seen,
                      vendor=CASE WHEN excluded.vendor!='' THEN excluded.vendor ELSE vendor END""",
                   (mac, ip, vendor, is_randomized(mac), now, now))
            self.ipmap[ip] = mac
            self.adopt("ip:" + ip, mac)
        # IPv6 neighbours, so lookups arriving over v6 still map to a device
        if self.a.iface and shutil.which("ip"):
            for line in run(["ip", "-6", "neigh", "show", "dev", self.a.iface]).splitlines():
                m = NEIGH6_RE.match(line)
                if m and m.group(2).lower() in found:
                    self.ipmap[m.group(1)] = m.group(2).lower()
                    if not m.group(1).startswith("fe80"):
                        self.x("UPDATE devices SET ip6=? WHERE mac=?", (m.group(1), m.group(2).lower()))
        self.resolve_names(now)
        self.last_scan = now

    def adopt(self, orphan, mac):
        """Lookups logged before a device was identified get moved onto it."""
        with self.lock:
            if self.db.execute("SELECT 1 FROM dns_hourly WHERE dev=? LIMIT 1", (orphan,)).fetchone():
                self.db.execute("""INSERT INTO dns_hourly SELECT ?, domain, base, hour, count FROM dns_hourly
                                   WHERE dev=? ON CONFLICT(dev, domain, hour)
                                   DO UPDATE SET count=count+excluded.count""", (mac, orphan))
                self.db.execute("DELETE FROM dns_hourly WHERE dev=?", (orphan,))
                self.db.commit()

    def resolve_names(self, now):
        rows = self.q("SELECT mac, ip FROM devices WHERE last_seen=? AND host_checked<? LIMIT 10",
                      (now, now - 6 * 3600))
        for r in rows:
            name = ""
            if shutil.which("avahi-resolve"):
                out = run(["avahi-resolve", "-a", r["ip"]], timeout=4).split()
                name = out[1] if len(out) > 1 else ""
            if not name and self.a.gateway and shutil.which("dig"):
                out = run(["dig", "+short", "+time=2", "+tries=1", "-x", r["ip"], "@" + self.a.gateway], timeout=5)
                name = out.strip().splitlines()[0].rstrip(".") if out.strip() else ""
            if name:
                self.x("UPDATE devices SET hostname=?, host_checked=? WHERE mac=?", (name[:100], now, r["mac"]))
            else:
                self.x("UPDATE devices SET host_checked=? WHERE mac=?", (now, r["mac"]))

    def scanner(self):
        while True:
            try:
                self.scan_once()
            except Exception as e:  # keep the thread alive whatever happens
                print("scan error:", e, flush=True)
            time.sleep(self.a.scan_interval)

    # ---- dns --------------------------------------------------------------
    def parse_line(self, line, now):
        m = QUERY_RE.match(line)
        if not m:
            return None
        mon, day, hms, qtype, domain, client = m.groups()
        domain = domain.lower().rstrip(".")
        if domain.endswith(".arpa") or client in ("127.0.0.1", "::1"):
            return None
        year = time.localtime(now).tm_year
        try:
            ts = int(time.mktime(time.strptime(f"{year} {mon} {day} {hms}", "%Y %b %d %H:%M:%S")))
        except ValueError:
            ts = now
        if ts > now + 86400:  # log line from late December read in January
            ts = int(time.mktime(time.strptime(f"{year - 1} {mon} {day} {hms}", "%Y %b %d %H:%M:%S")))
        return ts, self.ipmap.get(client, "ip:" + client), client, qtype, domain[:253]

    def flush(self, pending, f, inode):
        if pending:
            rows = [(dev, dom, base_domain(dom), hour, n) for (dev, dom, hour), n in pending.items()]
            self.x("""INSERT INTO dns_hourly VALUES(?,?,?,?,?) ON CONFLICT(dev, domain, hour)
                      DO UPDATE SET count=count+excluded.count""", rows, many=True)
            pending.clear()
        self.meta("log_pos", f"{inode}:{f.tell()}")

    def tailer(self):
        path, pending, last_prune = self.a.log, collections.Counter(), 0
        for _ in range(150):  # let the first sweep finish so clients can be attributed
            if self.last_scan:
                break
            time.sleep(1)
        while True:
            try:
                f = open(path, "r", errors="replace")
            except OSError:
                time.sleep(5)
                continue
            inode = os.fstat(f.fileno()).st_ino
            saved = (self.meta("log_pos") or "0:0").split(":")
            if int(saved[0]) == inode and int(saved[1]) <= os.fstat(f.fileno()).st_size:
                f.seek(int(saved[1]))
            last_flush = time.time()
            while True:
                pos = f.tell()
                line = f.readline()
                now = int(time.time())
                if line.endswith("\n"):
                    rec = self.parse_line(line, now)
                    if rec:
                        ts, dev, client, qtype, domain = rec
                        pending[(dev, domain, ts - ts % 3600)] += 1
                        self.live.append({"ts": ts, "dev": dev, "ip": client, "type": qtype, "domain": domain})
                    if time.time() - last_flush < 5:
                        continue
                else:
                    f.seek(pos)  # partial line: wait for the rest
                self.flush(pending, f, inode)
                last_flush = time.time()
                if now - last_prune > 3600:
                    self.x("DELETE FROM dns_hourly WHERE hour<?", (now - self.a.retention_days * 86400,))
                    last_prune = now
                if not line.endswith("\n"):
                    try:
                        st = os.stat(path)
                        if st.st_ino != inode or st.st_size < pos:
                            break  # rotated or truncated: reopen
                    except OSError:
                        break
                    time.sleep(1)
            f.close()

    # ---- api --------------------------------------------------------------
    def online_cutoff(self):
        return int(time.time()) - max(3 * self.a.scan_interval, 300)

    def api_summary(self, p):
        now = int(time.time())
        day = now - 86400
        d = self.q("""SELECT COUNT(*) total, COALESCE(SUM(last_seen>=?),0) online,
                      COALESCE(SUM(known=0),0) unknown FROM devices""", (self.online_cutoff(),))[0]
        t = self.q("SELECT COALESCE(SUM(count),0) queries, COUNT(DISTINCT base) domains FROM dns_hourly WHERE hour>=?",
                   (day,))[0]
        return {
            **d, **t, "last_scan": self.last_scan, "now": now,
            "hourly": self.q("SELECT hour, SUM(count) c FROM dns_hourly WHERE hour>=? GROUP BY hour ORDER BY hour", (day,)),
            "top": self.q("""SELECT base name, SUM(count) c, COUNT(DISTINCT dev) devs FROM dns_hourly
                             WHERE hour>=? GROUP BY base ORDER BY c DESC LIMIT 15""", (day,)),
            "fresh": self.q("""SELECT base name, MIN(hour) first, SUM(count) c, COUNT(DISTINCT dev) devs
                               FROM dns_hourly GROUP BY base HAVING first>=? ORDER BY first DESC, c DESC LIMIT 15""", (day,)),
        }

    def api_devices(self, p):
        day = int(time.time()) - 86400
        rows = self.q("""SELECT d.*, d.last_seen>=? online, COALESCE(s.c,0) queries FROM devices d
                         LEFT JOIN (SELECT dev, SUM(count) c FROM dns_hourly WHERE hour>=? GROUP BY dev) s
                         ON s.dev=d.mac ORDER BY d.known, online DESC, d.last_seen DESC""", (self.online_cutoff(), day))
        # clients that made lookups but were never matched to a MAC
        rows += self.q("""SELECT dev mac, substr(dev,4) ip, '' vendor, '' hostname, 'unidentified client' label,
                          1 known, 0 randomized, MIN(hour) first_seen, MAX(hour) last_seen, 0 online,
                          SUM(CASE WHEN hour>=? THEN count ELSE 0 END) queries FROM dns_hourly
                          WHERE dev LIKE 'ip:%' GROUP BY dev""", (day,))
        return rows

    def api_device(self, p):
        hours = min(max(int(p.get("hours", 24)), 1), 24 * 365)
        col = "domain" if p.get("group") == "domain" else "base"
        since = int(time.time()) - hours * 3600
        mac = p.get("mac", "")
        return {
            "top": self.q(f"""SELECT {col} name, SUM(count) c, MAX(hour) last FROM dns_hourly
                              WHERE dev=? AND hour>=? GROUP BY name ORDER BY c DESC LIMIT 50""", (mac, since)),
            "hourly": self.q("SELECT hour, SUM(count) c FROM dns_hourly WHERE dev=? AND hour>=? GROUP BY hour ORDER BY hour",
                             (mac, since)),
        }

    def api_domain(self, p):
        term = p.get("q", "").strip().lower()
        if len(term) < 2:
            return []
        like = "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        return self.q("""SELECT h.domain, h.dev, d.label, d.hostname, d.vendor, d.ip, SUM(h.count) c,
                         MIN(h.hour) first, MAX(h.hour) last FROM dns_hourly h LEFT JOIN devices d ON d.mac=h.dev
                         WHERE h.domain LIKE ? ESCAPE '\\' GROUP BY h.domain, h.dev ORDER BY last DESC, c DESC LIMIT 200""",
                      (like,))

    def api_live(self, p):
        names = {r["mac"]: r["label"] or r["hostname"] or r["vendor"] or r["mac"]
                 for r in self.q("SELECT mac, label, hostname, vendor FROM devices")}
        return [{**e, "name": names.get(e["dev"], e["ip"])} for e in reversed(self.live)]

    def api_update(self, body):
        mac = str(body.get("mac", ""))
        if "label" in body:
            self.x("UPDATE devices SET label=? WHERE mac=?", (str(body["label"])[:80], mac))
        if "known" in body:
            self.x("UPDATE devices SET known=? WHERE mac=?", (1 if body["known"] else 0, mac))
        return {"ok": True}


class Handler(BaseHTTPRequestHandler):
    server_version = "netinv"

    def log_message(self, *a):
        pass

    def host_ok(self):
        """Refuse unexpected Host headers (blocks DNS-rebinding from a web page)."""
        h = (self.headers.get("Host") or "").lower()
        h = h[1:h.index("]")] if h.startswith("[") and "]" in h else h.split(":")[0]
        try:
            ipaddress.ip_address(h)
            return True
        except ValueError:
            return h in self.server.allowed_hosts

    def send(self, code, body, ctype="application/json"):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.host_ok():
            return self.send(403, {"error": "unexpected Host header"})
        u = urlparse(self.path)
        p = {k: v[0] for k, v in parse_qs(u.query).items()}
        app = self.server.app
        if u.path == "/":
            with open(os.path.join(HERE, "dashboard.html"), "rb") as f:
                return self.send(200, f.read(), "text/html; charset=utf-8")
        fn = {"/api/summary": app.api_summary, "/api/devices": app.api_devices, "/api/device": app.api_device,
              "/api/domain": app.api_domain, "/api/live": app.api_live}.get(u.path)
        if not fn:
            return self.send(404, {"error": "not found"})
        try:
            self.send(200, fn(p))
        except (ValueError, sqlite3.Error) as e:
            self.send(400, {"error": str(e)})

    def do_POST(self):
        # JSON content type forces a CORS preflight, which we never answer:
        # other sites cannot make this request from a visitor's browser.
        if not self.host_ok() or self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            return self.send(403, {"error": "forbidden"})
        if self.path != "/api/device":
            return self.send(404, {"error": "not found"})
        try:
            body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 4096)))
            self.send(200, self.server.app.api_update(body))
        except (ValueError, AttributeError):
            self.send(400, {"error": "bad request"})


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="/var/lib/netinv/netinv.db")
    ap.add_argument("--log", default="/var/log/netinv/dnsmasq.log", help="dnsmasq query log to follow")
    ap.add_argument("--iface", default="", help="LAN interface, e.g. eth0")
    ap.add_argument("--gateway", default="", help="router IP, used for reverse-DNS hostnames")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--scan-interval", type=int, default=60, help="seconds between ARP sweeps")
    ap.add_argument("--retention-days", type=int, default=30)
    ap.add_argument("--scan-cmd", default="", help="override the scan command (testing)")
    ap.add_argument("--allow-host", action="append", default=[], help="extra hostname the dashboard is reached by")
    a = ap.parse_args()

    app = App(a)
    threading.Thread(target=app.scanner, daemon=True).start()
    threading.Thread(target=app.tailer, daemon=True).start()
    srv = ThreadingHTTPServer((a.bind, a.port), Handler)
    srv.app = app
    host = socket.gethostname().lower()
    srv.allowed_hosts = {"localhost", host, host + ".local", host + ".lan", host + ".home"} | {h.lower() for h in a.allow_host}
    print(f"netinv listening on http://{a.bind}:{a.port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
