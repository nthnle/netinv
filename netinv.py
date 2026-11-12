#!/usr/bin/env python3
"""netinv - home network inventory + DNS activity for a Raspberry Pi.

Three threads, one SQLite file, standard library only:
  scanner : ARP-sweeps the LAN (arp-scan) and keeps a device inventory
  tailer  : follows the dnsmasq query log and attributes lookups to devices
  web     : serves the dashboard and a small JSON API
"""
import argparse
import collections
import csv
import functools
import io
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
import urllib.request
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
CREATE TABLE IF NOT EXISTS blocked(domain TEXT PRIMARY KEY, added INTEGER);
CREATE TABLE IF NOT EXISTS dismissed(key TEXT PRIMARY KEY, ts INTEGER);
"""

ARP_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s*(.*)$")
NEIGH6_RE = re.compile(r"^(\S+)\s+(?:dev\s+\S+\s+)?lladdr\s+([0-9a-f:]{17})", re.I)
QUERY_RE = re.compile(
    r"^(\w{3})\s+(\d+)\s+(\d\d:\d\d:\d\d)\s+dnsmasq\[\d+\]:\s+(?:\d+\s+\S+\s+)?"
    r"query\[([\w-]+)\]\s+(\S+)\s+from\s+(\S+)")
# A name we are willing to write into dnsmasq's config: plain hostname labels, at least two of them.
DOMAIN_RE = re.compile(r"(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}")
PI_VENDOR = "this Pi (netinv)"
SECOND_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu", "or", "ne", "go"}

# Lookups that give away what a device is, for devices that report no name.
# (guess, is an operating system, domain suffixes). An OS match counts triple:
# a phone with the Ring app is still a phone, a Ring doorbell never asks for icloud.com.
FINGERPRINTS = [
    ("Apple device (iPhone, iPad or Mac)", 1, "icloud.com push.apple.com captive.apple.com gs-loc.apple.com "
                                              "mesu.apple.com mzstatic.com apple-dns.net"),
    ("Android phone or tablet", 1, "connectivitycheck.gstatic.com connectivitycheck.android.com "
                                   "android.clients.google.com android.googleapis.com"),
    ("Windows PC", 1, "msftconnecttest.com msftncsi.com windowsupdate.com wns.windows.com"),
    ("Linux computer", 1, "connectivity-check.ubuntu.com ntp.ubuntu.com fedoraproject.org archlinux.org"),
    ("Raspberry Pi", 1, "raspberrypi.com raspberrypi.org"),
    ("Samsung TV", 0, "samsungcloudsolution.com samsungcloudsolution.net samsungacr.com samsungads.com"),
    ("LG TV", 0, "lgtvsdp.com lgsmartad.com lgappstv.com lgtvcommon.com"),
    ("Roku", 0, "roku.com"),
    ("Amazon Echo or Fire device", 0, "amazonalexa.com device-metrics-us.amazon.com"),
    ("Google Nest device", 0, "nest.com"),
    ("Sonos speaker", 0, "sonos.com"),
    ("Xbox", 0, "xboxlive.com"),
    ("PlayStation", 0, "playstation.net playstation.com"),
    ("Nintendo console", 0, "nintendo.net nintendowifi.net"),
    ("Ring doorbell or camera", 0, "ring.com"),
    ("Wyze camera or sensor", 0, "wyzecam.com wyze.com"),
    ("Philips Hue bridge", 0, "meethue.com"),
    ("TP-Link / Kasa smart device", 0, "tplinkcloud.com tplinkra.com tplinknbu.com"),
    ("Tuya-based smart plug or bulb", 0, "tuyaus.com tuyaeu.com tuyacn.com tuya.com"),
    ("ecobee thermostat", 0, "ecobee.com"),
    ("Robot vacuum (iRobot)", 0, "irobotapi.com"),
    ("HP printer", 0, "hpeprint.com hpconnected.com"),
    ("Epson printer", 0, "epsonconnect.com"),
]
HINT_SUFFIX = {s: (guess, is_os) for guess, is_os, sufs in FINGERPRINTS for s in sufs.split()}

# What a lookup means in plain words: category -> "Service=suffix suffix; Service=suffix".
# Far from complete on purpose; anything not listed is reported as "Other".
OTHER, HIDDEN = "Other", "VPN & encrypted DNS"
BACKGROUND = {"System services", "Cloud & CDN", "Ads & tracking"}  # happens without anyone doing anything
UNBLOCKABLE = {"System services", "Cloud & CDN"}  # too much rides on these to block a whole service in one click
SERVICES = {
    "Streaming video": "Netflix=netflix.com nflxvideo.net nflximg.net nflxso.net nflxext.com; "
                       "YouTube=youtube.com googlevideo.com ytimg.com youtu.be youtubei.googleapis.com; "
                       "Disney+=disneyplus.com disney-plus.net bamgrid.com dssott.com; Hulu=hulu.com hulustream.com; "
                       "Prime Video=primevideo.com aiv-cdn.net aiv-delivery.net; Max=max.com hbomax.com; "
                       "Twitch=twitch.tv ttvnw.net jtvnw.net; Plex=plex.tv plex.direct; Peacock=peacocktv.com; "
                       "Paramount+=paramountplus.com; Apple TV=tv.apple.com; Roku=roku.com; Vimeo=vimeo.com vimeocdn.com",
    "Music & audio": "Spotify=spotify.com scdn.co spotifycdn.com; Apple Music=music.apple.com itunes.apple.com; "
                     "Pandora=pandora.com; SoundCloud=soundcloud.com sndcdn.com; Sonos=sonos.com; TuneIn=tunein.com; "
                     "Audible=audible.com; iHeart=iheart.com",
    "Social media": "Facebook=facebook.com fbcdn.net facebook.net fbsbx.com; Instagram=instagram.com cdninstagram.com; "
                    "TikTok=tiktok.com tiktokcdn.com tiktokcdn-us.com tiktokv.com tiktokv.us byteoversea.com ibytedtos.com musical.ly; "
                    "Snapchat=snapchat.com sc-cdn.net; X (Twitter)=twitter.com x.com twimg.com t.co; "
                    "Reddit=reddit.com redd.it redditmedia.com redditstatic.com; Pinterest=pinterest.com pinimg.com; "
                    "LinkedIn=linkedin.com licdn.com; Threads=threads.net; Bluesky=bsky.app bsky.social",
    "Messaging & calls": "WhatsApp=whatsapp.com whatsapp.net; Discord=discord.com discord.gg discordapp.com discordapp.net discord.media; "
                         "Telegram=telegram.org t.me; Signal=signal.org; Zoom=zoom.us zoom.com; Messenger=messenger.com; "
                         "Slack=slack.com slack-edge.com slackb.com; Skype / Teams=skype.com teams.microsoft.com teams.live.com; "
                         "FaceTime / iMessage=facetime.apple.com ess.apple.com",
    "Gaming": "Steam=steampowered.com steamcommunity.com steamstatic.com steamcontent.com; Xbox=xboxlive.com xbox.com; "
              "PlayStation=playstation.net playstation.com sonyentertainmentnetwork.com; "
              "Nintendo=nintendo.net nintendo.com nintendowifi.net; Epic Games=epicgames.com epicgames.dev fortnite.com; "
              "Roblox=roblox.com rbxcdn.com; Riot Games=riotgames.com leagueoflegends.com; Blizzard=blizzard.com battle.net; "
              "EA=ea.com origin.com; Minecraft=minecraft.net mojang.com minecraftservices.com",
    "Shopping": "Amazon=amazon.com amazon.ca amazon.co.uk media-amazon.com ssl-images-amazon.com; eBay=ebay.com ebaystatic.com ebayimg.com; "
                "Walmart=walmart.com walmartimages.com; Etsy=etsy.com etsystatic.com; Target=target.com; Temu=temu.com; "
                "Shein=shein.com; AliExpress=aliexpress.com alicdn.com; Costco=costco.com; Best Buy=bestbuy.com",
    "Email & work": "Microsoft 365=office.com office365.com office.net outlook.com sharepoint.com onedrive.com microsoftonline.com; "
                    "Gmail=gmail.com mail.google.com; Google Docs=docs.google.com drive.google.com; "
                    "GitHub=github.com githubusercontent.com githubassets.com; Dropbox=dropbox.com dropboxapi.com dropboxstatic.com; "
                    "Notion=notion.so; Atlassian=atlassian.com atlassian.net; Yahoo Mail=mail.yahoo.com; Proton=proton.me protonmail.com",
    "AI assistants": "ChatGPT=openai.com chatgpt.com oaistatic.com oaiusercontent.com; Claude=claude.ai anthropic.com; "
                     "Gemini=gemini.google.com; Copilot=copilot.microsoft.com; Perplexity=perplexity.ai",
    "Search & reference": "Bing=bing.com; DuckDuckGo=duckduckgo.com; Wikipedia=wikipedia.org wikimedia.org; "
                          "Yahoo=yahoo.com yimg.com; Google Search=www.google.com",
    "Smart home": "Ring=ring.com; Google Nest=nest.com; Alexa=amazonalexa.com device-metrics-us.amazon.com; "
                  "Tuya=tuya.com tuyaus.com tuyaeu.com tuyacn.com; TP-Link / Kasa=tplinkcloud.com tplinkra.com tplinknbu.com; "
                  "Philips Hue=meethue.com; Wyze=wyze.com wyzecam.com; ecobee=ecobee.com; SmartThings=smartthings.com; "
                  "iRobot=irobot.com irobotapi.com; Home Assistant=home-assistant.io nabucasa.com; Arlo=arlo.com; "
                  "Eufy=eufylife.com; Govee=govee.com; myQ=myqdevice.com",
    "Adult sites": "Pornhub=pornhub.com phncdn.com; XVideos=xvideos.com; xHamster=xhamster.com; XNXX=xnxx.com; OnlyFans=onlyfans.com",
    HIDDEN: "iCloud Private Relay=mask.icloud.com mask-h2.icloud.com mask-api.icloud.com; Google DNS-over-HTTPS=dns.google; "
            "Cloudflare DNS-over-HTTPS=cloudflare-dns.com one.one.one.one; Quad9 DNS=quad9.net; NextDNS=nextdns.io; "
            "AdGuard DNS=adguard-dns.com; NordVPN=nordvpn.com nordvpn.net; ExpressVPN=expressvpn.com; "
            "Proton VPN=protonvpn.com protonvpn.ch; Mullvad=mullvad.net; Surfshark=surfshark.com; Tailscale=tailscale.com; "
            "Tor=torproject.org",
    "Ads & tracking": "Google ads & analytics=doubleclick.net googlesyndication.com googleadservices.com google-analytics.com "
                      "googletagmanager.com googletagservices.com app-measurement.com crashlytics.com; "
                      "Amazon ads=amazon-adsystem.com; Meta ads=graph.facebook.com an.facebook.com; "
                      "Smart TV ad tracking=samsungads.com samsungacr.com lgsmartad.com; "
                      "Ad networks=adnxs.com criteo.com criteo.net taboola.com outbrain.com rubiconproject.com pubmatic.com "
                      "openx.net adsrvr.org moatads.com quantserve.com applovin.com unityads.unity3d.com scorecardresearch.com; "
                      "App analytics=branch.io appsflyer.com adjust.com mixpanel.com segment.io segment.com amplitude.com "
                      "newrelic.com nr-data.net sentry.io hotjar.com demdex.net omtrdc.net bugsnag.com",
    "System services": "Apple=apple.com icloud.com mzstatic.com apple-dns.net aaplimg.com icloud-content.com cdn-apple.com; "
                       "Google=google.com gstatic.com googleapis.com googleusercontent.com gvt1.com gvt2.com ggpht.com android.com; "
                       "Microsoft=microsoft.com windows.com windowsupdate.com msftconnecttest.com msftncsi.com live.com msn.com "
                       "windows.net msedge.net; Samsung=samsung.com samsungcloudsolution.com samsungcloudsolution.net; "
                       "LG=lgtvsdp.com lgappstv.com lgtvcommon.com; Time sync=ntp.org time.nist.gov; "
                       "Linux updates=ubuntu.com canonical.com debian.org raspberrypi.com raspberrypi.org fedoraproject.org; "
                       "Mozilla=mozilla.org mozilla.com mozilla.net firefox.com",
    "Cloud & CDN": "Amazon Web Services=amazonaws.com cloudfront.net awsstatic.com; "
                   "Akamai=akamai.net akamaiedge.net akamaihd.net akamaized.net edgekey.net edgesuite.net akadns.net; "
                   "Cloudflare=cloudflare.com cloudflare.net cdnjs.com; Fastly=fastly.net fastlylb.net; "
                   "Microsoft Azure=azure.com azureedge.net trafficmanager.net cloudapp.net azurewebsites.net; Google Cloud=1e100.net",
}
SERVICE = {dom: (item.partition("=")[0].strip(), cat) for cat, src in SERVICES.items()
           for item in src.split(";") for dom in item.partition("=")[2].split()}


@functools.lru_cache(maxsize=50000)
def classify(domain):
    """(service, category) for a looked-up name, by longest matching suffix."""
    name = domain
    while name:
        if name in SERVICE:
            return SERVICE[name]
        name = name.partition(".")[2]
    return "", OTHER


def site(domain):
    """What the dashboard needs to describe a name: service, and whether the whole service can be blocked."""
    svc, cat = classify(domain)
    return {"svc": svc, "risky": cat in UNBLOCKABLE, "whole": bool(svc) and cat not in UNBLOCKABLE}


def activity(rows):
    """Roll (domain, count) rows up into categories, biggest first, with the services seen in each."""
    cats, svcs = collections.Counter(), collections.defaultdict(collections.Counter)
    for r in rows:
        svc, cat = classify(r["domain"])
        cats[cat] += r["c"]
        if svc:
            svcs[cat][svc] += r["c"]
    return [{"cat": cat, "c": c, "background": cat in BACKGROUND or cat == OTHER,
             "services": [n for n, _ in svcs[cat].most_common(4)]} for cat, c in cats.most_common()]


def mostly(cats):
    """One short phrase for the device list: what a device mainly did, ignoring background chatter."""
    total = sum(c["c"] for c in cats)
    if not total:
        return ""
    fg = [c["cat"] for c in cats if not c["background"] and c["c"] >= max(2, total * 0.03)]
    if fg:
        return ", ".join(fg[:2])
    other = sum(c["c"] for c in cats if c["cat"] == OTHER)
    return "Other sites" if other > total / 2 else "Background only"


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
        self.hint_cache = (0, {})
        self.day_cache = (0, {}, [])
        try:
            self.write_blocklist()  # file and database agree from the start
        except ValueError:
            pass

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
                    found.setdefault(mymac, (m.group(1), PI_VENDOR))
            except OSError:
                pass
        before = {r["mac"] for r in self.q("SELECT mac FROM devices")}
        for mac, (ip, vendor) in found.items():
            if before and mac not in before:  # not on the very first sweep, when everything is new
                self.notify(f"New device on your network: {vendor or 'unknown maker'} at {ip} ({mac})")
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

    def notify(self, text):
        """Optional push alert: plain-text POST, which is what ntfy.sh and most webhooks take."""
        if not self.a.notify_url:
            return
        try:
            req = urllib.request.Request(self.a.notify_url, data=text.encode(), headers={"Title": "netinv"})
            urllib.request.urlopen(req, timeout=8).close()
        except (OSError, ValueError) as e:
            print("notify failed:", e, flush=True)

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
        named = lambda rows: [{**r, **site(r["name"])} for r in rows]
        top = self.q("""SELECT base name, SUM(count) c, COUNT(DISTINCT dev) devs FROM dns_hourly
                        WHERE hour>=? GROUP BY base ORDER BY c DESC LIMIT 15""", (day,))
        fresh = self.q("""SELECT base name, MIN(hour) first, SUM(count) c, COUNT(DISTINCT dev) devs
                          FROM dns_hourly GROUP BY base HAVING first>=? ORDER BY first DESC, c DESC LIMIT 15""", (day,))
        return {
            **d, **t, "last_scan": self.last_scan, "now": now, "activity": self.day_activity()[1],
            "can_block": bool(self.a.block_file), "blocked": [r["domain"] for r in self.q("SELECT domain FROM blocked")],
            "top": named(top), "fresh": named(fresh),
            "hourly": self.q("SELECT hour, SUM(count) c FROM dns_hourly WHERE hour>=? GROUP BY hour ORDER BY hour", (day,)),
        }

    def day_activity(self):
        """Last 24h rolled up into categories: ({device: categories}, whole network). Cached a minute."""
        now = time.time()
        if now - self.day_cache[0] < 60:
            return self.day_cache[1:]
        rows = self.q("SELECT dev, domain, SUM(count) c FROM dns_hourly WHERE hour>=? GROUP BY dev, domain",
                      (int(now) - 86400,))
        per = collections.defaultdict(list)
        for r in rows:
            per[r["dev"]].append(r)
        self.day_cache = (now, {dev: activity(rs) for dev, rs in per.items()}, activity(rows))
        return self.day_cache[1:]

    def sparks(self):
        """Lookups per hour for the last 24 hours, oldest first, per device."""
        now = int(time.time())
        first = now - now % 3600 - 23 * 3600
        out = collections.defaultdict(lambda: [0] * 24)
        for r in self.q("SELECT dev, hour, SUM(count) c FROM dns_hourly WHERE hour>=? GROUP BY dev, hour", (first,)):
            out[r["dev"]][(r["hour"] - first) // 3600] = r["c"]
        return out

    def hints(self):
        """Best guess at what each device is, from a week of its lookups. Cached 5 minutes."""
        now = time.time()
        if now - self.hint_cache[0] < 300:
            return self.hint_cache[1]
        bases = sorted({base_domain(s) for s in HINT_SUFFIX})
        rows = self.q(f"""SELECT dev, domain, SUM(count) c FROM dns_hourly WHERE hour>=? AND base IN
                          ({",".join("?" * len(bases))}) GROUP BY dev, domain""", (int(now) - 7 * 86400, *bases))
        score = collections.defaultdict(collections.Counter)
        for r in rows:
            name = r["domain"]
            while name:  # suffix match: a.b.icloud.com -> b.icloud.com -> icloud.com
                if name in HINT_SUFFIX:
                    guess, is_os = HINT_SUFFIX[name]
                    score[r["dev"]][(is_os, guess)] += r["c"]
                    break
                name = name.partition(".")[2]
        out = {}
        for dev, s in score.items():
            # an OS match wins unless something else dwarfs it (an Xbox pings Microsoft too)
            (is_os, guess), n = max(s.items(), key=lambda kv: kv[1] * (3 if kv[0][0] else 1))
            if n >= 2:
                out[dev] = guess
        self.hint_cache = (now, out)
        return out

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
        hints, doing, sparks = self.hints(), self.day_activity()[0], self.sparks()
        for r in rows:
            r["spark"] = sparks.get(r["mac"]) or [0] * 24
            cats = doing.get(r["mac"], [])
            r["hint"] = hints.get(r["mac"], "")
            # the router and this Pi do not ask netinv for addresses, so silence from them is normal
            r["infra"] = ("router" if self.a.gateway and r["ip"] == self.a.gateway
                          else "pi" if r["vendor"] == PI_VENDOR else "")
            r["mostly"] = mostly(cats)
            r["hidden"] = int(any(c["cat"] == HIDDEN for c in cats))
        return rows

    def devices_csv(self):
        iso = lambda ts: time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else ""
        # names come off the network: stop a spreadsheet from running one as a formula
        safe = lambda v: "'" + v if isinstance(v, str) and v and v[0] in "=+-@" else v
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["label", "hostname", "looks_like", "vendor", "ip", "mac", "private_mac", "reviewed", "online",
                    "first_seen", "last_seen", "lookups_24h", "mostly_24h"])
        for r in self.api_devices({}):
            w.writerow([safe(v) for v in (
                r["label"], r["hostname"] or "", r["hint"], r["vendor"] or "", r["ip"] or "",
                "" if r["mac"].startswith("ip:") else r["mac"], r["randomized"], r["known"], r["online"],
                iso(r["first_seen"]), iso(r["last_seen"]), r["queries"], r["mostly"])])
        return out.getvalue().encode("utf-8-sig")

    def api_device(self, p):
        hours = min(max(int(p.get("hours", 24)), 1), 24 * 365)
        col = "domain" if p.get("group") == "domain" else "base"
        since = int(time.time()) - hours * 3600
        mac = p.get("mac", "")
        top = self.q(f"""SELECT {col} name, SUM(count) c, MAX(hour) last FROM dns_hourly
                         WHERE dev=? AND hour>=? GROUP BY name ORDER BY c DESC LIMIT 50""", (mac, since))
        return {
            "top": [{**r, **site(r["name"])} for r in top],
            "activity": activity(self.q("SELECT domain, SUM(count) c FROM dns_hourly WHERE dev=? AND hour>=? GROUP BY domain",
                                        (mac, since))),
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
        hints = self.hints()
        names = {r["mac"]: r["label"] or r["hostname"] or hints.get(r["mac"]) or r["vendor"] or "Unknown device " + r["ip"]
                 for r in self.q("SELECT mac, ip, label, hostname, vendor FROM devices")}
        return [{**e, "name": names.get(e["dev"], e["ip"])} for e in reversed(self.live)]

    def api_attention(self, p):
        """Things worth a person's time, most urgent first. Each can be acted on or dismissed."""
        gone = {r["key"] for r in self.q("SELECT key FROM dismissed")}
        doing, now, items = self.day_activity()[0], time.time(), []
        for d in self.api_devices({}):
            mac = d["mac"]
            if mac.startswith("ip:"):
                continue
            if not d["known"]:
                items.append({"key": "new:" + mac, "kind": "new", "mac": mac})
                continue
            cats = {c["cat"]: c for c in doing.get(mac, [])}
            total = sum(c["c"] for c in cats.values())
            found = []
            if d["online"] and not d["queries"] and not d["infra"] and now - d["first_seen"] > 3600:
                found.append({"kind": "silent"})
            if HIDDEN in cats:
                found.append({"kind": "hidden", "services": cats[HIDDEN]["services"]})
            ads = cats.get("Ads & tracking")
            if ads and ads["c"] >= 50 and ads["c"] >= total * 0.3:
                found.append({"kind": "tracking", "services": ads["services"], "pct": round(ads["c"] / total * 100)})
            items += [{**f, "key": f"{f['kind']}:{mac}", "mac": mac} for f in found if f"{f['kind']}:{mac}" not in gone]
        return items

    def api_dismiss(self, body):
        self.x("INSERT OR REPLACE INTO dismissed VALUES(?,?)", (str(body.get("key", ""))[:80], int(time.time())))
        return {"ok": True}

    def api_forget(self, body):
        """Drop a device and its history. If it is still around, the next sweep lists it again as new."""
        mac = str(body.get("mac", ""))
        self.x("DELETE FROM devices WHERE mac=?", (mac,))
        self.x("DELETE FROM dns_hourly WHERE dev=?", (mac,))
        self.x("DELETE FROM dismissed WHERE key LIKE ?", ("%:" + mac,))
        for ip in [ip for ip, m in list(self.ipmap.items()) if m == mac]:
            self.ipmap.pop(ip, None)
        self.day_cache = (0, {}, [])
        return {"ok": True}

    # ---- blocking ---------------------------------------------------------
    def write_blocklist(self):
        """dnsmasq re-reads this file on SIGHUP. `server=/name/` with no address means: never
        forward this name or anything under it, so clients get "no such domain"."""
        if not self.a.block_file:
            return
        body = "# Managed by netinv. Edit the block list from the dashboard.\n" + "".join(
            f"server=/{r['domain']}/\n" for r in self.q("SELECT domain FROM blocked ORDER BY domain"))
        try:
            try:
                with open(self.a.block_file, newline="") as f:
                    if f.read() == body:
                        return
            except OSError:
                pass
            with open(self.a.block_file, "w", newline="\n") as f:
                f.write(body)
        except OSError as e:
            print("cannot write block list:", e, flush=True)
            raise ValueError("Could not write the block list file.")

    def api_block(self, body):
        if not self.a.block_file:
            raise ValueError("Blocking is not set up on this install. Re-run install.sh to enable it.")
        on = body.get("on", True)
        if body.get("service"):
            name = str(body["service"])
            domains = sorted(d for d, (svc, cat) in SERVICE.items() if svc == name and cat not in UNBLOCKABLE)
            if not domains:
                raise ValueError("netinv does not know that service well enough to block all of it.")
            if on:
                self.x("INSERT OR IGNORE INTO blocked VALUES(?,?)", [(d, int(time.time())) for d in domains], many=True)
            else:
                self.x("DELETE FROM blocked WHERE domain=?", [(d,) for d in domains], many=True)
            self.write_blocklist()
            return {"ok": True, "count": len(domains)}
        domain = str(body.get("domain", "")).strip().lower()
        domain = re.sub(r"^(?:https?://)?(?:\*\.)?", "", domain).split("/")[0].rstrip(".")
        parts = domain.split(".")
        if not DOMAIN_RE.fullmatch(domain):
            raise ValueError("That does not look like a site address. Try something like tiktok.com")
        if len(parts) == 2 and len(parts[1]) == 2 and parts[0] in SECOND_LEVEL:
            raise ValueError("That would block a whole country's sites. Name a specific site.")
        if on:
            self.x("INSERT OR IGNORE INTO blocked VALUES(?,?)", (domain, int(time.time())))
        else:
            self.x("DELETE FROM blocked WHERE domain=?", (domain,))
        self.write_blocklist()
        return {"ok": True, "domain": domain}

    def api_blocked(self, p):
        day, rows = int(time.time()) - 86400, self.q("SELECT domain, added FROM blocked ORDER BY added DESC")
        for r in rows:
            like = "%." + r["domain"].replace("_", "\\_")
            r.update(self.q("""SELECT COALESCE(SUM(count),0) c, COUNT(DISTINCT dev) devs FROM dns_hourly
                               WHERE hour>=? AND (domain=? OR domain LIKE ? ESCAPE '\\')""", (day, r["domain"], like))[0])
            r.update(site(r["domain"]))
        return {"enabled": bool(self.a.block_file), "rows": rows}

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

    def send(self, code, body, ctype="application/json", filename=None):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
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
        if u.path == "/api/devices.csv":
            return self.send(200, app.devices_csv(), "text/csv; charset=utf-8", "netinv-devices.csv")
        fn = {"/api/summary": app.api_summary, "/api/devices": app.api_devices, "/api/device": app.api_device,
              "/api/domain": app.api_domain, "/api/live": app.api_live, "/api/attention": app.api_attention,
              "/api/blocked": app.api_blocked}.get(u.path)
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
        app = self.server.app
        fn = {"/api/device": app.api_update, "/api/block": app.api_block, "/api/dismiss": app.api_dismiss,
              "/api/forget": app.api_forget}.get(self.path)
        if not fn:
            return self.send(404, {"error": "not found"})
        try:
            body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 4096)))
        except ValueError:
            return self.send(400, {"error": "bad request"})
        try:
            self.send(200, fn(body))
        except ValueError as e:  # raised with a message meant for the person at the dashboard
            self.send(400, {"error": str(e)})
        except (AttributeError, sqlite3.Error):
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
    ap.add_argument("--block-file", default="", help="dnsmasq servers-file netinv may write blocked domains to")
    ap.add_argument("--notify-url", default="",
                    help="POST a line of text here when a new device joins (e.g. an ntfy.sh topic URL)")
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
