#!/usr/bin/env python3
"""lanledger - what is on your home network, and what is it doing? For a Raspberry Pi.

One SQLite file, standard library only. A handful of threads:
  scanner : ARP-sweeps the LAN (arp-scan), keeps the device inventory, records who comes and goes
  tailer  : follows the dnsmasq query log and attributes every lookup to a device
  monitor : checks the internet is up, switches scheduled blocks on and off, refreshes block lists
  deco    : optional - asks a TP-Link Deco mesh what it knows about each device (see deco.py)
  web     : serves the dashboard and a small JSON API
"""
import argparse
import collections
import csv
import functools
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import sqlite3
import statistics
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))

try:
    import deco  # optional: only needed to talk to a TP-Link Deco mesh
except ImportError:
    deco = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(
  mac TEXT PRIMARY KEY, ip TEXT, ip6 TEXT, vendor TEXT, hostname TEXT,
  label TEXT DEFAULT '', known INTEGER DEFAULT 0, randomized INTEGER DEFAULT 0,
  first_seen INTEGER, last_seen INTEGER, host_checked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS dns_hourly(
  dev TEXT, domain TEXT, base TEXT, hour INTEGER, count INTEGER,
  PRIMARY KEY(dev, domain, hour)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS dns_hour ON dns_hourly(hour);
CREATE INDEX IF NOT EXISTS dns_base_hour ON dns_hourly(base, hour);
DROP INDEX IF EXISTS dns_base;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS blocked(domain TEXT PRIMARY KEY, added INTEGER);
CREATE TABLE IF NOT EXISTS dismissed(key TEXT PRIMARY KEY, ts INTEGER);
CREATE TABLE IF NOT EXISTS allowed(domain TEXT PRIMARY KEY, added INTEGER);
CREATE TABLE IF NOT EXISTS lists(id TEXT PRIMARY KEY, enabled INTEGER, updated INTEGER, count INTEGER);
CREATE TABLE IF NOT EXISTS events(ts INTEGER, mac TEXT, kind TEXT, info TEXT);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_mac ON events(mac);
CREATE TABLE IF NOT EXISTS health(ts INTEGER PRIMARY KEY, ok INTEGER, ms INTEGER);
CREATE TABLE IF NOT EXISTS speed(ts INTEGER PRIMARY KEY, down REAL);
CREATE TABLE IF NOT EXISTS usage_hourly(mac TEXT, hour INTEGER, down INTEGER, up INTEGER,
  PRIMARY KEY(mac, hour)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, expires INTEGER);
CREATE TABLE IF NOT EXISTS ports(mac TEXT PRIMARY KEY, ts INTEGER, open TEXT);
CREATE TABLE IF NOT EXISTS threats(dev TEXT, domain TEXT, listed TEXT, first INTEGER, last INTEGER, count INTEGER,
  PRIMARY KEY(dev, domain)) WITHOUT ROWID;
"""
# Columns added after the first release; applied to older databases at startup.
MIGRATIONS = [
    ("devices", "mdns", "TEXT DEFAULT ''"), ("devices", "services", "TEXT DEFAULT ''"),
    ("devices", "deco_name", "TEXT DEFAULT ''"), ("devices", "conn", "TEXT DEFAULT ''"),
    ("devices", "net", "TEXT DEFAULT ''"), ("devices", "parent", "TEXT DEFAULT ''"),
    ("devices", "owner", "TEXT DEFAULT ''"), ("devices", "node", "TEXT DEFAULT ''"), ("dns_hourly", "blocked", "INTEGER DEFAULT 0"),
    ("blocked", "t_from", "INTEGER"), ("blocked", "t_to", "INTEGER"),
    ("devices", "arp_seen", "INTEGER DEFAULT 0"),
]
SESSION_DAYS = 30
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=50000000"  # the server refuses much larger requests

# Ready-made block lists you can switch on: id -> (title, what it covers, where it comes from).
# All from Steven Black's hosts project, https://github.com/StevenBlack/hosts
_SB = "https://raw.githubusercontent.com/StevenBlack/hosts/master/"
# The one list that is watched whether or not it is switched on: a lookup of anything on it is reported,
# with the device that made it. Switching it on blocks those names as well. Kept small on purpose (the
# "mini" edition of a threat feed built from many sources), so it fits comfortably in a Pi's memory.
THREATS = "threats"
THREAT_DAYS = 7  # how long a hit stays on the to-do list
LISTS = {
    THREATS: ("Malware and phishing", "Sites known to spread malware, steal passwords or control infected devices. "
              "lanledger always watches for these and tells you which device tried one. Switch this on to block them as well.",
              "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt"),
    "ads": ("Ads, trackers and malware", "The usual ad networks, trackers and known malicious sites.", _SB + "hosts"),
    "adult": ("Adult sites", "Pornography.", _SB + "alternates/porn-only/hosts"),
    "gambling": ("Gambling", "Betting and casino sites.", _SB + "alternates/gambling-only/hosts"),
    "social": ("Social media", "Facebook, Instagram, TikTok, X and the like.", _SB + "alternates/social-only/hosts"),
    "fakenews": ("Fake news", "Sites known for fabricated news.", _SB + "alternates/fakenews-only/hosts"),
}

# The doors lanledger knocks on when asked to check a device: port -> (what it is, why it matters or "").
PORTS = {
    21: ("FTP file transfer", "Old and unencrypted. Turn it off if you do not use it."),
    22: ("SSH remote login", ""),
    23: ("Telnet remote login", "Unencrypted and a favourite of malware. A device should not have this open."),
    53: ("DNS server", ""),
    80: ("Web page (settings screen)", ""),
    139: ("Windows file sharing", ""),
    443: ("Secure web page", ""),
    445: ("Windows file sharing", ""),
    515: ("Printing", ""),
    548: ("Apple file sharing", ""),
    554: ("Camera video stream", "Anyone on your network may be able to watch if the camera has no password."),
    631: ("Printing", ""),
    1883: ("Smart-home messaging (MQTT)", "Often has no password."),
    2323: ("Telnet remote login (alternate)", "Unencrypted and a favourite of malware."),
    3306: ("Database", "Should not normally be reachable from other devices."),
    3389: ("Windows Remote Desktop", "Lets someone control the PC with its password."),
    5000: ("Web or media service", ""),
    5555: ("Android debugging", "Gives full control of the device without a password. Turn off developer debugging."),
    5900: ("Screen sharing (VNC)", "Lets someone see and control the screen."),
    7000: ("AirPlay", ""),
    8008: ("Chromecast", ""),
    8009: ("Chromecast", ""),
    8080: ("Web page (alternate)", ""),
    8443: ("Secure web page (alternate)", ""),
    8883: ("Smart-home messaging (secure MQTT)", ""),
    9100: ("Printing", ""),
    32400: ("Plex media server", ""),
    37777: ("Camera recorder", "Common on security cameras; make sure the default password was changed."),
    62078: ("iPhone / iPad sync", ""),
}

# Services a device announces on the network that give away what it is, most telling first.
SERVICE_HINTS = [
    ("googlecast", "Chromecast, Google TV or Nest speaker"), ("airplay", "Apple TV, HomePod or AirPlay speaker"),
    ("sonos", "Sonos speaker"), ("amzn-wplay", "Amazon Fire TV or Echo"), ("ipp", "Printer"), ("ipps", "Printer"),
    ("printer", "Printer"), ("pdl-datastream", "Printer"), ("hap", "HomeKit smart-home device"),
    ("spotify-connect", "Speaker or TV with Spotify"), ("raop", "AirPlay speaker"),
    ("companion-link", "Apple device (iPhone, iPad or Mac)"), ("smb", "Computer or network storage"),
    ("afpovertcp", "Mac or network storage"), ("ssh", "Computer"),
]
MDNS_NAMED = ("airplay", "companion-link", "hap", "sonos", "spotify-connect", "mediaremotetv", "raop",
              "ipp", "ipps", "printer")


def service_hint(services):
    have = set(services.split(","))
    return next((hint for svc, hint in SERVICE_HINTS if svc in have), "")


def parse_mdns(text):
    """Turn `avahi-browse -atrp` output into {ip: {"name": best name, "services": {types}}}."""
    def plain(s):  # avahi writes awkward characters as \DDD, one per byte
        raw = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), s).replace("\\.", ".")
        return raw.encode("latin-1", "ignore").decode("utf-8", "replace").strip()
    out = {}
    for line in text.splitlines():
        f = line.split(";")
        if len(f) < 9 or f[0] != "=" or f[2] != "IPv4":
            continue
        svc, ip, e = f[4].lstrip("_").split("._")[0], f[7], None
        e = out.setdefault(ip, {"name": "", "rank": 9, "services": set()})
        e["services"].add(svc)
        fn = re.search(r'"fn=([^"]+)"', ";".join(f[9:]))
        if svc == "googlecast" and fn:
            rank, name = 0, plain(fn.group(1))
        elif svc in MDNS_NAMED:
            rank, name = 1, plain(f[3]).split("@", 1)[-1]
        else:
            rank, name = 5, plain(f[6]).removesuffix(".local")
        if name and rank < e["rank"]:
            e["rank"], e["name"] = rank, name
    return out


ARP_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s*(.*)$")
NEIGH6_RE = re.compile(r"^(\S+)\s+(?:dev\s+\S+\s+)?lladdr\s+([0-9a-f:]{17})", re.I)
QUERY_RE = re.compile(
    r"^(\w{3})\s+(\d+)\s+(\d\d:\d\d:\d\d)\s+dnsmasq\[\d+\]:\s+(?:\d+\s+\S+\s+)?"
    r"query\[([\w-]+)\]\s+(\S+)\s+from\s+(\S+)")
# A name we are willing to write into dnsmasq's config: plain hostname labels, at least two of them.
DOMAIN_RE = re.compile(r"(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}")
PI_VENDOR = "this Pi (lanledger)"
SILENT_DAYS = 7  # an online device with no lookups for this long is flagged as bypassing lanledger
WHERE_EVERY = 300  # seconds between asking each mesh unit which devices are on it
ARP_TRUST = 600  # seconds the Pi's own sighting of an address outranks what the Deco says about it
CUT_OFF = 1800   # online according to the Deco but unanswered by the Pi for this long: isolated from the Pi
OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"  # the public register of who makes which hardware addresses
CONN_NAMES = {"wired": "Wired", "band2_4": "Wi-Fi 2.4 GHz", "band5": "Wi-Fi 5 GHz", "band6": "Wi-Fi 6 GHz"}

# What a device calls itself is better evidence of what it is than what it looks up.
NAME_HINTS = [(re.compile(p, re.I), hint) for p, hint in [
    (r"lg ?webos|webostv", "LG TV"), (r"lg_smart_", "LG smart appliance"), (r"litter-?robot", "Litter-Robot"),
    (r"rachio", "Rachio sprinkler controller"), (r"\bmyq\b", "myQ garage door opener"),
    (r"\b(hs|kp|ep|ks|kl|lb)\d{3}\b", "TP-Link / Kasa smart device"), (r"levoit", "Levoit appliance"),
    (r"\bbrw[0-9a-f]{12}\b|brother", "Brother printer"), (r"nanoleaf", "Nanoleaf light"), (r"narwal", "Narwal robot vacuum"),
    (r"vivint", "Vivint security hub"), (r"hubspace", "Hubspace smart device"), (r"roomba|irobot", "Robot vacuum (iRobot)"),
    (r"\biphone\b", "iPhone"), (r"\bipad\b", "iPad"), (r"macbook|\bimac\b", "Mac"), (r"apple-?watch", "Apple Watch"),
    (r"chromecast", "Chromecast"), (r"\broku", "Roku"), (r"nintendo", "Nintendo console"), (r"playstation|\bps[45]\b", "PlayStation"),
    (r"xbox", "Xbox"), (r"wyze", "Wyze camera or sensor"), (r"sonos", "Sonos speaker"), (r"reolink|\bnvr\b", "Camera recorder"),
    (r"espressif|\besp[-_ ]?(32|8266)", "Small Wi-Fi gadget (Espressif chip)"),
]]


def name_hint(r):
    text = " ".join(r.get(k) or "" for k in ("deco_name", "mdns", "hostname"))
    return next((hint for rx, hint in NAME_HINTS if rx.search(text)), "") if text.strip() else ""


def unit_of(r, nodes):
    """Which mesh unit a row of the inventory is. By address if it has the unit's own; otherwise by hardware
    address. Units bought together differ only in the last two digits, and each unit answers under a few
    addresses a digit or so from its own, so among units that share the rest, the nearest one is it."""
    for n in nodes:
        if n.get("ip") and n["ip"] == r["ip"]:
            return n
    try:
        last = int(r["mac"][15:], 16)
        near = [n for n in nodes if len(n.get("mac") or "") == 17 and n["mac"][:14] == r["mac"][:14]]
        return min(near, key=lambda n: abs(int(n["mac"][15:], 16) - last), default=None)
    except ValueError:
        return None


def parse_oui(text):
    """The IEEE register (CSV: registry, 6 hex digits, organisation, address) as {"AABBCC": "Maker"}."""
    out = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 3 and re.fullmatch(r"[0-9A-Fa-f]{6}", row[1].strip()):
            out[row[1].strip().upper()] = " ".join(row[2].split())[:80]
    return out
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


class SignIn(Exception):
    """Raised where the answer is "sign in first", with what to tell the person."""


class App:
    def __init__(self, a):
        self.a = a
        self.lock = threading.Lock()
        self.db = sqlite3.connect(a.db, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;" + SCHEMA)
        self.cache = {}  # answers the dashboard asks for again and again; thrown away whenever anything is written
        for table, col, decl in MIGRATIONS:  # columns added since the first release
            if col not in {r[1] for r in self.db.execute(f"PRAGMA table_info({table})")}:
                self.db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
        self.db.commit()
        self.db.execute("UPDATE devices SET conn='' WHERE conn='undefined'")  # the Deco's word for "do not know", stored by older versions
        self.db.commit()
        self.ipmap = {}
        self.arp_ip, self.arp_mac = {}, {}  # what the Pi's own sweep last saw: ip -> (mac, when), mac -> (ip, when)
        self.oui, self.oui_tried = {}, 0
        self.load_oui()
        # oldest first, so where two devices are on record with one address the one seen last has it
        for r in self.q("SELECT mac, ip, ip6 FROM devices ORDER BY last_seen"):
            for ip in (r["ip"], r["ip6"]):
                if ip:
                    self.ipmap[ip] = r["mac"]
        self.live = collections.deque(maxlen=3000)
        self.last_scan = 0
        self.hint_cache = (0, {})
        self.day_cache = (0, {}, [])
        self.parent = {}        # merged devices: second adapter -> the device it belongs to
        self.load_parents()
        self.presence = None    # mac -> online, as of the last sweep
        self.fails = {}         # wrong dashboard passwords: who tried -> [how many, locked until]
        self.pw_lock = threading.Lock()
        self.speed = {}         # mac -> (down, up) bytes/s, from the Deco
        self.deco = None
        self.deco_state = {"ok": False, "msg": "", "ts": 0, "clients": 0, "nodes": []}
        self.deco_halt = False
        self.deco_nodes_retry = 0
        self.deco_where_ts = 0
        self.deco_refused = set()  # units that would not list their own devices; said once in the log, not every poll
        self.net_up = None
        self.speed_lock = threading.Lock()
        self.block_active, self.allow, self.list_set = set(), set(), set()
        self.threat_set, self.threat_told = set(), {}  # listed names; device -> when we last sent an alert about it
        self.gw_strikes = {}                           # hardware address -> sweeps running it has answered as the router
        if self.watching():
            self.x("INSERT OR IGNORE INTO lists(id, enabled, updated, count) VALUES(?,0,0,0)", (THREATS,))
        self.lists_dir = os.path.join(os.path.dirname(os.path.abspath(a.db)), "lists")
        self.load_lists()
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
        self.cache.clear()

    def cached(self, key, fn, ttl=5):
        """One refresh of the dashboard asks for the device list three times over (list, attention, people),
        and several people may have it open. Work it out once. Any write empties this, so it is never out of date
        by more than what the writes do not cover: speeds and the time of the last sweep, a few seconds stale."""
        hit = self.cache.get(key)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
        value = fn()
        self.cache[key] = (time.time(), value)
        return value

    def meta(self, k, v=None):
        if v is None:
            r = self.q("SELECT v FROM meta WHERE k=?", (k,))
            return r[0]["v"] if r else None
        self.x("INSERT INTO meta VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))

    def event(self, kind, mac="", info=""):
        self.x("INSERT INTO events VALUES(?,?,?,?)", (int(time.time()), mac, kind, info[:200]))

    # ---- merged devices ---------------------------------------------------
    def load_parents(self):
        self.parent = {r["mac"]: r["parent"] for r in self.q("SELECT mac, parent FROM devices WHERE parent!=''")}

    def root(self, mac):
        return self.parent.get(mac, mac)

    def family(self, mac):
        return [mac] + [c for c, p in self.parent.items() if p == mac]

    # ---- inventory --------------------------------------------------------
    def scan_cmd(self):
        if self.a.scan_cmd:
            return shlex.split(self.a.scan_cmd)
        cmd = ["arp-scan", "--localnet", "--retry=2"]
        if self.a.iface:
            cmd.append("--interface=" + self.a.iface)
        return cmd

    def name_of(self, r):
        return (r.get("label") or r.get("deco_name") or r.get("mdns") or r.get("hostname")
                or r.get("vendor") or "unknown device")

    def seen(self, mac, ip, vendor, now, first_sweep=False, arp=True, claim=True):
        """Record that a device answered. Returns True when it is one we have never seen.
        arp=False means the Deco says so, not the Pi's own sweep. The Deco's list lags behind: it goes on
        reporting an address for a device after the router has handed that address to another. Believing it
        credits one device's lookups to another, so where the sweep has recently seen otherwise, the sweep wins.
        claim=False records the device without making it the one lookups from that address are credited to."""
        if ip and not arp:
            holder, mine = self.arp_ip.get(ip), self.arp_mac.get(mac)
            if (holder and holder[0] != mac and now - holder[1] < ARP_TRUST) or (mine and mine[0] != ip and now - mine[1] < ARP_TRUST):
                ip = ""
        elif ip:
            self.arp_mac[mac] = (ip, now)
            if claim:
                self.arp_ip[ip] = (mac, now)
        if not vendor and not is_randomized(mac):
            vendor = self.oui.get(mac[:8].replace(":", "").upper(), "")
        new = not self.q("SELECT 1 FROM devices WHERE mac=?", (mac,))
        self.x("""INSERT INTO devices(mac, ip, vendor, randomized, first_seen, last_seen, arp_seen)
                  VALUES(?,?,?,?,?,?,?) ON CONFLICT(mac) DO UPDATE SET
                  ip=CASE WHEN excluded.ip!='' THEN excluded.ip ELSE ip END, last_seen=excluded.last_seen,
                  arp_seen=CASE WHEN excluded.arp_seen THEN excluded.arp_seen ELSE arp_seen END,
                  vendor=CASE WHEN excluded.vendor!='' THEN excluded.vendor ELSE vendor END""",
               (mac, ip, vendor, is_randomized(mac), now, now, now if arp else 0))
        if ip and claim:
            self.ipmap[ip] = mac
            self.adopt("ip:" + ip, mac)
        if new and not first_sweep:
            self.event("joined", mac, f"{vendor or 'unknown maker'} at {ip}" if ip else vendor)
            self.notify(f"New device on your network: {vendor or 'unknown maker'}{' at ' + ip if ip else ''} ({mac})")
        return new

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
        first_sweep = not self.q("SELECT 1 FROM devices LIMIT 1")  # everything is new then; say nothing
        by_ip = collections.defaultdict(list)
        for mac, (ip, _) in found.items():
            by_ip[ip].append(mac)
        for mac, (ip, vendor) in found.items():
            # two devices answering for one address (a TV on cable and Wi-Fi at once): lookups stay with whichever had them
            owner = self.ipmap.get(ip) if self.ipmap.get(ip) in by_ip[ip] else by_ip[ip][0]
            self.seen(mac, ip, vendor, now, first_sweep, claim=mac == owner)
        # an address that has moved on is no longer its previous holder's
        stale = [(r["mac"],) for r in self.q("SELECT mac, ip FROM devices WHERE ip!=''") if r["ip"] in by_ip and r["mac"] not in by_ip[r["ip"]]]
        if stale:
            self.x("UPDATE devices SET ip='' WHERE mac=?", stale, many=True)
        # IPv6 neighbours, so lookups arriving over v6 still map to a device
        if self.a.iface and shutil.which("ip"):
            for line in run(["ip", "-6", "neigh", "show", "dev", self.a.iface]).splitlines():
                m = NEIGH6_RE.match(line)
                if m and m.group(2).lower() in found:
                    self.ipmap[m.group(1)] = m.group(2).lower()
                    if not m.group(1).startswith("fe80"):
                        self.x("UPDATE devices SET ip6=? WHERE mac=?", (m.group(1), m.group(2).lower()))
        self.check_gateway(by_ip, now)
        self.resolve_names(now)
        self.last_scan = now
        self.track_presence()

    def check_gateway(self, by_ip, now):
        """Has something else started answering as the router? That is how traffic on a home network gets
        intercepted: a device tells the others "the router's address is me" and everything flows through it.
        Seen two ways: who answers the sweep for the router's address, and who this Pi itself currently takes
        the router to be. A router or mesh unit has several hardware addresses, a digit apart, so those are not
        strangers; nor is anything you have said is fine. Twice running before a word is said: once is a blip."""
        gw = self.a.gateway
        if not gw:
            return
        claim = set(by_ip.get(gw, []))
        if shutil.which("ip"):
            m = re.search(r"lladdr\s+([0-9a-f:]{17})", run(["ip", "-4", "neigh", "show", gw]), re.I)
            if m:
                claim.add(m.group(1).lower())
        if not claim:
            return
        known = self.meta("gw_mac")
        if not known:
            if len(claim) == 1:  # the first clear sight of the router is taken to be the router
                self.meta("gw_mac", next(iter(claim)))
            return
        own = [known, *json.loads(self.meta("gw_trusted") or "[]"),
               *(n["mac"] for n in self.deco_state["nodes"] if len(n.get("mac") or "") == 17)]
        strangers = {mac for mac in claim if not any(mac[:14] == o[:14] for o in own)}
        self.gw_strikes = {mac: self.gw_strikes.get(mac, 0) + 1 for mac in strangers}
        alert = json.loads(self.meta("gw_alert") or "{}")
        for mac in sorted(strangers):
            if self.gw_strikes[mac] < 2:
                continue
            fresh = alert.get("mac") != mac or now - alert.get("last", 0) > 86400
            # alone: the router we knew no longer answers at all, as after replacing it
            alert = {"mac": mac, "first": now if fresh else alert.get("first", now), "last": now,
                     "alone": not any(c[:14] == known[:14] for c in claim)}
            self.meta("gw_alert", json.dumps(alert))
            if fresh:
                self.event("impostor", mac, gw)
                self.notify(f"A device ({mac}) is answering as your router ({gw}). If you did not just replace the router, "
                            "something may be intercepting your network's traffic. Open lanledger for details.")
            break

    def track_presence(self):
        """Write an event when a device comes or goes. 'Gone' means silent for the same
        few minutes the dashboard uses for 'offline', so a phone dozing does not flap."""
        cutoff = self.online_cutoff()
        state = {r["mac"]: r["last_seen"] >= cutoff for r in self.q("SELECT mac, last_seen FROM devices")}
        if self.presence is not None:
            for mac, on in state.items():
                if mac in self.presence and self.presence[mac] != on:
                    self.event("online" if on else "offline", mac)
        self.presence = state

    def notify(self, text):
        """Optional push alert: plain-text POST, which is what ntfy.sh and most webhooks take."""
        url = self.meta("notify_url") or self.a.notify_url
        if not url:
            return "No alert address is set."
        try:
            req = urllib.request.Request(url, data=text.encode(), headers={"Title": "lanledger"})
            urllib.request.urlopen(req, timeout=8).close()
            return ""
        except (OSError, ValueError) as e:
            print("notify failed:", e, flush=True)
            return f"Could not send: {e}"

    def adopt(self, orphan, mac):
        """Lookups logged before a device was identified get moved onto it."""
        with self.lock:
            if self.db.execute("SELECT 1 FROM dns_hourly WHERE dev=? LIMIT 1", (orphan,)).fetchone():
                self.db.execute("""INSERT INTO dns_hourly(dev, domain, base, hour, count, blocked)
                                   SELECT ?, domain, base, hour, count, blocked FROM dns_hourly
                                   WHERE dev=? ON CONFLICT(dev, domain, hour)
                                   DO UPDATE SET count=count+excluded.count, blocked=blocked+excluded.blocked""", (mac, orphan))
                self.db.execute("DELETE FROM dns_hourly WHERE dev=?", (orphan,))
                self.db.execute("UPDATE OR REPLACE threats SET dev=? WHERE dev=?", (mac, orphan))
                self.db.commit()
                self.cache.clear()

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

    def browse_mdns(self):
        """Ask the network what devices announce about themselves (names, and services that give away the type)."""
        if not shutil.which("avahi-browse"):
            return
        self.record_mdns(parse_mdns(run(["avahi-browse", "-atrp"], timeout=20)))

    def record_mdns(self, by_ip):
        got = {self.ipmap[ip]: info for ip, info in by_ip.items() if ip in self.ipmap}
        for mac, info in got.items():
            self.x("UPDATE devices SET mdns=?, services=? WHERE mac=?",
                   (info["name"][:80], ",".join(sorted(info["services"]))[:300], mac))
        # a name now announced by one device is no longer another's: it was pinned on that one by a recycled address
        owner = {info["name"][:80]: mac for mac, info in got.items() if info["name"]}
        moved = [(r["mac"],) for r in self.q("SELECT mac, mdns FROM devices WHERE mdns!=''")
                 if r["mac"] not in got and owner.get(r["mdns"], r["mac"]) != r["mac"]]
        if moved:
            self.x("UPDATE devices SET mdns='', services='' WHERE mac=?", moved, many=True)

    def scanner(self):
        n = 0
        while True:
            try:
                self.scan_once()
                if n % 10 == 0:
                    self.browse_mdns()
            except Exception as e:  # keep the thread alive whatever happens
                print("scan error:", e, flush=True)
            n += 1
            time.sleep(self.a.scan_interval)

    # ---- the Deco mesh ----------------------------------------------------
    def deco_config(self):
        return self.meta("deco_host") or "", self.meta("deco_password") or ""

    def deco_poll(self, last):
        host, password = self.deco_config()
        if not host or not password or deco is None or self.deco_halt:
            if not host:
                self.speed, self.deco = {}, None
            return last
        if self.deco is None or (self.deco.host, self.deco.password) != (deco.Deco(host, "").host, password):
            self.deco = deco.Deco(host, password)
        now = int(time.time())
        try:
            clients = self.deco.clients()
            if not self.deco_state["nodes"] or now - self.deco_state.get("nodes_ts", 0) > 600:
                self.deco_state.update(nodes=self.deco.nodes(), nodes_ts=now)
        except deco.BadPassword as e:
            self.deco_halt = True  # never hammer the Deco with a wrong password: it locks the account
            self.deco_state.update(ok=False, msg=str(e), ts=now)
            return now
        except deco.DecoError as e:
            self.deco_state.update(ok=False, msg=str(e), ts=now)
            return now
        dt, hour, speed, usage = min(now - last, 120) if last else 0, now - now % 3600, {}, []
        for c in clients:
            mac = c["mac"]
            if c["online"]:
                self.seen(mac, c["ip"], "", now, arp=False)
            elif not self.q("SELECT 1 FROM devices WHERE mac=?", (mac,)):
                continue  # the Deco remembers devices from long ago; do not import ghosts
            # an unknown connection (the Deco says so for devices that are off) keeps the last known one
            self.x("UPDATE devices SET deco_name=?, conn=CASE WHEN ?!='' THEN ? ELSE conn END, net=? WHERE mac=?",
                   (c["name"][:80], c["conn"], c["conn"], c["net"], mac))
            if c["online"] and (c["down"] or c["up"]):
                speed[mac] = (c["down"], c["up"])
                if dt:
                    usage.append((mac, hour, c["down"] * dt, c["up"] * dt))
        if usage:
            self.x("""INSERT INTO usage_hourly VALUES(?,?,?,?) ON CONFLICT(mac, hour)
                      DO UPDATE SET down=down+excluded.down, up=up+excluded.up""", usage, many=True)
        self.speed = speed
        self.deco_state.update(ok=True, msg="", ts=now, clients=sum(c["online"] for c in clients))
        self.deco_where(now)
        return now

    def deco_where(self, now):
        """Which mesh unit each device is connected through: a strong hint to where it physically is.
        Asked unit by unit. Some firmware refuses that, so a failure only pauses this part."""
        units = [n for n in self.deco_state["nodes"] if n.get("online") and n.get("id")]
        # Which unit a device is on changes when it is carried about the house, not by the half minute. Asking every
        # unit on every poll made six requests where one will do, more than a Deco's web interface answers in time.
        if len(units) < 2 or now < self.deco_nodes_retry or now - self.deco_where_ts < WHERE_EVERY:
            return
        self.deco_where_ts = now
        where, answered = {}, False
        for n in sorted(units, key=lambda n: not n["main"]):  # main unit first: if it lists everyone, the others correct it
            try:
                for c in self.deco.clients(n["id"]):
                    if c["online"]:
                        where[c["mac"]] = n["name"]
                answered = True
            except deco.DecoError as e:
                if n["id"] not in self.deco_refused:
                    self.deco_refused.add(n["id"])
                    print("deco: could not list devices on", n["name"], "-", e, flush=True)
        if not answered:
            self.deco_nodes_retry = now + 900
            return
        self.x("UPDATE devices SET node=? WHERE mac=? AND node!=?", [(name[:60], mac, name[:60]) for mac, name in where.items()], many=True)

    def deco_loop(self):
        last = 0
        while True:
            try:
                last = self.deco_poll(last)
            except Exception as e:
                print("deco error:", e, flush=True)
            time.sleep(30)

    # ---- internet health, schedules, list refresh -------------------------
    def probe(self):
        """Is the internet reachable, and how quickly? A TCP handshake to two public resolvers."""
        for host in ("1.1.1.1", "9.9.9.9"):
            t = time.time()
            try:
                socket.create_connection((host, 443), timeout=3).close()
                return True, int((time.time() - t) * 1000)
            except OSError:
                continue
        return False, 0

    def health_tick(self):
        now = int(time.time())
        ok, ms = self.probe()
        self.x("INSERT OR REPLACE INTO health VALUES(?,?,?)", (now, int(ok), ms))
        if self.net_up is not None and ok != self.net_up[0]:
            if ok:
                mins = max(1, round((now - self.net_up[1]) / 60))
                self.event("internet_up", info=f"after {mins} min")
                self.notify(f"Your internet is back. It was down for about {mins} minute{'s' if mins != 1 else ''}.")
            else:
                self.event("internet_down")
        if self.net_up is None or ok != self.net_up[0]:
            self.net_up = (ok, now)

    def monitor(self):
        n = 0
        while True:
            try:
                self.write_blocklist()  # scheduled blocks switch on and off here
                if not self.a.no_probe and n % 2 == 0:
                    self.health_tick()
                if n % 120 == 0:
                    self.refresh_lists()
                    self.refresh_oui()
                    old = int(time.time()) - self.a.retention_days * 86400
                    for t in ("events", "health", "speed"):
                        self.x(f"DELETE FROM {t} WHERE ts<?", (old,))
                    self.x("DELETE FROM usage_hourly WHERE hour<?", (old,))
                    self.x("DELETE FROM sessions WHERE expires<?", (int(time.time()),))
            except Exception as e:
                print("monitor error:", e, flush=True)
            n += 1
            time.sleep(30)

    # ---- who makes what: the IEEE register of hardware-address prefixes ----
    def oui_path(self):
        return os.path.join(os.path.dirname(os.path.abspath(self.a.db)), "oui.tsv")

    def load_oui(self):
        try:
            with open(self.oui_path(), encoding="utf-8") as f:
                self.oui = dict(line.rstrip("\n").split("\t", 1) for line in f if "\t" in line)
        except OSError:
            self.oui = {}

    def refresh_oui(self, force=False):
        """arp-scan ships a maker list that is years old on most systems, so half of a modern home shows no maker.
        Fetch the register itself once a month and fill in what is missing. Failing is fine: try again in six hours."""
        now = time.time()
        try:
            fresh = now - os.stat(self.oui_path()).st_mtime < 30 * 86400
        except OSError:
            fresh = False
        if not self.a.oui_url or (not force and (fresh or now - self.oui_tried < 6 * 3600)):
            return
        self.oui_tried = now
        try:
            req = urllib.request.Request(self.a.oui_url, headers={"User-Agent": "Mozilla/5.0 (compatible; lanledger)"})
            with urllib.request.urlopen(req, timeout=60) as r:
                table = parse_oui(r.read(40_000_000).decode("utf-8", "replace"))
            if len(table) < 1000:
                raise ValueError("the register came back nearly empty")
        except (OSError, ValueError) as e:
            print("maker list not refreshed:", e, flush=True)
            return
        tmp = self.oui_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.writelines(f"{k}\t{v}\n" for k, v in sorted(table.items()))
        os.replace(tmp, self.oui_path())
        self.oui = table
        self.fill_makers()

    def fill_makers(self):
        rows = [(self.oui[k], r["mac"]) for r in self.q("SELECT mac FROM devices WHERE (vendor IS NULL OR vendor='') AND randomized=0")
                for k in [r["mac"][:8].replace(":", "").upper()] if k in self.oui]
        if rows:
            self.x("UPDATE devices SET vendor=? WHERE mac=?", rows, many=True)

    def api_health(self, p):
        now = int(time.time())
        rows = self.q("SELECT ts, ok, ms FROM health WHERE ts>=? ORDER BY ts", (now - 7 * 86400,))
        day = [r for r in rows if r["ts"] >= now - 86400]
        outages, start, prev = [], None, None
        for r in rows:  # two failed checks in a row count as an outage; one is a blip
            if not r["ok"]:
                start = start or (r["ts"] if prev is not None and not prev["ok"] else None)
            elif start:
                outages.append({"start": start, "end": r["ts"]})
                start = None
            prev = r
        if start:
            outages.append({"start": start, "end": None})
        first = now - now % 3600 - 23 * 3600
        hours = [{"hour": first + i * 3600, "ms": 0, "n": 0, "fail": 0} for i in range(24)]
        for r in day:
            i = (r["ts"] - first) // 3600
            if 0 <= i < 24:
                h = hours[i]
                h["n"] += 1
                h["fail"] += not r["ok"]
                h["ms"] += r["ms"] if r["ok"] else 0
        for h in hours:
            good = h["n"] - h["fail"]
            h["ms"] = round(h["ms"] / good) if good else 0
        pct = lambda rs: round(100 * sum(r["ok"] for r in rs) / len(rs), 2) if rs else None
        good_ms = [r["ms"] for r in day if r["ok"]]
        return {"ok": bool(rows[-1]["ok"]) if rows else None, "checked": rows[-1]["ts"] if rows else 0,
                "uptime_day": pct(day), "uptime_week": pct(rows), "ms": int(statistics.median(good_ms)) if good_ms else None,
                "hours": hours, "outages": outages[-10:][::-1],
                "speed": self.q("SELECT ts, down FROM speed ORDER BY ts DESC LIMIT 8")}

    def api_speedtest(self, body):
        """Download for a few seconds and time it. Measures the Pi's own connection."""
        if not self.speed_lock.acquire(blocking=False):
            raise ValueError("A speed test is already running.")
        try:
            got, t0 = 0, time.time()
            try:
                while time.time() - t0 < 6:  # a fast line finishes one download early: keep going for a fair reading
                    req = urllib.request.Request(SPEED_URL, headers={"User-Agent": "lanledger"})
                    with urllib.request.urlopen(req, timeout=10) as r:
                        while time.time() - t0 < 8:
                            chunk = r.read(262144)
                            if not chunk:
                                break
                            got += len(chunk)
            except (OSError, ValueError) as e:
                raise ValueError(f"The speed test could not run ({e}).")
            secs = time.time() - t0
            if got < 100000 or secs <= 0:
                raise ValueError("The speed test did not get enough data to measure.")
            down = round(got * 8 / secs / 1e6, 1)
            self.x("INSERT OR REPLACE INTO speed VALUES(?,?)", (int(time.time()), down))
            return {"ok": True, "down": down}
        finally:
            self.speed_lock.release()

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

    def flush(self, pending, f, inode, hits=None):
        if hits:
            self.record_threats(hits)
        if pending:
            rows = [(dev, dom, base_domain(dom), hour, n, b) for (dev, dom, hour), (n, b) in pending.items()]
            self.x("""INSERT INTO dns_hourly(dev, domain, base, hour, count, blocked) VALUES(?,?,?,?,?,?)
                      ON CONFLICT(dev, domain, hour) DO UPDATE SET count=count+excluded.count,
                      blocked=blocked+excluded.blocked""", rows, many=True)
            pending.clear()
        self.meta("log_pos", f"{inode}:{f.tell()}")

    def tailer(self):
        path, pending, hits, last_prune = self.a.log, {}, {}, 0
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
                        # whether it was refused is worked out from our own lists, not dnsmasq's reply lines
                        hit = self.is_blocked(domain)
                        n = pending.get((dev, domain, ts - ts % 3600), (0, 0))
                        pending[(dev, domain, ts - ts % 3600)] = (n[0] + 1, n[1] + bool(hit))
                        listed = self.threat(domain)
                        if listed:
                            was = hits.get((dev, domain))
                            hits[(dev, domain)] = (listed, was[1] if was else ts, ts, (was[3] if was else 0) + 1)
                        self.live.append({"ts": ts, "dev": dev, "ip": client, "type": qtype, "domain": domain, "blocked": hit})
                    if time.time() - last_flush < 5:
                        continue
                else:
                    f.seek(pos)  # partial line: wait for the rest
                self.flush(pending, f, inode, hits)
                last_flush = time.time()
                if now - last_prune > 3600:
                    self.x("DELETE FROM dns_hourly WHERE hour<?", (now - self.a.retention_days * 86400,))
                    self.x("DELETE FROM threats WHERE last<?", (now - self.a.retention_days * 86400,))
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

    # ---- api: summary, devices -------------------------------------------
    def online_cutoff(self):
        return int(time.time()) - max(3 * self.a.scan_interval, 300)

    def site(self, name):
        return {**site(name), "blocked": self.is_blocked(name)}

    def api_summary(self, p):
        return self.cached("summary", self.summary)

    def summary(self):
        now = int(time.time())
        day = now - 86400
        d = self.q("""SELECT COUNT(*) total, COALESCE(SUM(last_seen>=?),0) online,
                      COALESCE(SUM(known=0),0) unknown FROM devices WHERE parent=''""", (self.online_cutoff(),))[0]
        t = self.q("""SELECT COALESCE(SUM(count),0) queries, COALESCE(SUM(blocked),0) refused,
                      COUNT(DISTINCT base) domains FROM dns_hourly WHERE hour>=?""", (day,))[0]
        named = lambda rows: [{**r, **self.site(r["name"])} for r in rows]
        top = self.q("""SELECT base name, SUM(count) c, COUNT(DISTINCT dev) devs FROM dns_hourly INDEXED BY dns_hour
                        WHERE hour>=? GROUP BY base ORDER BY c DESC, name LIMIT 15""", (day,))
        # sites never seen before today: today's sites, less any with an earlier row
        fresh = self.q("""SELECT base name, MIN(hour) first, SUM(count) c, COUNT(DISTINCT dev) devs
                          FROM dns_hourly d INDEXED BY dns_hour WHERE hour>=?
                          AND NOT EXISTS (SELECT 1 FROM dns_hourly o WHERE o.base=d.base AND o.hour<?)
                          GROUP BY base ORDER BY first DESC, c DESC LIMIT 15""", (day, day))
        return {
            **d, **t, "last_scan": self.last_scan, "now": now, "activity": self.day_activity()[1],
            "can_block": bool(self.a.block_file), "blocked": sorted(self.block_active),
            "deco": bool(self.deco_config()[0]) and self.deco_state["ok"],
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
            per[self.root(r["dev"])].append(r)
        self.day_cache = (now, {dev: activity(rs) for dev, rs in per.items()}, activity(rows))
        return self.day_cache[1:]

    def sparks(self):
        """Lookups per hour for the last 24 hours, oldest first, per device."""
        now = int(time.time())
        first = now - now % 3600 - 23 * 3600
        out = collections.defaultdict(lambda: [0] * 24)
        for r in self.q("SELECT dev, hour, SUM(count) c FROM dns_hourly WHERE hour>=? GROUP BY dev, hour", (first,)):
            out[self.root(r["dev"])][(r["hour"] - first) // 3600] += r["c"]
        return out

    def hints(self):
        """Best guess at what each device is, from a week of its lookups. Cached 5 minutes."""
        now = time.time()
        if now - self.hint_cache[0] < 300:
            return self.hint_cache[1]
        bases = sorted({base_domain(s) for s in HINT_SUFFIX})
        rows = self.q(f"""SELECT dev, domain, SUM(count) c FROM dns_hourly WHERE hour>=? AND base IN
                          ({",".join("?" * len(bases))}) GROUP BY dev, domain""", (int(now) - 7 * 86400, *bases))
        score, kinds = collections.defaultdict(collections.Counter), collections.defaultdict(set)
        for r in rows:
            name = r["domain"]
            while name:  # suffix match: a.b.icloud.com -> b.icloud.com -> icloud.com
                if name in HINT_SUFFIX:
                    guess, is_os = HINT_SUFFIX[name]
                    score[self.root(r["dev"])][(is_os, guess)] += r["c"]
                    kinds[self.root(r["dev"]), guess].add(name)
                    break
                name = name.partition(".")[2]
        out = {}
        for dev, s in score.items():
            # A phone or PC talks to its maker in several ways all day; one stray name (an app on a TV checking in
            # with Google) says nothing. Calling a fridge a "Windows PC" is worse than saying nothing.
            s = {k: n for k, n in s.items() if n >= 3 and (not k[0] or len(kinds[dev, k[1]]) >= 2)}
            if not s:
                continue
            # an OS match wins unless something else dwarfs it (an Xbox pings Microsoft too)
            (is_os, guess), n = max(s.items(), key=lambda kv: kv[1] * (3 if kv[0][0] else 1))
            out[dev] = guess
        self.hint_cache = (now, out)
        return out

    def api_devices(self, p):
        return self.cached("devices", self.devices)

    def devices(self):
        now = int(time.time())
        day, week, cutoff = now - 86400, now - SILENT_DAYS * 86400, self.online_cutoff()
        rows = self.q("SELECT *, last_seen>=? online FROM devices ORDER BY known, online DESC, last_seen DESC", (cutoff,))
        counts, last = collections.Counter(), collections.Counter()
        for r in self.q("""SELECT dev, MAX(hour) m, SUM(CASE WHEN hour>=? THEN count ELSE 0 END) c
                           FROM dns_hourly WHERE hour>=? GROUP BY dev""", (day, week)):
            root = self.root(r["dev"])
            counts[root] += r["c"]
            last[root] = max(last[root], r["m"])
        used = collections.defaultdict(lambda: [0, 0])
        for r in self.q("SELECT mac, SUM(down) d, SUM(up) u FROM usage_hourly WHERE hour>=? GROUP BY mac", (day,)):
            used[self.root(r["mac"])][0] += r["d"]
            used[self.root(r["mac"])][1] += r["u"]
        by_mac = {r["mac"]: r for r in rows}
        out = []
        for r in rows:  # a merged adapter lends its presence to the device it belongs to and drops out of the list
            head = by_mac.get(r["parent"]) if r["parent"] else None
            if head:
                head.setdefault("also", []).append({"mac": r["mac"], "ip": r["ip"], "conn": r["conn"], "online": r["online"]})
                head["online"] = max(head["online"], r["online"])
                head["last_seen"] = max(head["last_seen"] or 0, r["last_seen"] or 0)
                if r["online"] and not by_mac[r["parent"]].get("conn_live"):
                    head["conn_live"] = r["conn"]
            else:
                out.append(r)
        # clients that made lookups but were never matched to a MAC
        out += self.q("""SELECT dev mac, substr(dev,4) ip, '' vendor, '' hostname, 'unidentified client' label,
                         1 known, 0 randomized, MIN(hour) first_seen, MAX(hour) last_seen, 0 online
                         FROM dns_hourly WHERE dev LIKE 'ip:%' GROUP BY dev""")
        hints, doing, sparks = self.hints(), self.day_activity()[0], self.sparks()
        swept = self.deco_state["ok"] and self.last_scan > now - max(5 * self.a.scan_interval, 300)
        # A mesh unit shows up on the network under several faces: its own address, a neighbouring
        # hardware address (each radio and port has one, a digit apart), or simply the name "Deco".
        nodes = self.deco_state["nodes"]
        mesh_ips = {n["ip"] for n in nodes if n.get("ip")}
        mesh_macs = {n["mac"][:14] for n in nodes if len(n.get("mac") or "") == 17}

        def is_mesh(r):
            name = r.get("deco_name") or r.get("mdns") or r.get("hostname") or ""
            return bool(r["ip"] in mesh_ips or r["mac"][:14] in mesh_macs or re.match(r"deco\b", name, re.I))
        for r in out:
            mac = r["mac"]
            r.pop("host_checked", None)
            r["queries"] = counts.get(mac, 0)
            r["last_lookup"] = last.get(mac, 0)  # 0: nothing in the last SILENT_DAYS days
            r["spark"] = sparks.get(mac) or [0] * 24
            cats = doing.get(mac, [])
            r["hint"] = name_hint(r) or service_hint(r.get("services") or "") or hints.get(mac, "")
            # the router, the mesh units and this Pi do not ask lanledger for addresses, so silence from them is normal
            r["infra"] = ("router" if self.a.gateway and r["ip"] == self.a.gateway else "pi" if r["vendor"] == PI_VENDOR
                          else "mesh" if is_mesh(r) else "")
            # which mesh unit this row is, so the map can draw each unit with its own devices around it
            unit = r["infra"] and unit_of(r, nodes)
            r["unit"], r["unit_main"] = (unit["name"][:60], int(bool(unit.get("main")))) if unit else ("", 0)
            # The Deco says it is online, yet it has not answered the Pi's sweep for a good while: the two are being
            # kept apart, which is what the Deco's Device Isolation does. Its lookups cannot reach lanledger either.
            r["isolated"] = int(bool(swept and r["online"] and not r["infra"] and not r["randomized"] and not mac.startswith("ip:")
                                     and (r.get("arp_seen") or 0) < now - CUT_OFF and r["first_seen"] < now - CUT_OFF))
            r["mostly"] = mostly(cats)
            r["hidden"] = int(any(c["cat"] == HIDDEN for c in cats))
            fam = self.family(mac)
            r["down"], r["up"] = (sum(self.speed.get(m, (0, 0))[i] for m in fam) for i in (0, 1))
            r["used_down"], r["used_up"] = used.get(mac, (0, 0))
        return out

    def devices_csv(self):
        iso = lambda ts: time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else ""
        # names come off the network: stop a spreadsheet from running one as a formula
        safe = lambda v: "'" + v if isinstance(v, str) and v and v[0] in "=+-@\t\r" else v
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["name", "person", "name_in_deco_app", "announced_name", "hostname", "looks_like", "maker", "ip", "mac",
                    "connection", "deco_unit", "private_mac", "reviewed", "online", "first_seen", "last_seen", "lookups_24h", "mostly_24h", "isolated"])
        for r in self.api_devices({}):
            w.writerow([safe(v) for v in (
                r["label"], r.get("owner", ""), r.get("deco_name", ""), r.get("mdns", ""), r["hostname"] or "", r["hint"],
                r["vendor"] or "", r["ip"] or "", "" if r["mac"].startswith("ip:") else r["mac"],
                CONN_NAMES.get(r.get("conn") or "", r.get("conn") or ""), r.get("node", ""),
                r["randomized"], r["known"], r["online"], iso(r["first_seen"]), iso(r["last_seen"]), r["queries"], r["mostly"], r.get("isolated", 0))])
        return out.getvalue().encode("utf-8-sig")

    def api_device(self, p):
        hours = min(max(int(p.get("hours", 24)), 1), 24 * 365)
        col = "domain" if p.get("group") == "domain" else "base"
        since = int(time.time()) - hours * 3600
        fam = self.family(p.get("mac", ""))
        marks = ",".join("?" * len(fam))
        top = self.q(f"""SELECT {col} name, SUM(count) c, SUM(blocked) refused, MAX(hour) last FROM dns_hourly
                         WHERE dev IN ({marks}) AND hour>=? GROUP BY name ORDER BY c DESC LIMIT 50""", (*fam, since))
        ports = self.q("SELECT ts, open FROM ports WHERE mac=?", (fam[0],))
        return {
            "top": [{**r, **self.site(r["name"])} for r in top],
            "activity": activity(self.q(f"""SELECT domain, SUM(count) c FROM dns_hourly WHERE dev IN ({marks}) AND hour>=?
                                            GROUP BY domain""", (*fam, since))),
            "hourly": self.q(f"""SELECT hour, SUM(count) c FROM dns_hourly WHERE dev IN ({marks}) AND hour>=?
                                 GROUP BY hour ORDER BY hour""", (*fam, since)),
            "usage": self.q(f"""SELECT COALESCE(SUM(down),0) down, COALESCE(SUM(up),0) up FROM usage_hourly
                                WHERE mac IN ({marks}) AND hour>=?""", (*fam, since))[0],
            "events": self.q(f"SELECT ts, kind, info FROM events WHERE mac IN ({marks}) ORDER BY ts DESC LIMIT 12", tuple(fam)),
            "threats": self.q(f"""SELECT domain name, listed, first, last, count c FROM threats WHERE dev IN ({marks}) AND last>=?
                                  ORDER BY last DESC LIMIT 20""", (*fam, since)),
            "ports": {"ts": ports[0]["ts"], "open": json.loads(ports[0]["open"])} if ports else None,
        }

    def api_domain(self, p):
        term = p.get("q", "").strip().lower()
        if len(term) < 2:
            return []
        like = "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        rows = self.q("""SELECT domain, dev, SUM(count) c, MIN(hour) first, MAX(hour) last FROM dns_hourly
                         WHERE domain LIKE ? ESCAPE '\\' GROUP BY domain, dev ORDER BY last DESC, c DESC LIMIT 200""", (like,))
        for r in rows:
            r["dev"] = self.root(r["dev"])
            r["blocked"] = self.is_blocked(r["domain"])
        return rows

    def names(self):
        hints = self.hints()
        return {r["mac"]: r["label"] or r["deco_name"] or r["mdns"] or r["hostname"] or hints.get(r["mac"]) or r["vendor"]
                or "Unknown device " + (r["ip"] or "") for r in self.q("SELECT * FROM devices")}

    def api_live(self, p):
        names = self.names()
        return [{**e, "dev": self.root(e["dev"]), "name": names.get(self.root(e["dev"]), e["ip"])}
                for e in list(reversed(self.live))[:600]]

    def api_events(self, p):
        names = self.names()
        rows = self.q("SELECT ts, mac, kind, info FROM events ORDER BY ts DESC LIMIT 60")
        return [{**r, "mac": self.root(r["mac"]), "name": names.get(self.root(r["mac"]), "")} for r in rows]

    def api_people(self, p):
        """Activity grouped by the person each device belongs to."""
        doing, people = self.day_activity()[0], {}
        for d in self.api_devices({}):
            who = (d.get("owner") or "").strip()
            if not who:
                continue
            e = people.setdefault(who, {"person": who, "devices": 0, "online": 0, "queries": 0, "cats": collections.Counter(), "svcs": collections.Counter()})
            e["devices"] += 1
            e["online"] += d["online"]
            e["queries"] += d["queries"]
            for c in doing.get(d["mac"], []):
                if not c["background"]:
                    e["cats"][c["cat"]] += c["c"]
                    for s in c["services"][:3]:
                        e["svcs"][s] += c["c"]
        return [{**{k: e[k] for k in ("person", "devices", "online", "queries")},
                 "mostly": ", ".join(c for c, _ in e["cats"].most_common(2)), "services": [s for s, _ in e["svcs"].most_common(4)]}
                for e in sorted(people.values(), key=lambda e: -e["queries"])]

    def api_attention(self, p):
        """Things worth a person's time, most urgent first. Each can be acted on or dismissed."""
        gone = {r["key"] for r in self.q("SELECT key FROM dismissed")}
        doing, now, items = self.day_activity()[0], time.time(), []
        # security first: something answering as the router, then devices reaching for known-bad sites
        alert = json.loads(self.meta("gw_alert") or "{}")
        if alert.get("mac") and now - alert.get("last", 0) < 86400 and "impostor:" + alert["mac"] not in gone:
            items.append({"key": "impostor:" + alert["mac"], "kind": "impostor", "mac": alert["mac"], "gateway": self.a.gateway,
                          "alone": bool(alert.get("alone")), "last": alert["last"]})
        by_dev = collections.defaultdict(list)
        for r in self.q("SELECT dev, domain, listed, first, last, count FROM threats WHERE last>=? ORDER BY last DESC", (now - THREAT_DAYS * 86400,)):
            by_dev[self.root(r["dev"])].append(r)
        for mac, rows in by_dev.items():
            key = f"threat:{mac}:{max(r['first'] for r in rows)}"  # a new site brings back an alert you had ignored
            if key not in gone:
                items.append({"key": key, "kind": "threat", "mac": mac, "count": sum(r["count"] for r in rows), "last": rows[0]["last"],
                              "sites": [{"name": r["domain"], "listed": r["listed"], "blocked": bool(self.is_blocked(r["domain"]))} for r in rows[:6]],
                              "more": max(0, len(rows) - 6)})
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
            # Appliances look up their server once and then hold the connection for days, so a quiet
            # day means nothing. A quiet week from something that is online is worth a look.
            if d["online"] and not d["last_lookup"] and not d["infra"] and not d["isolated"] and now - d["first_seen"] > SILENT_DAYS * 86400:
                found.append({"kind": "silent"})
            if HIDDEN in cats:
                found.append({"kind": "hidden", "services": cats[HIDDEN]["services"]})
            ads = cats.get("Ads & tracking")
            if ads and ads["c"] >= 50 and ads["c"] >= total * 0.3:
                found.append({"kind": "tracking", "services": ads["services"], "pct": round(ads["c"] / total * 100)})
            if d.get("net") == "guest":
                found.append({"kind": "guest"})
            items += [{**f, "key": f"{f['kind']}:{mac}", "mac": mac} for f in found if f"{f['kind']}:{mac}" not in gone]
        return items

    def api_dismiss(self, body):
        key = str(body.get("key", ""))[:80]
        if key.startswith("impostor:"):  # "this is fine": it is part of the router from now on, and never asked about again
            trusted = set(json.loads(self.meta("gw_trusted") or "[]")) | {key[9:]}
            self.meta("gw_trusted", json.dumps(sorted(trusted)))
            self.x("DELETE FROM meta WHERE k='gw_alert'")
        self.x("INSERT OR REPLACE INTO dismissed VALUES(?,?)", (key, int(time.time())))
        return {"ok": True}

    def api_forget(self, body):
        """Drop a device and its history. If it is still around, the next sweep lists it again as new."""
        mac = str(body.get("mac", ""))
        self.x("UPDATE devices SET parent='' WHERE parent=?", (mac,))
        self.x("DELETE FROM devices WHERE mac=?", (mac,))
        for t, col in (("dns_hourly", "dev"), ("usage_hourly", "mac"), ("events", "mac"), ("ports", "mac"), ("threats", "dev")):
            self.x(f"DELETE FROM {t} WHERE {col}=?", (mac,))
        self.x("DELETE FROM dismissed WHERE key LIKE ? OR key LIKE ?", ("%:" + mac, f"threat:{mac}:%"))
        for ip in [ip for ip, m in list(self.ipmap.items()) if m == mac]:
            self.ipmap.pop(ip, None)
        self.load_parents()
        self.day_cache = (0, {}, [])
        return {"ok": True}

    def api_update(self, body):
        mac = str(body.get("mac", ""))
        if "label" in body:
            self.x("UPDATE devices SET label=? WHERE mac=?", (str(body["label"])[:80], mac))
        if "owner" in body:
            self.x("UPDATE devices SET owner=? WHERE mac=?", (str(body["owner"]).strip()[:40], mac))
        if "known" in body:
            self.x("UPDATE devices SET known=? WHERE mac=?", (1 if body["known"] else 0, mac))
        if "parent" in body:  # "this is the same device as ..."
            head = self.root(str(body["parent"] or ""))
            if head == mac or (head and not self.q("SELECT 1 FROM devices WHERE mac=?", (head,))):
                raise ValueError("Pick a different device to merge into.")
            self.x("UPDATE devices SET parent=? WHERE mac=?", (head, mac))
            if head:  # anything already merged into this one follows it
                self.x("UPDATE devices SET parent=?, known=1 WHERE parent=? OR mac=?", (head, mac, mac))
            self.load_parents()
            self.day_cache, self.hint_cache = (0, {}, []), (0, {})
        return {"ok": True}

    def api_ports(self, body):
        """Knock on the common doors of one of our own devices and say which are open."""
        mac = str(body.get("mac", ""))
        rows = self.q("SELECT ip FROM devices WHERE mac=?", (mac,))
        try:
            ip = ipaddress.ip_address(rows[0]["ip"]) if rows else None
        except ValueError:
            ip = None
        if not ip or not ip.is_private:
            raise ValueError("lanledger only checks devices on your own network, and this one has no address right now.")

        def knock(port):
            try:
                socket.create_connection((str(ip), port), timeout=1.2).close()
                return port
            except OSError:
                return None
        with ThreadPoolExecutor(max_workers=24) as pool:
            hits = sorted(p for p in pool.map(knock, PORTS) if p)
        found = [{"port": p, "what": PORTS[p][0], "risk": PORTS[p][1]} for p in hits]
        self.x("INSERT OR REPLACE INTO ports VALUES(?,?,?)", (mac, int(time.time()), json.dumps(found)))
        return {"ok": True, "open": found}

    # ---- blocking ---------------------------------------------------------
    def is_blocked(self, name):
        """'manual' for something blocked from the dashboard, 'list' for a subscribed list, '' otherwise."""
        n = name
        while n:
            if n in self.block_active:
                return "manual"
            n = n.partition(".")[2]
        if name in self.list_set and not self.is_allowed(name):
            return "list"
        return ""

    def is_allowed(self, name):
        while name:
            if name in self.allow:
                return True
            name = name.partition(".")[2]
        return False

    @staticmethod
    def window(row, minute):
        a, b = row["t_from"], row["t_to"]
        if a is None or b is None or a == b:
            return True
        return a <= minute < b if a < b else (minute >= a or minute < b)

    def write_blocklist(self):
        """dnsmasq re-reads this file on SIGHUP. `server=/name/` with no address means: never
        forward this name or anything under it, so clients get "no such domain".
        Blocks with a time window are only written while the window is open."""
        t = time.localtime()
        rows = self.q("SELECT domain, t_from, t_to FROM blocked ORDER BY domain")
        active = {r["domain"] for r in rows if self.window(r, t.tm_hour * 60 + t.tm_min)}
        self.block_active = active
        self.allow = {r["domain"] for r in self.q("SELECT domain FROM allowed")}
        if not self.a.block_file:
            return
        body = "# Managed by lanledger. Edit the block list from the dashboard.\n" + "".join(f"server=/{d}/\n" for d in sorted(active))
        self.write_if_changed(self.a.block_file, body)

    @staticmethod
    def write_if_changed(path, body):
        try:
            try:
                with open(path, newline="") as f:
                    if f.read() == body:
                        return
            except OSError:
                pass
            # written in place, not renamed over: the systemd path unit watches this very file
            with open(path, "w", newline="\n") as f:
                f.write(body)
            os.chmod(path, 0o644)  # dnsmasq runs as another user and must read this, whatever lanledger's own files default to
        except OSError as e:
            print("cannot write", path, e, flush=True)
            raise ValueError("Could not write the block list file.")

    def clean_domain(self, text):
        domain = str(text or "").strip().lower()
        domain = re.sub(r"^(?:https?://)?(?:\*\.)?", "", domain).split("/")[0].rstrip(".")
        parts = domain.split(".")
        if not DOMAIN_RE.fullmatch(domain):
            raise ValueError("That does not look like a site address. Try something like tiktok.com")
        if len(parts) == 2 and len(parts[1]) == 2 and parts[0] in SECOND_LEVEL:
            raise ValueError("That would cover a whole country's sites. Name a specific site.")
        return domain

    def targets(self, body):
        """The addresses a block request is about: one site, or everything a known service uses."""
        if body.get("service"):
            name = str(body["service"])
            domains = sorted(d for d, (svc, cat) in SERVICE.items() if svc == name and cat not in UNBLOCKABLE)
            if not domains:
                raise ValueError("lanledger does not know that service well enough to block all of it.")
            return domains
        return [self.clean_domain(body.get("domain"))]

    @staticmethod
    def minutes(text):
        m = re.fullmatch(r"(\d{1,2}):(\d{2})", str(text or ""))
        if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
            return None
        return int(m.group(1)) * 60 + int(m.group(2))

    def api_block(self, body):
        if not self.a.block_file:
            raise ValueError("Blocking is not set up on this install. Re-run install.sh to enable it.")
        domains = self.targets(body)
        if body.get("on", True):
            self.x("INSERT OR IGNORE INTO blocked(domain, added) VALUES(?,?)", [(d, int(time.time())) for d in domains], many=True)
            if "from" in body:  # "" for always, or a daily window such as 21:00 to 07:00
                a, b = self.minutes(body.get("from")), self.minutes(body.get("to"))
                if (a is None) != (b is None) or (a is not None and a == b):
                    raise ValueError("Give both a start and an end time, and make them different.")
                self.x("UPDATE blocked SET t_from=?, t_to=? WHERE domain=?", [(a, b, d) for d in domains], many=True)
        else:
            self.x("DELETE FROM blocked WHERE domain=?", [(d,) for d in domains], many=True)
        self.write_blocklist()
        return {"ok": True, "count": len(domains), "domain": domains[0]}

    def api_allow(self, body):
        """An exception to the subscribed lists: this site (and anything under it) is never list-blocked."""
        domain = self.clean_domain(body.get("domain"))
        if body.get("on", True):
            self.x("INSERT OR IGNORE INTO allowed VALUES(?,?)", (domain, int(time.time())))
        else:
            self.x("DELETE FROM allowed WHERE domain=?", (domain,))
        self.write_blocklist()
        self.write_hosts()
        return {"ok": True, "domain": domain}

    def api_blocked(self, p):
        t = time.localtime()
        day, rows = int(time.time()) - 86400, self.q("SELECT domain, added, t_from, t_to FROM blocked ORDER BY added DESC")
        for r in rows:
            like = "%." + r["domain"].replace("_", "\\_")
            r.update(self.q("""SELECT COALESCE(SUM(count),0) c, COUNT(DISTINCT dev) devs FROM dns_hourly
                               WHERE hour>=? AND (domain=? OR domain LIKE ? ESCAPE '\\')""", (day, r["domain"], like))[0])
            r.update(site(r["domain"]))
            r["active"] = self.window(r, t.tm_hour * 60 + t.tm_min)
        state = {r["id"]: r for r in self.q("SELECT * FROM lists")}
        lists = [{"id": i, "title": title, "about": about, "enabled": bool(state.get(i, {}).get("enabled")),
                  "count": state.get(i, {}).get("count") or 0, "updated": state.get(i, {}).get("updated") or 0}
                 for i, (title, about, _) in LISTS.items()]
        refused = self.q("""SELECT domain name, SUM(blocked) c, COUNT(DISTINCT dev) devs FROM dns_hourly
                            WHERE hour>=? AND blocked>0 GROUP BY domain ORDER BY c DESC LIMIT 25""", (day,))
        return {"enabled": bool(self.a.block_file), "rows": rows, "lists": lists, "can_lists": bool(self.a.block_hosts),
                "allowed": self.q("SELECT domain, added FROM allowed ORDER BY added DESC"),
                "refused": [{**r, **self.site(r["name"])} for r in refused]}

    # ---- subscribed block lists ------------------------------------------
    def list_path(self, list_id):
        return os.path.join(self.lists_dir, list_id + ".txt")

    def load_lists(self):
        names = set()
        for r in self.q("SELECT id FROM lists WHERE enabled=1"):
            try:
                with open(self.list_path(r["id"]), encoding="utf-8") as f:
                    names.update(line.strip() for line in f if line.strip())
            except OSError:
                pass
        self.list_set = names
        watched = set()
        if self.watching():
            try:
                with open(self.list_path(THREATS), encoding="utf-8") as f:
                    watched = {line.strip() for line in f if line.strip()}
            except OSError:
                pass
        self.threat_set = watched

    def watching(self):
        return not getattr(self.a, "no_threat_list", False)

    def threat(self, name):
        """The listed name a lookup falls under ("login.bad.example" under "bad.example"), or "".
        A name you have allowed as an exception is never reported."""
        n = name
        while "." in n:  # never a bare top-level domain
            if n in self.threat_set:
                return "" if self.is_allowed(name) else n
            n = n.partition(".")[2]
        return ""

    def record_threats(self, hits):
        """hits: {(device, name looked up): (listed name, first seen, last seen, how many)}."""
        for (dev, domain), (listed, first, last, n) in hits.items():
            new = not self.q("SELECT 1 FROM threats WHERE dev=? AND domain=?", (dev, domain))
            self.x("""INSERT INTO threats VALUES(?,?,?,?,?,?) ON CONFLICT(dev, domain)
                      DO UPDATE SET last=MAX(last, excluded.last), count=count+excluded.count""", (dev, domain, listed, first, last, n))
            if new:
                root = self.root(dev)
                self.event("threat", root, domain)
                if time.time() - self.threat_told.get(root, 0) > 3600:  # an infected device can try hundreds: say it once an hour
                    self.threat_told[root] = time.time()
                    self.notify(f"{self.names().get(root, root)} tried to reach a site on the malware and phishing list: {domain}")
        hits.clear()

    def write_hosts(self):
        """One hosts-format file for dnsmasq (addn-hosts): every listed name answers with a dead address."""
        if not self.a.block_hosts:
            return
        names = sorted(n for n in self.list_set if not self.is_allowed(n))
        self.write_if_changed(self.a.block_hosts, "# Managed by lanledger: subscribed block lists.\n" +
                              "".join(f"0.0.0.0 {n}\n:: {n}\n" for n in names))

    def fetch_list(self, list_id):
        url = (self.a.list_base.rstrip("/") + "/" + list_id) if self.a.list_base else LISTS[list_id][2]
        with urllib.request.urlopen(url, timeout=60) as r:
            text = r.read(40_000_000).decode("utf-8", "replace")
        names = set()
        for line in text.splitlines():  # hosts format: "0.0.0.0 ads.example.com"
            parts = line.split("#", 1)[0].split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1") and DOMAIN_RE.fullmatch(parts[1].lower()):
                names.add(parts[1].lower())
            elif len(parts) == 1 and DOMAIN_RE.fullmatch(parts[0].lower()):  # or simply one name to a line
                names.add(parts[0].lower())
        if len(names) < 10:
            raise ValueError("the list came back empty")
        os.makedirs(self.lists_dir, exist_ok=True)
        with open(self.list_path(list_id), "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(sorted(names)) + "\n")
        self.x("UPDATE lists SET updated=?, count=? WHERE id=?", (int(time.time()), len(names), list_id))

    def refresh_lists(self, force=None):
        """Download enabled lists that are missing or more than a day old."""
        changed, err = False, ""
        for r in self.q("SELECT id, updated FROM lists WHERE enabled=1 OR id=?", (THREATS if self.watching() else "",)):
            if r["id"] in LISTS and (r["id"] == force or (r["updated"] or 0) < time.time() - 86400):
                try:
                    self.fetch_list(r["id"])
                    changed = True
                except (OSError, ValueError) as e:
                    err = f"Could not download the list ({e})."
                    print("list", r["id"], "failed:", e, flush=True)
        if changed or force:
            self.load_lists()
            self.write_hosts()
        return err

    def api_list(self, body):
        list_id = str(body.get("id", ""))
        if list_id not in LISTS:
            raise ValueError("Unknown list.")
        if not self.a.block_hosts:
            raise ValueError("Block lists are not set up on this install. Re-run install.sh to enable them.")
        on = bool(body.get("on"))
        self.x("INSERT INTO lists(id, enabled, updated, count) VALUES(?,?,0,0) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled",
               (list_id, int(on)))
        err = self.refresh_lists(force=list_id) if on else ""
        if not on:
            self.load_lists()
            self.write_hosts()
        if err:
            self.x("UPDATE lists SET enabled=0 WHERE id=?", (list_id,))
            raise ValueError(err)
        return {"ok": True}

    # ---- password and settings -------------------------------------------
    @staticmethod
    def pw_hash(password, salt):
        return hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32).hex()

    def pw_check(self, password):
        stored = self.meta("pw_hash") or ""
        if ":" not in stored:
            return False
        salt, digest = stored.split(":")
        return hmac.compare_digest(self.pw_hash(str(password), bytes.fromhex(salt)), digest)

    def guess(self, password, who, wrong="Wrong password."):
        """Check a password someone typed, wherever it was typed (signing in, or "current password" when changing it).
        The caller holds pw_lock: each check costs real memory and processor time on purpose, and a burst would stall the Pi.
        Wrong tries are counted per address, so a device guessing passwords locks itself out and nobody else.
        After five, each further wrong try doubles the wait: a minute, two, four, up to an hour."""
        now = time.time()
        fails = self.fails.setdefault(who, [0, 0, now])  # how many, locked until, last try
        if fails[1] > now:
            raise ValueError(f"Too many wrong tries. Wait {int(fails[1] - now) + 1} seconds.")
        if self.pw_check(password):
            self.fails.pop(who, None)
            return
        fails[0], fails[2] = fails[0] + 1, now
        if fails[0] >= 5:
            fails[1] = now + min(3600, 60 * 2 ** (fails[0] - 5))
        if len(self.fails) > 500:
            # Keep this from growing without end, without handing out a clean slate: only those neither waiting
            # nor heard from for two hours are forgotten, and beyond that the ones quiet longest.
            keep = {k: v for k, v in self.fails.items() if v[1] > now or v[2] > now - 7200 or k == who}
            for k in sorted(keep, key=lambda k: keep[k][2])[:max(0, len(keep) - 500)]:
                if k != who:
                    del keep[k]
            self.fails = keep
        raise ValueError(wrong)

    def new_session(self):
        token = secrets.token_urlsafe(32)
        self.x("INSERT INTO sessions VALUES(?,?)", (hashlib.sha256(token.encode()).hexdigest(), int(time.time()) + SESSION_DAYS * 86400))
        return token

    def login(self, password, who=""):
        """Returns a session token, or raises with what to tell the person."""
        with self.pw_lock:
            self.guess(password, who)
        return self.new_session()

    def session_ok(self, token):
        # No password yet means nobody is signed in: the dashboard offers to choose one and nothing else.
        if not token or not self.meta("pw_hash"):
            return False
        return bool(self.q("SELECT 1 FROM sessions WHERE token=? AND expires>?",
                           (hashlib.sha256(token.encode()).hexdigest(), int(time.time()))))

    def api_password(self, body, who="", signed_in=True):
        """Choose the first password (allowed without signing in, once) or change it (needs the current one)."""
        new = str(body.get("new", ""))
        if len(new) < 8:
            raise ValueError("Use at least 8 characters.")
        # Under the lock from the question "is there a password yet?" to writing one: of two browsers choosing
        # the first password at the same moment, one wins and the other is asked to sign in.
        with self.pw_lock:
            if self.meta("pw_hash"):
                if not signed_in:
                    raise SignIn("A password has just been set from another browser. Sign in with it.")
                self.guess(str(body.get("current", "")), who, "The current password is not right.")
            salt = secrets.token_bytes(16)
            self.meta("pw_hash", salt.hex() + ":" + self.pw_hash(new, salt))
            self.x("DELETE FROM sessions")  # everyone signs in again, including this browser
            return {"ok": True, "token": self.new_session()}

    def api_settings(self, p):
        host, password = self.deco_config()
        return {"notify_url": self.meta("notify_url") or self.a.notify_url,
                "deco": {"available": deco is not None, "host": host, "configured": bool(host and password),
                         "halted": self.deco_halt, **{k: self.deco_state[k] for k in ("ok", "msg", "ts", "clients", "nodes")}}}

    def api_set_deco(self, body):
        host, password = str(body.get("host", "")).strip(), str(body.get("password", ""))
        if not host:
            self.x("DELETE FROM meta WHERE k IN ('deco_host','deco_password')")
            self.deco, self.deco_halt, self.speed = None, False, {}
            self.deco_state = {"ok": False, "msg": "", "ts": 0, "clients": 0, "nodes": []}
            self.x("UPDATE devices SET conn='', net='', node=''")
            return {"ok": True}
        if deco is None:
            raise ValueError("deco.py is missing next to lanledger.py. Re-run install.sh.")
        if not password:
            raise ValueError("Enter the Deco owner password.")
        m = re.fullmatch(r"(https?://)?([A-Za-z0-9.\-]+)(:\d+)?/?", host)
        if not m:
            raise ValueError("That does not look like an address. Use something like 192.168.68.1")
        # A name is looked up once, here, and the address it gave is what gets stored and used from then on.
        # Keeping the name would mean trusting every later answer for it with the Deco password.
        # A home name may also have a public IPv6 address; the Deco is reached at its private one, so only that matters.
        try:
            found = sorted({i[4][0] for i in socket.getaddrinfo(m.group(2), None, socket.AF_INET)})
        except (OSError, ValueError):
            found = []
        home = [ip for ip in found if ipaddress.ip_address(ip).is_private]
        if not home:
            raise ValueError("The Deco address must be on your own network. Use its address there, something like 192.168.68.1"
                             if found else "Could not find that address. Use something like 192.168.68.1")
        host = (m.group(1) or "") + home[0] + (m.group(3) or "")
        trial = deco.Deco(host, password)
        try:
            found = trial.clients()  # prove it works before saving anything
        except deco.DecoError as e:
            raise ValueError(str(e))
        self.meta("deco_host", host)
        self.meta("deco_password", password)
        self.deco, self.deco_halt = trial, False
        self.deco_state.update(ok=True, msg="", ts=int(time.time()), clients=sum(c["online"] for c in found), nodes=[])
        return {"ok": True, "clients": len(found)}

    def api_set_notify(self, body):
        url = str(body.get("url", "")).strip()
        if url and not re.fullmatch(r"https?://[^\s]{4,300}", url):
            raise ValueError("That does not look like a web address. Example: https://ntfy.sh/my-secret-topic")
        if url:
            self.meta("notify_url", url)
        else:
            self.x("DELETE FROM meta WHERE k='notify_url'")
        if url and body.get("test"):
            err = self.notify("Test from lanledger: alerts are working.")
            if err:
                raise ValueError(err)
        return {"ok": True}


ICON = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0" stop-color="#4cc9f0"/><stop offset="1" stop-color="#8b7cf6"/></linearGradient></defs>'
        '<rect width="64" height="64" rx="14" fill="#090c13"/><g fill="none" stroke="url(#g)" stroke-width="3.6" stroke-linecap="round">'
        '<path d="M32 32 15 17M32 32l20-11M32 32 17 50M32 32l18 15"/></g><g fill="url(#g)"><circle cx="32" cy="32" r="7.5"/>'
        '<circle cx="15" cy="17" r="5"/><circle cx="52" cy="21" r="5"/><circle cx="17" cy="50" r="5"/><circle cx="50" cy="47" r="5"/></g></svg>')
MANIFEST = {"name": "lanledger", "short_name": "lanledger", "start_url": "/", "display": "standalone",
            "background_color": "#090c13", "theme_color": "#090c13",
            "icons": [{"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any"}]}


class Handler(BaseHTTPRequestHandler):
    server_version = "lanledger"
    timeout = 30  # a connection that goes quiet is dropped, not held open for ever

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

    def who(self):
        """The address wrong passwords are counted against. Behind a proxy on the Pi itself every visitor arrives
        from this machine, so there the proxy's word for who they are is taken. From anywhere else it is ignored."""
        peer = self.client_address[0]
        via = (self.headers.get("X-Forwarded-For") or "").split(",")[-1].strip()
        try:
            return str(ipaddress.ip_address(via)) if via and ipaddress.ip_address(peer).is_loopback else peer
        except ValueError:
            return peer

    def token(self):
        m = re.search(r"(?:^|;\s*)lanledger=([A-Za-z0-9_\-]{20,80})", self.headers.get("Cookie") or "")
        return m.group(1) if m else ""

    def send(self, code, body, ctype="application/json", filename=None, token=None):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        if token is not None:  # "" signs out
            age = SESSION_DAYS * 86400 if token else 0
            self.send_header("Set-Cookie", f"lanledger={token}; Path=/; Max-Age={age}; HttpOnly; SameSite=Strict")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        try:
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass  # the browser went away; nothing to tell it

    def do_GET(self):
        if not self.host_ok():
            return self.send(403, {"error": "unexpected Host header"})
        u = urlparse(self.path)
        p = {k: v[0] for k, v in parse_qs(u.query).items()}
        app = self.server.app
        if u.path == "/":
            with open(os.path.join(HERE, "dashboard.html"), "rb") as f:
                return self.send(200, f.read(), "text/html; charset=utf-8")
        if u.path == "/icon.svg":
            return self.send(200, ICON.encode(), "image/svg+xml")
        if u.path == "/manifest.json":
            return self.send(200, MANIFEST, "application/manifest+json")
        authed = app.session_ok(self.token())
        if u.path == "/api/session":
            return self.send(200, {"setup": not app.meta("pw_hash"), "signed_in": authed})
        if not authed:
            return self.send(401, {"error": "sign in", "setup": not app.meta("pw_hash")})
        if u.path == "/api/devices.csv":
            return self.send(200, app.devices_csv(), "text/csv; charset=utf-8", "lanledger-devices.csv")
        fn = {"/api/summary": app.api_summary, "/api/devices": app.api_devices, "/api/device": app.api_device,
              "/api/domain": app.api_domain, "/api/live": app.api_live, "/api/attention": app.api_attention,
              "/api/blocked": app.api_blocked, "/api/events": app.api_events, "/api/health": app.api_health,
              "/api/people": app.api_people, "/api/settings": app.api_settings}.get(u.path)
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
        try:
            # Nothing the dashboard sends is anywhere near this size. A length that is negative means
            # "read until the sender stops", which would let anyone fill the Pi's memory before signing in.
            size = int(self.headers.get("Content-Length", 0))
            if not 0 <= size <= 4096:
                raise ValueError
            body = json.loads(self.rfile.read(size))
            if not isinstance(body, dict):
                raise ValueError
        except (ValueError, OSError):
            return self.send(400, {"error": "bad request"})
        try:
            if self.path == "/api/login":
                return self.send(200, {"ok": True}, token=app.login(str(body.get("password", "")), self.who()))
            authed = app.session_ok(self.token())
            if self.path == "/api/password":  # choosing the first password is the one thing allowed without signing in
                return self.send(200, {"ok": True}, token=app.api_password(body, self.who(), authed)["token"])
            if not authed:
                return self.send(401, {"error": "sign in", "setup": not app.meta("pw_hash")})
            if self.path == "/api/logout":
                app.x("DELETE FROM sessions WHERE token=?", (hashlib.sha256(self.token().encode()).hexdigest(),))
                return self.send(200, {"ok": True}, token="")
            fn = {"/api/device": app.api_update, "/api/block": app.api_block, "/api/dismiss": app.api_dismiss,
                  "/api/forget": app.api_forget, "/api/allow": app.api_allow, "/api/list": app.api_list,
                  "/api/ports": app.api_ports, "/api/speedtest": app.api_speedtest,
                  "/api/settings/deco": app.api_set_deco, "/api/settings/notify": app.api_set_notify}.get(self.path)
            if not fn:
                return self.send(404, {"error": "not found"})
            self.send(200, fn(body))
        except SignIn as e:
            self.send(401, {"error": str(e), "setup": False})
        except ValueError as e:  # raised with a message meant for the person at the dashboard
            self.send(400, {"error": str(e) or "bad request"})
        except (AttributeError, TypeError, sqlite3.Error):
            self.send(400, {"error": "bad request"})


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="/var/lib/lanledger/lanledger.db")
    ap.add_argument("--log", default="/var/log/lanledger/dnsmasq.log", help="dnsmasq query log to follow")
    ap.add_argument("--iface", default="", help="LAN interface, e.g. eth0")
    ap.add_argument("--gateway", default="", help="router IP, used for reverse-DNS hostnames")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--scan-interval", type=int, default=60, help="seconds between ARP sweeps")
    ap.add_argument("--retention-days", type=int, default=30)
    ap.add_argument("--scan-cmd", default="", help="override the scan command (testing)")
    ap.add_argument("--block-file", default="", help="dnsmasq servers-file lanledger may write blocked domains to")
    ap.add_argument("--block-hosts", default="", help="dnsmasq addn-hosts file lanledger may write subscribed block lists to")
    ap.add_argument("--list-base", default="", help="fetch block lists from <base>/<id> instead of their usual home (testing)")
    ap.add_argument("--notify-url", default="",
                    help="POST a line of text here when a new device joins (e.g. an ntfy.sh topic URL)")
    ap.add_argument("--oui-url", default=OUI_URL, help="where to fetch the register of hardware makers; empty to never fetch")
    ap.add_argument("--no-threat-list", action="store_true", help="do not fetch or watch the malware and phishing list")
    ap.add_argument("--no-probe", action="store_true", help="do not check internet reachability")
    ap.add_argument("--reset-password", action="store_true", help="remove the dashboard password (and the stored Deco password) and exit")
    ap.add_argument("--allow-host", action="append", default=[], help="extra hostname the dashboard is reached by")
    a = ap.parse_args()

    app = App(a)
    if a.reset_password:
        app.x("DELETE FROM meta WHERE k IN ('pw_hash','deco_host','deco_password')")
        app.x("DELETE FROM sessions")
        print("Dashboard password removed, and the Deco connection with it. Open the dashboard to choose a new password, "
              "then connect the Deco again in Settings.")
        return
    for job in (app.scanner, app.tailer, app.monitor, app.deco_loop):
        threading.Thread(target=job, daemon=True).start()
    srv = ThreadingHTTPServer((a.bind, a.port), Handler)
    srv.app = app
    host = socket.gethostname().lower()
    srv.allowed_hosts = {"localhost", host, host + ".local", host + ".lan", host + ".home"} | {h.lower() for h in a.allow_host}
    print(f"lanledger listening on http://{a.bind}:{a.port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
