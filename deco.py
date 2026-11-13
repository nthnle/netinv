#!/usr/bin/env python3
"""Read-only client for the local web interface of a TP-Link Deco mesh.

Used by netinv to learn what the Deco knows about each device: the name set in the
Deco app, wired or Wi-Fi, main or guest network, and current up/down speed.

The protocol (RSA-wrapped login, AES-CBC request bodies) follows the open-source Home
Assistant integration at https://github.com/amosyuen/ha-tplink-deco. Standard library
only, so AES and the RSA padding are implemented here. It is a small, slow AES meant for
a few kilobytes every half minute, not for anything else.

Try it by hand:  python3 deco.py http://192.168.68.1
"""
import base64
import hashlib
import json
import secrets
import ssl
import urllib.error
import urllib.parse
import urllib.request


class DecoError(Exception):
    """Carries a message fit to show the person setting this up."""


class SessionLost(DecoError):
    """The Deco no longer accepts our session; signing in again may fix it."""


class BadPassword(DecoError):
    """Do not retry with the same password: the Deco locks the account after a few tries."""


# ---- AES-128-CBC with PKCS#7 padding -------------------------------------------------
def _rotl8(x, s):
    return ((x << s) | (x >> (8 - s))) & 0xFF


def _make_sbox():
    sbox, p, q = [0] * 256, 1, 1
    while True:
        p = (p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)) & 0xFF  # multiply by 3
        q ^= q << 1  # divide by 3
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        sbox[p] = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4) ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


SBOX = _make_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i


def _mul(a, b):
    """Multiply in GF(2^8)."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1
        b >>= 1
    return r


def _round_keys(key):
    if len(key) != 16:
        raise ValueError("AES-128 needs a 16-byte key")
    w, rcon = [list(key[i:i + 4]) for i in range(0, 16, 4)], 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _mul(rcon, 2)
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [sum(w[r * 4:r * 4 + 4], []) for r in range(11)]


def _encrypt_block(block, keys):
    s = [b ^ k for b, k in zip(block, keys[0])]
    for rnd in range(1, 11):
        s = [SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]  # ShiftRows, state held column by column
        if rnd < 10:
            m = []
            for c in range(0, 16, 4):
                a = s[c:c + 4]
                m += [_mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3], a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3],
                      a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3), _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)]
            s = m
        s = [b ^ k for b, k in zip(s, keys[rnd])]
    return s


def _decrypt_block(block, keys):
    s = [b ^ k for b, k in zip(block, keys[10])]
    for rnd in range(9, -1, -1):
        s = [s[(i - 4 * (i % 4)) % 16] for i in range(16)]  # inverse ShiftRows
        s = [INV_SBOX[b] for b in s]
        s = [b ^ k for b, k in zip(s, keys[rnd])]
        if rnd:
            m = []
            for c in range(0, 16, 4):
                a = s[c:c + 4]
                m += [_mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9),
                      _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13),
                      _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11),
                      _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)]
            s = m
    return s


def aes_cbc_encrypt(key, iv, data):
    keys, pad = _round_keys(key), 16 - len(data) % 16
    data, prev, out = data + bytes([pad]) * pad, list(iv), bytearray()
    for i in range(0, len(data), 16):
        prev = _encrypt_block([b ^ p for b, p in zip(data[i:i + 16], prev)], keys)
        out += bytes(prev)
    return bytes(out)


def aes_cbc_decrypt(key, iv, data):
    if not data or len(data) % 16:
        raise ValueError("ciphertext is not a whole number of blocks")
    keys, prev, out = _round_keys(key), list(iv), bytearray()
    for i in range(0, len(data), 16):
        block = list(data[i:i + 16])
        out += bytes(b ^ p for b, p in zip(_decrypt_block(block, keys), prev))
        prev = block
    pad = out[-1]
    if not 1 <= pad <= 16:
        raise ValueError("bad padding")
    return bytes(out[:-pad])


# ---- RSA, PKCS#1 v1.5 encryption padding ---------------------------------------------
def rsa_encrypt(n, e, plaintext):
    """TP-Link splits long text into blocks and concatenates the hex of each."""
    k, out = (n.bit_length() + 7) // 8, ""
    for i in range(0, len(plaintext), k - 11):
        chunk = plaintext[i:i + k - 11]
        pad = bytes(secrets.randbelow(255) + 1 for _ in range(k - 3 - len(chunk)))
        out += pow(int.from_bytes(b"\x00\x02" + pad + b"\x00" + chunk, "big"), e, n).to_bytes(k, "big").hex()
    return out


# ---- the Deco ------------------------------------------------------------------------
def _name(value):
    """Device names arrive base64-encoded; older firmware sends them plain."""
    if not value:
        return ""
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return str(value)


class Deco:
    def __init__(self, host, password, username="admin", timeout=10):
        host = host.strip().rstrip("/")
        self.host = host if host.startswith(("http://", "https://")) else "http://" + host
        self.username, self.password, self.timeout = username, password, timeout
        # a Deco's own certificate is self-signed; this only ever talks to the address the owner typed in
        self.ctx = ssl._create_unverified_context() if self.host.startswith("https://") else None
        # the firmware expects the AES key and IV as 16-digit decimal strings
        self.key = str(secrets.randbelow(9 * 10 ** 15) + 10 ** 15)
        self.iv = str(secrets.randbelow(9 * 10 ** 15) + 10 ** 15)
        self.reset()

    def reset(self):
        self.stok = self.cookie = self.seq = self.sign_key = None

    def _post(self, path, form, body):
        url = f"{self.host}/cgi-bin/luci/;stok={self.stok or ''}/{path}?form={form}"
        req = urllib.request.Request(url, data=body.encode(), headers={"Content-Type": "application/json"})
        if self.cookie:
            req.add_header("Cookie", self.cookie)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                for c in r.headers.get_all("Set-Cookie") or []:
                    if c.startswith("sysauth="):
                        self.cookie = c.split(";")[0]
                return json.loads(r.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            if e.code == 403:
                self.reset()
                raise SessionLost("The Deco refused the login. This usually means the owner account is signed in "
                                "somewhere else (the Deco app). See the README about using a manager account in the app.")
            if e.code == 401:
                self.reset()
                raise DecoError("This Deco's firmware uses an older sign-in method that netinv does not support.")
            raise DecoError(f"The Deco answered with an error (HTTP {e.code}).")
        except (OSError, ValueError) as e:
            raise DecoError(f"Could not reach the Deco at {self.host} ({e}).")

    def _seal(self, payload):
        data = base64.b64encode(aes_cbc_encrypt(self.key.encode(), self.iv.encode(),
                                                json.dumps(payload, separators=(",", ":")).encode())).decode()
        digest = hashlib.md5((self.username + self.password).encode()).hexdigest()
        sign = rsa_encrypt(*self.sign_key, f"k={self.key}&i={self.iv}&h={digest}&s={self.seq + len(data)}".encode())
        return f"sign={sign}&data={urllib.parse.quote_plus(data)}"

    def _open(self, response):
        data = response.get("data")
        if isinstance(data, dict):
            return data
        if not data:
            self.reset()
            raise DecoError("The Deco sent an empty answer (the session probably expired).")
        try:
            return json.loads(aes_cbc_decrypt(self.key.encode(), self.iv.encode(), base64.b64decode(data)).decode())
        except ValueError:
            self.reset()
            raise DecoError("Could not read the Deco's answer.")

    def login(self):
        self.reset()
        try:
            keys = self._post("login", "keys", json.dumps({"operation": "read"}))["result"]["password"]
            auth = self._post("login", "auth", json.dumps({"operation": "read"}))["result"]
            self.sign_key, self.seq = (int(auth["key"][0], 16), int(auth["key"][1], 16)), int(auth["seq"])
        except (KeyError, TypeError, ValueError, IndexError):
            raise DecoError("The address answered, but not like a Deco. Check the Deco address.")
        secret = rsa_encrypt(int(keys[0], 16), int(keys[1], 16), self.password.encode())
        data = self._open(self._post("login", "login", self._seal({"params": {"password": secret}, "operation": "login"})))
        if data.get("error_code") == -5002:
            left = (data.get("result") or {}).get("attemptsAllowed")
            self.reset()
            raise BadPassword("The Deco rejected the password." + (f" Attempts left before it locks: {left}." if left is not None else ""))
        try:
            self.stok = data["result"]["stok"]
        except (KeyError, TypeError):
            self.reset()
            raise DecoError(f"The Deco did not accept the login (code {data.get('error_code')}).")
        if not self.cookie:
            self.reset()
            raise DecoError("The Deco accepted the login but did not start a session.")

    def call(self, path, form, payload):
        for attempt in (0, 1):
            if not self.stok:
                self.login()
            try:
                data = self._open(self._post(path, form, self._seal(payload)))
            except SessionLost:
                if attempt:
                    raise
                continue
            code = data.get("error_code") or data.get("errorcode")
            if not code:
                return data.get("result") or {}
            self.reset()  # most often an expired session: sign in again once
            if attempt:
                raise DecoError(f"The Deco returned an error ({code}).")

    def clients(self, node="default"):
        """Every device the mesh knows, or with a unit's id (from nodes()) only those connected
        through that unit. Speeds are bytes per second."""
        out = []
        for c in self.call("admin/client", "client_list", {"operation": "read", "params": {"device_mac": node}}).get("client_list", []):
            mac = str(c.get("mac", "")).replace("-", ":").lower()
            if len(mac) != 17:
                continue
            kbit = lambda v: int(float(v or 0) * 125)  # the Deco reports kilobits per second
            out.append({"mac": mac, "name": _name(c.get("name")), "ip": c.get("ip") or "", "online": bool(c.get("online")),
                        "conn": c.get("connection_type") or "", "net": c.get("interface") or "",
                        "down": kbit(c.get("down_speed")), "up": kbit(c.get("up_speed"))})
        return out

    def nodes(self):
        """The Deco units themselves."""
        out = []
        for d in self.call("admin/device", "device_list", {"operation": "read"}).get("device_list", []):
            out.append({"id": d.get("mac") or "", "mac": str(d.get("mac", "")).replace("-", ":").lower(), "name": _name(d.get("custom_nickname")) or d.get("nickname") or "Deco",
                        "model": d.get("device_model") or "", "ip": d.get("device_ip") or "", "main": d.get("role") == "master",
                        "online": d.get("group_status") == "connected", "internet": d.get("inet_status") == "online"})
        return out


if __name__ == "__main__":
    import getpass
    import sys
    if len(sys.argv) != 2:
        sys.exit("usage: python3 deco.py http://<address of the main Deco>")
    deco = Deco(sys.argv[1], getpass.getpass("Deco owner password (your TP-Link ID password): "))
    try:
        for n in deco.nodes():
            print(f"Deco  {n['name']:<22} {n['model']:<8} {n['ip']:<15} {'main' if n['main'] else 'satellite'}  {'online' if n['online'] else 'offline'}")
        where = {}
        for n in deco.nodes():
            try:
                where.update({c["mac"]: n["name"] for c in deco.clients(n["id"]) if c["online"]})
            except DecoError as e:
                print(f"(could not ask {n['name']} for its own devices: {e})")
        for c in sorted(deco.clients(), key=lambda c: not c["online"]):
            print(f"{where.get(c['mac'], '-')[:14]:<14} ", end="")
            print(f"{'on ' if c['online'] else 'off'}   {c['name'][:22]:<22} {c['mac']}  {c['ip']:<15} {c['conn']:<8} {c['net']:<6} "
                  f"down {c['down'] / 1000:.0f} kB/s  up {c['up'] / 1000:.0f} kB/s")
    except DecoError as e:
        sys.exit(str(e))
