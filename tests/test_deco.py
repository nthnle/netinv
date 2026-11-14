"""The Deco client against a pretend Deco that speaks the same protocol, and checks what it is sent.

The pretend Deco holds real RSA keys and undoes the client's encryption properly: a client that wrapped
the password, signed the request or sealed the body wrongly is refused, as a real Deco would refuse it.

    python3 -m unittest discover tests
"""
import base64
import hashlib
import json
import os
import random
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import deco  # noqa: E402

PASSWORD = "owner password"


def prime(bits, rng):
    """A probable prime of that size (Miller-Rabin), from a fixed seed so every run uses the same keys."""
    while True:
        n = rng.getrandbits(bits) | 1 | 1 << (bits - 1)
        d, r = n - 1, 0
        while d % 2 == 0:
            d, r = d // 2, r + 1
        for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            x = pow(a, d, n)
            if x in (1, n - 1):
                continue
            for _ in range(r - 1):
                x = x * x % n
                if x == n - 1:
                    break
            else:
                break
        else:
            return n


class Key:
    def __init__(self, rng, e=65537):
        p, q = prime(256, rng), prime(256, rng)
        self.n, self.e, self.d = p * q, e, pow(e, -1, (p - 1) * (q - 1))
        self.k = (self.n.bit_length() + 7) // 8

    def public(self):
        return [format(self.n, "x"), format(self.e, "x")]

    def open(self, hexed):
        """Undo deco.rsa_encrypt: blocks of k bytes, each PKCS#1 v1.5 padded."""
        out = b""
        for i in range(0, len(hexed), self.k * 2):
            block = pow(int(hexed[i:i + self.k * 2], 16), self.d, self.n).to_bytes(self.k, "big")
            if block[:2] != b"\x00\x02" or b"\x00" not in block[2:]:
                raise ValueError("bad padding")
            out += block[block.index(b"\x00", 2) + 1:]
        return out


class PretendDeco:
    def __init__(self):
        rng = random.Random(2026)
        self.pw_key, self.sign_key, self.seq = Key(rng), Key(rng), 4321
        self.stok, self.cookie, self.aes = "", "", None
        self.logins = self.expire_after = self.lock_out = 0
        self.requests = []
        self.clients = {"default": [
            {"mac": "AA-BB-CC-00-00-01", "name": base64.b64encode("Sam’s iPhone".encode()).decode(), "ip": "192.168.68.21", "online": True,
             "connection_type": "band5", "interface": "main", "down_speed": 800, "up_speed": 16},
            {"mac": "AA-BB-CC-00-00-02", "name": "plain-old-name", "ip": "192.168.68.30", "online": False,
             "connection_type": "undefined", "interface": "guest"},
            {"mac": "not a mac", "name": "", "ip": ""}]}
        self.clients["60-83-E7-00-00-14"] = self.clients["default"][:1]
        self.nodes = [{"mac": "60-83-E7-00-00-10", "custom_nickname": base64.b64encode(b"Laundry").decode(), "device_model": "X55",
                       "device_ip": "192.168.68.1", "role": "master", "group_status": "connected", "inet_status": "online"},
                      {"mac": "60-83-E7-00-00-14", "nickname": "office", "device_ip": "192.168.68.2", "role": "slave", "group_status": "connected"}]

    def answer(self, path, form, body, cookie):
        self.requests.append((path, form))
        if path.endswith("/login") and form == "keys":
            return {"result": {"password": self.pw_key.public()}}, None
        if path.endswith("/login") and form == "auth":
            return {"result": {"key": self.sign_key.public(), "seq": self.seq}}, None
        fields = parse_qs(body)
        sign = dict(p.split("=", 1) for p in self.sign_key.open(fields["sign"][0]).decode().split("&"))
        data = fields["data"][0]
        signing_in = path.endswith("/login") and form == "login"            # there the password itself is checked, and the answer says so
        if int(sign["s"]) != self.seq + len(data) or (not signing_in and sign["h"] != hashlib.md5(("admin" + PASSWORD).encode()).hexdigest()):
            return {"data": ""}, None                                    # a request that was not signed by someone who knows the password
        aes = (sign["k"].encode(), sign["i"].encode())
        payload = json.loads(deco.aes_cbc_decrypt(*aes, base64.b64decode(data)))
        seal = lambda obj: {"data": base64.b64encode(deco.aes_cbc_encrypt(*aes, json.dumps(obj).encode())).decode()}
        if signing_in:
            if self.pw_key.open(payload["params"]["password"]).decode() != PASSWORD or self.lock_out:
                return seal({"error_code": -5002, "result": {"attemptsAllowed": 4}}), None
            self.logins += 1
            self.stok, self.cookie = f"stok{self.logins}", f"sysauth=cookie{self.logins}"
            return seal({"error_code": 0, "result": {"stok": self.stok}}), self.cookie + "; path=/"
        if f";stok={self.stok}/" not in path or cookie != self.cookie:
            return None, 403                                             # not signed in (or signed in elsewhere since)
        if self.expire_after and len(self.requests) > self.expire_after:
            self.expire_after = 0
            return seal({"error_code": -1}), None                        # the session ran out: the client should sign in again
        if form == "client_list":
            return seal({"error_code": 0, "result": {"client_list": self.clients.get(payload["params"]["device_mac"], [])}}), None
        if form == "device_list":
            return seal({"error_code": 0, "result": {"device_list": self.nodes}}), None
        return seal({"error_code": -404}), None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        u = urlparse(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        reply, extra = self.server.deco.answer(u.path, parse_qs(u.query)["form"][0], body, self.headers.get("Cookie"))
        if reply is None:
            self.send_response(extra)
            self.end_headers()
            return
        out = json.dumps(reply).encode()
        self.send_response(200)
        if extra:
            self.send_header("Set-Cookie", extra)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


class Client(unittest.TestCase):
    def setUp(self):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.fake = self.srv.deco = PretendDeco()
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.deco = deco.Deco(f"127.0.0.1:{self.srv.server_address[1]}", PASSWORD)

    def test_signing_in_and_reading_the_devices(self):
        got = self.deco.clients()
        self.assertEqual([c["mac"] for c in got], ["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"])    # the line with no hardware address is dropped
        self.assertEqual(got[0], {"mac": "aa:bb:cc:00:00:01", "name": "Sam’s iPhone", "ip": "192.168.68.21", "online": True,
                                  "conn": "band5", "net": "main", "down": 100000, "up": 2000})    # kilobits a second in, bytes a second out
        self.assertEqual((got[1]["name"], got[1]["conn"], got[1]["online"]), ("plain-old-name", "", False))   # "undefined" is not a connection
        self.assertEqual(self.fake.logins, 1)

    def test_one_sign_in_serves_many_requests(self):
        for _ in range(3):
            self.deco.clients()
        self.assertEqual(self.fake.logins, 1)

    def test_the_mesh_units_and_who_is_on_each(self):
        nodes = self.deco.nodes()
        self.assertEqual([(n["name"], n["mac"], n["ip"], n["main"], n["online"]) for n in nodes],
                         [("Laundry", "60:83:e7:00:00:10", "192.168.68.1", True, True), ("office", "60:83:e7:00:00:14", "192.168.68.2", False, True)])
        self.assertEqual([c["mac"] for c in self.deco.clients(nodes[1]["id"])], ["aa:bb:cc:00:00:01"])

    def test_a_wrong_password_is_reported_as_such_and_not_retried(self):
        wrong = deco.Deco(self.deco.host, "not the password")
        with self.assertRaisesRegex(deco.BadPassword, "rejected the password.*Attempts left.*4"):
            wrong.clients()
        self.assertEqual([r for r in self.fake.requests if r[1] == "login"], [("/cgi-bin/luci/;stok=/login", "login")])   # asked once

    def test_a_session_that_ran_out_is_renewed_without_fuss(self):
        self.deco.clients()
        self.fake.expire_after = len(self.fake.requests)                 # the next request finds the session gone
        self.assertEqual(len(self.deco.clients()), 2)
        self.assertEqual(self.fake.logins, 2)

    def test_being_signed_out_by_the_app_is_explained(self):
        self.deco.clients()
        self.fake.stok, self.fake.lock_out = "taken-by-the-app", 1       # the owner signed in elsewhere, and our next sign-in is refused
        with self.assertRaises(deco.DecoError):
            self.deco.clients()

    def test_an_address_that_is_not_a_deco(self):
        self.fake.answer = lambda *a: ({"hello": "world"}, None)
        with self.assertRaisesRegex(deco.DecoError, "not like a Deco"):
            self.deco.clients()

    def test_nothing_listening(self):
        self.srv.shutdown()
        self.srv.server_close()
        gone = deco.Deco(self.deco.host, PASSWORD, timeout=2)
        with self.assertRaisesRegex(deco.DecoError, "Could not reach the Deco"):
            gone.clients()

    def test_names(self):
        self.assertEqual([deco._name(v) for v in (base64.b64encode("Café".encode()).decode(), "not base64!", "", None)], ["Café", "not base64!", "", ""])


if __name__ == "__main__":
    unittest.main()
