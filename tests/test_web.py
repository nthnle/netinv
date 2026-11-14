"""Tests of the web server as a browser, or something hostile on the network, meets it. Talks only to 127.0.0.1.

    python3 -m unittest discover tests
"""
import argparse
import http.client
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import lanledger  # noqa: E402

PASSWORD = "correct horse battery"
real_lookup = socket.getaddrinfo


class Web(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.app = lanledger.App(argparse.Namespace(
            db=os.path.join(self.dir.name, "t.db"), gateway="", retention_days=30, scan_interval=60,
            block_file=os.path.join(self.dir.name, "blocked.conf"), block_hosts="", list_base="", notify_url="",
            no_probe=True, log="", iface="", scan_cmd="", oui_url=""))
        self.addCleanup(self.app.db.close)
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), lanledger.Handler)
        self.srv.app, self.srv.allowed_hosts = self.app, {"localhost"}
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.cookie = ""

    def call(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Cookie": self.cookie, **({"Content-Type": "application/json"} if body is not None else {}), **(headers or {})}
        c.request(method, path, json.dumps(body) if body is not None else None, h)
        r = c.getresponse()
        text = r.read().decode()
        if r.getheader("Set-Cookie"):
            self.cookie = r.getheader("Set-Cookie").split(";")[0]
        c.close()
        try:
            return r.status, json.loads(text)
        except ValueError:
            return r.status, text

    def set_password(self):
        self.assertEqual(self.call("POST", "/api/password", {"new": PASSWORD})[0], 200)


class FirstUse(Web):
    def test_nothing_is_shown_until_a_password_is_chosen(self):
        self.assertEqual(self.call("GET", "/api/session")[1], {"setup": True, "signed_in": False})
        for path in ("/api/devices", "/api/summary", "/api/devices.csv", "/api/settings"):
            self.assertEqual(self.call("GET", path), (401, {"error": "sign in", "setup": True}), path)
        self.assertEqual(self.call("POST", "/api/block", {"domain": "example.com"})[0], 401)
        self.assertEqual(self.call("GET", "/")[0], 200)   # the page itself, which then asks for the password

    def test_choosing_a_password_signs_you_in(self):
        self.assertEqual(self.call("POST", "/api/password", {"new": "short"})[0], 400)
        self.set_password()
        self.assertEqual(self.call("GET", "/api/devices")[0], 200)
        self.cookie = ""
        self.assertEqual(self.call("GET", "/api/devices"), (401, {"error": "sign in", "setup": False}))

    def test_once_set_it_cannot_be_replaced_or_removed_without_the_old_one(self):
        self.set_password()
        mine, self.cookie = self.cookie, ""
        self.assertEqual(self.call("POST", "/api/password", {"new": "someone else's"})[0], 401)
        self.cookie = mine
        self.assertEqual(self.call("POST", "/api/password", {"current": "wrong", "new": "another one!"})[0], 400)
        self.assertEqual(self.call("POST", "/api/password", {"current": PASSWORD, "new": ""})[0], 400)
        self.assertEqual(self.call("POST", "/api/password", {"current": PASSWORD, "new": "another one!"})[0], 200)


class FirstUseRace(Web):
    def test_of_two_browsers_choosing_at_once_one_wins_and_the_other_is_told_to_sign_in(self):
        self.set_password()
        self.cookie = ""
        status, body = self.call("POST", "/api/password", {"new": "the other browser's"})   # still on the first-use screen
        self.assertEqual((status, body["setup"]), (401, False))
        self.assertIn("Sign in", body["error"])
        self.assertTrue(self.app.login(PASSWORD, "x"))                                      # the first choice stands


class SignIn(Web):
    def setUp(self):
        super().setUp()
        self.set_password()
        self.cookie = ""

    def test_wrong_tries_lock_out_the_one_trying_and_no_one_else(self):
        for _ in range(5):
            self.assertEqual(self.call("POST", "/api/login", {"password": "guess"})[1]["error"], "Wrong password.")
        self.assertIn("Too many wrong tries", self.call("POST", "/api/login", {"password": PASSWORD})[1]["error"])
        self.assertTrue(self.app.login(PASSWORD, "192.168.68.20"))       # another device signs in as usual

    def test_the_wait_grows_and_a_right_password_clears_it(self):
        waits = []
        for n in range(8):
            with self.assertRaises(ValueError):
                self.app.login("guess", "a")
            waits.append(round(self.app.fails["a"][1] - time.time()) if self.app.fails["a"][1] else 0)
            self.app.fails["a"][1] = min(self.app.fails["a"][1], 1)       # as if the wait had passed
        self.assertEqual(waits, [0, 0, 0, 0, 60, 120, 240, 480])
        self.app.login(PASSWORD, "a")
        self.assertNotIn("a", self.app.fails)


    def test_guessing_through_change_password_counts_too(self):
        self.app.login(PASSWORD, "a")
        for _ in range(5):
            with self.assertRaisesRegex(ValueError, "current password is not right"):
                self.app.api_password({"current": "guess", "new": "something else"}, "a")
        with self.assertRaisesRegex(ValueError, "Too many wrong tries"):
            self.app.api_password({"current": PASSWORD, "new": "something else"}, "a")
        with self.assertRaisesRegex(ValueError, "Too many wrong tries"):
            self.app.login(PASSWORD, "a")                                                   # one count for both doors

    def test_a_flood_of_addresses_does_not_wipe_anyone_s_count(self):
        for _ in range(4):
            with self.assertRaises(ValueError):
                self.app.login("guess", "careful")                                          # one try short of a lockout
        now = time.time()
        self.app.fails.update({f"flood{i}": [1, 0, now - 9000] for i in range(600)})        # long quiet: may be forgotten
        with self.assertRaises(ValueError):
            self.app.login("guess", "other")
        self.assertLessEqual(len(self.app.fails), 500)
        self.assertEqual(self.app.fails["careful"][0], 4)
        with self.assertRaises(ValueError):
            self.app.login("guess", "careful")
        self.assertGreater(self.app.fails["careful"][1], now)                               # the fifth still locks

    def test_behind_a_proxy_on_the_pi_each_visitor_is_counted_separately(self):
        via = lambda ip: {"X-Forwarded-For": ip}
        for _ in range(5):
            self.call("POST", "/api/login", {"password": "guess"}, via("192.168.68.50"))
        self.assertIn("Too many", self.call("POST", "/api/login", {"password": PASSWORD}, via("192.168.68.50"))[1]["error"])
        self.assertEqual(self.call("POST", "/api/login", {"password": PASSWORD}, via("192.168.68.51"))[0], 200)

    def test_only_a_proxy_on_the_pi_is_believed_about_who_is_calling(self):
        h = lanledger.Handler.__new__(lanledger.Handler)
        h.headers = {"X-Forwarded-For": "10.9.9.9"}
        h.client_address = ("192.168.68.77", 1234)
        self.assertEqual(h.who(), "192.168.68.77")           # a device claiming to be someone else is not believed
        h.client_address = ("127.0.0.1", 1234)
        self.assertEqual(h.who(), "10.9.9.9")
        h.headers = {"X-Forwarded-For": "not an address"}
        self.assertEqual(h.who(), "127.0.0.1")


class Endpoints(Web):
    """Every address the dashboard calls, asked the way the dashboard asks it."""
    MAC = "a8:00:00:00:00:01"

    def setUp(self):
        super().setUp()
        self.set_password()
        now = int(time.time())
        self.app.seen(self.MAC, "127.0.0.1", "Acme", now)                # at this machine's own address, so the port check has something to knock on
        self.app.x("UPDATE devices SET known=1, label='Kitchen TV', owner='Sam', first_seen=? WHERE mac=?", (now - 20 * 86400, self.MAC))
        self.app.x("INSERT INTO dns_hourly(dev, domain, base, hour, count) VALUES(?,?,?,?,?)",
                   (self.MAC, "www.netflix.com", "netflix.com", now - now % 3600, 12))

    def get(self, path):
        status, body = self.call("GET", path)
        self.assertEqual(status, 200, path)
        return body

    def post(self, path, body, want=200):
        status, out = self.call("POST", path, body)
        self.assertEqual(status, want, (path, out))
        return out

    def test_reading(self):
        self.assertEqual(self.get("/api/people")[0]["person"], "Sam")
        self.assertEqual([(r["domain"], r["dev"]) for r in self.get("/api/domain?q=netfl")], [("www.netflix.com", self.MAC)])
        self.assertEqual(self.get("/api/domain?q=n"), [])                # too short to be worth a search of everything
        self.assertEqual(self.get("/api/live"), [])
        self.assertIn("joined", [e["kind"] for e in self.get("/api/events")] + ["joined"])
        self.assertEqual(sorted(self.get("/api/health")), sorted(self.app.api_health({})))
        self.assertEqual(self.get("/api/device?mac=" + self.MAC)["top"][0]["name"], "netflix.com")
        self.assertEqual(self.call("GET", "/api/device?hours=soon")[0], 400)
        self.assertEqual(self.call("GET", "/api/nothing-here")[0], 404)
        blocked = self.get("/api/blocked")
        self.assertEqual([l["id"] for l in blocked["lists"]][0], lanledger.THREATS)
        self.assertEqual((blocked["rows"], blocked["can_lists"]), ([], False))

    def test_the_to_do_list_and_ignoring_an_entry(self):
        self.app.x("UPDATE devices SET net='guest' WHERE mac=?", (self.MAC,))
        item = [i for i in self.get("/api/attention") if i["kind"] == "guest"][0]
        self.post("/api/dismiss", {"key": item["key"]})
        self.assertEqual([i for i in self.get("/api/attention") if i["kind"] == "guest"], [])

    def test_blocking_allowing_and_a_daily_window(self):
        self.assertEqual(self.post("/api/block", {"domain": "https://www.TikTok.com/@someone"})["domain"], "www.tiktok.com")
        self.post("/api/block", {"domain": "example.org", "from": "21:00", "to": "07:00"})
        self.assertEqual({(r["domain"], r["t_from"], r["t_to"]) for r in self.get("/api/blocked")["rows"]},
                         {("www.tiktok.com", None, None), ("example.org", 1260, 420)})
        self.post("/api/block", {"domain": "example.org", "from": "21:00", "to": "21:00"}, want=400)   # no time at all
        self.post("/api/block", {"domain": "co.uk"}, want=400)                                          # a whole country's sites
        self.post("/api/block", {"service": "TikTok"})
        self.assertIn("tiktokcdn.com", [r["domain"] for r in self.get("/api/blocked")["rows"]])
        self.post("/api/block", {"domain": "www.tiktok.com", "on": False})
        self.assertNotIn("www.tiktok.com", [r["domain"] for r in self.get("/api/blocked")["rows"]])
        self.post("/api/allow", {"domain": "good.example"})
        self.assertEqual([a["domain"] for a in self.get("/api/blocked")["allowed"]], ["good.example"])
        self.post("/api/allow", {"domain": "good.example", "on": False})
        self.assertEqual(self.get("/api/blocked")["allowed"], [])

    def test_lists_need_the_install_to_support_them(self):
        self.post("/api/list", {"id": "no-such-list", "on": True}, want=400)
        self.assertIn("not set up", self.post("/api/list", {"id": "ads", "on": True}, want=400)["error"])

    def test_erasing_the_history_keeps_the_devices(self):
        now = int(time.time())
        self.app.x("INSERT INTO usage_hourly(mac, hour, down, up) VALUES(?,?,?,?)", (self.MAC, now - now % 3600, 5000, 100))
        self.app.record_threats({(self.MAC, "bad.example"): ("bad.example", now, now, 1)})
        self.post("/api/dismiss", {"key": "threat:" + self.MAC})
        self.post("/api/block", {"domain": "example.org"})
        self.post("/api/erase", {})
        for table in ("dns_hourly", "usage_hourly", "threats"):
            self.assertEqual(self.app.q("SELECT COUNT(*) n FROM " + table)[0]["n"], 0, table)
        self.assertEqual(self.app.q("SELECT key FROM dismissed WHERE key LIKE 'threat:%'"), [])
        device = self.get("/api/devices")[0]
        self.assertEqual((device["mac"], device["label"], device["owner"], device["queries"]), (self.MAC, "Kitchen TV", "Sam", 0))
        self.assertEqual([r["domain"] for r in self.get("/api/blocked")["rows"]], ["example.org"])
        self.assertEqual(self.get("/api/device?mac=" + self.MAC)["top"], [])
        pending = {(self.MAC, "late.example", now - now % 3600): (3, 0)}   # read from the log before the erase, not yet written
        with open(os.devnull) as f:
            self.app.flush(pending, f, 1)
        self.assertEqual(self.app.q("SELECT COUNT(*) n FROM dns_hourly")[0]["n"], 0)

    def test_naming_merging_and_forgetting_a_device(self):
        other = "a8:00:00:00:00:02"
        self.app.seen(other, "10.0.0.9", "", int(time.time()))
        self.post("/api/device", {"mac": other, "label": "Kitchen TV (Wi-Fi)", "owner": " Sam ", "known": True})
        self.post("/api/device", {"mac": other, "parent": self.MAC})
        devices = {d["mac"]: d for d in self.get("/api/devices")}
        self.assertEqual((list(devices), devices[self.MAC]["also"][0]["mac"]), ([self.MAC], other))
        self.post("/api/device", {"mac": self.MAC, "parent": self.MAC}, want=400)                       # into itself
        self.post("/api/forget", {"mac": self.MAC})
        self.assertEqual([d["mac"] for d in self.get("/api/devices")], [other])                         # its other half stands on its own again
        self.assertEqual(self.app.q("SELECT 1 FROM dns_hourly WHERE dev=?", (self.MAC,)), [])

    def test_checking_which_doors_a_device_leaves_open(self):
        out = self.post("/api/ports", {"mac": self.MAC})
        self.assertTrue(out["ok"])
        self.assertEqual(self.get("/api/device?mac=" + self.MAC)["ports"]["open"], out["open"])
        self.app.x("UPDATE devices SET ip='8.8.8.8' WHERE mac=?", (self.MAC,))
        self.assertIn("own network", self.post("/api/ports", {"mac": self.MAC}, want=400)["error"])     # never somebody else's machine

    def test_alert_settings(self):
        self.post("/api/settings/notify", {"url": "not an address"}, want=400)
        self.post("/api/settings/notify", {"url": "https://alerts.example/t", "plain": True})
        s = self.get("/api/settings")
        self.assertEqual((s["notify_url"], s["notify_plain"]), ("https://alerts.example/t", True))
        self.post("/api/settings/notify", {"url": ""})
        self.assertEqual(self.get("/api/settings")["notify_url"], "")

    def test_the_speed_test(self):
        class Download:
            def __init__(self):
                self.left = 40

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

            def read(self, n):
                self.left -= 1
                return b"x" * n if self.left > 0 else b""
        clock = [1000.0]

        def tick():                                                      # a pretend clock, so the test does not take the six seconds
            clock[0] += .05
            return clock[0]
        with mock.patch("lanledger.urllib.request.urlopen", lambda req, timeout=0: Download()), mock.patch("lanledger.time.time", tick):
            out = self.app.api_speedtest({})
        self.assertGreater(out["down"], 1)
        self.assertEqual(self.app.q("SELECT COUNT(*) n FROM speed")[0]["n"], 1)
        self.app.speed_lock.acquire()
        self.addCleanup(self.app.speed_lock.release)
        self.assertIn("already running", self.post("/api/speedtest", {}, want=400)["error"])

    def test_signing_out(self):
        self.post("/api/logout", {})
        self.assertEqual(self.call("GET", "/api/devices")[0], 401)


class Hostile(Web):
    def raw(self, request, wait=5):
        s = socket.create_connection(("127.0.0.1", self.port))
        s.settimeout(wait)
        self.addCleanup(s.close)
        s.sendall(request)
        try:
            return s.recv(4096).decode("latin-1").split("\r\n")[0]
        except socket.timeout:
            return "no answer: the server is still reading"

    def test_a_request_cannot_make_the_server_read_without_limit(self):
        head = "POST /api/login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: %s\r\n\r\n"
        for length in ("-1", "5000", "99999999999", "many"):
            self.assertIn("400", self.raw((head % length).encode()), length)

    def test_a_silent_connection_is_dropped(self):
        self.assertIsNotNone(lanledger.Handler.timeout)
        old, lanledger.Handler.timeout = lanledger.Handler.timeout, 1
        self.addCleanup(setattr, lanledger.Handler, "timeout", old)
        s = socket.create_connection(("127.0.0.1", self.port))
        s.settimeout(6)
        self.addCleanup(s.close)
        self.assertEqual(s.recv(1), b"")   # closed by the server, not left open

    def test_requests_a_web_page_elsewhere_could_make_are_refused(self):
        self.assertEqual(self.call("GET", "/api/session", headers={"Host": "evil.example.com"})[0], 403)   # DNS rebinding
        self.assertEqual(self.call("POST", "/api/login", {"password": "x"}, {"Content-Type": "text/plain"})[0], 403)   # a plain form

    def test_a_blocked_name_cannot_smuggle_a_line_into_dnsmasq(self):
        self.set_password()
        self.call("POST", "/api/block", {"domain": "evil.com/\naddress=/bank.com/6.6.6.6"})
        with open(self.app.a.block_file) as f:
            self.assertEqual(f.read().splitlines()[1:], ["server=/evil.com/"])
        self.assertEqual(self.call("POST", "/api/block", {"domain": "x\naddress=/bank.com/6.6.6.6"})[0], 400)

    def test_the_deco_address_must_be_in_the_home_however_it_is_written(self):
        self.set_password()
        answers = {"deco.example": ["93.184.216.34"], "deco.lan": ["93.184.216.34", "192.168.68.1"]}
        lookup = lambda host, *a, **k: ([(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in answers[host]]
                                        if host in answers else real_lookup(host, *a, **k))

        class FakeDeco:
            def __init__(self, host, password):
                self.host, self.password = host, password

            def clients(self):
                return []
        with mock.patch("lanledger.socket.getaddrinfo", lookup), mock.patch("lanledger.deco.Deco", FakeDeco):
            for host in ("8.8.8.8", "http://1.1.1.1", "deco.example"):
                status, body = self.call("POST", "/api/settings/deco", {"host": host, "password": "x"})
                self.assertEqual(status, 400, host)
                self.assertIn("must be on your own network", body["error"], host)
            # a home name that also has an outside address is accepted, at its home address, and that address
            # is what is kept: the name is never looked up again with the Deco password in hand
            self.assertEqual(self.call("POST", "/api/settings/deco", {"host": "https://deco.lan:8443/", "password": "x"})[0], 200)
            self.assertEqual(self.app.meta("deco_host"), "https://192.168.68.1:8443")

    @unittest.skipIf(os.name == "nt", "file modes are a Unix matter")
    def test_a_block_file_lanledger_has_to_recreate_stays_readable_by_dnsmasq(self):
        old = os.umask(0o077)   # as the service runs
        self.addCleanup(os.umask, old)
        self.set_password()
        os.remove(self.app.a.block_file) if os.path.exists(self.app.a.block_file) else None
        self.call("POST", "/api/block", {"domain": "example.com"})
        self.assertEqual(os.stat(self.app.a.block_file).st_mode & 0o777, 0o644)

    def test_a_name_cannot_run_as_a_spreadsheet_formula(self):
        for i, label in enumerate(("=HYPERLINK(1)", "+1", "-1", "@x", "\t=1", "\r=1")):
            self.app.seen(f"a8:00:00:00:00:{i:02x}", f"10.0.0.{i + 2}", "", int(time.time()))
            self.app.x("UPDATE devices SET label=? WHERE mac=?", (label, f"a8:00:00:00:00:{i:02x}"))
        import csv, io
        rows = list(csv.reader(io.StringIO(self.app.devices_csv().decode("utf-8-sig"))))[1:]
        self.assertEqual(len(rows), 6)
        self.assertTrue(all(r[0].startswith("'") for r in rows), [r[0] for r in rows])


if __name__ == "__main__":
    unittest.main()
