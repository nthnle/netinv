"""Tests for the parts of lanledger that have gone wrong before. Standard library only:

    python3 -m unittest discover tests
"""
import argparse
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import deco  # noqa: E402
import lanledger  # noqa: E402

DAY = 86400
A, B, C = "a8:aa:aa:aa:aa:01", "a8:aa:aa:aa:aa:02", "a8:aa:aa:aa:aa:03"
PY = sys.executable.replace("\\", "/")


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.app = lanledger.App(argparse.Namespace(
            db=os.path.join(self.dir.name, "t.db"), gateway="", retention_days=30, scan_interval=60, block_file="",
            block_hosts="", list_base="", notify_url="", no_probe=True, log="", iface="", scan_cmd="", oui_url="", no_threat_list=False))
        self.addCleanup(self.app.db.close)
        self.now = int(time.time())

    def device(self, mac, first_days_ago=20, **cols):
        self.app.seen(mac, cols.pop("ip", "10.0.0." + str(int(mac[-2:], 16))), "", self.now)
        cols = {"known": 1, "first_seen": self.now - first_days_ago * DAY, **cols}
        self.app.x(f"UPDATE devices SET {', '.join(k + '=?' for k in cols)} WHERE mac=?", (*cols.values(), mac))

    def lookups(self, mac, days_ago, domain="x.example.com", count=5):
        hour = self.now - self.now % 3600 - days_ago * DAY
        self.app.x("INSERT INTO dns_hourly(dev, domain, base, hour, count) VALUES(?,?,?,?,?)",
                   (mac, domain, lanledger.base_domain(domain), hour, count))
        self.app.hint_cache, self.app.day_cache = (0, {}), (0, {}, [])

    def devices(self):
        return {d["mac"]: d for d in self.app.api_devices({})}

    def attention(self, kind):
        return {i["mac"] for i in self.app.api_attention({}) if i["kind"] == kind}


class Silent(Case):
    def test_only_a_week_of_silence_is_flagged(self):
        for mac in (A, B, C):
            self.device(mac)
        self.lookups(B, 3)   # quiet today, but looked something up this week: an appliance holding a connection
        self.lookups(C, 9)   # nothing for over a week
        self.assertEqual(self.attention("silent"), {A, C})

    def test_a_device_that_just_arrived_is_not_flagged(self):
        self.device(A, first_days_ago=2)
        self.assertEqual(self.attention("silent"), set())


class Attribution(Case):
    """Lookups are credited by address, so who holds an address has to be right."""

    def line(self, ip):
        return self.app.parse_line(f"Nov 12 10:00:00 dnsmasq[1]: query[A] example.com from {ip}", self.now)[1]

    def test_the_sweep_outranks_a_stale_deco_list(self):
        self.app.seen(A, "10.0.0.5", "", self.now)                   # the laptop answers the Pi at .5
        self.app.seen(B, "10.0.0.5", "", self.now, arp=False)        # the Deco still lists the fridge there
        self.assertEqual(self.line("10.0.0.5"), A)
        self.assertEqual(self.devices()[B]["ip"], "")

    def test_the_deco_is_believed_when_the_sweep_has_nothing(self):
        self.app.seen(B, "10.0.0.6", "", self.now, arp=False)
        self.assertEqual(self.line("10.0.0.6"), B)

    def test_an_old_sighting_no_longer_outranks_the_deco(self):
        self.app.seen(A, "10.0.0.5", "", self.now - lanledger.ARP_TRUST - 1)
        self.app.seen(B, "10.0.0.5", "", self.now, arp=False)
        self.assertEqual(self.line("10.0.0.5"), B)

    def test_the_deco_cannot_move_a_device_the_sweep_just_saw_elsewhere(self):
        self.app.seen(A, "10.0.0.5", "", self.now)
        self.app.seen(A, "10.0.0.9", "", self.now, arp=False)
        self.assertEqual(self.devices()[A]["ip"], "10.0.0.5")
        self.assertEqual(self.line("10.0.0.9"), "ip:10.0.0.9")

    def test_a_reused_address_leaves_its_previous_holder(self):
        self.app.seen(A, "10.0.0.5", "", self.now - 3600)
        self.app.a.scan_cmd = f'{PY} -c "print(\'10.0.0.5\\t{B}\\tAcme\')"'
        self.app.scan_once()
        d = self.devices()
        self.assertEqual((d[A]["ip"], d[B]["ip"]), ("", "10.0.0.5"))
        self.assertEqual(self.line("10.0.0.5"), B)

    def test_two_devices_on_one_address_do_not_trade_lookups(self):
        self.app.seen(B, "10.0.0.5", "", self.now - 60)
        self.app.a.scan_cmd = f'{PY} -c "print(\'10.0.0.5\\t{A}\\tAcme\\n10.0.0.5\\t{B}\\tAcme\')"'
        for _ in range(2):
            self.app.scan_once()
            self.assertEqual(self.line("10.0.0.5"), B)   # whoever had it keeps it, whatever order they answer in
        self.assertEqual(self.devices()[A]["ip"], "10.0.0.5")

    def test_at_startup_the_device_seen_last_has_the_address(self):
        self.app.seen(A, "10.0.0.5", "", self.now - 3600, arp=False)
        self.app.seen(B, "10.0.0.5", "", self.now, arp=False)
        self.app.x("UPDATE devices SET ip='10.0.0.5'")
        again = lanledger.App(self.app.a)
        self.addCleanup(again.db.close)
        self.assertEqual(again.ipmap["10.0.0.5"], B)


class Hints(Case):
    def test_its_own_name_beats_what_it_looks_up(self):
        self.device(A, deco_name="LG_Smart_Fridge2_open")
        for d in ("www.msftconnecttest.com", "ctldl.windowsupdate.com"):
            self.lookups(A, 0, d, 40)
        self.assertEqual(self.devices()[A]["hint"], "LG smart appliance")

    def test_one_stray_name_is_not_a_phone(self):
        self.device(A)
        self.lookups(A, 0, "connectivitycheck.gstatic.com", 50)
        self.assertEqual(self.devices()[A]["hint"], "")

    def test_a_real_phone_is_still_recognised(self):
        self.device(A)
        for d in ("gateway.icloud.com", "init.push.apple.com", "captive.apple.com"):
            self.lookups(A, 0, d, 10)
        self.assertEqual(self.devices()[A]["hint"], "Apple device (iPhone, iPad or Mac)")

    def test_names(self):
        for name, want in (("HS300", "TP-Link / Kasa smart device"), ("MyQ-3FC", "myQ garage door opener"), ("LGwebOSTV", "LG TV"),
                           ("BRWBCF4D443D255", "Brother printer"), ("espressif", "Small Wi-Fi gadget (Espressif chip)"),
                           ("Android-2", ""), ("wlan0", ""), ("", "")):
            self.assertEqual(lanledger.name_hint({"deco_name": name}), want, name)

    def test_an_announced_name_follows_the_device_that_has_it_now(self):
        self.device(A, ip="10.0.0.7", mdns="Clock", services="googlecast")
        self.device(B, ip="10.0.0.8")
        self.app.record_mdns({"10.0.0.8": {"name": "Clock", "services": {"googlecast"}}})
        d = self.devices()
        self.assertEqual((d[A]["mdns"], d[A]["services"], d[B]["mdns"]), ("", "", "Clock"))


class Makers(Case):
    CSV = 'Registry,Assignment,Organization Name,Organization Address\nMA-L,788CB5,"TP-Link  Corporation Limited","x"\nMA-L,zz,Bad,x\n'

    def test_the_register_is_read(self):
        self.assertEqual(lanledger.parse_oui(self.CSV), {"788CB5": "TP-Link Corporation Limited"})

    def test_missing_makers_are_filled_in_but_private_addresses_are_not(self):
        private = "7a:8c:b5:00:00:01"  # locally administered: made up by the phone, tells nothing about its maker
        self.app.seen("78:8c:b5:a0:ec:6a", "10.0.0.2", "", self.now)
        self.app.oui = lanledger.parse_oui(self.CSV) | {"7A8CB5": "Nobody"}
        self.app.fill_makers()
        self.app.seen("78:8c:b5:a0:ec:6b", "10.0.0.3", "", self.now)
        self.app.seen(private, "10.0.0.4", "", self.now)
        d = self.devices()
        self.assertEqual([d[m]["vendor"] for m in ("78:8c:b5:a0:ec:6a", "78:8c:b5:a0:ec:6b", private)],
                         ["TP-Link Corporation Limited"] * 2 + [""])

    def test_what_the_sweep_reports_is_kept(self):
        self.app.oui = lanledger.parse_oui(self.CSV)
        self.app.seen("78:8c:b5:a0:ec:6a", "10.0.0.2", "From arp-scan", self.now)
        self.assertEqual(self.devices()["78:8c:b5:a0:ec:6a"]["vendor"], "From arp-scan")


class Isolated(Case):
    """Online according to the Deco, unanswered by the Pi: kept apart, as the Deco's Device Isolation does."""
    LONG = lanledger.CUT_OFF + 60

    def setUp(self):
        super().setUp()
        self.app.deco_state["ok"] = True
        self.app.last_scan = self.app.sweep_ok = self.now

    def deco_only(self, mac, since):
        self.app.seen(mac, "10.0.0.9", "", self.now, arp=False)
        self.app.x("UPDATE devices SET known=1, first_seen=? WHERE mac=?", (self.now - 20 * DAY, mac))
        self.app.deco_since[mac] = self.now - since

    def test_online_per_the_deco_but_unreachable_from_the_pi(self):
        self.device(A)                                                   # answers the Pi
        self.deco_only(B, self.LONG)                                     # only the Deco sees it, and has for a good while
        d = self.devices()
        self.assertEqual((d[A]["isolated"], d[B]["isolated"]), (0, 1))
        self.assertEqual(self.attention("silent"), {A})                 # isolation explains the silence: no alert

    def test_a_device_just_back_is_not_called_isolated(self):
        self.deco_only(B, 120)                                           # the Deco saw it return two minutes ago
        self.app.x("UPDATE devices SET arp_seen=? WHERE mac=?", (self.now - 3600, B))   # the Pi last heard it an hour ago
        self.assertEqual(self.devices()[B]["isolated"], 0)

    def test_a_failed_sweep_does_not_isolate_the_whole_house(self):
        self.deco_only(B, self.LONG)
        self.app.sweep_ok = self.now - 3600                              # sweeps have been coming back empty
        self.assertEqual(self.devices()[B]["isolated"], 0)

    def test_an_empty_sweep_is_not_counted_as_a_working_one(self):
        self.app.sweep_ok = self.now - 3600
        self.app.a.scan_cmd = f'{PY} -c "print()"'
        self.app.scan_once()
        self.assertLess(self.app.sweep_ok, self.now - 1800)
        self.assertIn("sweep", self.app.trouble)
        self.app.a.scan_cmd = f'{PY} -c "print(\'10.0.0.5\\t{A}\\tAcme\')"'
        self.app.scan_once()
        self.assertGreaterEqual(self.app.sweep_ok, self.now)
        self.assertEqual(self.app.api_summary({})["trouble"], [])

    def test_a_merged_device_answering_on_its_other_adapter_is_reachable(self):
        self.deco_only(B, self.LONG)                                     # the Wi-Fi side: silent towards the Pi
        self.device(C)                                                   # the cable side: answers the sweep
        self.app.deco_since[C] = self.now - self.LONG
        self.app.api_update({"mac": C, "parent": B})
        self.assertEqual(self.devices()[B]["isolated"], 0)


class Summary(Case):
    def test_new_sites_are_those_never_seen_before_today(self):
        self.device(A)
        self.lookups(A, 0, "www.new.com")
        self.lookups(A, 0, "www.old.com")
        self.lookups(A, 5, "cdn.old.com")
        s = self.app.api_summary({})
        self.assertEqual([r["name"] for r in s["fresh"]], ["new.com"])
        self.assertEqual({r["name"] for r in s["top"]}, {"new.com", "old.com"})

    def test_a_change_shows_at_once_despite_the_cache(self):
        self.device(A)
        self.assertEqual(self.devices()[A]["label"], "")
        self.assertIs(self.app.api_devices({}), self.app.api_devices({}))   # asked twice, worked out once
        self.app.x("UPDATE devices SET label='Fridge' WHERE mac=?", (A,))
        self.assertEqual(self.devices()[A]["label"], "Fridge")


class DecoCipher(unittest.TestCase):
    """The Deco's replies are AES-128-CBC. Two ways of doing it here: a library if present, plain Python if not."""
    KEY, IV = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"), bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    def test_the_published_test_vector(self):   # NIST SP 800-38A, F.2.1
        plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51")
        want = "7649abac8119b246cee98e9b12e9197d" "5086cb9b507219ee95db113a917678b2"
        for fast in (False, True):
            self.assertEqual(deco.aes_cbc_encrypt(self.KEY, self.IV, plain, fast=fast)[:32].hex(), want)

    def test_both_ways_agree_and_undo_each_other(self):
        for size in (0, 1, 15, 16, 17, 1000, 20000):
            data = os.urandom(size)
            slow = deco.aes_cbc_encrypt(self.KEY, self.IV, data, fast=False)
            self.assertEqual(deco.aes_cbc_encrypt(self.KEY, self.IV, data, fast=True), slow, size)
            for fast in (False, True):
                self.assertEqual(deco.aes_cbc_decrypt(self.KEY, self.IV, slow, fast=fast), data, size)

    def test_damaged_replies_are_refused(self):
        for fast in (False, True):
            with self.assertRaises(ValueError):
                deco.aes_cbc_decrypt(self.KEY, self.IV, b"not a whole block", fast=fast)


class MeshUnits(Case):
    def test_units_from_one_box_are_told_apart(self):
        # three units bought together: hardware addresses alike but for the last two digits, as on a real mesh
        nodes = [{"name": "Living Room", "mac": "48:22:54:d5:5e:10", "ip": "192.168.68.1", "main": True},
                 {"name": "Office", "mac": "48:22:54:d5:5e:14", "ip": "192.168.71.249", "main": False},
                 {"name": "Laundry", "mac": "48:22:54:d5:5e:18", "ip": "192.168.71.248", "main": False}]
        unit = lambda mac, ip="": (lanledger.unit_of({"mac": mac, "ip": ip}, nodes) or {}).get("name")
        self.assertEqual([unit(n["mac"]) for n in nodes], ["Living Room", "Office", "Laundry"])
        self.assertEqual(unit("48:22:54:d5:5e:15"), "Office")                 # a unit's second address, a digit away
        self.assertEqual(unit("48:22:54:d5:5e:19"), "Laundry")
        self.assertEqual(unit("aa:bb:cc:00:00:01", "192.168.71.248"), "Laundry")   # by address, whatever the hardware says
        self.assertIsNone(unit("aa:bb:cc:00:00:01", "192.168.68.50"))

    def test_the_map_gets_each_unit_under_its_own_name(self):
        self.app.a.gateway = "10.0.0.1"
        self.app.deco_state["nodes"] = [{"name": "Living Room", "mac": "48:22:54:d5:5e:10", "ip": "10.0.0.1", "main": True},
                                        {"name": "Office", "mac": "48:22:54:d5:5e:14", "ip": "10.0.0.2", "main": False}]
        for n in self.app.deco_state["nodes"]:
            self.app.seen(n["mac"], n["ip"], "", self.now)
        d = self.devices()
        self.assertEqual([(d[m]["infra"], d[m]["unit"], d[m]["unit_main"]) for m in ("48:22:54:d5:5e:10", "48:22:54:d5:5e:14")],
                         [("router", "Living Room", 1), ("mesh", "Office", 0)])


class Threats(Case):
    """Lookups of names on the malware and phishing list are reported with the device that made them."""

    def setUp(self):
        super().setUp()
        self.app.threat_set = {"bad.example", "phish.example"}
        self.said = []
        self.app.notify = lambda text, plain="": self.said.append(text) or ""
        self.device(A, label="Desktop")
        self.said.clear()                                                # the "new device" alert is not what is under test

    def hit(self, name, dev=A, n=1, ago=0):
        self.app.record_threats({(dev, name): (self.app.threat(name), self.now - ago, self.now - ago, n)})

    def test_a_name_under_a_listed_one_counts_and_others_do_not(self):
        for name, want in (("bad.example", "bad.example"), ("login.bad.example", "bad.example"), ("a.b.bad.example", "bad.example"),
                           ("notbad.example", ""), ("example", ""), ("bad.example.com", "")):
            self.assertEqual(self.app.threat(name), want, name)

    def test_an_exception_you_allowed_is_never_reported(self):
        self.app.allow = {"bad.example"}
        self.assertEqual(self.app.threat("login.bad.example"), "")

    def test_the_list_is_read_one_name_to_a_line_or_as_a_hosts_file(self):
        src = os.path.join(self.dir.name, "src")
        os.makedirs(src)
        with open(os.path.join(src, lanledger.THREATS), "w") as f:
            f.write("# a comment\nbad.example\n0.0.0.0 phish.example\nnot a name\nlocalhost\n" + "".join(f"x{i}.example\n" for i in range(10)))
        import pathlib
        self.app.a.list_base = pathlib.Path(src).as_uri()
        self.app.refresh_lists()
        self.assertEqual(len(self.app.threat_set), 12)
        self.assertTrue({"bad.example", "phish.example"} <= self.app.threat_set)
        self.assertEqual(self.app.list_set, set())                       # watched, not blocked, until switched on
        self.assertEqual(self.app.is_blocked("bad.example"), "")

    def test_a_hit_goes_on_the_to_do_list_first_and_into_the_history(self):
        self.hit("login.bad.example", n=3)
        item = self.app.api_attention({})[0]
        self.assertEqual((item["kind"], item["mac"], item["count"]), ("threat", A, 3))
        self.assertEqual(item["sites"], [{"name": "login.bad.example", "listed": "bad.example", "blocked": False}])
        self.assertEqual([(e["kind"], e["info"]) for e in self.app.api_events({}) if e["kind"] == "threat"], [("threat", "login.bad.example")])
        self.assertEqual(self.app.api_device({"mac": A})["threats"][0]["name"], "login.bad.example")

    def test_you_are_told_once_not_for_every_lookup(self):
        self.hit("login.bad.example")
        self.hit("login.bad.example", n=40)
        self.hit("phish.example")
        self.assertEqual(self.said, ["Desktop tried to reach a site on the malware and phishing list: login.bad.example"])
        self.assertEqual(self.app.q("SELECT count FROM threats WHERE domain='login.bad.example'")[0]["count"], 41)

    def test_ignoring_holds_until_the_device_tries_somewhere_new(self):
        self.hit("login.bad.example", ago=100)
        key = self.attention_keys("threat")[0]
        self.app.api_dismiss({"key": key})
        self.hit("login.bad.example", n=5)                               # the same site again: still ignored
        self.assertEqual(self.attention_keys("threat"), [])
        self.hit("phish.example", ago=-5)                                # a new one, after you pressed Ignore: back on the list
        self.assertEqual(len(self.attention_keys("threat")), 1)

    def test_an_ignored_warning_does_not_return_when_an_old_hit_ages_out(self):
        self.hit("login.bad.example", ago=6 * DAY)                       # still being tried
        self.hit("phish.example", ago=6 * DAY - 60)                      # tried once, a minute later
        self.app.api_dismiss({"key": self.attention_keys("threat")[0]})
        self.app.x("DELETE FROM threats WHERE domain='phish.example'")   # ...and now too old to keep
        self.hit("login.bad.example", n=3)
        self.assertEqual(self.attention_keys("threat"), [])

    def test_blocking_the_site_is_reflected(self):
        self.hit("login.bad.example")
        self.app.block_active = {"bad.example"}
        self.assertTrue(self.app.api_attention({})[0]["sites"][0]["blocked"])

    def test_hits_made_before_a_device_was_identified_follow_it(self):
        self.hit("phish.example", dev="ip:10.0.0.77")
        self.app.x("INSERT INTO dns_hourly(dev, domain, base, hour, count) VALUES('ip:10.0.0.77','phish.example','phish.example',?,1)", (self.now - self.now % 3600,))
        self.app.seen(B, "10.0.0.77", "", self.now)
        self.assertEqual([r["dev"] for r in self.app.q("SELECT dev FROM threats")], [B])

    def test_old_hits_drop_off_the_to_do_list(self):
        self.hit("phish.example", ago=(lanledger.THREAT_DAYS + 1) * DAY)
        self.assertEqual(self.attention_keys("threat"), [])

    def attention_keys(self, kind):
        return [i["key"] for i in self.app.api_attention({}) if i["kind"] == kind]


class RouterImpostor(Case):
    """Something else answering for the router's address is how a home network's traffic gets intercepted."""
    GW, ROUTER, OTHER = "10.0.0.1", "60:83:e7:72:c3:da", "00:1c:c2:78:4e:43"

    def setUp(self):
        super().setUp()
        self.app.a.gateway = self.GW
        self.said = []
        self.app.notify = lambda text, plain="": self.said.append(text) or ""
        lanledger.shutil.which, self._which = (lambda name: None), lanledger.shutil.which   # no `ip` command: the sweep alone
        self.addCleanup(setattr, lanledger.shutil, "which", self._which)
        self.sweep(self.ROUTER)                                          # first clear sight: this is the router

    def sweep(self, *macs):
        self.app.check_gateway({self.GW: list(macs)}, self.now)

    def alerts(self):
        return [i for i in self.app.api_attention({}) if i["kind"] == "impostor"]

    def test_the_first_clear_sight_of_the_router_is_remembered(self):
        self.assertEqual(self.app.meta("gw_mac"), self.ROUTER)
        self.sweep(self.ROUTER)
        self.assertEqual((self.alerts(), self.said), ([], []))

    def test_a_second_device_answering_is_reported_after_two_sweeps_running(self):
        self.sweep(self.ROUTER, self.OTHER)
        self.assertEqual(self.alerts(), [])                              # once is a blip
        self.sweep(self.ROUTER, self.OTHER)
        a = self.alerts()[0]
        self.assertEqual((a["mac"], a["alone"], a["gateway"]), (self.OTHER, False, self.GW))
        self.assertEqual(len(self.said), 1)
        self.sweep(self.ROUTER, self.OTHER)
        self.assertEqual(len(self.said), 1)                              # told once, not every minute
        self.assertEqual(self.app.api_attention({})[0]["kind"], "impostor")   # and it heads the list

    def test_a_blip_does_not_add_up(self):
        self.sweep(self.ROUTER, self.OTHER)
        self.sweep(self.ROUTER)
        self.sweep(self.ROUTER, self.OTHER)
        self.assertEqual(self.alerts(), [])

    def test_the_router_s_own_other_addresses_and_mesh_units_are_not_strangers(self):
        self.app.deco_state["nodes"] = [{"mac": "48:22:54:d5:5e:10"}]
        for _ in range(3):
            self.sweep(self.ROUTER, "60:83:e7:72:c3:db", "48:22:54:d5:5e:14")
        self.assertEqual(self.alerts(), [])

    def test_a_replaced_router_is_reported_as_a_change_and_can_be_accepted(self):
        for _ in range(2):
            self.sweep(self.OTHER)
        a = self.alerts()[0]
        self.assertTrue(a["alone"])
        self.app.api_dismiss({"key": a["key"]})                          # "this is fine"
        for _ in range(3):
            self.sweep(self.OTHER)
        self.assertEqual((self.alerts(), len(self.said)), ([], 1))

    def test_what_the_pi_itself_believes_counts_too(self):
        lanledger.shutil.which = lambda name: "/sbin/ip"
        real = lanledger.run
        lanledger.run = lambda cmd, timeout=10: f"{self.GW} dev eth0 lladdr {self.OTHER} REACHABLE" if cmd[:2] == ["ip", "-4"] else real(cmd, timeout)
        self.addCleanup(setattr, lanledger, "run", real)
        for _ in range(2):
            self.sweep(self.ROUTER)                                      # the sweep looks normal, but the Pi has been told otherwise
        self.assertEqual(self.alerts()[0]["mac"], self.OTHER)


class LogReader(Case):
    """Every lookup dnsmasq logs is counted against a device, and nothing ends the counting for good."""
    LINE = "Nov 12 10:00:00 dnsmasq[1]: query[A] %s from 10.0.0.1\n"

    def setUp(self):
        super().setUp()
        self.device(A)                                                   # at 10.0.0.1
        self.pending, self.hits = {}, {}

    def take(self, name):
        self.app.take(self.LINE % name, self.now, self.pending, self.hits)

    def test_lookups_are_counted_per_device_site_and_hour_and_written(self):
        self.app.block_active = {"ads.example"}
        for name in ("www.example.com", "www.example.com", "x.ads.example", "1.0.0.10.in-addr.arpa"):
            self.take(name)
        self.assertEqual(sorted((dev, dom, n) for (dev, dom, _), n in self.pending.items()),
                         [(A, "www.example.com", (2, 0)), (A, "x.ads.example", (1, 1))])   # reverse lookups are noise; a refused one is marked
        self.assertEqual([e["domain"] for e in self.app.live], ["www.example.com", "www.example.com", "x.ads.example"])
        log = os.path.join(self.dir.name, "dns.log")
        with open(log, "w") as f:
            f.write("x" * 40)
        with open(log) as f:
            f.read()
            self.app.flush(self.pending, f, 7, self.hits)
        self.assertEqual(self.pending, {})
        self.assertEqual({(r["domain"], r["count"], r["blocked"]) for r in self.app.q("SELECT * FROM dns_hourly")},
                         {("www.example.com", 2, 0), ("x.ads.example", 1, 1)})
        self.assertEqual(self.app.meta("log_pos"), "7:40")              # where to pick up after a restart

    def test_a_listed_site_is_noted_as_it_goes_by(self):
        self.app.threat_set = {"bad.example"}
        self.take("login.bad.example")
        self.take("login.bad.example")
        self.assertEqual({k: (v[0], v[3]) for k, v in self.hits.items()}, {(A, "login.bad.example"): ("bad.example", 2)})

    def test_an_error_does_not_end_the_recording(self):
        calls = []

        def follow(path, pending, hits):
            calls.append(1)
            if len(calls) == 1:
                raise lanledger.sqlite3.OperationalError("database or disk is full")
            raise KeyboardInterrupt                                      # only so the test can stop a loop that never ends
        self.app.follow, self.app.last_scan = follow, self.now
        sleep, lanledger.time.sleep = lanledger.time.sleep, lambda s: None
        self.addCleanup(setattr, lanledger.time, "sleep", sleep)
        with self.assertRaises(KeyboardInterrupt):
            self.app.tailer()
        self.assertEqual(len(calls), 2)                                  # it came back for more after the error
        self.assertIn("disk is full", self.app.api_summary({})["trouble"][0])   # and the dashboard is told meanwhile

    def test_a_log_that_cannot_be_read_is_reported(self):
        sleep, lanledger.time.sleep = lanledger.time.sleep, lambda s: None
        self.addCleanup(setattr, lanledger.time, "sleep", sleep)
        self.app.follow(os.path.join(self.dir.name, "missing.log"), {}, {})
        self.assertIn("cannot be read", self.app.trouble["log"])


class NotRecorded(Case):
    """A device can be left out: nothing it looks up is kept, though it is still watched for known-bad sites."""

    def setUp(self):
        super().setUp()
        self.device(A)
        self.device(B)
        for mac in (A, B):
            self.lookups(mac, 0, "www.example.com")
        self.app.api_update({"mac": A, "private": True})

    def test_its_history_is_erased_and_only_its(self):
        self.assertEqual({r["dev"] for r in self.app.q("SELECT dev FROM dns_hourly")}, {B})
        self.assertEqual(self.devices()[A]["private"], 1)

    def test_nothing_more_is_kept_but_a_known_bad_site_is_still_noted(self):
        self.app.threat_set = {"bad.example"}
        pending, hits = {}, {}
        for name in ("www.example.com", "login.bad.example"):
            self.app.take(f"Nov 12 10:00:00 dnsmasq[1]: query[A] {name} from 10.0.0.1\n", self.now, pending, hits)
        self.assertEqual((pending, list(self.app.live)), ({}, []))
        self.assertEqual(list(hits), [(A, "login.bad.example")])

    def test_it_is_not_then_called_silent(self):
        self.assertEqual(self.attention("silent"), set())                # B looked something up; A is not recorded by choice

    def test_recording_can_be_switched_back_on(self):
        self.app.api_update({"mac": A, "private": False})
        pending = {}
        self.app.take("Nov 12 10:00:00 dnsmasq[1]: query[A] www.example.com from 10.0.0.1\n", self.now, pending, {})
        self.assertEqual(len(pending), 1)


class DecoPoll(Case):
    """What lanledger does with the Deco's answers, with a stand-in for the Deco."""
    PI = "e4:5f:01:5e:1f:dc"

    class Stub:
        host, password = "http://10.0.0.1", "pw"

        def __init__(self):
            self.asked = []
            self.list = [{"mac": A, "name": "Fridge", "ip": "10.0.0.1", "online": True, "conn": "band2_4", "net": "main", "down": 1000, "up": 100},
                         {"mac": "a8:aa:aa:aa:aa:77", "name": "Ghost", "ip": "", "online": False, "conn": "", "net": "main", "down": 0, "up": 0}]

        def clients(self, node="default"):
            self.asked.append(node)
            return self.list if node in ("default", "U1") else []        # everything here is on the main unit

        def nodes(self):
            return [{"id": "U1", "mac": "60:83:e7:00:00:10", "name": "Laundry", "ip": "10.0.0.250", "main": True, "online": True},
                    {"id": "U2", "mac": "60:83:e7:00:00:14", "name": "Office", "ip": "10.0.0.251", "main": False, "online": True}]

    def setUp(self):
        super().setUp()
        self.app.meta("deco_host", "10.0.0.1")
        self.app.meta("deco_password", "pw")
        self.stub = self.app.deco = self.Stub()

    def test_names_connection_speed_and_usage_come_in(self):
        last = self.app.deco_poll(0)
        d = self.devices()[A]
        self.assertEqual((d["deco_name"], d["conn"], d["net"], d["down"], d["up"], d["node"]), ("Fridge", "band2_4", "main", 1000, 100, "Laundry"))
        self.assertNotIn("a8:aa:aa:aa:aa:77", self.devices())           # something the Deco remembers from long ago is not imported
        self.assertTrue(self.app.deco_state["ok"])
        self.app.deco_poll(last - 30)                                    # half a minute on: usage adds up
        self.assertEqual(self.app.q("SELECT down, up FROM usage_hourly WHERE mac=?", (A,)), [{"down": 30000, "up": 3000}])

    def test_an_unknown_connection_keeps_the_last_known_one(self):
        self.app.deco_poll(0)
        self.stub.list[0]["conn"] = ""                                   # what the Deco says for a device that has gone quiet
        self.app.deco_poll(0)
        self.assertEqual(self.devices()[A]["conn"], "band2_4")

    def test_each_unit_is_asked_only_every_few_minutes(self):
        for _ in range(4):
            self.app.deco_poll(0)
        self.assertEqual(self.stub.asked.count("U1"), 1)
        self.assertEqual(self.stub.asked.count("default"), 4)
        self.app.deco_where_ts -= lanledger.WHERE_EVERY + 1
        self.app.deco_poll(0)
        self.assertEqual(self.stub.asked.count("U1"), 2)

    def test_the_deco_never_rewrites_a_maker_or_this_pi_s_marker(self):
        self.app.oui = {"E45F01": "Raspberry Pi Trading Ltd", "A8AAAA": "From The Register"}
        self.app.seen(self.PI, "10.0.0.2", lanledger.PI_VENDOR, self.now)
        self.app.seen(A, "10.0.0.1", "As arp-scan spells it", self.now)
        self.stub.list.append({"mac": self.PI, "name": "focus", "ip": "10.0.0.2", "online": True, "conn": "wired", "net": "main", "down": 0, "up": 0})
        self.app.deco_poll(0)
        d = self.devices()
        self.assertEqual((d[self.PI]["vendor"], d[self.PI]["infra"], d[A]["vendor"]), (lanledger.PI_VENDOR, "pi", "As arp-scan spells it"))

    def test_how_long_the_deco_has_called_a_device_online_is_kept(self):
        self.app.deco_poll(0)
        first = self.app.deco_since[A]
        self.app.deco_since[A] = first - 500
        self.app.deco_poll(0)
        self.assertEqual(self.app.deco_since[A], first - 500)            # still online: the clock keeps running
        self.stub.list[0]["online"] = False
        self.app.deco_poll(0)
        self.assertNotIn(A, self.app.deco_since)                         # gone: it starts afresh when it returns

    def test_a_wrong_password_stops_the_asking(self):
        def refuse(node="default"):
            raise deco.BadPassword("The Deco rejected the password.")
        self.stub.clients = refuse
        self.app.deco_poll(0)
        self.assertTrue(self.app.deco_halt)                              # a Deco locks the account after a few wrong tries
        self.stub.clients = lambda node="default": self.fail("asked again")
        self.app.deco_poll(0)


class BlockingTheList(Case):
    """Switching on the malware and phishing list has to block what the warnings are about: names under a listed one."""

    def setUp(self):
        super().setUp()
        self.app.a.block_file = os.path.join(self.dir.name, "blocked.conf")
        self.app.a.block_hosts = os.path.join(self.dir.name, "lists.hosts")
        os.makedirs(self.app.lists_dir, exist_ok=True)
        with open(self.app.list_path(lanledger.THREATS), "w") as f:
            f.write("bad.example\nphish.example\n")
        self.app.x("UPDATE lists SET enabled=1 WHERE id=?", (lanledger.THREATS,))

    def files(self):
        self.app.load_lists()
        self.app.write_hosts()
        self.app.write_blocklist()
        with open(self.app.a.block_file) as f, open(self.app.a.block_hosts) as h:
            return f.read().splitlines()[1:], [line for line in h.read().splitlines() if not line.startswith("#")]

    def test_everything_under_a_listed_name_is_refused(self):
        servers, hosts = self.files()
        self.assertEqual((servers, hosts), (["server=/bad.example/", "server=/phish.example/"], []))
        self.assertEqual([self.app.is_blocked(n) for n in ("bad.example", "login.bad.example", "good.example")], ["list", "list", ""])

    def test_your_own_blocks_and_exceptions_share_the_file(self):
        self.app.x("INSERT INTO blocked(domain, added) VALUES('tiktok.com', 1)")
        self.app.x("INSERT INTO allowed VALUES('ok.bad.example', 1)")     # one address under a listed name that you trust
        self.app.x("INSERT INTO allowed VALUES('phish.example', 1)")      # and a listed name you say is wrongly listed
        servers, _ = self.files()
        self.assertEqual(servers, ["server=/bad.example/", "server=/tiktok.com/", "server=/ok.bad.example/#"])
        self.assertEqual([self.app.is_blocked(n) for n in ("ok.bad.example", "x.bad.example", "phish.example", "www.tiktok.com")],
                         ["", "list", "", "manual"])

    def test_switched_off_it_blocks_nothing_but_is_still_watched(self):
        self.app.x("UPDATE lists SET enabled=0 WHERE id=?", (lanledger.THREATS,))
        self.assertEqual(self.files(), ([], []))
        self.assertEqual((self.app.is_blocked("login.bad.example"), self.app.threat("login.bad.example")), ("", "bad.example"))

    def test_an_old_dnsmasq_gets_exact_names_which_is_all_it_handles_well(self):
        self.app.wild_ok = False
        servers, hosts = self.files()
        self.assertEqual((servers, hosts[:2]), ([], ["0.0.0.0 bad.example", ":: bad.example"]))

    def test_the_big_file_is_not_rebuilt_when_nothing_changed(self):
        self.files()
        os.remove(self.app.a.block_file)
        with open(self.app.a.block_file, "w") as f:
            f.write("left alone")
        self.app.write_blocklist()
        with open(self.app.a.block_file) as f:
            self.assertEqual(f.read(), "left alone")
        self.app.x("INSERT INTO blocked(domain, added) VALUES('tiktok.com', 1)")
        self.app.write_blocklist()
        with open(self.app.a.block_file) as f:
            self.assertIn("server=/tiktok.com/", f.read())


class Alerts(Case):
    def setUp(self):
        super().setUp()
        self.sent = []

        class Reply:
            def close(self):
                pass
        real = lanledger.urllib.request.urlopen
        lanledger.urllib.request.urlopen = lambda req, timeout=0: self.sent.append((req.full_url, req.data.decode())) or Reply()
        self.addCleanup(setattr, lanledger.urllib.request, "urlopen", real)
        self.app.api_set_notify({"url": "https://alerts.example/topic"})

    def test_an_alert_names_the_device_and_site_unless_asked_not_to(self):
        self.app.threat_set = {"bad.example"}
        self.device(A, label="Kids tablet")
        self.sent.clear()
        self.app.record_threats({(A, "login.bad.example"): ("bad.example", self.now, self.now, 1)})
        self.assertEqual(self.sent, [("https://alerts.example/topic", "Kids tablet tried to reach a site on the malware and phishing list: login.bad.example")])
        self.app.api_set_notify({"url": "https://alerts.example/topic", "plain": True})
        self.assertTrue(self.app.api_settings({})["notify_plain"])
        self.sent.clear()
        self.app.record_threats({(B, "x.bad.example"): ("bad.example", self.now, self.now, 1)})
        self.app.seen(C, "10.0.0.50", "Acme", self.now)
        for _, text in self.sent:
            self.assertNotRegex(text, "bad.example|Acme|10\\.0\\.0|a8:aa", text)   # nothing that says who or what
        self.assertEqual(len(self.sent), 2)

    def test_with_no_address_nothing_is_sent(self):
        self.app.api_set_notify({"url": ""})
        self.sent.clear()
        self.assertEqual(self.app.notify("hello"), "No alert address is set.")
        self.assertEqual(self.sent, [])


class Odds(Case):
    def test_an_answer_worked_out_during_a_write_is_not_kept(self):
        def slow():
            self.app.x("UPDATE devices SET label='changed meanwhile'")    # someone renames a device while the list is being put together
            return "worked out before the change"
        self.assertEqual(self.app.cached("k", slow), "worked out before the change")
        self.assertEqual(self.app.cached("k", lambda: "fresh"), "fresh")

    def test_a_second_adapter_keeps_the_name_its_device_announces(self):
        self.device(A, ip="10.0.0.7", mdns="Living Room TV", services="airplay")   # the cable side
        self.device(B, ip="10.0.0.7")                                             # the Wi-Fi side, same address
        self.app.ipmap["10.0.0.7"] = B
        self.app.record_mdns({"10.0.0.7": {"name": "Living Room TV", "services": {"airplay"}}})
        d = self.devices()
        self.assertEqual((d[A]["mdns"], d[B]["mdns"]), ("Living Room TV", "Living Room TV"))

    def test_changing_the_password_after_the_session_ended_says_so(self):
        self.app.api_password({"new": "first password"}, signed_in=False)
        with self.assertRaisesRegex(lanledger.SignIn, "session has ended"):
            self.app.api_password({"current": "first password", "new": "second password"}, signed_in=False)
        with self.assertRaisesRegex(lanledger.SignIn, "another browser"):
            self.app.api_password({"new": "someone else's"}, signed_in=False)

    def test_the_count_at_the_top_matches_the_list(self):
        self.device(A)
        self.lookups("ip:10.0.0.99", 0)                                  # a client that looked things up but was never identified
        self.assertEqual(self.app.api_summary({})["total"], len(self.app.api_devices({})))

    def test_a_backup_is_a_complete_usable_copy(self):
        self.device(A, label="Fridge")
        out = os.path.join(self.dir.name, "copy.db")
        argv, sys.argv = sys.argv, ["lanledger", "--db", self.app.a.db, "--backup", out]
        self.addCleanup(setattr, sys, "argv", argv)
        lanledger.main()
        copy = lanledger.sqlite3.connect(out)
        self.addCleanup(copy.close)
        self.assertEqual(copy.execute("SELECT label FROM devices").fetchall(), [("Fridge",)])

    def test_a_maker_list_that_cannot_be_saved_is_still_used(self):
        class Reply:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

            def read(self, n):
                return ("Registry,Assignment,Organization Name,Address\n" + "".join(f"MA-L,{i:06X},Maker {i},x\n" for i in range(1200))).encode()
        real = lanledger.urllib.request.urlopen
        lanledger.urllib.request.urlopen = lambda req, timeout=0: Reply()
        self.addCleanup(setattr, lanledger.urllib.request, "urlopen", real)
        self.app.a.oui_url = "https://register.example/oui.csv"
        self.app.oui_path = lambda: os.path.join(self.dir.name, "no such folder", "oui.tsv")
        self.app.refresh_oui()                                           # must not raise: the hour's other housekeeping follows it
        self.assertEqual(self.app.oui["0004AF"], "Maker 1199")


class Export(Case):
    def test_connection_is_in_words_and_never_undefined(self):
        self.assertEqual([deco._conn(v) for v in ("band2_4", "undefined", None, "")], ["band2_4", "", "", ""])
        self.device(A, conn="band2_4")
        rows = self.app.devices_csv().decode("utf-8-sig").splitlines()
        self.assertIn("Wi-Fi 2.4 GHz", rows[1])
        self.assertNotIn("band2_4", rows[1])


if __name__ == "__main__":
    unittest.main()
