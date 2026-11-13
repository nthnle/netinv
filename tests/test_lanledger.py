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
            block_hosts="", list_base="", notify_url="", no_probe=True, log="", iface="", scan_cmd="", oui_url=""))
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
    def setUp(self):
        super().setUp()
        self.app.deco_state["ok"] = True
        self.app.last_scan = self.now

    def test_online_per_the_deco_but_unreachable_from_the_pi(self):
        self.device(A)                                                   # answers the Pi
        self.app.seen(B, "10.0.0.9", "", self.now, arp=False)           # only the Deco sees it
        self.app.x("UPDATE devices SET known=1, first_seen=? WHERE mac=?", (self.now - 20 * DAY, B))
        d = self.devices()
        self.assertEqual((d[A]["isolated"], d[B]["isolated"]), (0, 1))
        self.assertEqual(self.attention("silent"), {A})                 # isolation explains the silence: no alert

    def test_not_claimed_without_a_recent_sweep_or_for_newcomers(self):
        self.app.seen(B, "10.0.0.9", "", self.now, arp=False)
        self.assertEqual(self.devices()[B]["isolated"], 0)              # just arrived
        self.app.x("UPDATE devices SET first_seen=?", (self.now - DAY,))
        self.app.last_scan = self.now - 3600
        self.assertEqual(self.devices()[B]["isolated"], 0)              # the sweep itself is stale


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


class Export(Case):
    def test_connection_is_in_words_and_never_undefined(self):
        self.assertEqual([deco._conn(v) for v in ("band2_4", "undefined", None, "")], ["band2_4", "", "", ""])
        self.device(A, conn="band2_4")
        rows = self.app.devices_csv().decode("utf-8-sig").splitlines()
        self.assertIn("Wi-Fi 2.4 GHz", rows[1])
        self.assertNotIn("band2_4", rows[1])


if __name__ == "__main__":
    unittest.main()
