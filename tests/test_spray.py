"""High-rate login spray: one source sending a flood of completed connections to one service,
minute after minute (Microsoft saw up to 2,900 failed logins a minute from one Storm-0940 address).
Checked from Zeek and from Palo Alto exports with and without start times, against a scan, a short
flurry and a public service that must not fire."""
import json
import os
import random
import tempfile
import unittest

from pentaiwatch.errors import UserError
from pentaiwatch.pipeline import run
from tests import kit, sample

SPRAYER = "144.172.64.99"            # Microsoft's Storm-0940 spray address (on the bundled list)
UNLISTED = "198.51.100.160"
VPN = ("10.10.1.10", 4443)


def spray(src=UNLISTED, minutes=6, per_minute=90, start=15000, state="SF", seed=2, service=VPN):
    rng = random.Random(seed)
    out = []
    for m in range(minutes):
        base = sample.T0 + start + 60 * m
        out += [kit.session(base + rng.uniform(0, 59.9), src, service[0], service[1], state) for _ in range(per_minute)]
    return out


class Spray(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def analyze(self, sessions, zeek=True, firewall=False, settings=None, **pa):
        src = os.path.join(self.tmp.name, f"in{len(os.listdir(self.tmp.name))}")
        os.makedirs(src)
        if zeek:
            kit.write_zeek_conn(os.path.join(src, "conn.log"), sessions)
        if firewall:
            kit.write_paloalto(os.path.join(src, "traffic.csv"), sessions, **pa)
        if settings:
            with open(os.path.join(src, "pentaiwatch.json"), "w", encoding="utf-8") as fh:
                json.dump(settings, fh)
        res, paths = run([src], os.path.join(src, "out"))
        with open(paths["report.md"], encoding="utf-8") as fh:
            return res["detection"], fh.read()

    def sprayers(self, det):
        return {v["source"]: v["runs"] for v in det["spray_sources"]}

    def test_a_spray_is_flagged_from_each_log(self):
        for zeek, firewall, pa in ((True, False, {}), (False, True, {}), (False, True, {"start": False})):
            with self.subTest(zeek=zeek, firewall=firewall, **pa):
                det, md = self.analyze(sample.sessions() + spray(), zeek, firewall, **pa)
                [r] = self.sprayers(det)[UNLISTED]
                self.assertEqual(r["service"], "10.10.1.10:4443/tcp")
                self.assertEqual(r["target"], "Edge device admin or VPN")
                self.assertGreaterEqual(r["minutes"], 5)
                self.assertGreaterEqual(r["peak_per_minute"], 80)
                self.assertIn("### High-rate login spray", md)
                self.assertIn(f"| {UNLISTED} | ", md)
                self.assertIn("- High-rate login spray: 60+ sessions a minute", md)
                self.assertEqual([f["source"] for f in det["findings"]], [sample.AGENT])

    def test_a_listed_sprayer_shows_in_both_places(self):
        det, md = self.analyze(sample.sessions() + spray(src=SPRAYER))
        self.assertIn(SPRAYER, self.sprayers(det))
        self.assertIn(SPRAYER, [k["source"] for k in det["known_sources"]])

    def test_near_misses_do_not_fire(self):
        cases = {"a scan (connections fail)": spray(state="S0"),
                 "a short flurry": spray(minutes=3),
                 "a slow rate": spray(per_minute=40)}
        for what, extra in cases.items():
            with self.subTest(what):
                det, md = self.analyze(sample.sessions() + extra)
                self.assertNotIn(UNLISTED, self.sprayers(det))
                self.assertNotIn("### High-rate login spray", md)

    def test_public_services_are_left_out(self):
        rng = random.Random(8)
        visitors = [kit.session(sample.T0 + rng.uniform(0, 40000), f"192.0.2.{100 + i}", *VPN, "SF")
                    for i in range(25) for _ in range(2)]
        det, _ = self.analyze(sample.sessions() + visitors + spray())
        self.assertEqual(det["spray_sources"], [])
        det, _ = self.analyze(sample.sessions() + visitors + spray(), settings={"spray": {"max_service_sources": 50}})
        self.assertIn(UNLISTED, self.sprayers(det))

    def test_a_tool_following_up_on_what_it_found_is_not_a_spray(self):
        det, _ = self.analyze(sample.sessions() + sample.other_pace())
        self.assertEqual(det["spray_sources"], [])

    def test_a_steady_source_is_listed_once(self):
        from tests.test_steady import BRUTE, brute
        det, _ = self.analyze(sample.sessions() + brute(n=600, gap=0.5))
        self.assertIn(BRUTE, [v["source"] for v in det["steady_sources"]])
        self.assertNotIn(BRUTE, self.sprayers(det))

    def test_the_sample_has_no_spray(self):
        det, _ = self.analyze(sample.sessions())
        self.assertEqual(det["spray_sources"], [])
        self.assertEqual(det["findings"][0]["spray"], [])

    def test_settings(self):
        det, _ = self.analyze(sample.sessions() + spray(), settings={"spray": {"min_per_minute": 200}})
        self.assertEqual(det["spray_sources"], [])
        with self.assertRaises(UserError):
            self.analyze(sample.sessions(), settings={"spray": {"min_answered_share": 2}})


if __name__ == "__main__":
    unittest.main()
