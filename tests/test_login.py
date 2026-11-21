"""The repeated failed-login pattern: one source keeps sending short sessions to one service for a
quarter of an hour or more, answered with small replies of nearly one size, as a login page refusing
password after password does. Public services count, because that is where sprays go. A lead on its
own; a sweep flags it. Built for ARTEX's SSO spray: about one attempt a second for 40 minutes, too
uneven for a fixed interval and just under the high-rate threshold."""
import io
import json
import os
import random
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from pentaiwatch import config
from pentaiwatch.cli import main
from pentaiwatch.errors import UserError
from pentaiwatch.pipeline import run
from pentaiwatch.web.jobs import summary
from tests import kit, sample
from tests.test_leads import sweep

SPRAYER = "203.0.113.160"
PORTAL = ("10.10.1.20", 443)               # the sample's public web portal
VISITORS = [f"198.18.50.{i}" for i in range(10, 40)]   # thirty ordinary visitors make it public


def visitors(start=0.0, seed=7):
    rng = random.Random(seed)
    return [kit.session(sample.T0 + start + rng.uniform(0, 86000), ip, *PORTAL, "SF", rb=rng.randint(3000, 90000))
            for ip in VISITORS for _ in range(6)]


def spray(src=SPRAYER, start=20000.0, minutes=40, seed=8, reply=(90, 160), gaps=(0.8, 1.4)):
    """One login attempt every 0.8 to 1.4 seconds, each refused with a small page."""
    rng = random.Random(seed)
    t, end, out = sample.T0 + start, sample.T0 + start + 60 * minutes, []
    while t < end:
        out.append(kit.session(t, src, *PORTAL, "SF", rb=rng.randint(*reply)))
        t += rng.uniform(*gaps)
    return out


class LoginPattern(unittest.TestCase):
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
            return res, fh.read()

    @staticmethod
    def login(res, source):
        return next((v for v in res["detection"]["login_sources"] if v["source"] == source), None)

    def test_a_spray_on_a_public_portal_is_a_lead_the_other_detectors_miss(self):
        base = sample.sessions() + visitors()
        for zeek, firewall, pa in ((True, False, {}), (False, True, {}), (False, True, {"start": False, "elapsed": True}),
                                   (False, True, {"start": False, "elapsed": False})):
            with self.subTest(zeek=zeek, firewall=firewall, **pa):
                res, md = self.analyze(base + spray(), zeek, firewall, **pa)
                det = res["detection"]
                self.assertNotIn(SPRAYER, [v["source"] for v in det["steady_sources"] + det["spray_sources"]])
                v = self.login(res, SPRAYER)
                self.assertEqual((v["status"], v["backed_by"]), ("lead", []))
                [r] = v["runs"]
                self.assertEqual(r["service"], "10.10.1.20:443/tcp")
                self.assertGreaterEqual(r["minutes"], 39)
                self.assertGreaterEqual(r["service_share"], 0.9)        # thirty visitors use it too
                self.assertIn(f"| {SPRAYER} | Lead |", md)
                self.assertIn("### Repeated failed-login pattern", md)

    def test_a_sweep_first_flags_it(self):
        swept, end = sweep(src=SPRAYER)
        res, _ = self.analyze(sample.sessions() + visitors() + swept + spray(start=end + 3600))
        v = self.login(res, SPRAYER)
        self.assertEqual((v["status"], v["backed_by"]), ("flagged", ["sweep"]))
        entry = next(e for e in summary(res)["flagged"] if e["source"] == SPRAYER)
        self.assertEqual((entry["tag"], entry["lead"]), ("Login pattern", False))

    def test_downloads_short_stretches_and_a_shared_portal_are_not_it(self):
        base = sample.sessions() + visitors()
        cases = {
            "replies of every size": spray(reply=(300, 60000)),
            "large pages": spray(reply=(40000, 41000)),
            "ten minutes": spray(minutes=10),
            "under 20 a minute": spray(gaps=(3.5, 4.5)),
        }
        for name, extra in cases.items():
            with self.subTest(name):
                res, _ = self.analyze(base + extra)
                self.assertIsNone(self.login(res, SPRAYER))
        # a portal this busy with other people is not one source's spray: it is a third of the traffic
        others = [s for i in range(2) for s in spray(src=f"198.18.60.{i}", seed=20 + i)]
        res, _ = self.analyze(base + spray() + others)
        self.assertIsNone(self.login(res, SPRAYER))

    def test_the_command_line_and_coverage_name_it(self):
        src = os.path.join(self.tmp.name, "cli")
        os.makedirs(src)
        kit.write_zeek_conn(os.path.join(src, "conn.log"), sample.sessions() + visitors() + spray())
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            self.assertEqual(main(["analyze", src, "--out", os.path.join(src, "out")]), 0)
        self.assertIn(f"{SPRAYER}  repeated failed-login pattern (lead):", out.getvalue())
        with open(os.path.join(src, "out", "results.json"), encoding="utf-8") as fh:
            rows = {r["detector"]: r["status"] for r in json.load(fh)["detection"]["coverage"]}
        self.assertEqual(rows["Repeated failed-login pattern"], "checked")

    def test_it_can_be_turned_off_and_is_checked(self):
        res, md = self.analyze(sample.sessions() + visitors() + spray(), settings={"login_spray": {"check": False}})
        self.assertEqual(res["detection"]["login_sources"], [])
        self.assertIn("- Repeated failed-login pattern: not checked", md)
        cfg = config.Config()
        cfg.login_spray.max_reply_spread = -1
        with self.assertRaises(UserError):
            config.check(cfg)


if __name__ == "__main__":
    unittest.main()
