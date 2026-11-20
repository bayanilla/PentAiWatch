"""Regular clients: a fixed-interval or high-rate lead from a source that already repeated to the same
service a day or more before is marked regular and listed last. It is never dropped, and a source
that also swept is flagged whatever its history."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from pentaiwatch import config
from pentaiwatch.cli import main
from pentaiwatch.errors import UserError
from pentaiwatch.pipeline import run
from pentaiwatch.web.jobs import summary
from tests import kit, sample
from tests.test_leads import MONITOR, PARTNER, TOOL, health_check, partner_push, sweep
from tests.test_steady import brute

DAY = 86400.0


class RegularClients(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def analyze(self, sessions, settings=None, firewall=False):
        src = os.path.join(self.tmp.name, f"in{len(os.listdir(self.tmp.name))}")
        os.makedirs(src)
        if firewall:
            kit.write_paloalto(os.path.join(src, "traffic.csv"), sessions)
        else:
            kit.write_zeek_conn(os.path.join(src, "conn.log"), sessions)
        if settings:
            with open(os.path.join(src, "pentaiwatch.json"), "w", encoding="utf-8") as fh:
                json.dump(settings, fh)
        res, paths = run([src], os.path.join(src, "out"))
        with open(paths["report.md"], encoding="utf-8") as fh:
            return res, fh.read()

    @staticmethod
    def entry(items, source):
        return next(v for v in items if v["source"] == source)

    def test_a_health_check_that_ran_yesterday_too_is_a_regular_client(self):
        yesterday = health_check(n=200, start=3000 - DAY)
        for firewall in (False, True):
            with self.subTest(firewall=firewall):
                res, md = self.analyze(sample.sessions() + yesterday + health_check(), firewall=firewall)
                v = self.entry(res["detection"]["steady_sources"], MONITOR)
                self.assertEqual((v["status"], v["backed_by"]), ("regular", []))
                self.assertTrue(v["runs"][0]["regular_since"])
                self.assertRegex(md, rf"\| {MONITOR} \| Regular client \(since [^)]+\) \|")
                self.assertIn("; repeated to it since", md)
                e = next(x for x in summary(res)["flagged"] if x["source"] == MONITOR)
                self.assertTrue(e["lead"] and e["regular"])
                self.assertEqual([f["source"] for f in res["detection"]["findings"]], [sample.AGENT])

    def test_without_earlier_history_it_stays_a_lead(self):
        res, _ = self.analyze(sample.sessions() + health_check())
        self.assertEqual(self.entry(res["detection"]["steady_sources"], MONITOR)["status"], "lead")
        # history that is too recent (6 hours before) or too thin (29 sessions) does not count
        for earlier in (health_check(n=200, start=3000 - DAY / 4), health_check(n=29, start=3000 - DAY)):
            res, _ = self.analyze(sample.sessions() + earlier + health_check())
            self.assertEqual(self.entry(res["detection"]["steady_sources"], MONITOR)["status"], "lead")

    def test_a_health_check_that_has_run_all_day_is_a_regular_client(self):
        res, _ = self.analyze(sample.sessions() + health_check(n=10000, start=3000 - DAY / 2))
        self.assertEqual(self.entry(res["detection"]["steady_sources"], MONITOR)["status"], "regular")

    def test_history_older_than_the_lookback_counts(self):
        earlier = health_check(n=200, start=3000 - 2 * DAY)
        res, _ = self.analyze(sample.sessions() + earlier + health_check(), settings={"lookback_hours": 24})
        self.assertEqual(self.entry(res["detection"]["steady_sources"], MONITOR)["status"], "regular")

    def test_a_partner_that_pushed_yesterday_too_is_a_regular_client(self):
        res, _ = self.analyze(sample.sessions() + partner_push(start=15000 - DAY) + partner_push())
        self.assertEqual(self.entry(res["detection"]["spray_sources"], PARTNER)["status"], "regular")

    def test_a_source_that_swept_is_flagged_whatever_its_history(self):
        swept, end = sweep()
        yesterday = brute(src=TOOL, start=end + 3600 - DAY)
        res, _ = self.analyze(sample.sessions() + yesterday + swept + brute(src=TOOL, start=end + 3600))
        v = self.entry(res["detection"]["steady_sources"], TOOL)
        self.assertEqual((v["status"], v["backed_by"]), ("flagged", ["sweep"]))

    def test_regular_clients_are_listed_last_and_counted_apart(self):
        sessions = (sample.sessions() + health_check(n=200, start=3000 - DAY) + health_check()
                    + health_check(src="198.51.100.201", start=40000, seed=3))
        src = os.path.join(self.tmp.name, "cli")
        os.makedirs(src)
        kit.write_zeek_conn(os.path.join(src, "conn.log"), sessions)
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            self.assertEqual(main(["analyze", src, "--out", os.path.join(src, "out")]), 0)
        self.assertIn("1 source flagged; 1 lead to look at (not flagged); 1 regular client.", out.getvalue())
        with open(os.path.join(src, "out", "results.json"), encoding="utf-8") as fh:
            steady = json.load(fh)["detection"]["steady_sources"]
        self.assertEqual([v["status"] for v in steady], ["lead", "regular"])

    def test_it_can_be_turned_off_and_is_checked(self):
        res, md = self.analyze(sample.sessions() + health_check(n=200, start=3000 - DAY) + health_check(),
                               settings={"baseline": {"check": False}})
        self.assertEqual(self.entry(res["detection"]["steady_sources"], MONITOR)["status"], "lead")
        self.assertIn("- Regular clients: not checked", md)
        for bad in ({"before_hours": -1}, {"min_sessions": 0}):
            cfg = config.Config()
            for k, v in bad.items():
                setattr(cfg.baseline, k, v)
            with self.assertRaises(UserError):
                config.check(cfg)


if __name__ == "__main__":
    unittest.main()
