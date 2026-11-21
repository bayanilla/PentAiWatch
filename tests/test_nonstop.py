"""No overnight break: a finding, lead or published address whose source stayed active for most of a
day with no long gap (AWS watched Cairn agents work one target for about 16 hours). Extra evidence
only: it must never flag a source or turn a lead into a flag."""
import json
import os
import tempfile
import unittest

from pentaiwatch.errors import UserError
from pentaiwatch.pipeline import run
from tests import kit, sample

MONITOR = "198.51.100.150"


def monitor(hours=17.0, gap=5.0, start=900.25):
    return [kit.session(sample.T0 + start + gap * i, MONITOR, "10.10.1.20", 443)
            for i in range(int(hours * 3600 / gap))]


class NoOvernightBreak(unittest.TestCase):
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
            return res["detection"], fh.read()

    def coverage(self, det):
        return {c["detector"]: c["status"] for c in det["coverage"]}["No overnight break"]

    def test_an_agent_that_works_eighteen_hours_says_so_on_its_finding(self):
        for firewall in (False, True):
            with self.subTest(firewall=firewall):
                det, md = self.analyze(sample.sessions(hours=18.0), firewall=firewall)
                [f] = det["findings"]
                self.assertEqual((f["source"], f["level"]), (sample.AGENT, 1))
                self.assertGreaterEqual(f["nonstop"]["hours"], 18.0)
                self.assertLess(f["nonstop"]["hours"], 18.5)
                self.assertLess(f["nonstop"]["longest_gap_minutes"], 3)
                self.assertEqual(f["nonstop"]["sessions"], f["sessions"])
                self.assertTrue("| No overnight break | active for 18" in md)
                self.assertEqual(self.coverage(det), "checked")

    def test_a_break_of_three_hours_or_a_short_campaign_is_not_named(self):
        det, md = self.analyze(sample.sessions(hours=18.0, pause_at=8.0, pause_hours=3.0))
        [f] = det["findings"]
        self.assertIsNone(f["nonstop"])
        self.assertFalse("| No overnight break | active" in md)
        det, md = self.analyze(sample.sessions())                 # four hours; the data covers about twelve
        self.assertIsNone(det["findings"][0]["nonstop"])
        self.assertEqual(self.coverage(det), "not checked")
        self.assertTrue("16 or more are needed" in md)

    def test_it_never_turns_a_lead_into_a_flag(self):
        det, md = self.analyze(sample.sessions() + monitor())
        [v] = det["steady_sources"]
        # a monitor that has run that long is a regular client: listed, never flagged
        self.assertEqual((v["source"], v["status"], v["backed_by"]), (MONITOR, "regular", []))
        self.assertGreaterEqual(v["nonstop"]["hours"], 16.9)
        self.assertTrue("; no overnight break: active for 17 hours" in md)
        self.assertEqual([f["source"] for f in det["findings"]], [sample.AGENT])
        # a source that is not a finding, a lead or a published address is never named, however long it runs
        det, md = self.analyze(sample.sessions() + monitor(gap=47.0))
        self.assertEqual(det["steady_sources"], [])
        self.assertFalse("no overnight break" in md.split("### What the tiers and levels mean")[0].lower())

    def test_the_settings(self):
        det, md = self.analyze(sample.sessions(hours=18.0), settings={"nonstop": {"check": False}})
        self.assertIsNone(det["findings"][0]["nonstop"])
        self.assertTrue("- No overnight break: not checked" in md)
        det, _ = self.analyze(sample.sessions(), settings={"nonstop": {"min_hours": 3, "max_quiet_hours": 1}})
        self.assertGreaterEqual(det["findings"][0]["nonstop"]["hours"], 4.0)
        with self.assertRaises(UserError):
            self.analyze(sample.sessions(), settings={"nonstop": {"min_hours": 2, "max_quiet_hours": 2}})


if __name__ == "__main__":
    unittest.main()
