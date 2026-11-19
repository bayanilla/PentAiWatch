"""Several attack paths at once: a flagged source whose bursts, after narrowing, take turns between
two or more services (as ARTEX's side-by-side attack paths did) gets higher confidence. One that
finishes each service before the next, or works one service per burst, does not. It never flags a
source on its own. Checked from Zeek and from a Palo Alto export."""
import json
import os
import tempfile
import unittest

from pentaiwatch.errors import UserError
from pentaiwatch.pipeline import run
from tests import kit, sample


class Parallel(unittest.TestCase):
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

    def test_interleaved_paths_raise_confidence_from_each_log(self):
        for zeek, firewall in ((True, False), (False, True)):
            with self.subTest(zeek=zeek, firewall=firewall):
                det, md = self.analyze(sample.sessions(paths=2), zeek, firewall)
                [f] = det["findings"]
                self.assertEqual((f["source"], f["level"], f["confidence"]), (sample.AGENT, 1, "higher"))
                p = f["parallel"]
                self.assertGreaterEqual(p["bursts"], 100)
                self.assertEqual(p["most_services"], 2)
                self.assertEqual(sorted(p["services"]),
                                 ["10.10.1.10:443/tcp", "10.10.1.11:8443/tcp", "10.10.1.12:11434/tcp"])
                self.assertIn("| Several attack paths at once | Higher confidence: ", md)
                self.assertIn("- Several attack paths at once: 5+ bursts", md)

    def test_three_paths(self):
        det, md = self.analyze(sample.sessions(paths=3))
        self.assertEqual(det["findings"][0]["parallel"]["most_services"], 3)
        self.assertIn("worked 2 to 3 services", md)

    def test_one_path_at_a_time_does_not(self):
        for kw in ({}, {"paths": 2, "interleave": False}):
            with self.subTest(**kw):
                det, md = self.analyze(sample.sessions(**kw))
                [f] = det["findings"]
                self.assertEqual((f["confidence"], f["parallel"]), ("standard", None))
                self.assertNotIn("| Several attack paths at once |", md)

    def test_it_never_flags_on_its_own(self):
        # the scanner touches many services in one long burst, never narrows, and stays unflagged
        det, _ = self.analyze(sample.sessions(paths=2))
        self.assertEqual([f["source"] for f in det["findings"]], [sample.AGENT])

    def test_without_start_times_it_cannot_be_seen(self):
        det, _ = self.analyze(sample.sessions(paths=2), zeek=False, firewall=True, start=False)
        [f] = det["findings"]
        self.assertEqual((f["level"], f["parallel"], f["confidence"]), (0, None, "standard"))

    def test_settings(self):
        det, _ = self.analyze(sample.sessions(paths=2), settings={"parallel": {"min_bursts": 100000}})
        self.assertIsNone(det["findings"][0]["parallel"])
        with self.assertRaises(UserError):
            self.analyze(sample.sessions(), settings={"parallel": {"min_services": 1}})


if __name__ == "__main__":
    unittest.main()
