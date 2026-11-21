"""Fixed-interval repetition: one source hitting one service over and over at an almost constant gap,
as CyberStrikeAI's scripted FortiGate logins did (one every 1.5 seconds). Checked from Zeek, from a
Palo Alto export (whole-second times) and both, against near misses that must not fire."""
import json
import os
import random
import tempfile
import unittest

from pentaiwatch.errors import UserError
from pentaiwatch.pipeline import run
from tests import kit, sample

BRUTE = "198.51.100.150"
FORTI = ("10.10.1.11", 8443)


def brute(n=120, gap=1.5, jitter=0.0, start=9000, src=BRUTE, state="RSTO", seed=3):
    rng = random.Random(seed)
    t, out = sample.T0 + start, []
    for _ in range(n):
        out.append(kit.session(t, src, FORTI[0], FORTI[1], state))
        t += gap * (1 + rng.uniform(-jitter, jitter))
    return out


class Steady(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def analyze(self, sessions, zeek=True, firewall=False, settings=None):
        src = os.path.join(self.tmp.name, f"in{len(os.listdir(self.tmp.name))}")
        os.makedirs(src)
        if zeek:
            kit.write_zeek_conn(os.path.join(src, "conn.log"), sessions)
        if firewall:
            kit.write_paloalto(os.path.join(src, "traffic.csv"), sessions)
        if settings:
            with open(os.path.join(src, "pentaiwatch.json"), "w", encoding="utf-8") as fh:
                json.dump(settings, fh)
        res, paths = run([src], os.path.join(src, "out"))
        with open(paths["report.md"], encoding="utf-8") as fh:
            return res["detection"], fh.read()

    def steady(self, det):
        return {v["source"]: v["runs"] for v in det["steady_sources"]}

    def test_fixed_interval_brute_force_is_flagged_from_each_log(self):
        for zeek, firewall in ((True, False), (False, True), (True, True)):
            with self.subTest(zeek=zeek, firewall=firewall):
                det, md = self.analyze(sample.sessions() + brute(), zeek, firewall)
                [run_] = self.steady(det)[BRUTE]
                self.assertEqual(run_["service"], "10.10.1.11:8443/tcp")
                self.assertEqual(run_["sessions"], 120)
                self.assertAlmostEqual(run_["gap_seconds"], 1.5, delta=0.02)
                self.assertEqual(run_["whole_seconds"], not zeek)
                self.assertEqual([f["source"] for f in det["findings"]], [sample.AGENT])
                self.assertIn(f"| {BRUTE} |", md)
                self.assertIn("### Fixed-interval repetition", md)

    def test_small_jitter_still_counts_and_large_does_not(self):
        det, _ = self.analyze(sample.sessions() + brute(jitter=0.1))
        self.assertIn(BRUTE, self.steady(det))
        det, _ = self.analyze(sample.sessions() + brute(jitter=0.6))
        self.assertNotIn(BRUTE, self.steady(det))

    def test_near_misses(self):
        cases = {"too few in a row": brute(n=29), "too slow": brute(gap=12),
                 "broken by a pause": brute(n=25) + brute(n=25, start=9000 + 25 * 1.5 + 30)}
        for why, extra in cases.items():
            with self.subTest(why):
                det, md = self.analyze(sample.sessions() + extra)
                self.assertEqual(det["steady_sources"], [], why)
                self.assertNotIn("### Fixed-interval repetition", md)

    def test_the_sample_traffic_has_none(self):
        det, _ = self.analyze(sample.sessions())          # the agent's bursts are uneven on purpose
        self.assertEqual(det["steady_sources"], [])
        self.assertEqual(det["findings"][0]["steady"], [])

    def test_many_sessions_a_second_on_the_firewall_are_not_steady(self):
        # whole-second firewall times put several sessions in one second: gaps of 0 and 1 are not a pace
        rng = random.Random(6)
        busy, t = [], sample.T0 + 9000
        for _ in range(400):
            busy.append(kit.session(t, BRUTE, FORTI[0], FORTI[1], "SF"))
            t += rng.uniform(0.0, 0.3)
        det, _ = self.analyze(sample.sessions() + busy, zeek=False, firewall=True)
        self.assertNotIn(BRUTE, self.steady(det))

    def test_an_uneven_one_second_pace_on_the_firewall_is_not_steady(self):
        # about one a second, give or take 40%: whole-second gaps of 0, 1 and 2, not two neighbours
        det, _ = self.analyze(sample.sessions() + brute(n=150, gap=1.0, jitter=0.4), zeek=False, firewall=True)
        self.assertNotIn(BRUTE, self.steady(det))

    def test_a_flagged_source_carries_its_runs(self):
        agent_brute = brute(src=sample.AGENT, start=600 + 300 * 1.4 + 4 * 3600)
        det, md = self.analyze(sample.sessions() + agent_brute)
        [f] = det["findings"]
        self.assertEqual(f["source"], sample.AGENT)
        self.assertEqual([r["sessions"] for r in f["steady"]], [120])
        self.assertEqual(det["steady_sources"], [])
        self.assertIn("| Fixed-interval repetition | 10.10.1.11:8443/tcp (Edge device admin or VPN): 120 sessions", md)

    def test_known_scanners_are_left_out(self):
        det, _ = self.analyze(sample.sessions() + brute(), settings={"allowlist": [BRUTE]})
        self.assertEqual(det["steady_sources"], [])

    def test_settings(self):
        det, md = self.analyze(sample.sessions() + brute(n=30), settings={"steady": {"min_sessions": 25}})
        self.assertIn(BRUTE, self.steady(det))
        self.assertIn("Fixed-interval repetition (timing pattern b, and a lead on its own): 25+ sessions in a row", md)
        with self.assertRaisesRegex(UserError, "steady.min_sessions must be 3 or more"):
            self.analyze(sample.sessions(), settings={"steady": {"min_sessions": 2}})


if __name__ == "__main__":
    unittest.main()
