"""The two bundled samples, from Zeek, from Palo Alto with and without a start time, and both.

samples/ holds PentAIWatch's copies of VulnScope MAX's ARTEX and CyberStrikeAI stories, with a
made-up sweep added (scripts/samples/build.py says how). The Palo Alto versions are written by the
same script at test time, so only the Zeek logs are kept in the repository.

What each sample should give, and why:
- ARTEX: two operator addresses sweep, narrow and work in short bursts with pauses: Level 1, burst
  and pause. Two more sweep and narrow at an uneven pace: not flagged, since a sweep and a return
  alone are what a person with a scanner does too.
- CyberStrikeAI: one address sweeps and then logs in every 1.5 seconds: Level 1, fixed-interval
  cadence. The other two step through the FortiGate's ports every 2 seconds, but only 24 in a row,
  short of the 30 a fixed-interval run needs: not flagged (a near miss, kept as one).
- From a firewall export with no start time but elapsed seconds, burst and pause still reads (its
  pauses are 20 seconds and more); a 1.5-second cadence does not, and the report says so.
- With no start time at all, every source that swept and narrowed is Tier 0, and timing is not read.
- Zeek and Palo Alto together count each session once."""
import os
import shutil
import tempfile
import unittest

from pentaiwatch.pipeline import run
from scripts.samples import build

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")
ARTEX = "artex_ai_agentic_intrusion"
CYBERSTRIKE = "cyberstrike_ai_fortigate_intrusion"
TIMED = ("zeek", "paloalto", "both")

# per sample: Level 1 sources and their timing pattern; sources that sweep and narrow but stay unflagged
EXPECTED = {
    ARTEX: {"level_1": {"144.172.64.99": "burst and pause", "144.172.64.128": "burst and pause"},
            "unflagged": ["144.172.64.60", "104.194.150.21"]},
    CYBERSTRIKE: {"level_1": {"212.11.64.250": "fixed-interval cadence"},
                  "unflagged": ["146.190.195.154", "64.176.48.93"]},
}


class BundledSamples(unittest.TestCase):
    results: dict = {}

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        for name in EXPECTED:
            base = os.path.join(cls.tmp.name, name)
            os.makedirs(os.path.join(base, "zeek"))
            conn = os.path.join(ROOT, name, "conn.log")
            shutil.copy(conn, os.path.join(base, "zeek"))
            build.paloalto(conn, base)
            os.makedirs(os.path.join(base, "both"))
            shutil.copy(conn, os.path.join(base, "both"))
            shutil.copy(os.path.join(base, "paloalto", "traffic.csv"), os.path.join(base, "both"))
            for variant in TIMED + ("paloalto_elapsed_only", "paloalto_no_start"):
                res, _ = run([os.path.join(base, variant)], os.path.join(base, "out_" + variant))
                cls.results[name, variant] = res

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def findings(self, name, variant):
        return {f["source"]: f for f in self.results[name, variant]["detection"]["findings"]}

    def test_level_1_sources_and_their_timing_pattern(self):
        for name, want in EXPECTED.items():
            for variant in TIMED:
                with self.subTest(sample=name, variant=variant):
                    found = self.findings(name, variant)
                    self.assertEqual({s: (f["level"], f["timing"]["patterns"]) for s, f in found.items()},
                                     {s: (1, [p]) for s, p in want["level_1"].items()})

    def test_a_sweep_and_a_return_without_a_machine_pace_is_not_flagged(self):
        for name, want in EXPECTED.items():
            for variant in TIMED:
                with self.subTest(sample=name, variant=variant):
                    narrowed = self.results[name, variant]["detection"]["narrowing_sources"]
                    self.assertEqual(narrowed, len(want["level_1"]) + len(want["unflagged"]))
                    self.assertFalse(set(want["unflagged"]) & set(self.findings(name, variant)))

    def test_elapsed_seconds_read_bursts_but_not_a_short_cadence(self):
        found = self.findings(ARTEX, "paloalto_elapsed_only")
        self.assertEqual({s: (f["level"], f["timing"]["patterns"]) for s, f in found.items()},
                         {s: (1, [p]) for s, p in EXPECTED[ARTEX]["level_1"].items()})
        res = self.results[CYBERSTRIKE, "paloalto_elapsed_only"]
        self.assertEqual(res["detection"]["findings"], [])
        self.assertTrue(any("fixed-interval cadence cannot be checked" in w for w in res["warnings"]))

    def test_with_no_start_time_every_narrowing_source_is_tier_0(self):
        for name, want in EXPECTED.items():
            with self.subTest(sample=name):
                found = self.findings(name, "paloalto_no_start")
                self.assertEqual(set(found), set(want["level_1"]) | set(want["unflagged"]))
                self.assertEqual({f["level"] for f in found.values()}, {0})

    def test_zeek_and_palo_alto_together_count_each_session_once(self):
        for name in EXPECTED:
            with self.subTest(sample=name):
                self.assertEqual(self.results[name, "both"]["sessions"], self.results[name, "zeek"]["sessions"])
                self.assertEqual(self.results[name, "paloalto"]["sessions"], self.results[name, "zeek"]["sessions"])

    def test_the_build_is_deterministic(self):
        conn = os.path.join(ROOT, CYBERSTRIKE, "conn.log")
        a, b = (os.path.join(self.tmp.name, x) for x in ("det_a", "det_b"))
        build.paloalto(conn, a)
        build.paloalto(conn, b)
        for folder in build.VARIANTS:
            with self.subTest(folder=folder):
                with open(os.path.join(a, folder, "traffic.csv"), "rb") as x, \
                        open(os.path.join(b, folder, "traffic.csv"), "rb") as y:
                    self.assertEqual(x.read(), y.read())


if __name__ == "__main__":
    unittest.main()
