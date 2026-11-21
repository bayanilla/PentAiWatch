"""Fixed-interval calls out: an internal host connecting out to one outside service at an almost
constant gap, as CyberStrikeAI's implant does (one check-in every five seconds, no jitter). A lead on
its own; flagged when what it goes to backs it. From Zeek, from a Palo Alto export (whole-second
times) and both, against near misses that must not fire."""
import json
import os
import random
import tempfile
import unittest

from pentaiwatch.errors import UserError
from pentaiwatch.pipeline import run
from tests import kit, sample

HOST, OTHER = "10.10.1.12", "10.10.2.40"
C2 = "198.51.100.201"                # not on any list, never came in
LISTED = "43.240.29.11"              # Elastic's CyberStrikeAI server (on the bundled list)


def checkins(n=200, gap=5.0, jitter=0.0, start=20000.25, src=HOST, dst=C2, port=443, state="SF", seed=5):
    rng = random.Random(seed)
    t, out = sample.T0 + start, []
    for _ in range(n):
        out.append(kit.session(t, src, dst, port, state))
        t += gap * (1 + rng.uniform(-jitter, jitter))
    return out


class Beacons(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def analyze(self, sessions, zeek=True, firewall=False, settings=None, inbound=True):
        src = os.path.join(self.tmp.name, f"in{len(os.listdir(self.tmp.name))}")
        os.makedirs(src)
        sessions = (sample.sessions() if inbound else []) + sessions
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

    def test_a_five_second_check_in_is_a_lead_from_each_log(self):
        for zeek, firewall in ((True, False), (False, True), (True, True)):
            with self.subTest(zeek=zeek, firewall=firewall):
                det, md = self.analyze(checkins(), zeek, firewall)
                [b] = det["beacons"]
                self.assertEqual((b["host"], b["service"], b["sessions"], b["answered"], b["runs"]),
                                 (HOST, f"{C2}:443/tcp", 200, 200, 1))
                self.assertAlmostEqual(b["gap_seconds"], 5.0, delta=0.02)
                self.assertEqual(b["whole_seconds"], not zeek)
                self.assertEqual((b["status"], b["backed_by"], det["beacons_total"]), ("lead", [], 1))
                self.assertIn("### Fixed-interval calls out", md)
                self.assertIn(f"| {HOST} | {C2}:443/tcp | Lead | 200 sessions (200 answered), one every 5 s", md)
                # nothing else moved: the inbound finding is what it was, and no outbound contact appears
                self.assertEqual([f["source"] for f in det["findings"]], [sample.AGENT])
                self.assertEqual((det["outbound_contacts"], det["c2_hints"], det["steady_sources"]), ([], [], []))

    def test_what_it_goes_to_flags_it(self):
        cases = ((dict(dst=LISTED), "the address is a published attacker address"),
                 (dict(dst=sample.AGENT), "the address is a finding in this report"),
                 (dict(port=50050), "the port is the default of Cobalt Strike teamserver"),
                 (dict(port=8000), "the port is the default of Cairn server"),
                 (dict(port=28001), "the port is the default of PentAGI worker"))
        for kw, why in cases:
            with self.subTest(why=why):
                det, md = self.analyze(checkins(**kw))
                [b] = det["beacons"]
                self.assertEqual((b["status"], b["backed_by"]), ("flagged", [why]))
                self.assertIn(f"Flagged: {why}", md)

    def test_near_misses_do_not_fire(self):
        rng = random.Random(1)
        for name, sessions in (("jitter of 30%", checkins(jitter=0.3)),
                               ("too few", checkins(n=59)),
                               ("too slow", checkins(gap=30.0)),
                               ("uneven gaps", [kit.session(sample.T0 + 20000 + 4 * i + rng.uniform(0, 3), HOST, C2, 443)
                                                for i in range(200)]),
                               ("many addresses, one each", [s for i in range(80)
                                                             for s in checkins(n=3, dst=f"198.51.100.{i + 1}", start=20000 + i)])):
            with self.subTest(name=name):
                det, md = self.analyze(sessions)
                self.assertEqual((det["beacons"], det["beacons_total"]), ([], 0))
                self.assertNotIn("### Fixed-interval calls out", md)

    def test_runs_are_counted_per_service_and_inbound_repetition_is_not_a_call_out(self):
        again = checkins(n=80, start=40000)
        det, _ = self.analyze(checkins() + again + checkins(src=OTHER, port=8443, gap=2.0, n=100))
        got = {(b["host"], b["service"]): (b["sessions"], b["runs"], b["sessions_all"]) for b in det["beacons"]}
        self.assertEqual(got, {(HOST, f"{C2}:443/tcp"): (200, 2, 280), (OTHER, f"{C2}:8443/tcp"): (100, 1, 100)})
        # the same cadence coming IN is fixed-interval repetition, as before, and not a call out
        det, _ = self.analyze(checkins(src=C2, dst=HOST))
        self.assertEqual(det["beacons"], [])
        self.assertEqual([v["source"] for v in det["steady_sources"]], [C2])

    def test_with_only_outbound_traffic_and_the_settings(self):
        det, md = self.analyze(checkins(dst=LISTED), inbound=False)
        self.assertEqual([b["status"] for b in det["beacons"]], ["flagged"])
        self.assertIn("### Fixed-interval calls out", md)
        det, md = self.analyze(checkins(), settings={"beacon": {"check": False}})
        self.assertEqual(det["beacons"], [])
        self.assertIn("- Fixed-interval calls out: not checked", md)
        det, _ = self.analyze(checkins(n=59), settings={"beacon": {"min_sessions": 50}})
        self.assertEqual(len(det["beacons"]), 1)
        det, _ = self.analyze(checkins(), settings={"allowlist": [C2]})
        self.assertEqual(det["beacons"], [])
        with self.assertRaises(UserError):
            self.analyze([], settings={"beacon": {"min_sessions": 2}})

    def test_the_upload_page_lists_the_host_as_a_lead(self):
        from pentaiwatch.web.jobs import summary
        src = os.path.join(self.tmp.name, "web")
        os.makedirs(src)
        kit.write_zeek_conn(os.path.join(src, "conn.log"), sample.sessions() + checkins())
        res, _ = run([src], os.path.join(src, "out"))
        [entry] = [f for f in summary(res)["flagged"] if f["source"] == HOST]
        self.assertEqual((entry["tag"], entry["lead"]), ("Calls out", True))


if __name__ == "__main__":
    unittest.main()
