"""Standalone behaviours are leads unless another behaviour backs them, and fixed-interval cadence is
the second timing pattern.

Fixed-interval repetition, high-rate repeated connections and rotating sources each have an ordinary
look-alike (a health check, a busy integration, clients that start near a sweep), so on their own
they are listed as leads. A sweep, or one of the other two behaviours from the same source, flags
them. A source that swept and narrowed at a fixed interval is Level 1, with that pattern named."""
import json
import os
import random
import tempfile
import unittest

from pentaiwatch.pipeline import run
from pentaiwatch.web.jobs import summary
from tests import kit, sample
from tests.test_steady import BRUTE, FORTI, brute

MONITOR = "198.51.100.200"     # a health check every 5 seconds
PARTNER = "198.51.100.210"     # an integration partner pushing to its own endpoint
TOOL = "203.0.113.120"         # sweeps, then logs in at a fixed interval
PARTNER_API = ("10.10.1.13", 9443)


def health_check(src=MONITOR, n=1440, gap=5.0, start=3000.0, seed=1):
    rng = random.Random(seed)
    t, out = sample.T0 + start, []
    for _ in range(n):
        out.append(kit.session(t, src, "10.10.1.10", 443, "SF"))
        t += gap * (1 + rng.uniform(-0.02, 0.02))
    return out


def partner_push(src=PARTNER, minutes=30, per_minute=90, start=15000.0, seed=2):
    rng = random.Random(seed)
    out = []
    for m in range(minutes):
        base = sample.T0 + start + 60 * m
        out += [kit.session(base + rng.uniform(0, 59.9), src, *PARTNER_API, "SF") for _ in range(per_minute)]
    return out


def sweep(src=TOOL, start=20000.0, seed=4):
    """A sweep of 30 hosts x 10 ports, about one a second; the open services answer."""
    rng = random.Random(seed)
    out, t = [], sample.T0 + start
    targets = [(h, p) for h in sample.HOSTS[:30] for p in sample.AGENT_PORTS]
    rng.shuffle(targets)
    for host, port in targets:
        out.append(kit.session(t, src, host, port, "SF" if (host, port) in sample.OPEN else "S0"))
        t += rng.uniform(0.6, 1.4)
    return out, t - sample.T0


class Leads(unittest.TestCase):
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
    def by_source(items):
        return {v["source"]: v for v in items}

    def test_a_health_check_is_a_lead_not_a_flag(self):
        for zeek, firewall in ((True, False), (False, True)):
            with self.subTest(zeek=zeek, firewall=firewall):
                res, md = self.analyze(sample.sessions() + health_check(), zeek, firewall)
                det = res["detection"]
                v = self.by_source(det["steady_sources"])[MONITOR]
                self.assertEqual((v["status"], v["backed_by"]), ("lead", []))
                self.assertIn(f"| {MONITOR} | Lead |", md)
                self.assertEqual([f["source"] for f in det["findings"]], [sample.AGENT])
                entry = next(e for e in summary(res)["flagged"] if e["source"] == MONITOR)
                self.assertTrue(entry["lead"])

    def test_a_busy_integration_is_a_lead_not_a_flag(self):
        for zeek, firewall in ((True, False), (False, True)):
            with self.subTest(zeek=zeek, firewall=firewall):
                res, md = self.analyze(sample.sessions() + partner_push(), zeek, firewall)
                v = self.by_source(res["detection"]["spray_sources"])[PARTNER]
                self.assertEqual((v["status"], v["backed_by"]), ("lead", []))
                self.assertIn(f"| {PARTNER} | Lead |", md)

    def test_a_sweep_backs_a_later_fixed_interval_run(self):
        # the sweep fires signal 1; the brute force starts an hour later, so it is not narrowing
        swept, end = sweep()
        res, md = self.analyze(sample.sessions() + swept + brute(src=TOOL, start=end + 3600))
        det = res["detection"]
        self.assertNotIn(TOOL, [f["source"] for f in det["findings"]])
        v = self.by_source(det["steady_sources"])[TOOL]
        self.assertEqual((v["status"], v["backed_by"]), ("flagged", ["sweep"]))
        self.assertIn(f"| {TOOL} | Flagged: also sweep |", md)

    def test_fixed_interval_and_high_rate_back_each_other_only_on_different_services(self):
        # one fast stream to one service is both, measured twice: still a lead
        res, _ = self.analyze(sample.sessions() + brute(n=600, gap=0.5))
        v = self.by_source(res["detection"]["steady_sources"])[BRUTE]
        self.assertEqual((v["status"], v["backed_by"]), ("lead", []))
        # a fixed-interval run on one service and a flood on another back each other
        res, _ = self.analyze(sample.sessions() + brute() + partner_push(src=BRUTE))
        v = self.by_source(res["detection"]["steady_sources"])[BRUTE]
        self.assertEqual((v["status"], v["backed_by"]), ("flagged", ["high-rate repeated connections"]))

    def test_sweep_then_fixed_interval_logins_is_level_1_with_that_pattern(self):
        # CyberStrikeAI's shape: a sweep, then logins every 1.5 seconds to a service that answered it
        swept, end = sweep()
        logins = brute(src=TOOL, start=end + 60)
        for zeek, firewall in ((True, False), (False, True), (True, True)):
            with self.subTest(zeek=zeek, firewall=firewall):
                res, md = self.analyze(sample.sessions() + swept + logins, zeek, firewall)
                f = self.by_source(res["detection"]["findings"])[TOOL]
                self.assertEqual(f["level"], 1)
                self.assertEqual(f["timing"]["patterns"], ["fixed-interval cadence"])
                self.assertAlmostEqual(f["timing"]["cadence_seconds"], 1.5, delta=0.02)
                self.assertEqual(f["timing"]["cadence_service"], f"{FORTI[0]}:{FORTI[1]}/tcp")
                self.assertEqual(f["timing"]["cadence_whole_seconds"], not zeek)
                self.assertIn("| Timing pattern | fixed-interval cadence |", md)
                self.assertIn("| Cadence interval | one session every 1.5 s to 10.10.1.11:8443/tcp", md)
                self.assertEqual(self.by_source(res["detection"]["findings"])[sample.AGENT]["timing"]["patterns"],
                                 ["burst and pause"])

    def test_fingerprinting_in_turn_at_a_fixed_interval_is_level_1(self):
        # after its sweep the tool steps through six services that answered, one session every 2.0
        # seconds, five each: no one service gets a run of 30, but the source keeps the interval
        swept, end = sweep()
        services = sorted(sample.OPEN - {("10.10.2.15", 25)})
        steps = [kit.session(sample.T0 + end + 60 + 2.0 * i, TOOL, *services[i % 6], "SF") for i in range(30)]
        for zeek, firewall in ((True, False), (False, True)):
            with self.subTest(zeek=zeek, firewall=firewall):
                res, md = self.analyze(sample.sessions() + swept + steps, zeek, firewall)
                f = self.by_source(res["detection"]["findings"])[TOOL]
                self.assertEqual((f["level"], f["timing"]["patterns"]), (1, ["fixed-interval cadence"]))
                self.assertEqual(f["timing"]["cadence_service"], "6 services in turn")
                self.assertIn("| Cadence interval | one session every 2 s to 6 services in turn", md)
        # the same steps with an uneven pace are not a cadence: the source is not flagged
        rng = random.Random(9)
        t, uneven = sample.T0 + end + 60, []
        for i in range(30):
            uneven.append(kit.session(t, TOOL, *services[i % 6], "SF"))
            t += rng.uniform(1.0, 6.0)
        res, _ = self.analyze(sample.sessions() + swept + uneven)
        self.assertNotIn(TOOL, [f["source"] for f in res["detection"]["findings"]])

    def test_cadence_is_never_read_from_elapsed_seconds(self):
        # the same tool from a firewall export with no start time: its start is end minus elapsed,
        # too coarse for a 1.5-second step, so the cadence is not checked, and the report says so
        swept, end = sweep()
        res, _ = self.analyze(sample.sessions() + swept + brute(src=TOOL, start=end + 60),
                              zeek=False, firewall=True, start=False, elapsed=True)
        det = res["detection"]
        self.assertNotIn(TOOL, [f["source"] for f in det["findings"]])
        self.assertNotIn(TOOL, [v["source"] for v in det["steady_sources"]])
        self.assertEqual(self.by_source(det["findings"])[sample.AGENT]["level"], 1)
        self.assertTrue(any("fixed-interval cadence cannot be checked" in w for w in res["warnings"]))

    def test_a_monitor_and_a_client_near_a_plain_sweep_are_a_rotation_lead(self):
        # from Zeek, the monitor and the sample's ordinary client both start within 15 minutes of the
        # plain scanner's sweep and use only services it found: a rotation by the rule, but nothing backs it
        res, md = self.analyze(sample.sessions() + health_check())
        [g] = res["detection"]["rotations"]
        self.assertEqual(g["sweeper"], sample.SCANNER)
        self.assertEqual((g["status"], g["backed_by"]), ("lead", []))
        self.assertIn(f"| {sample.SCANNER} | Lead |", md)

    def test_a_rotation_whose_sweep_is_a_finding_is_flagged(self):
        from tests.test_rotation import PROXIES, proxy
        rng = random.Random(4)
        sessions = sample.sessions()
        first_return = min(s["ts"] for s in sessions if s["src"] == sample.AGENT and s["state"] == "SF"
                           and (s["dst"], s["dport"]) in sample.NARROWED)
        extra = [x for i, ip in enumerate(PROXIES[:2]) for x in proxy(rng, ip, first_return + 60 * (i + 1))]
        res, _ = self.analyze(sessions + extra)
        [g] = res["detection"]["rotations"]
        self.assertEqual((g["status"], g["backed_by"]), ("flagged", ["the sweeping address is a finding"]))

    def test_the_command_line_counts_leads_apart_from_flags(self):
        import io
        from contextlib import redirect_stderr, redirect_stdout

        from pentaiwatch.cli import main
        src = os.path.join(self.tmp.name, "cli")
        os.makedirs(src)
        kit.write_zeek_conn(os.path.join(src, "conn.log"), sample.sessions() + health_check(start=40000))
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            self.assertEqual(main(["analyze", src, "--out", os.path.join(src, "out")]), 0)
        self.assertIn("1 source flagged; 1 lead to look at (not flagged).", out.getvalue())
        self.assertIn(f"{MONITOR}  fixed-interval repetition (lead)", out.getvalue())


if __name__ == "__main__":
    unittest.main()
