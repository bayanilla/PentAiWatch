"""Rotating sources: one address sweeps and new addresses come straight back to what it found, as an
operator rotating through proxies does (CrowdStrike lists nine proxies for one ARTEX operator). Each
address alone stays under the thresholds; together they are one campaign. Checked from Zeek and
from a Palo Alto export, against ordinary visitors and public services that must not tie in."""
import json
import os
import random
import tempfile
import unittest

from pentaiwatch.errors import UserError
from pentaiwatch.pipeline import run
from tests import kit, sample

SWEEPER = "203.0.113.70"
PROXIES = ["101.53.80.20", "205.214.59.31", "124.155.252.63"]


def sweep_only(rng, src=SWEEPER, start=20000.0):
    """The agent's sweep (30 hosts x 10 ports), and nothing after it from this address."""
    out, t = [], sample.T0 + start
    targets = [(h, p) for h in sample.HOSTS[:30] for p in sample.AGENT_PORTS]
    rng.shuffle(targets)
    for host, port in targets:
        out.append(kit.session(t, src, host, port, "SF" if (host, port) in sample.OPEN else "S0"))
        t += rng.uniform(0.6, 1.4)
    return out, t


def proxy(rng, src, t, minutes=40.0, services=None):
    """Bursts to services the sweep found, from an address never seen before."""
    out, end = [], t + minutes * 60
    services = services or sample.NARROWED
    while t < end:
        host, port = rng.choice(services)
        for _ in range(rng.randint(1, 6)):
            out.append(kit.session(t, src, host, port, "SF"))
            t += rng.uniform(0.7, 1.3)
        t += rng.uniform(5, 60)
    return out


def rotation(n_proxies=3, delay=120.0, seed=5, services=None):
    rng = random.Random(seed)
    out, end = sweep_only(rng)
    for i, src in enumerate(PROXIES[:n_proxies]):
        out += proxy(rng, src, end + delay + 60 * i, services=services)
    return out


class Rotating(unittest.TestCase):
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

    def test_a_sweep_and_its_proxies_are_one_campaign_from_each_log(self):
        for zeek, firewall in ((True, False), (False, True)):
            with self.subTest(zeek=zeek, firewall=firewall):
                det, md = self.analyze(sample.sessions() + rotation(), zeek, firewall)
                self.assertEqual([f["source"] for f in det["findings"]], [sample.AGENT])
                [g] = det["rotations"]
                self.assertEqual(g["sweeper"], SWEEPER)
                self.assertFalse(g["flagged"])
                self.assertEqual([j["source"] for j in g["joiners"]], PROXIES)
                self.assertEqual(sorted(g["services"]),
                                 ["10.10.1.10:443/tcp", "10.10.1.11:8443/tcp", "10.10.1.12:11434/tcp"])
                self.assertIn("### Rotating sources", md)
                self.assertIn(f"| {SWEEPER} | ", md)
                self.assertIn("- Rotating sources: 2+ new addresses", md)

    def test_a_flagged_sweep_carries_its_proxies(self):
        rng = random.Random(4)
        sessions = sample.sessions()
        first_return = min(s["ts"] for s in sessions if s["src"] == sample.AGENT and s["state"] == "SF"
                           and (s["dst"], s["dport"]) in sample.NARROWED)
        extra = [x for i, ip in enumerate(PROXIES[:2]) for x in proxy(rng, ip, first_return + 60 * (i + 1))]
        det, md = self.analyze(sessions + extra)
        [g] = det["rotations"]
        self.assertEqual((g["sweeper"], g["flagged"]), (sample.AGENT, True))
        self.assertIn("| Rotating sources | 2 new addresses came straight back to what its sweep found: ", md)
        self.assertIn(f"| {sample.AGENT} (also a finding above) |", md)

    def test_one_proxy_is_not_enough(self):
        det, md = self.analyze(sample.sessions() + rotation(n_proxies=1))
        self.assertEqual(det["rotations"], [])
        self.assertNotIn("### Rotating sources", md)

    def test_addresses_that_arrive_long_after_the_sweep_do_not_join(self):
        det, _ = self.analyze(sample.sessions() + rotation(delay=3600))
        self.assertEqual(det["rotations"], [])

    def test_public_services_never_tie_addresses_together(self):
        # 25 ordinary visitors of the public web site make it public; proxies that only use it don't join
        rng = random.Random(9)
        visitors = [kit.session(sample.T0 + rng.uniform(0, 40000), f"192.0.2.{100 + i}", "10.10.1.20", 443, "SF")
                    for i in range(25) for _ in range(3)]
        web = [("10.10.1.20", 443)]
        det, _ = self.analyze(sample.sessions() + visitors + rotation(services=web))
        self.assertEqual(det["rotations"], [])
        det, _ = self.analyze(sample.sessions() + visitors + rotation(services=web),
                              settings={"rotation": {"max_service_sources": 100}})
        self.assertEqual(len(det["rotations"]), 1)

    def test_the_sample_has_no_rotation(self):
        det, _ = self.analyze(sample.sessions())
        self.assertEqual(det["rotations"], [])

    def test_settings(self):
        det, _ = self.analyze(sample.sessions() + rotation(), settings={"rotation": {"min_joiners": 4}})
        self.assertEqual(det["rotations"], [])
        with self.assertRaises(UserError):
            self.analyze(sample.sessions(), settings={"rotation": {"min_joiners": 0}})


if __name__ == "__main__":
    unittest.main()
