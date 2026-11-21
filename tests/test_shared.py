"""Shared sweeps: several addresses split one sweep between them, each too small to fire the probing
signal, and an address that was quiet before comes back to a service they found. A lead around that
service; flagged only when an address in it is a finding of its own. Ordinary internet scanning,
many addresses trying the same few ports, does not split anything and is not one."""
import json
import os
import random
import tempfile
import unittest

from pentaiwatch import config
from pentaiwatch.errors import UserError
from pentaiwatch.pipeline import run
from tests import kit, sample

PROXIES = [f"192.0.2.{i}" for i in range(101, 113)]       # twelve addresses, sixteen probes each
RETURNER = "198.51.100.150"
FORTI = ("10.10.1.11", 8443)
START = 30000.0


def split_sweep(start=START, seed=5, proxies=PROXIES, overlap=False):
    """Each proxy takes its own sixteen of 10.10.1.10-29 x ten ports (shared ones when ``overlap``),
    about one probe every 3 seconds, all of them at once."""
    rng = random.Random(seed)
    targets = [(h, p) for h in sample.HOSTS[:20] for p in sample.AGENT_PORTS]
    rng.shuffle(targets)
    out, end = [], 0.0
    for i, src in enumerate(proxies):
        mine = targets[:16] if overlap else targets[16 * i:16 * (i + 1)]
        t = sample.T0 + start + rng.uniform(0, 5)
        for host, port in mine:
            out.append(kit.session(t, src, host, port, "SF" if (host, port) in sample.OPEN else "S0"))
            t += rng.uniform(2, 4)
        end = max(end, t)
    return out, end - sample.T0


def comes_back(src=RETURNER, start=0.0, n=8):
    return [kit.session(sample.T0 + start + 15 * i, src, *FORTI, "SF") for i in range(n)]


class SharedSweeps(unittest.TestCase):
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

    def test_a_split_sweep_and_a_new_address_coming_back_is_a_lead(self):
        swept, end = split_sweep()
        sessions = sample.sessions() + swept + comes_back(start=end + 120)
        for firewall in (False, True):
            with self.subTest(firewall=firewall):
                res, md = self.analyze(sessions, firewall=firewall)
                det = res["detection"]
                self.assertEqual(det["probing_sources"], 2)          # none of the proxies fires on its own
                [g] = det["shared_sweeps"]
                self.assertEqual((g["network"], g["sweepers"], g["status"]), ("10.10.1.0/24", sorted(PROXIES), "lead"))
                self.assertEqual(g["services_probed"], 192)
                [r] = g["returns"]
                self.assertEqual((r["service"], r["sources"], r["answered"]), ("10.10.1.11:8443/tcp", [RETURNER], 8))
                self.assertNotIn(RETURNER, [f["source"] for f in det["findings"]])
                self.assertIn("### Shared sweeps", md)
                self.assertIn("| 10.10.1.11:8443/tcp | Lead | 12 addresses", md)

    def test_ordinary_scanning_of_the_same_ports_is_not_a_shared_sweep(self):
        swept, end = split_sweep(overlap=True)
        res, _ = self.analyze(sample.sessions() + swept + comes_back(start=end + 120))
        self.assertEqual(res["detection"]["shared_sweeps"], [])

    def test_an_address_that_was_already_using_the_service_is_not_coming_back(self):
        swept, end = split_sweep()
        before = comes_back(start=START - 1800, n=3)                 # half an hour before the sweep
        res, _ = self.analyze(sample.sessions() + before + swept + comes_back(start=end + 120))
        self.assertEqual(res["detection"]["shared_sweeps"], [])

    def test_coming_back_too_late_or_too_little_is_not_one(self):
        swept, end = split_sweep()
        for extra in (comes_back(start=end + 3600), comes_back(start=end + 120, n=4)):
            res, _ = self.analyze(sample.sessions() + swept + extra)
            self.assertEqual(res["detection"]["shared_sweeps"], [])

    def test_two_addresses_are_not_enough(self):
        swept, end = split_sweep(proxies=PROXIES[:2])
        res, _ = self.analyze(sample.sessions() + swept + comes_back(start=end + 120))
        self.assertEqual(res["detection"]["shared_sweeps"], [])

    def test_it_is_flagged_when_an_address_in_it_is_a_finding(self):
        # the proxies split a sweep just before the agent starts; the agent then comes back to what
        # they found as part of its own work, and its own finding backs the shared sweep
        swept, _ = split_sweep(start=500)
        res, _ = self.analyze(sample.sessions() + swept, settings={"rotation": {"quiet_before_hours": 0.05}})
        [g] = res["detection"]["shared_sweeps"]
        self.assertEqual((g["status"], g["backed_by"]), ("flagged", [f"{sample.AGENT} is a finding"]))
        self.assertIn(sample.AGENT, {ip for r in g["returns"] for ip in r["sources"]})

    def test_it_can_be_turned_off_and_is_checked(self):
        swept, end = split_sweep()
        res, md = self.analyze(sample.sessions() + swept + comes_back(start=end + 120),
                               settings={"shared_sweep": {"check": False}})
        self.assertEqual(res["detection"]["shared_sweeps"], [])
        self.assertIn("- Shared sweeps: not checked", md)
        cfg = config.Config()
        cfg.shared_sweep.min_sources = 1
        with self.assertRaises(UserError):
            config.check(cfg)


if __name__ == "__main__":
    unittest.main()
