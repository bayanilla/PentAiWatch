"""Named targets: the kinds of service the ARTEX and CyberStrikeAI reporting names (edge-device
consoles and VPNs, AI model gateways, databases, remote access) are named by port on a finding, its
services, its fixed-interval runs and published-address entries, from either log, and the setting
can add, replace and drop names. Naming never changes what is flagged."""
import json
import os
import tempfile
import unittest

from pentaiwatch import config
from pentaiwatch.errors import UserError
from pentaiwatch.pipeline import run
from tests import kit, sample
from tests.test_steady import BRUTE, brute


class Targets(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def analyze(self, sessions, zeek=True, firewall=False, settings=None, known_bad=None):
        src = os.path.join(self.tmp.name, f"in{len(os.listdir(self.tmp.name))}")
        os.makedirs(src)
        if zeek:
            kit.write_zeek_conn(os.path.join(src, "conn.log"), sessions)
        if firewall:
            kit.write_paloalto(os.path.join(src, "traffic.csv"), sessions)
        if settings is not None:
            with open(os.path.join(src, "pentaiwatch.json"), "w", encoding="utf-8") as fh:
                json.dump(settings, fh)
        if known_bad:
            with open(os.path.join(src, "known_bad.csv"), "w", encoding="utf-8") as fh:
                fh.write("address,name\n" + "".join(f"{ip},test entry\n" for ip in known_bad))
        res, paths = run([src], os.path.join(src, "out"))
        with open(paths["report.md"], encoding="utf-8") as fh:
            return res, fh.read()

    def test_a_finding_names_its_targets_from_each_log(self):
        for zeek, firewall in ((True, False), (False, True)):
            with self.subTest(zeek=zeek, firewall=firewall):
                res, md = self.analyze(sample.sessions(), zeek, firewall)
                [f] = res["detection"]["findings"]
                self.assertEqual(sorted(f["targets"]), ["AI model gateway", "Edge device admin or VPN"])
                kinds = {s["port"]: s["target"] for s in f["services"]}
                self.assertEqual(kinds, {443: "", 8443: "Edge device admin or VPN", 11434: "AI model gateway"})
                self.assertIn("| Named targets | ", md)
                self.assertIn("| 10.10.1.12 11434/tcp | AI model gateway |", md)
                self.assertIn("- Named targets: Edge device admin or VPN (ports 541, 4443", md)

    def test_naming_changes_nothing_that_is_flagged(self):
        plain, _ = self.analyze(sample.sessions())
        none, md = self.analyze(sample.sessions(), settings={"targets": {name: [] for name in config.DEFAULT_TARGETS}})
        self.assertEqual([f["source"] for f in none["detection"]["findings"]],
                         [f["source"] for f in plain["detection"]["findings"]])
        self.assertEqual(none["detection"]["findings"][0]["targets"], [])
        self.assertNotIn("| Named targets |", md)
        self.assertIn("- Named targets: none.", md)

    def test_your_names_are_added_and_replace_defaults(self):
        res, md = self.analyze(sample.sessions(), settings={"targets": {
            "AI model gateway": [], "Inference API": [11434], "Backup console": [9392]}})
        st = res["settings"]["targets"]
        self.assertNotIn("AI model gateway", st)
        self.assertEqual(st["Inference API"], [11434])
        self.assertIn("Edge device admin or VPN", st)
        [f] = res["detection"]["findings"]
        self.assertIn("Inference API", f["targets"])

    def test_steady_runs_and_published_addresses_name_their_targets(self):
        res, md = self.analyze(sample.sessions() + brute(start=9000) + brute(n=10, src="198.51.100.151", start=12000),
                               known_bad=["198.51.100.151"])
        det = res["detection"]
        [steady] = det["steady_sources"]
        self.assertEqual(steady["source"], BRUTE)
        self.assertEqual(steady["runs"][0]["target"], "Edge device admin or VPN")
        [known] = det["known_sources"]
        self.assertEqual(known["targets"], ["Edge device admin or VPN"])
        self.assertIn("; named targets: Edge device admin or VPN |", md)
        self.assertIn("10.10.1.11:8443/tcp (Edge device admin or VPN): 120 sessions", md)

    def test_bad_settings_are_refused(self):
        for targets, words in (({"Database": [70000]}, "is not a port number"),
                               ({"Database": ["3306"]}, "must be a list of port numbers"),
                               ({"Mine": [3306]}, "is in both 'Database' and 'Mine'"),
                               ({"Database": True}, "must be a list of port numbers")):
            with self.subTest(targets=targets), self.assertRaises(UserError) as cm:
                path = os.path.join(self.tmp.name, "pentaiwatch.json")
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump({"targets": targets}, fh)
                config.read(path)
            self.assertIn(words, str(cm.exception))


if __name__ == "__main__":
    unittest.main()
