"""MITRE ATT&CK and ATLAS labels: every detector in the coverage table has a row in frameworks.csv,
the report shows them, and they change nothing about what is found."""
import json
import os
import tempfile
import unittest

from pentaiwatch import frameworks
from pentaiwatch.config import Config
from pentaiwatch.pipeline import run
from tests import kit, sample


class Frameworks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def analyze(self, settings=None):
        src = os.path.join(self.tmp.name, f"in{len(os.listdir(self.tmp.name))}")
        os.makedirs(src)
        kit.write_zeek_conn(os.path.join(src, "conn.log"), sample.sessions())
        if settings:
            with open(os.path.join(src, "pentaiwatch.json"), "w", encoding="utf-8") as fh:
                json.dump(settings, fh)
        res, paths = run([src], os.path.join(src, "out"))
        with open(paths["report.md"], encoding="utf-8") as fh:
            md = fh.read()
        with open(paths["report.html"], encoding="utf-8") as fh:
            return res["detection"], md, fh.read()

    def test_the_file_is_well_formed_and_covers_every_detector(self):
        labels = frameworks.labels()
        self.assertEqual(sorted(labels), sorted(frameworks.DETECTORS))
        for key, rows in labels.items():
            self.assertTrue(rows or frameworks.reasons().get(key), key)
            for lab in rows:
                self.assertIn(lab["framework"], frameworks.FRAMEWORKS)
                self.assertIn(lab["fit"], frameworks.FITS)
                self.assertEqual(lab["id"].startswith("AML."), lab["framework"] == "atlas", lab)
        self.assertEqual(frameworks.url("attack", "T1595.001"), "https://attack.mitre.org/techniques/T1595/001/")
        self.assertEqual(frameworks.url("atlas", "AML.T0116"), "https://atlas.mitre.org/techniques/AML.T0116")
        # whether an agent chose the step is never in a log: no ATLAS label about autonomy claims to be direct
        for key in ("sweep", "burst_pause", "shared_sweep", "watched_names"):
            self.assertEqual({lab["fit"] for lab in labels[key] if lab["framework"] == "atlas"}, {"possible"})

    def test_every_coverage_row_is_a_known_detector_with_every_check_on_or_off(self):
        off = {name: {"check": False} for name in ("login_spray", "shared_sweep", "baseline", "nonstop", "web",
                                                    "beacon", "outbound")}
        self.assertTrue(set(off) <= set(Config().settings()))
        for settings in (None, off):
            det, _, _ = self.analyze(settings)
            for row in det["coverage"]:
                keys = frameworks.keys_for(row["detector"])
                self.assertTrue(keys or row["detector"] in frameworks.NOT_DETECTORS, row["detector"])
                self.assertEqual(row["techniques"], frameworks.ids_for(row["detector"]))

    def test_the_report_shows_the_labels_and_the_finding_is_what_it_was(self):
        det, md, page = self.analyze()
        [f] = det["findings"]
        self.assertEqual((f["source"], f["level"]), (sample.AGENT, 1))
        rows = {r["detector"]: r["techniques"] for r in det["coverage"]}
        self.assertEqual(rows["Sweep and narrowing (signals 1 and 2)"], ["T1595", "T1595.001", "AML.T0116"])
        self.assertEqual(rows["Repeated failed-login pattern"], ["T1110.003"])
        self.assertEqual(rows["Regular clients"], [])
        self.assertTrue("| MITRE techniques | T1595 Active Scanning (ATT&CK); T1595.001 Scanning IP Blocks (ATT&CK); "
                        "AML.T0116 Autonomous Reconnaissance (ATLAS, possible); "
                        "AML.T0117 Autonomous Attack-Path Adaptation (ATLAS, possible) |" in md)
        self.assertTrue("### MITRE ATT&CK and ATLAS labels" in md)
        self.assertTrue("| Repeated failed-login pattern | T1110.003 Password Spraying (ATT&CK) | Credential Access "
                        "| Direct |" in md)
        self.assertTrue("| No overnight break | none | | | Extra evidence" in md)
        self.assertTrue("ATT&amp;CK" in page and "AML.T0117" in page)
        self.assertFalse("mitre.org" in page)             # the report never links outside the run


if __name__ == "__main__":
    unittest.main()
