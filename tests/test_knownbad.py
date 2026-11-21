"""Published attacker addresses (knownbad.py): the bundled list, your own known_bad.csv, and how a
source on a list is flagged whatever its traffic looked like."""
import csv
import json
import os
import tempfile
import unittest

from pentaiwatch import knownbad
from pentaiwatch.errors import UserError
from pentaiwatch.pipeline import run
from tests import kit, sample

LISTED = "31.40.205.155"          # in the bundled list (Unit 42, 2026-10-30)


def visits(src, n=6, port=443, host="10.10.1.10", start=5000):
    return [kit.session(sample.T0 + start + i * 7, src, host, port, "SF") for i in range(n)]


class Lists(unittest.TestCase):
    def test_bundled_list_loads_and_names_its_sources(self):
        entries = knownbad.bundled()
        self.assertGreater(len(entries), 50)
        hit = knownbad.KnownBad(entries).match(LISTED)
        self.assertIn("Unit 42", hit["name"])
        self.assertEqual(hit["list_name"], "bundled list")
        self.assertTrue(all(e["confidence"] in knownbad.CONFIDENCE for e in entries))
        # the November 2026 reports: Cairn (Unit 42, AWS), CyberStrikeAI (Elastic), ARTEX (SentinelOne)
        lists = knownbad.KnownBad(entries)
        for ip, who, confidence in (("154.44.31.4", "Cairn", "high"), ("142.4.107.34", "AWS", "medium"),
                                    ("43.240.29.11", "CyberStrikeAI", "high"), ("157.22.126.128", "SentinelOne", "low")):
            hit = lists.match(ip)
            self.assertIn(who, hit["name"])
            self.assertEqual(hit["confidence"], confidence)
        self.assertIsNone(lists.match("199.19.77.18"))       # published as a Tor exit node: left out
        # a published "first-last" range becomes CIDR ranges that cover exactly it
        lists = knownbad.KnownBad(entries)
        self.assertIsNotNone(lists.match("38.11.173.1"))
        self.assertIsNotNone(lists.match("38.11.173.125"))
        self.assertIsNone(lists.match("38.11.173.126"))

    def test_the_addresses_collected_on_21_november_2026_keep_the_publishers_own_caution(self):
        lists = knownbad.KnownBad(knownbad.bundled())
        for ip, who, confidence in (("141.148.43.50", "Fireworks AI incident: attacker egress IP", "medium"),
                                    ("136.144.242.56", "Anthropic", "high"),
                                    ("176.65.144.71", "may be in legitimate use (JPCERT/CC case E)", "low"),
                                    ("104.238.38.202", "commercial proxy server (Unit 42)", "low"),
                                    ("2001:bc8:711:5854:dc00:1ff:fe18:ba53", "Anthropic", "high"),
                                    ("139.180.197.150", "Cisco Talos", "high")):
            hit = lists.match(ip)
            self.assertIn(who, hit["name"])
            self.assertEqual(hit["confidence"], confidence)
        # every row of the collected file is in the bundled list, and whatever says proxy is low
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "scripts", "known_bad", "reports_2026_11.csv")
        with open(path, encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 108)
        for r in rows:
            self.assertEqual(lists.match(r["address"])["reference"], r["reference"], r["address"])
            self.assertTrue(r["reference"].startswith("https://"))
            if "proxy" in r["name"].lower():
                self.assertEqual(r["confidence"], "low", r["address"])
        # read only in someone else's collection, or on a page that could not be read in full: left out
        for ip in ("103.142.140.158", "118.107.47.11", "47.79.4.33", "102.216.154.102"):
            self.assertIsNone(lists.match(ip))

    def test_your_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "known_bad.csv")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("# ours\naddress,name,confidence,reference\n203.0.113.0/28,Incident 7,HIGH,ticket 1\n"
                         "198.51.100.7\n192.0.2.1-192.0.2.2,,maybe,\n\n")
            got = knownbad.read(path)
            self.assertEqual([e["cidr"] for e in got], ["203.0.113.0/28", "198.51.100.7/32", "192.0.2.1/32", "192.0.2.2/32"])
            self.assertEqual((got[0]["confidence"], got[0]["reference"], got[0]["list_name"]), ("high", "ticket 1", "known_bad.csv"))
            self.assertEqual(got[2]["confidence"], "")          # not one of high / medium / low
            with open(path, "a", encoding="utf-8") as fh:
                fh.write("not-an-address,x\n")
            with self.assertRaisesRegex(UserError, "known_bad.csv line 7: 'not-an-address'"):
                knownbad.read(path)

    def test_most_specific_then_yours_wins(self):
        lists = knownbad.KnownBad([{"cidr": "203.0.113.0/24", "name": "wide", "list_name": "a"},
                                   {"cidr": "203.0.113.5/32", "name": "narrow", "list_name": "a"},
                                   {"cidr": "203.0.113.5/32", "name": "yours", "list_name": "b"}])
        self.assertEqual(lists.match("203.0.113.5")["name"], "yours")
        self.assertEqual(lists.match("203.0.113.9")["name"], "wide")
        self.assertIsNone(lists.match("not an ip"))


class Detection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def analyze(self, sessions, files=None, **kw):
        src = os.path.join(self.tmp.name, f"in{len(os.listdir(self.tmp.name))}")
        os.makedirs(src)
        kit.write_zeek_conn(os.path.join(src, "conn.log"), sessions)
        for name, text in (files or {}).items():
            with open(os.path.join(src, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        res, paths = run([src], os.path.join(src, "out"), **kw)
        with open(paths["report.md"], encoding="utf-8") as fh:
            return res, fh.read()

    def test_a_listed_source_is_flagged_on_sight(self):
        res, md = self.analyze(sample.sessions() + visits(LISTED))
        det = res["detection"]
        self.assertEqual([f["source"] for f in det["findings"]], [sample.AGENT])
        self.assertIsNone(det["findings"][0]["known"])
        [k] = det["known_sources"]
        self.assertEqual((k["source"], k["sessions"], k["answered"], k["hosts"]), (LISTED, 6, 6, 1))
        self.assertEqual(k["services"], ["10.10.1.10:443/tcp"])
        self.assertIn("## Context: published attacker addresses", md)
        self.assertLess(md.index("### Known limitations"), md.index("## Context: published attacker addresses"))
        self.assertIn(f"| {LISTED} | ARTEX: primary origin", md)
        self.assertIn("Flagged on sight: the bundled list", md)

    def test_a_flagged_agent_on_your_list_carries_its_entry(self):
        res, md = self.analyze(sample.sessions(), {"known_bad.csv": f"{sample.AGENT},Our incident 7,high,ticket 1\n"})
        [f] = res["detection"]["findings"]
        self.assertEqual(f["known"]["name"], "Our incident 7")
        self.assertEqual(res["detection"]["known_sources"], [])
        self.assertIn("| Published attacker address | Our incident 7 (known_bad.csv, high confidence); ticket 1 |", md)
        self.assertIn("known attacker addresses", md)                    # named under Read from
        self.assertEqual([i for i in res["inputs"] if i["file"].endswith("known_bad.csv")], [])   # not read as a log
        self.assertEqual(res["known_bad_lists"]["yours"], 1)

    def test_the_allowlist_wins_and_says_so(self):
        res, _ = self.analyze(sample.sessions() + visits(LISTED),
                              {"pentaiwatch.json": json.dumps({"allowlist": [LISTED]})})
        self.assertEqual(res["detection"]["known_sources"], [])
        self.assertTrue(any("also on your allowlist" in w and LISTED in w for w in res["warnings"]))

    def test_the_bundled_list_can_be_turned_off(self):
        res, md = self.analyze(sample.sessions() + visits(LISTED),
                               {"pentaiwatch.json": json.dumps({"known_bad_bundled": False})})
        self.assertEqual(res["detection"]["known_sources"], [])
        self.assertIn("Flagged on sight: no list of attacker addresses", md)

    def test_an_internal_address_is_never_matched(self):
        res, _ = self.analyze(sample.sessions(), {"known_bad.csv": "10.10.1.0/24,oops\n"})
        self.assertEqual(res["detection"]["known_sources"], [])

    def test_command_line_file(self):
        path = os.path.join(self.tmp.name, "mine.csv")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("198.51.100.200,Partner feed\n")
        res, _ = self.analyze(sample.sessions() + visits("198.51.100.200"), known_bad=path)
        self.assertEqual([k["name"] for k in res["detection"]["known_sources"]], ["Partner feed"])


if __name__ == "__main__":
    unittest.main()
