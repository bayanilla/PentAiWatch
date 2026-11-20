"""Scoped, expiring authorizations in known_scanners.csv. A row with only an address and a name still
leaves the source out of the scoring. A row with an owner, an expiry or a scope is scored like any
other source: what it does inside its scope and before it expires is listed as authorized, not
flagged; anything outside its scope or after it expires is flagged as usual, with a note."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone

from pentaiwatch import scanners
from pentaiwatch.cli import main
from pentaiwatch.errors import UserError
from pentaiwatch.pipeline import run
from pentaiwatch.web.jobs import summary
from tests import kit, sample
from tests.test_leads import MONITOR, health_check

START = datetime.fromtimestamp(sample.T0, timezone.utc)
LATER = (START + timedelta(days=30)).strftime("%Y-%m-%d")
EARLIER = (START - timedelta(days=1)).strftime("%Y-%m-%d")
HEADER = "address,name,owner,expires,scope\n"


class Authorized(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def folder(self, listing, sessions=None):
        src = os.path.join(self.tmp.name, f"in{len(os.listdir(self.tmp.name))}")
        os.makedirs(src)
        kit.write_zeek_conn(os.path.join(src, "conn.log"), sessions or sample.sessions())
        with open(os.path.join(src, "known_scanners.csv"), "w", encoding="utf-8") as fh:
            fh.write(listing)
        return src

    def analyze(self, listing, sessions=None):
        src = self.folder(listing, sessions)
        res, paths = run([src], os.path.join(src, "out"))
        with open(paths["report.md"], encoding="utf-8") as fh:
            return res, fh.read()

    def test_a_plain_row_still_leaves_the_source_out(self):
        res, _ = self.analyze(f"{sample.AGENT},Our red team\n")
        det = res["detection"]
        self.assertEqual((det["findings"], det["authorized"]), ([], []))
        self.assertEqual(det["never_flagged_sources"], 1)

    def test_an_authorized_test_in_scope_and_in_time_is_listed_not_flagged(self):
        res, md = self.analyze(HEADER + f"{sample.AGENT},Q4 pentest,Acme Security,{LATER},10.10.0.0/16\n")
        det = res["detection"]
        self.assertEqual(det["findings"], [])
        self.assertEqual(det["never_flagged_sources"], 0)
        [a] = det["authorized"]
        self.assertEqual((a["source"], a["name"], a["owner"], a["scope"], a["behaviours"]),
                         (sample.AGENT, "Q4 pentest", "Acme Security", ["10.10.0.0/16"], ["Level 1 finding"]))
        self.assertTrue(a["expires"].startswith(LATER))
        self.assertIn("### Authorized activity", md)
        self.assertIn(f"| {sample.AGENT} | Q4 pentest | Acme Security |", md)
        self.assertIn("- Authorized (scored, and not flagged while in scope and before expiry): 203.0.113.50/32 "
                      "Q4 pentest, owner Acme Security", md)
        entry = next(e for e in summary(res)["flagged"] if e["source"] == sample.AGENT)
        self.assertEqual((entry["tag"], entry["authorized"]), ("Authorized", True))

    def test_after_it_expired_the_source_is_flagged_with_a_note(self):
        res, md = self.analyze(HEADER + f"{sample.AGENT},Q3 pentest,Acme Security,{EARLIER},\n")
        [f] = [f for f in res["detection"]["findings"] if f["source"] == sample.AGENT]
        self.assertEqual(f["level"], 1)
        self.assertIn("began after it expired", f["authorization"])
        self.assertIn("so it is flagged as usual", md)
        self.assertEqual(res["detection"]["authorized"], [])

    def test_outside_its_scope_the_source_is_flagged_with_a_note(self):
        res, _ = self.analyze(HEADER + f"{sample.AGENT},Web test,Acme Security,,10.10.1.10 10.10.1.11\n")
        [f] = [f for f in res["detection"]["findings"] if f["source"] == sample.AGENT]
        self.assertIn("went to hosts outside its scope", f["authorization"])
        self.assertIn("Authorized in known_scanners.csv as Web test (Acme Security)", " ".join(f["notes"]))

    def test_a_lead_can_be_authorized_too(self):
        res, _ = self.analyze(f"{MONITOR},Uptime checks,NOC\n", sample.sessions() + health_check())
        det = res["detection"]
        self.assertNotIn(MONITOR, [v["source"] for v in det["steady_sources"]])
        self.assertEqual([(a["source"], a["behaviours"]) for a in det["authorized"]],
                         [(MONITOR, ["fixed-interval repetition"])])

    def test_the_command_line_counts_authorized_sources_apart(self):
        src = self.folder(HEADER + f"{sample.AGENT},Q4 pentest,Acme Security,{LATER},\n")
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            self.assertEqual(main(["analyze", src, "--out", os.path.join(src, "out")]), 0)
        self.assertIn("0 sources flagged; 1 authorized source (not flagged).", out.getvalue())
        self.assertIn(f"{sample.AGENT}  authorized: Q4 pentest (Acme Security), would have been Level 1 finding",
                      out.getvalue())


class Reading(unittest.TestCase):
    def read(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as fh:
            fh.write(text)
        self.addCleanup(os.unlink, fh.name)
        return scanners.read(fh.name)

    def test_columns_by_header_or_by_position(self):
        [a] = self.read("ip,scope,expires,name\n203.0.113.7,10.50.1.0/24;10.50.2.10,2026-12-15,Pentest\n")
        self.assertEqual((a["name"], a["owner"], a["expires"], a["scope"]),
                         ("Pentest", "", "2026-12-15T23:59:59Z", ["10.50.1.0/24", "10.50.2.10/32"]))
        self.assertTrue(scanners.is_authorization(a))
        [b] = self.read("10.20.0.15,Nessus\n")
        self.assertEqual(b, {"cidr": "10.20.0.15/32", "name": "Nessus", "owner": "", "expires": "", "scope": []})
        self.assertFalse(scanners.is_authorization(b))
        [c] = self.read("203.0.113.7,Pentest,Acme,2026-12-15T18:00:00+02:00\n")
        self.assertEqual(c["expires"], "2026-12-15T16:00:00Z")

    def test_bad_dates_and_scopes_name_the_line(self):
        with self.assertRaisesRegex(UserError, "line 2: expires: 'next week'"):
            self.read("address,name,owner,expires\n203.0.113.7,Pentest,Acme,next week\n")
        with self.assertRaisesRegex(UserError, "line 1: scope: 'web01'"):
            self.read("203.0.113.7,Pentest,Acme,,web01\n")


if __name__ == "__main__":
    unittest.main()
