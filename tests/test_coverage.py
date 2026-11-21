"""Per-detector coverage: what each detector could check on this data, so a detector that could not
run is never read as a clean bill. Published attacker addresses are context, kept apart from the
behavioural findings."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from pentaiwatch.cli import main
from pentaiwatch.pipeline import run
from tests import kit, sample

TIMING_A = "Timing pattern a: burst and pause"
TIMING_B = "Timing pattern b and fixed-interval repetition"


class Coverage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def folder(self, zeek=True, **pa):
        src = os.path.join(self.tmp.name, f"in{len(os.listdir(self.tmp.name))}")
        os.makedirs(src)
        if zeek:
            kit.write_zeek_conn(os.path.join(src, "conn.log"), sample.sessions())
        else:
            kit.write_paloalto(os.path.join(src, "traffic.csv"), sample.sessions(), **pa)
        return src

    def coverage(self, **kw):
        src = self.folder(**kw)
        res, paths = run([src], os.path.join(src, "out"))
        with open(paths["report.md"], encoding="utf-8") as fh:
            md = fh.read()
        return {r["detector"]: r for r in res["detection"]["coverage"]}, md

    def test_zeek_lets_both_timing_patterns_run(self):
        rows, md = self.coverage()
        n = len(sample.sessions())
        self.assertEqual((rows[TIMING_A]["status"], rows[TIMING_B]["status"]), ("checked", "checked"))
        self.assertTrue(rows[TIMING_B]["detail"].startswith(f"{n:,} of {n:,} sessions"))
        self.assertEqual(rows["Levels 2 and 3 (threat logs)"], {"detector": "Levels 2 and 3 (threat logs)",
                                                               "status": "not checked",
                                                               "detail": "threat logs not provided"})
        self.assertIn("### What could be checked", md)
        self.assertIn(f"| {TIMING_B} | Checked |", md)

    def test_elapsed_seconds_only_cannot_run_pattern_b(self):
        rows, md = self.coverage(zeek=False, start=False, elapsed=True)
        self.assertEqual((rows[TIMING_A]["status"], rows[TIMING_B]["status"]), ("checked", "not checked"))
        self.assertTrue(rows[TIMING_B]["detail"].startswith("0 of "))
        self.assertIn(f"| {TIMING_B} | Not checked | 0 of ", md)

    def test_no_start_time_runs_neither_timing_pattern(self):
        rows, _ = self.coverage(zeek=False, start=False, elapsed=False)
        self.assertEqual((rows[TIMING_A]["status"], rows[TIMING_B]["status"]), ("not checked", "not checked"))
        self.assertEqual(rows["Sweep and narrowing (signals 1 and 2)"]["status"], "checked")

    def test_a_short_capture_cannot_learn_regular_clients(self):
        rows, _ = self.coverage()
        self.assertEqual(rows["Regular clients"]["status"], "checked")        # the sample spans a day
        src = os.path.join(self.tmp.name, "short")
        os.makedirs(src)
        kit.write_zeek_conn(os.path.join(src, "conn.log"),
                            [s for s in sample.sessions() if s["ts"] < sample.T0 + 6 * 3600])
        res, _ = run([src], os.path.join(src, "out"))
        rows = {r["detector"]: r for r in res["detection"]["coverage"]}
        self.assertEqual(rows["Regular clients"]["status"], "not checked")
        self.assertIn("12 or more are needed", rows["Regular clients"]["detail"])

    def test_the_command_line_names_what_was_not_checked(self):
        src = self.folder(zeek=False, start=False, elapsed=True)
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            self.assertEqual(main(["analyze", src, "--out", os.path.join(src, "out")]), 0)
        self.assertIn(f"  not checked: {TIMING_B} (0 of ", out.getvalue())
        self.assertNotIn("Levels 2 and 3", out.getvalue())


if __name__ == "__main__":
    unittest.main()
