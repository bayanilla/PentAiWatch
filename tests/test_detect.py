"""The three signals from Zeek conn.log, end to end into the report. (Timing has tests of its own in
test_timing.py.)"""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from pentaiwatch import config, engine
from pentaiwatch.cli import main
from pentaiwatch.config import Config
from pentaiwatch.detect import LEVEL_1, detect
from pentaiwatch.errors import MissingField, UserError
from pentaiwatch.load import load
from pentaiwatch.pipeline import run
from tests import kit, sample


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def path(self, name):
        return os.path.join(self.dir, name)

    @staticmethod
    def read(path):
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def detect(self, sessions, cfg=None):
        ds = load([kit.write_zeek_conn(self.path("conn.log"), sessions)], workdir=self.dir)
        self.addCleanup(ds.close)
        return detect(ds.flow_con(), cfg or Config())


class ThreeSourceTests(Base):
    def test_only_the_agentic_source_is_flagged(self):
        got = self.detect(sample.sessions())
        self.assertEqual([f.source for f in got.findings], [sample.AGENT])
        f = got.findings[0]
        self.assertEqual((f.level, f.label), (1, LEVEL_1))
        self.assertEqual(f.log_sources, ["zeek"])
        self.assertEqual(list(f.start_times), ["zeek_ts"])
        self.assertEqual((f.services_probed, f.hosts_probed, f.ports_probed), (300, 30, 10))
        self.assertGreaterEqual(f.failed_share, 0.7)
        self.assertEqual({(s.host, s.port) for s in f.services}, set(sample.NARROWED))
        self.assertEqual(f.hosts_hit, sorted({h for h, _ in sample.NARROWED}))
        self.assertLess(f.probe_start, f.narrowing_start)
        # the scanner swept (signal 1) but never narrowed; the client did neither
        self.assertEqual((got.probing_sources, got.narrowing_sources), (2, 1))
        self.assertEqual(got.outside_sources, 3)

    def test_zeek_only_finding_says_threat_logs_not_provided(self):
        f = self.detect(sample.sessions()).findings[0]
        self.assertEqual(f.threat_evidence, "threat logs not provided")

    def test_campaign_that_pauses_an_hour_and_resumes_is_one_finding(self):
        got = self.detect(sample.sessions(pause_at=2.0, pause_hours=1.0))
        self.assertEqual([f.source for f in got.findings], [sample.AGENT])
        self.assertGreater(got.findings[0].campaign_hours, 5.0)

    def test_sweep_across_a_window_edge_still_fires(self):
        # move the sample so the agent's sweep starts two minutes before a two-hour boundary
        sweep_start = sample.T0 + 600
        shift = (7200 - sweep_start % 7200) - 120
        got = self.detect(sample.sessions(shift=shift))
        self.assertEqual([f.source for f in got.findings], [sample.AGENT])
        self.assertEqual(got.findings[0].services_probed, 300)

    def test_same_input_gives_the_same_findings(self):
        a = self.detect(sample.sessions()).to_dict()
        b = self.detect(sample.sessions()).to_dict()
        self.assertEqual(a, b)


class SettingsTests(Base):
    def test_allowlisted_source_is_never_flagged(self):
        got = self.detect(sample.sessions(), Config(allowlist=[sample.AGENT + "/32"]))
        self.assertEqual(got.findings, [])

    def test_known_scanners_file_entry_is_never_flagged(self):
        cfg = Config()
        cfg.known_scanners = [{"cidr": "203.0.113.0/24", "name": "Our red team"}]
        self.assertEqual(self.detect(sample.sessions(), cfg).findings, [])

    def test_thresholds_come_from_settings(self):
        cfg = Config()
        cfg.narrowing.min_sessions_per_service = 5000
        self.assertEqual(self.detect(sample.sessions(), cfg).findings, [])
        cfg = Config()
        cfg.probing.min_ports, cfg.probing.min_hosts = 500, 500
        got = self.detect(sample.sessions(), cfg)
        self.assertEqual((got.findings, got.probing_sources), ([], 0))

    def test_zeek_state_lists_come_from_settings(self):
        cfg = Config()
        cfg.probing.zeek_failed_states = ["RSTR"]          # the sample's sweep fails with S0 and REJ
        self.assertEqual(self.detect(sample.sessions(), cfg).probing_sources, 0)

    def test_network_map_ranges_count_as_internal(self):
        moved = [dict(s, dst=s["dst"].replace("10.10.", "172.31.")) for s in sample.sessions()]
        cfg = Config(internal_nets=["192.168.0.0/16"])
        got = self.detect(moved, cfg)
        self.assertEqual(got.findings, [])
        self.assertIn("internal_nets", got.warnings[0])
        cfg.networks = [{"cidr": "172.31.0.0/16", "name": "Cloud", "type": "aws", "cloud": True}]
        got = self.detect(moved, cfg)
        self.assertEqual([f.source for f in got.findings], [sample.AGENT])
        self.assertEqual({s.network for s in got.findings[0].services}, {"Cloud"})

    def test_lookback_leaves_out_older_sessions(self):
        late = kit.session(sample.T0 + 80 * 3600, sample.CLIENT, "10.10.1.20", 443, "SF")
        got = self.detect(sample.sessions() + [late], Config(lookback_hours=24))
        self.assertEqual(got.findings, [])
        self.assertEqual(got.inbound_sessions, 1)
        # what the lookback left out is said, never dropped quietly
        self.assertIn(f"{len(sample.sessions()):,} session(s) are older than the 24-hour lookback", got.warnings[0])

    def test_settings_file(self):
        p = self.path("pentaiwatch.json")
        with open(p, "w") as fh:
            json.dump({"lookback_hours": 48, "allowlist": ["198.51.100.0/28"],
                       "probing": {"min_ports": 80}}, fh)
        cfg = config.read(p)
        self.assertEqual((cfg.lookback_hours, cfg.probing.min_ports, cfg.probing.min_hosts), (48, 80, 20))
        self.assertEqual(cfg.allowlist, ["198.51.100.0/28"])

    def test_settings_file_refuses_what_it_does_not_know(self):
        for body, message in (({"probing": {"min_port": 80}}, "probing.min_port"),
                              ({"lookback_hours": "two days"}, "must be a number"),
                              ({"allowlist": ["not-an-address"]}, "not an address"),
                              ({"probing": {"min_failed_share": 70}}, "between 0 and 1")):
            p = self.path("pentaiwatch.json")
            with open(p, "w") as fh:
                json.dump(body, fh)
            with self.assertRaisesRegex(UserError, message):
                config.read(p)


class DataQualityTests(Base):
    def test_conn_log_without_conn_state_fails_with_a_clear_message(self):
        p = kit.write_zeek_conn(self.path("conn.log"), sample.sessions()[:20])
        with open(p) as fh:
            text = fh.read().replace("conn_state", "state_removed")
        with open(p, "w") as fh:
            fh.write(text)
        with self.assertRaisesRegex(MissingField, r"conn\.log: .*conn_state"):
            load([p], workdir=self.dir)

    def test_untimed_sessions_are_left_out_with_a_warning(self):
        p = kit.write_zeek_conn(self.path("conn.log"), sample.sessions())
        with open(p) as fh:
            lines = fh.read().split("\n")
        lines[10] = "-" + lines[10][lines[10].index("\t"):]          # one record with no ts
        with open(p, "w") as fh:
            fh.write("\n".join(lines))
        ds = load([p], workdir=self.dir)
        self.addCleanup(ds.close)
        got = detect(ds.flow_con(), Config())
        self.assertIn("1 session(s) had no readable time", got.warnings[0])
        self.assertEqual([f.source for f in got.findings], [sample.AGENT])


class EngineTests(unittest.TestCase):
    """A faulty DuckDB does not crash, it quietly finds nothing, so known-bad versions are refused."""

    def test_versions_that_cannot_be_trusted_are_refused(self):
        with self.assertRaisesRegex(UserError, "drops matching rows"):
            engine.check("1.3.0")
        with self.assertRaisesRegex(UserError, "too old"):
            engine.check("1.1.3")

    def test_good_versions_pass(self):
        for text in ("1.2.0", "1.3.1", "1.5.6", "1.4.0.dev12", "2.0.0"):
            engine.check(text)
        engine.check()                                   # the version installed here

    def test_requirements_exclude_what_the_check_refuses(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "requirements.txt"), encoding="utf-8") as fh:
            line = next(l.strip() for l in fh if l.startswith("duckdb"))
        self.assertIn(">=" + ".".join(map(str, engine.MINIMUM[:2])), line)
        for bad in engine.BROKEN:
            self.assertIn("!=" + ".".join(map(str, bad)), line)


class EndToEndTests(Base):
    def folder(self):
        d = self.path("in")
        os.makedirs(d)
        kit.write_zeek_conn(os.path.join(d, "conn.log"), sample.sessions())
        with open(os.path.join(d, "network_map.csv"), "w") as fh:
            fh.write("cidr,name,type\n10.10.1.0/24,DMZ,on-prem\n")
        return d

    def test_command_line_writes_the_report(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["analyze", self.folder(), "-o", self.path("out"), "--workdir", self.dir])
        self.assertEqual(code, 0, err.getvalue())
        self.assertIn(f"{sample.AGENT}  level 1: {LEVEL_1}", out.getvalue())
        with open(self.path("out/results.json")) as fh:
            res = json.load(fh)
        self.assertEqual([f["source"] for f in res["detection"]["findings"]], [sample.AGENT])
        with open(self.path("out/report.md")) as fh:
            md = fh.read()
        self.assertIn("## Agentic activity", md)
        self.assertIn(f"### {sample.AGENT}: Level 1. {LEVEL_1}", md)
        self.assertIn("| 10.10.1.10 443/tcp |  | DMZ |", md)
        self.assertIn("threat logs not provided", md)
        self.assertIn("proxies or Tor", md)
        self.assertNotIn(sample.SCANNER, md)
        with open(self.path("out/report.html")) as fh:
            page = fh.read()
        self.assertIn("<h2>Agentic activity</h2>", page)
        self.assertIn("<td>10.10.1.10 443/tcp</td>", page)

    def test_settings_file_in_the_folder_is_used(self):
        d = self.folder()
        with open(os.path.join(d, "pentaiwatch.json"), "w") as fh:
            json.dump({"allowlist": [sample.AGENT]}, fh)
        res, _ = run([d], self.path("out"), workdir=self.dir)
        self.assertEqual(res["detection"]["findings"], [])
        self.assertEqual(res["settings"]["allowlist"], [sample.AGENT])

    def test_a_list_that_hides_a_source_does_not_do_it_quietly(self):
        # A settings file left in a log folder is used without being asked for, and its allowlist can
        # take a source out of the scoring. The results and the report name the file and count what
        # the list kept out.
        d = self.folder()
        hidden = sum(1 for x in sample.sessions() if x["src"] == sample.AGENT)
        with open(os.path.join(d, "pentaiwatch.json"), "w") as fh:
            json.dump({"allowlist": [sample.AGENT]}, fh)
        res, paths = run([d], self.path("out"), workdir=self.dir)
        det = res["detection"]
        self.assertEqual(det["findings"], [])
        self.assertEqual((det["never_flagged_sources"], det["never_flagged_sessions"]), (1, hidden))
        self.assertEqual(res["settings_files"], [
            {"kind": "settings", "file": os.path.join(d, "pentaiwatch.json"), "found_in_input": True},
            {"kind": "network_map", "file": os.path.join(d, "network_map.csv"), "found_in_input": True}])
        md = self.read(paths["report.md"])
        self.assertIn(f"Left out of the scoring: {hidden:,} sessions from 1 outside source on the allowlist "
                      "or in known_scanners.csv.", md)
        self.assertIn(f"- Read from: settings {os.path.join(d, 'pentaiwatch.json')} (found among the input files); "
                      f"network map {os.path.join(d, 'network_map.csv')} (found among the input files).", md)
        self.assertIn(f"- Never flagged: {sample.AGENT}. That left out 1 outside source with {hidden:,} inbound "
                      "sessions.", md)

    def test_a_known_scanner_list_in_the_folder_is_counted_the_same_way(self):
        d = self.folder()
        with open(os.path.join(d, "known_scanners.csv"), "w") as fh:
            fh.write(f"address,name\n{sample.SCANNER},Our scanner\n")
        skipped = sum(1 for x in sample.sessions() if x["src"] == sample.SCANNER)
        res, paths = run([d], self.path("out"), workdir=self.dir)
        det = res["detection"]
        self.assertEqual([f["source"] for f in det["findings"]], [sample.AGENT])
        self.assertEqual((det["never_flagged_sources"], det["never_flagged_sessions"]), (1, skipped))
        self.assertEqual(res["settings_files"][-1], {"kind": "known_scanners", "found_in_input": True,
                                                     "file": os.path.join(d, "known_scanners.csv")})
        self.assertIn(f"Left out of the scoring: {skipped:,} sessions from 1 outside source", self.read(paths["report.md"]))

    def test_files_named_on_the_command_line_are_listed_as_named(self):
        d = self.folder()
        cfg, listed = self.path("mine.json"), self.path("ours.csv")
        with open(cfg, "w") as fh:
            json.dump({}, fh)
        with open(listed, "w") as fh:
            fh.write("address,name\n198.51.100.7,Our scanner\n")
        res, paths = run([d], self.path("out"), config_path=cfg, known_scanners=listed, workdir=self.dir)
        self.assertEqual(res["settings_files"], [
            {"kind": "settings", "file": cfg, "found_in_input": False},
            {"kind": "network_map", "file": os.path.join(d, "network_map.csv"), "found_in_input": True},
            {"kind": "known_scanners", "file": listed, "found_in_input": False}])
        md = self.read(paths["report.md"])
        self.assertIn(f"- Read from: settings {cfg}; network map {os.path.join(d, 'network_map.csv')} "
                      f"(found among the input files); known scanners {listed}.", md)
        # nothing in the logs matched the list, so nothing is said to be left out
        self.assertEqual((res["detection"]["never_flagged_sources"], res["detection"]["never_flagged_sessions"]), (0, 0))
        self.assertNotIn("Left out of the scoring", md)
        self.assertIn("- Never flagged: 198.51.100.7/32.\n", md)

    def test_no_settings_file_says_the_defaults_apply(self):
        d = self.path("plain")
        os.makedirs(d)
        kit.write_zeek_conn(os.path.join(d, "conn.log"), sample.sessions())
        res, paths = run([d], self.path("out"), workdir=self.dir)
        self.assertEqual(res["settings_files"], [])
        self.assertIn("- Read from: no settings file, network map or known-scanner list. The defaults apply.",
                      self.read(paths["report.md"]))

    def test_two_settings_files_in_the_input_are_not_chosen_between_quietly(self):
        d = self.folder()
        os.makedirs(os.path.join(d, "site-b"))
        first, second = os.path.join(d, "pentaiwatch.json"), os.path.join(d, "site-b", "pentaiwatch.json")
        for path, allow in ((first, []), (second, [sample.AGENT])):
            with open(path, "w") as fh:
                json.dump({"allowlist": allow}, fh)
        res, _ = run([d], self.path("out"), workdir=self.dir)
        self.assertEqual([w for w in res["warnings"] if "settings files" in w],
                         [f"2 settings files (pentaiwatch.json) were found among the input files. Only {first} was "
                          f"used; ignored: {second}. Name the one to use with --config."])
        self.assertEqual([f["source"] for f in res["detection"]["findings"]], [sample.AGENT])
        # naming one settles it: no warning, and the named file is the one used
        res, _ = run([d], self.path("out2"), config_path=second, workdir=self.dir)
        self.assertEqual([w for w in res["warnings"] if "settings files" in w], [])
        self.assertEqual(res["detection"]["findings"], [])
        self.assertEqual(res["settings_files"][0], {"kind": "settings", "file": second, "found_in_input": False})

    def test_when_the_lists_leave_nothing_to_score_the_warning_says_so(self):
        # every outside session comes from an allowlisted source: the reason is the list, not the
        # internal ranges, and the warning must not send the reader to the wrong setting
        d = self.path("only")
        os.makedirs(d)
        agent = [x for x in sample.sessions() if x["src"] == sample.AGENT]
        kit.write_zeek_conn(os.path.join(d, "conn.log"), agent)
        cfg = Config()
        cfg.allowlist = [sample.AGENT]
        res, _ = run([d], self.path("out"), cfg, workdir=self.dir)
        self.assertEqual(res["detection"]["inbound_sessions"], 0)
        self.assertEqual(res["warnings"], [f"Nothing was scored: all {len(agent):,} session(s) from outside addresses "
                                           "to internal hosts came from 1 source(s) on the allowlist or in "
                                           "known_scanners.csv."])

    def test_two_runs_write_the_same_files(self):
        d = self.folder()
        texts = []
        for name in ("a", "b"):
            _, paths = run([d], self.path(name), workdir=self.dir)
            texts.append([self.read(p) for p in paths.values()])
        self.assertEqual(texts[0], texts[1])

    def test_no_logs_is_an_error_not_an_empty_report(self):
        err = io.StringIO()
        os.makedirs(self.path("empty"))
        with redirect_stderr(err):
            code = main(["analyze", self.path("empty"), "-o", self.path("out")])
        self.assertEqual(code, 2)
        self.assertIn("No log files were given", err.getvalue())


if __name__ == "__main__":
    unittest.main()
