"""Palo Alto traffic logs: read through the field map in the settings, given a start time, scored
like Zeek sessions, and counted once when Zeek recorded the same session."""
import csv
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone

import pentaiwatch.detect as detector
from pentaiwatch import config
from pentaiwatch.config import Config
from pentaiwatch.detect import TIER_0, detect
from pentaiwatch.errors import MissingField, UserError
from pentaiwatch.load import load
from pentaiwatch.pipeline import run
from pentaiwatch.schema import START_END_MINUS_ELAPSED, START_FIELD, START_NONE
from tests import kit, sample


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name
        self.n = 0

    def path(self, name):
        self.n += 1
        d = os.path.join(self.dir, str(self.n))
        os.makedirs(d)
        return os.path.join(d, name)

    def zeek(self, sessions):
        return kit.write_zeek_conn(self.path("conn.log"), sessions)

    def firewall(self, sessions, **kw):
        return kit.write_paloalto(self.path("traffic.csv"), sessions, **kw)

    def load(self, *paths, cfg=None):
        cfg = cfg or Config()
        ds = load(list(paths), workdir=self.dir, skew_seconds=cfg.dedup_skew_seconds,
                  options={"paloalto": cfg.paloalto})
        self.addCleanup(ds.close)
        return ds

    def detect(self, *paths, cfg=None):
        cfg = cfg or Config()
        return detect(self.load(*paths, cfg=cfg).flow_con(), cfg)


def _summary(f):
    """What must not depend on which log a finding was built from."""
    return (f.source, f.level, f.label, f.services_probed, f.hosts_probed, f.ports_probed,
            sorted((s.host, s.port, s.sessions) for s in f.services), f.hosts_hit, f.sessions)


class ThreeWaysTests(Base):
    """The same sessions as Zeek only, Palo Alto only, and both."""

    def setUp(self):
        super().setUp()
        self.sessions = sample.sessions()

    def test_each_way_flags_the_same_source_with_the_same_evidence(self):
        zeek = self.detect(self.zeek(self.sessions))
        firewall = self.detect(self.firewall(self.sessions))
        both = self.detect(self.zeek(self.sessions), self.firewall(self.sessions))
        for got in (zeek, firewall, both):
            self.assertEqual([f.source for f in got.findings], [sample.AGENT])
            self.assertEqual((got.findings[0].level, got.findings[0].label), (0, TIER_0))
        self.assertEqual(_summary(zeek.findings[0]), _summary(firewall.findings[0]))
        self.assertEqual(_summary(zeek.findings[0]), _summary(both.findings[0]))
        self.assertEqual({(s.host, s.port) for s in both.findings[0].services}, set(sample.NARROWED))
        # each finding says which logs it was built from
        self.assertEqual([got.findings[0].log_sources for got in (zeek, firewall, both)],
                         [["zeek"], ["paloalto"], ["paloalto", "zeek"]])
        # the plain scanner sweeps in every case and is flagged in none
        self.assertEqual([got.probing_sources for got in (zeek, firewall, both)], [2, 2, 2])

    def test_sessions_both_logs_recorded_count_once(self):
        ds = self.load(self.zeek(self.sessions), self.firewall(self.sessions))
        self.assertEqual(len(ds.flows), len(self.sessions))
        self.assertEqual(ds.duplicate_flows + ds.cross_sensor_duplicates, len(self.sessions))
        got = detect(ds.flow_con(), Config())
        self.assertEqual(got.inbound_sessions, len(self.sessions))
        self.assertEqual(got.warnings, [])

    def test_one_log_alone_skips_the_matching(self):
        ds = self.load(self.firewall(self.sessions))
        self.assertEqual((ds.duplicate_flows, ds.cross_sensor_duplicates), (0, 0))
        self.assertEqual(ds.sensors, ["paloalto"])

    def test_syslog_lines_without_a_header_give_the_same_finding(self):
        csv_way = self.detect(self.firewall(self.sessions, packets=True))
        syslog = self.detect(kit.write_paloalto_syslog(self.path("fw.log"), self.sessions))
        self.assertEqual(_summary(syslog.findings[0]), _summary(csv_way.findings[0]))
        self.assertEqual(syslog.findings[0].start_times, {START_FIELD: syslog.findings[0].sessions})
        self.assertEqual(syslog.findings[0].notes, [])


class StartTimeTests(Base):
    """A firewall session's time is its START: the start field, else end minus elapsed, else none."""

    def setUp(self):
        super().setUp()
        # sessions that last a while, so start and end are well apart
        self.sessions = [dict(s, duration=40.0 if s["state"] in ("SF", "RSTO") else 3.0) for s in sample.sessions()]

    def times(self, ds):
        return sorted(f.ts for f in ds.flows)

    def expected(self, at):
        return sorted(datetime.fromtimestamp(int(at(s)), tz=timezone.utc) for s in self.sessions)

    def test_start_field_is_used_when_the_export_has_one(self):
        ds = self.load(self.firewall(self.sessions, elapsed=True))
        self.assertEqual({f.start_method for f in ds.flows}, {START_FIELD})
        self.assertEqual(self.times(ds), self.expected(lambda s: s["ts"]))

    def test_no_start_field_but_elapsed_gives_end_minus_elapsed(self):
        ds = self.load(self.firewall(self.sessions, start=False, elapsed=True))
        self.assertEqual({f.start_method for f in ds.flows}, {START_END_MINUS_ELAPSED})
        self.assertEqual(self.times(ds), self.expected(lambda s: s["ts"]))       # the real starts, to the second
        got = detect(ds.flow_con(), Config())
        f = got.findings[0]
        self.assertEqual((f.source, f.start_times), (sample.AGENT, {START_END_MINUS_ELAPSED: f.sessions}))
        self.assertEqual(got.warnings, [])

    def test_neither_start_nor_elapsed_is_still_reported_with_a_warning(self):
        ds = self.load(self.firewall(self.sessions, start=False))
        self.assertEqual({f.start_method for f in ds.flows}, {START_NONE})
        # the only time there is, the END time, is kept and marked as not a start
        self.assertEqual(self.times(ds), self.expected(lambda s: s["ts"] + s["duration"]))
        got = detect(ds.flow_con(), Config())
        f = got.findings[0]
        self.assertEqual((f.source, f.level, f.label), (sample.AGENT, 0, TIER_0))
        self.assertEqual(f.start_times, {START_NONE: f.sessions})
        self.assertEqual(len(got.warnings), 1)                                   # said once, not per session
        self.assertIn("neither a start time nor an elapsed time", got.warnings[0])
        self.assertIn("never used for timing", got.warnings[0])
        self.assertIn("had neither a start time nor an elapsed time", " ".join(ds.stats[0].notes))

    def test_start_worked_out_from_elapsed_still_matches_zeek(self):
        ds = self.load(self.zeek(self.sessions), self.firewall(self.sessions, start=False, elapsed=True))
        self.assertEqual(len(ds.flows), len(self.sessions))

    def test_end_times_cannot_be_matched_to_zeek_and_the_report_says_so(self):
        got = self.detect(self.zeek(self.sessions), self.firewall(self.sessions, start=False))
        self.assertGreater(got.inbound_sessions, len(self.sessions))            # long sessions were not matched
        self.assertIn("may be counted twice", " ".join(got.warnings))

    def test_each_row_falls_back_on_its_own(self):
        # one export, three kinds of row: with a start, with only end and elapsed, with only end
        header, rows = kit.paloalto_rows(self.sessions[:30], elapsed=True)
        at = {h: i for i, h in enumerate(header)}
        for i, row in enumerate(rows):
            if i % 3:
                row[at["Start Time"]] = ""
            if i % 3 == 2:
                row[at["Elapsed Time (sec)"]] = ""
        p = self.path("traffic.csv")
        with open(p, "w", newline="") as fh:
            csv.writer(fh).writerows([header] + rows)
        ds = self.load(p)
        methods = [f.start_method for f in ds.flows]
        self.assertEqual({m: methods.count(m) for m in set(methods)},
                         {START_FIELD: 10, START_END_MINUS_ELAPSED: 10, START_NONE: 10})


class FieldMapTests(Base):
    """Column names and positions come from the settings, never from the code."""

    RENAME = {"Source address": "Client", "Destination address": "Server", "Destination Port": "Server Port",
              "Bytes Received": "Bytes In", "Start Time": "Session Opened", "Action": "Verdict"}
    FIELDS = {"source": ["Client"], "destination": ["Server"], "destination_port": ["Server Port"],
              "bytes_received": ["Bytes In"], "start": ["Session Opened"], "action": ["Verdict"]}

    def test_other_column_names_are_refused_until_the_settings_name_them(self):
        p = self.firewall(sample.sessions(), rename=self.RENAME)
        with self.assertRaises(MissingField) as caught:
            self.load(p)
        message = str(caught.exception)
        for part in ("traffic.csv", "the source address", "Source address", "bytes received", "Client",
                     "paloalto.fields"):
            self.assertIn(part, message)
        cfg = Config()
        cfg.paloalto.fields.update(self.FIELDS)
        got = self.detect(p, cfg=cfg)
        self.assertEqual([f.source for f in got.findings], [sample.AGENT])

    def test_settings_file_names_the_columns(self):
        p = self.path("pentaiwatch.json")
        with open(p, "w") as fh:
            json.dump({"paloalto": {"fields": {**self.FIELDS, "elapsed": "Seconds"},
                                    "syslog_offsets": {"elapsed": None, "start": 30},
                                    "answered_min_bytes_received": 200}}, fh)
        cfg = config.read(p)
        self.assertEqual(cfg.paloalto.fields["source"], ["Client"])
        self.assertEqual(cfg.paloalto.fields["elapsed"], ["Seconds"])            # one name need not be a list
        self.assertEqual(cfg.paloalto.fields["protocol"], ["IP Protocol", "Protocol"])   # the rest keep defaults
        self.assertEqual((cfg.paloalto.syslog_offsets["elapsed"], cfg.paloalto.syslog_offsets["start"]), (None, 30))
        self.assertEqual(cfg.paloalto.answered_min_bytes_received, 200)
        self.assertEqual(cfg.settings()["paloalto"]["fields"]["source"], ["Client"])

    def test_settings_file_refuses_what_it_does_not_know(self):
        for body, message in (({"paloalto": {"fields": {"sorce": ["Client"]}}}, r"paloalto\.fields\.sorce"),
                              ({"paloalto": {"fields": {"source": 5}}}, "column name"),
                              ({"paloalto": {"syslog_offsets": {"start": "32"}}}, "whole number"),
                              ({"paloalto": {"syslog_offsets": {"start": 5000}}}, "cannot be right"),
                              ({"paloalto": {"answered_min_bytes_received": 0}}, "must be 1 or more"),
                              ({"paloalto": {"deny_actions": []}}, "at least one action")):
            p = self.path("pentaiwatch.json")
            with open(p, "w") as fh:
                json.dump(body, fh)
            with self.assertRaisesRegex(UserError, message):
                config.read(p)

    def test_names_are_matched_ignoring_case_spaces_and_punctuation(self):
        got = self.detect(self.firewall(sample.sessions(), rename={
            "Source address": "SOURCE_ADDRESS", "Bytes Received": "bytes-received", "Start Time": "start  time"}))
        self.assertEqual([f.source for f in got.findings], [sample.AGENT])

    def test_missing_time_columns_stop_the_run(self):
        header, rows = kit.paloalto_rows(sample.sessions()[:20], start=False)
        keep = [i for i, h in enumerate(header) if h != "Receive Time"]
        p = self.path("traffic.csv")
        with open(p, "w", newline="") as fh:
            csv.writer(fh).writerows([[row[i] for i in keep] for row in [header] + rows])
        with self.assertRaisesRegex(MissingField, r"the session start time .*or the log \(end\) time"):
            self.load(p)

    def test_syslog_positions_come_from_the_settings(self):
        p = kit.write_paloalto_syslog(self.path("fw.log"), sample.sessions())
        cfg = Config()
        cfg.paloalto.syslog_offsets["action"] = None
        with self.assertRaisesRegex(MissingField, r"fw\.log: paloalto\.syslog_offsets .* the action"):
            self.load(p, cfg=cfg)
        cfg = Config()
        cfg.paloalto.syslog_offsets["start"] = None                 # no start position: end minus elapsed
        got = self.detect(p, cfg=cfg)
        self.assertEqual(list(got.findings[0].start_times), [START_END_MINUS_ELAPSED])

    def test_the_report_lists_which_column_each_time_came_from(self):
        ds = self.load(self.firewall(sample.sessions()[:50]))
        notes = " ".join(ds.stats[0].notes)
        self.assertIn("the session start time = Start Time", notes)
        self.assertIn("elapsed seconds = not in the export", notes)
        self.assertIn("firewall times are read as UTC", notes)


class OutcomeTests(Base):
    """When a firewall session failed or was answered."""

    def one(self, state, cfg=None, **kw):
        ds = self.load(self.firewall([kit.session(sample.T0, sample.AGENT, "10.10.1.10", 443, state)], **kw), cfg=cfg)
        cfg = cfg or Config()
        con = ds.flow_con()
        self.assertEqual(detect(con, cfg).inbound_sessions, 1)
        # detect() drops its working tables, so build the common shape again to read the outcome
        detector._classify_addresses(con, cfg)
        detector._common_sessions(con, cfg, datetime(2000, 1, 1))
        return con.execute("SELECT outcome FROM pw_sessions").fetchone()[0]

    def test_outcomes_follow_the_rule(self):
        self.assertEqual(self.one("S0"), "failed")                               # denied by policy
        self.assertEqual(self.one("S0", denied=()), "failed")                    # allowed, nothing back (bytes)
        self.assertEqual(self.one("S0", denied=(), packets=True), "failed")      # allowed, no packets back
        self.assertEqual(self.one("SF"), "answered")                             # allowed, bytes back
        self.assertEqual(self.one("SF", packets=True), "answered")

    def test_a_refused_connection_counts_as_answered_unless_the_setting_says_otherwise(self):
        # a closed port on a permitted path answers with one reset: 60 bytes and one packet back
        self.assertEqual(self.one("REJ", packets=True), "answered")
        cfg = Config()
        cfg.paloalto.failed_max_packets_received = 1
        self.assertEqual(self.one("REJ", cfg=cfg, packets=True), "failed")
        cfg = Config()
        cfg.paloalto.answered_min_bytes_received = 100        # no packet count: at least stop calling it answered
        self.assertEqual(self.one("REJ", cfg=cfg), "other")

    def test_a_sweep_of_refusing_ports_needs_that_setting_on_the_firewall(self):
        refusing = sample.sessions(refused=0.3)
        self.assertEqual([f.source for f in self.detect(self.zeek(refusing)).findings], [sample.AGENT])
        p = self.firewall(refusing, packets=True)
        self.assertEqual(self.detect(p).findings, [])
        cfg = Config()
        cfg.paloalto.failed_max_packets_received = 1
        self.assertEqual([f.source for f in self.detect(p, cfg=cfg).findings], [sample.AGENT])

    def test_export_without_a_packet_count_is_noted_on_the_finding(self):
        with_count = self.detect(self.firewall(sample.sessions(), packets=True)).findings[0]
        without = self.detect(self.firewall(sample.sessions())).findings[0]
        self.assertEqual(with_count.notes, [])
        self.assertEqual(len(without.notes), 1)
        self.assertIn("zero bytes received stood in for 'no packets back'", without.notes[0])

    def test_actions_that_mean_stopped_come_from_the_settings(self):
        header, rows = kit.paloalto_rows(sample.sessions()[:6], denied=())
        at = header.index("Action")
        for row, action in zip(rows, ["allow", "deny", "drop", "reset-both", "reset-server", "quarantine"]):
            row[at] = action
        p = self.path("traffic.csv")
        with open(p, "w", newline="") as fh:
            csv.writer(fh).writerows([header] + rows)
        self.assertEqual(sorted(f.action for f in self.load(p).flows), ["allow", "allow"] + ["deny"] * 4)
        cfg = Config()
        cfg.paloalto.deny_actions = ["quarantine"]
        self.assertEqual(sorted(f.action for f in self.load(p, cfg=cfg).flows), ["allow"] * 5 + ["deny"])

    def test_session_start_records_are_left_out_and_counted(self):
        header, rows = kit.paloalto_rows(sample.sessions()[:10])
        at = header.index("Threat/Content Type")
        opening = [list(r) for r in rows[:4]]
        for row in opening:                      # the same sessions, logged when they opened
            row[at] = "start"
            row[header.index("Bytes Received")] = 0
        p = self.path("traffic.csv")
        with open(p, "w", newline="") as fh:
            csv.writer(fh).writerows([header] + opening + rows)
        ds = self.load(p)
        self.assertEqual(len(ds.flows), 10)
        self.assertEqual(sum(ds.stats[0].dropped.values()), 4)
        self.assertIn("session-start record", next(iter(ds.stats[0].dropped)))

    def test_allowed_row_without_a_bytes_value_is_dropped_not_read_as_zero(self):
        header, rows = kit.paloalto_rows([kit.session(sample.T0, sample.AGENT, "10.10.1.10", 443, "SF")])
        rows[0][header.index("Bytes Received")] = ""
        p = self.path("traffic.csv")
        with open(p, "w", newline="") as fh:
            csv.writer(fh).writerows([header] + rows)
        ds = self.load(p)
        self.assertEqual(len(ds.flows), 0)
        self.assertEqual(dict(ds.stats[0].dropped), {"allowed session with no bytes-received value": 1})


class ClockTests(Base):
    def test_clocks_that_disagree_are_warned_about(self):
        ss = sample.sessions()
        got = self.detect(self.zeek(ss), self.firewall(ss, clock_offset=300))
        self.assertEqual(got.inbound_sessions, 2 * len(ss))                      # nothing could be matched
        self.assertEqual(len(got.warnings), 1)
        self.assertIn("clocks disagree", got.warnings[0])
        self.assertIn("5 minutes later than Zeek's", got.warnings[0])
        got = self.detect(self.zeek(ss), self.firewall(ss, clock_offset=-5 * 3600))   # firewall on local time
        self.assertIn("5.0 hours earlier than Zeek's", " ".join(got.warnings))

    def test_clocks_in_step_are_not(self):
        ss = sample.sessions()
        self.assertEqual(self.detect(self.zeek(ss), self.firewall(ss, clock_offset=1)).warnings, [])


class ThreatRowTests(Base):
    def test_threat_rows_are_read_and_the_finding_says_they_are_not_scored_yet(self):
        p = self.firewall(sample.sessions())
        with open(p, "a", newline="") as fh:
            csv.writer(fh).writerow([
                "2026/09/21 15:00:00", "016401000001", "THREAT", "vulnerability", sample.AGENT, "10.10.1.10",
                "inbound", "ssl", "untrust", "dmz", 40000, 443, "tcp", "reset-both", "", "", "", "",
                "Example VPN Portal Command Injection(90001)", "critical"])
        ds = self.load(p)
        self.assertEqual([(t.name, t.severity, t.action) for t in ds.threats],
                         [("Example VPN Portal Command Injection(90001)", "critical", "reset-both")])
        f = detect(ds.flow_con(), Config()).findings[0]
        self.assertIn("threat logs were read (1 event) but are not scored yet", f.threat_evidence)
        # threat rows never flag a source on their own, and they are not sessions
        self.assertEqual(len(ds.flows), len(sample.sessions()))

    def test_without_threat_rows_the_finding_says_not_provided(self):
        f = self.detect(self.firewall(sample.sessions())).findings[0]
        self.assertEqual(f.threat_evidence, "threat logs not provided")


class EndToEndTests(Base):
    def folder(self, **kw):
        d = os.path.dirname(self.path("x"))
        kit.write_zeek_conn(os.path.join(d, "conn.log"), sample.sessions())
        kit.write_paloalto(os.path.join(d, "traffic.csv"), sample.sessions(), **kw)
        return d

    def test_folder_with_both_logs_reports_both(self):
        out = os.path.join(self.dir, "out")
        res, paths = run([self.folder()], out, workdir=self.dir)
        self.assertEqual(res["log_sources"], ["paloalto", "zeek"])
        self.assertEqual(res["sessions"], len(sample.sessions()))
        self.assertEqual(sum(res["duplicates_removed"].values()), len(sample.sessions()))
        self.assertEqual(res["warnings"], [])
        f = res["detection"]["findings"][0]
        self.assertEqual((f["source"], f["log_sources"]), (sample.AGENT, ["paloalto", "zeek"]))
        with open(paths["report.md"]) as fh:
            md = fh.read()
        self.assertIn("| Built from | Palo Alto traffic log and Zeek conn.log |", md)
        self.assertIn("firewall start-time field", md)
        self.assertIn("| Notes | ", md)
        self.assertIn("Palo Alto: stopped when the action starts with deny, drop, reset or block", md)
        self.assertIn("columns used: the session start time = Start Time", md)

    def test_settings_file_in_the_folder_reaches_the_firewall_reader(self):
        d = self.folder(rename=FieldMapTests.RENAME)
        with self.assertRaises(MissingField):
            run([d], os.path.join(self.dir, "out"), workdir=self.dir)
        with open(os.path.join(d, "pentaiwatch.json"), "w") as fh:
            json.dump({"paloalto": {"fields": FieldMapTests.FIELDS}}, fh)
        res, _ = run([d], os.path.join(self.dir, "out"), workdir=self.dir)
        self.assertEqual([f["source"] for f in res["detection"]["findings"]], [sample.AGENT])
        self.assertEqual(res["settings"]["paloalto"]["fields"]["source"], ["Client"])

    def test_files_read_in_parallel_get_the_same_settings(self):
        d = self.folder(rename=FieldMapTests.RENAME)
        with open(os.path.join(d, "pentaiwatch.json"), "w") as fh:
            json.dump({"paloalto": {"fields": FieldMapTests.FIELDS}}, fh)
        os.environ["PENTAIWATCH_PARSE_WORKERS"] = "2"          # one reader process per file
        self.addCleanup(os.environ.pop, "PENTAIWATCH_PARSE_WORKERS", None)
        res, _ = run([d], os.path.join(self.dir, "out"), workdir=self.dir)
        self.assertEqual([f["source"] for f in res["detection"]["findings"]], [sample.AGENT])
        self.assertEqual(sum(res["duplicates_removed"].values()), len(sample.sessions()))

    def test_file_that_is_neither_kind_of_log_is_left_out_with_a_warning(self):
        d = self.folder()
        with open(os.path.join(d, "inventory.csv"), "w") as fh:
            fh.write("host,owner\n10.10.1.10,web team\n")
        res, _ = run([d], os.path.join(self.dir, "out"), workdir=self.dir)
        self.assertIn("neither Zeek nor Palo Alto logs and were left out: inventory.csv", res["warnings"][0])

    def test_export_with_only_session_start_records_is_an_error_not_an_empty_report(self):
        header, rows = kit.paloalto_rows(sample.sessions()[:50])
        for row in rows:
            row[header.index("Threat/Content Type")] = "start"
        d = os.path.dirname(self.path("x"))
        with open(os.path.join(d, "traffic.csv"), "w", newline="") as fh:
            csv.writer(fh).writerows([header] + rows)
        with self.assertRaisesRegex(UserError, r"No sessions could be read.*session-start record.*50 rows"):
            run([d], os.path.join(self.dir, "out"), workdir=self.dir)


if __name__ == "__main__":
    unittest.main()
