"""Signal 3, timing: short bursts of sessions separated by pauses the length of a model's think
time. What the detection reports is checked against a plain reading of the same sessions written
here (``pace``), which shares no code with it."""
import io
import json
import os
import statistics
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime

from pentaiwatch import config
from pentaiwatch.cli import main
from pentaiwatch.config import Config
from pentaiwatch.detect import LEVEL_1, detect
from pentaiwatch.errors import UserError
from pentaiwatch.load import load
from pentaiwatch.pipeline import run
from tests import kit, sample

PERSON = "203.0.113.91"       # sweeps and narrows, then waits a minute or more between bursts


def pace(sessions, src, cfg=None, whole_seconds=False):
    """The bursts and pauses of ``src``, read plainly from the sessions' start times. Returns
    (short bursts followed by a pause in the band, all bursts, the median of those pauses,
    {window number: [such bursts, pauses, pauses in the band]}). ``whole_seconds``: as a firewall
    logs them. Otherwise to the microsecond, as the Zeek log holds them."""
    cfg = cfg or Config()
    t, step = cfg.timing, cfg.window_hours * 3600 / 2
    starts = sorted(float(int(s["ts"])) if whole_seconds else int(f"{s['ts']:.6f}".replace(".", "")) / 1e6
                    for s in sessions if s["src"] == src)
    bursts = [[starts[0]]]
    for before, after in zip(starts, starts[1:]):
        if after - before > t.burst_gap_seconds:
            bursts.append([])
        bursts[-1].append(after)
    paced, windows = [], {}
    for burst, following in zip(bursts, bursts[1:]):
        pause = following[0] - burst[-1]
        in_band = t.pause_min_seconds <= pause <= t.pause_max_seconds
        short = len(burst) <= t.max_burst_sessions
        if in_band and short:
            paced.append(pause)
        bucket = int(burst[-1] // step)
        for k in (bucket, bucket - 1):
            w = windows.setdefault(k, [0, 0, 0])
            w[0] += in_band and short
            w[1] += 1
            w[2] += in_band
    return len(paced), len(bursts), round(statistics.median(paced), 1) if paced else None, windows


def fired(windows, cfg=None):
    """The windows in which signal 3 fires, by the rule in METHODS.md."""
    t = (cfg or Config()).timing
    return {k: w for k, w in windows.items() if w[0] >= t.min_cycles and w[2] >= t.min_pause_share * w[1]}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name
        self.n = 0

    def path(self, name):
        self.n += 1
        folder = os.path.join(self.dir, str(self.n))
        os.makedirs(folder)
        return os.path.join(folder, name)

    def detect(self, sessions, cfg=None, firewall=None):
        """Detect on ``sessions`` as a Zeek log, or as a Palo Alto export written with ``firewall`` options."""
        cfg = cfg or Config()
        log = (kit.write_zeek_conn(self.path("conn.log"), sessions) if firewall is None
               else kit.write_paloalto(self.path("traffic.csv"), sessions, **firewall))
        ds = load([log], workdir=self.dir, skew_seconds=cfg.dedup_skew_seconds, options={"paloalto": cfg.paloalto})
        self.addCleanup(ds.close)
        return detect(ds.flow_con(), cfg)

    def assert_timing_matches(self, timing, sessions, src, cfg=None, whole_seconds=False):
        """The finding's timing says what a plain reading of the sessions says."""
        cfg = cfg or Config()
        paced, bursts, typical, windows = pace(sessions, src, cfg, whole_seconds)
        self.assertEqual((timing.bursts, timing.bursts_all, timing.typical_pause_seconds), (paced, bursts, typical))
        firing = fired(windows, cfg)
        self.assertTrue(firing)
        # the window named is one that fired, and none fired with more such bursts (the earliest on a tie)
        step = cfg.window_hours * 3600 / 2
        start = datetime.fromisoformat(timing.window_start.replace("Z", "+00:00")).timestamp()
        k = int(start // step)
        self.assertEqual(start, k * step)
        best = max(w[0] for w in firing.values())
        self.assertEqual(k, min(key for key, w in firing.items() if w[0] == best))
        self.assertEqual((timing.window_bursts, timing.window_pause_share),
                         (firing[k][0], round(firing[k][2] / firing[k][1], 3)))


class SignalTests(Base):
    def test_the_agentic_source_is_level_1_with_its_bursts_and_pauses(self):
        sessions = sample.sessions()
        got = self.detect(sessions)
        self.assertEqual([(f.source, f.level, f.label) for f in got.findings], [(sample.AGENT, 1, LEVEL_1)])
        t = got.findings[0].timing
        self.assertEqual((t.status, t.reason, t.sessions_timed), ("agentic", "", got.findings[0].sessions))
        self.assert_timing_matches(t, sessions, sample.AGENT)
        # hundreds of bursts, nearly all followed by a pause in the band, about 28 seconds long
        self.assertGreater(t.bursts, 300)
        self.assertGreater(t.window_pause_share, 0.9)
        self.assertTrue(20 <= t.typical_pause_seconds <= 35)

    def test_the_reference_agrees_that_only_the_agent_keeps_that_pace(self):
        # the plain reading itself: the scanner never pauses in the band; the client does now and
        # then, by chance, and far from "mostly"
        sessions = sample.sessions()
        self.assertTrue(fired(pace(sessions, sample.AGENT)[3]))
        self.assertEqual(pace(sessions, sample.SCANNER)[0], 0)
        self.assertGreaterEqual(max(w[0] for w in pace(sessions, sample.CLIENT)[3].values()), Config().timing.min_cycles)
        self.assertFalse(fired(pace(sessions, sample.CLIENT)[3]))

    def test_same_sweep_and_narrowing_at_another_pace_is_not_flagged(self):
        # a scanner following up on what it found (never a pause) and a person at work (a minute
        # or more between bursts) sweep and narrow exactly as the agent does
        sessions = sorted(sample.sessions() + sample.other_pace()
                          + sample.other_pace(seed=12, think=(60, 400), src=PERSON), key=lambda s: s["ts"])
        got = self.detect(sessions)
        self.assertEqual([(f.source, f.level) for f in got.findings], [(sample.AGENT, 1)])
        # all three narrowed, and the scanner of the sample swept without narrowing
        self.assertEqual((got.probing_sources, got.narrowing_sources), (4, 3))
        # the follower: its sweep, two minutes, then one long burst. One pause, and not in the band
        self.assertEqual(pace(sessions, sample.FOLLOWER)[:2], (0, 2))
        self.assertFalse(fired(pace(sessions, PERSON)[3]))

    def test_campaign_that_pauses_an_hour_and_resumes_is_one_level_1_finding(self):
        sessions = sample.sessions(pause_at=2.0, pause_hours=1.0)
        got = self.detect(sessions)
        self.assertEqual([(f.source, f.level) for f in got.findings], [(sample.AGENT, 1)])
        # the bursts before and after the hour are counted together
        self.assert_timing_matches(got.findings[0].timing, sessions, sample.AGENT)
        self.assertGreater(got.findings[0].campaign_hours, 5.0)

    def test_where_the_window_edges_fall_does_not_matter(self):
        counts = set()
        for shift in (0, 1234.5, 3599, 5400.25):
            with self.subTest(shift=shift):
                sessions = sample.sessions(shift=shift)
                f = self.detect(sessions).findings[0]
                self.assertEqual((f.source, f.level), (sample.AGENT, 1))
                self.assert_timing_matches(f.timing, sessions, sample.AGENT)
                counts.add((f.timing.bursts_all, f.sessions))
        self.assertEqual(len(counts), 1)                    # the same bursts, wherever the clock puts them

    def test_whole_second_firewall_times_are_precise_enough(self):
        sessions = sample.sessions()
        for options in ({}, {"start": False, "elapsed": True}):
            with self.subTest(options=options):
                f = self.detect(sessions, firewall=options).findings[0]
                self.assertEqual((f.source, f.level), (sample.AGENT, 1))
                self.assert_timing_matches(f.timing, sessions, sample.AGENT, whole_seconds=True)

    def test_same_input_gives_the_same_timing(self):
        a = self.detect(sample.sessions()).to_dict()
        b = self.detect(sample.sessions()).to_dict()
        self.assertEqual(a["findings"][0]["timing"], b["findings"][0]["timing"])


class SettingsTests(Base):
    def flagged(self, **timing):
        cfg = Config()
        for key, value in timing.items():
            setattr(cfg.timing, key, value)
        config.check(cfg)
        sessions = sample.sessions()
        got = self.detect(sessions, cfg)
        for f in got.findings:
            self.assert_timing_matches(f.timing, sessions, f.source, cfg)
        return [(f.source, f.level) for f in got.findings]

    def test_every_threshold_comes_from_the_settings(self):
        agent = [(sample.AGENT, 1)]
        self.assertEqual(self.flagged(), agent)
        # more cycles than any window holds
        self.assertEqual(self.flagged(min_cycles=5000), [])
        # the band moved away from the agent's pauses, and moved back over them
        self.assertEqual(self.flagged(pause_min_seconds=40, pause_max_seconds=60), [])
        self.assertEqual(self.flagged(pause_min_seconds=18, pause_max_seconds=40), agent)
        # "mostly" asked to mean all but one in a hundred
        self.assertEqual(self.flagged(min_pause_share=0.99), [])
        # a 40 second gap no longer ends a burst, so the agent's sessions are one long burst
        self.assertEqual(self.flagged(burst_gap_seconds=40, pause_min_seconds=40, pause_max_seconds=60), [])
        # only single sessions count as a short burst: one burst in fourteen, too few for 100 cycles
        self.assertEqual(self.flagged(min_cycles=100), agent)
        self.assertEqual(self.flagged(min_cycles=100, max_burst_sessions=1), [])

    def test_settings_file_sets_them_and_refuses_what_cannot_work(self):
        def read(data):
            path = self.path("pentaiwatch.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"timing": data}, fh)
            return config.read(path).timing

        t = read({"pause_min_seconds": 25, "pause_max_seconds": 31, "min_cycles": 8})
        self.assertEqual((t.pause_min_seconds, t.pause_max_seconds, t.min_cycles, t.burst_gap_seconds), (25, 31, 8, 15))
        for data, said in (({"min_pause_share": 60}, "between 0 and 1"),
                           ({"min_timed_share": -0.1}, "between 0 and 1"),
                           ({"min_cycles": 0}, "timing.min_cycles must be more than 0"),
                           ({"max_burst_sessions": 0}, "timing.max_burst_sessions must be more than 0"),
                           ({"burst_gap_seconds": 0}, "timing.burst_gap_seconds must be more than 0"),
                           ({"pause_min_seconds": 40}, "pause_max_seconds cannot be less than timing.pause_min_seconds"),
                           ({"burst_gap_seconds": 30}, "pause_min_seconds cannot be less than timing.burst_gap_seconds"),
                           ({"pause_minimum": 20}, "'timing.pause_minimum' is not a setting")):
            with self.subTest(data=data):
                with self.assertRaises(UserError) as caught:
                    read(data)
                self.assertIn(said, str(caught.exception))


class ReportTests(Base):
    def folder(self, sessions):
        d = os.path.dirname(self.path("conn.log"))
        kit.write_zeek_conn(os.path.join(d, "conn.log"), sessions)
        return d

    def test_report_gives_the_burst_count_and_the_typical_pause(self):
        sessions = sample.sessions()
        res, paths = run([self.folder(sessions)], self.path("out"), workdir=self.dir)
        t = res["detection"]["findings"][0]["timing"]
        paced, bursts, typical, _ = pace(sessions, sample.AGENT)
        with open(paths["report.md"], encoding="utf-8") as fh:
            md = fh.read()
        self.assertIn(f"### {sample.AGENT}: Level 1. {LEVEL_1}", md)
        self.assertIn(f"| Burst count | {paced:,} short bursts (15 sessions or fewer), each followed by a 20 to 35 "
                      f"second pause, of {bursts:,} bursts in all |", md)
        self.assertIn(f"| Typical pause length | {typical:g} seconds (median of those pauses) |", md)
        start = t["window_start"].replace("T", " ").replace("Z", " UTC")
        self.assertIn(f"| Timing fired in | the 2 hours from {start}: {t['window_bursts']:,} such bursts, and "
                      f"{t['window_pause_share']:.0%} of all the pauses in that window in the band |", md)
        self.assertIn("1 outside source swept your hosts, returned only to the services that answered, and worked "
                      "in short bursts separated by 20 to 35 second pauses", md)
        self.assertIn("- **Level 1. Agentic behaviour.**", md)
        self.assertIn("- Timing: a gap of more than 15 seconds between session starts ends a burst.", md)
        self.assertIn("Timing reads when sessions start and nothing inside them.", md)
        # the plain scanner is still counted, and nothing narrowed at another pace
        self.assertIn("1 other source swept many hosts or ports and did not narrow.", md)
        self.assertNotIn("swept and then narrowed, but not in short bursts", md)

    def test_report_counts_the_sources_that_narrowed_at_another_pace(self):
        sessions = sorted(sample.sessions() + sample.other_pace(), key=lambda s: s["ts"])
        res, paths = run([self.folder(sessions)], self.path("out"), workdir=self.dir)
        self.assertEqual([f["source"] for f in res["detection"]["findings"]], [sample.AGENT])
        self.assertEqual((res["detection"]["probing_sources"], res["detection"]["narrowing_sources"]), (3, 2))
        with open(paths["report.md"], encoding="utf-8") as fh:
            md = fh.read()
        self.assertIn("1 other source swept and then narrowed, but not in short bursts and 20 to 35 second pauses. "
                      "That looks like a scanner following up on what it found, or a person at work, and is not "
                      "flagged.", md)
        self.assertIn("1 other source swept many hosts or ports and did not narrow.", md)
        self.assertNotIn(sample.FOLLOWER, md)

    def test_report_says_so_when_nothing_keeps_an_agents_pace(self):
        res, paths = run([self.folder(sample.other_pace())], self.path("out"), workdir=self.dir)
        self.assertEqual(res["detection"]["findings"], [])
        with open(paths["report.md"], encoding="utf-8") as fh:
            md = fh.read()
        self.assertIn("No outside source showed a sweep, then narrowing, at the pace of an agentic tool.", md)
        self.assertIn("1 other source swept and then narrowed, but not in short bursts", md)

    def test_report_of_a_tier_0_finding_says_why_timing_was_not_evaluated(self):
        d = os.path.dirname(self.path("traffic.csv"))
        kit.write_paloalto(os.path.join(d, "traffic.csv"), sample.sessions(), start=False)
        res, paths = run([d], self.path("out"), workdir=self.dir)
        self.assertEqual([(f["source"], f["level"]) for f in res["detection"]["findings"]], [(sample.AGENT, 0)])
        with open(paths["report.md"], encoding="utf-8") as fh:
            md = fh.read()
        why = "not evaluated: none of its sessions has a start time"
        self.assertIn(f"| Burst count | {why} |", md)
        self.assertIn(f"| Typical pause length | {why} |", md)
        self.assertNotIn("| Timing fired in |", md)
        self.assertIn("1 outside source swept your hosts and then returned only to the services that answered, but "
                      "the sessions have no start time, so the pace could not be checked. That is reported as tier 0.", md)

    def test_command_line_names_the_level(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["analyze", self.folder(sample.sessions()), "-o", self.path("out"), "--workdir", self.dir])
        self.assertEqual(code, 0, err.getvalue())
        self.assertIn(f"{sample.AGENT}  level 1: {LEVEL_1}  (3 hosts hit)", out.getvalue())


if __name__ == "__main__":
    unittest.main()
