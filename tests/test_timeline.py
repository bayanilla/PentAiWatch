"""The Timeline's data: what the page replays of a source is what that source did, in the order it did
it, with the bursts and pauses exactly as the timing signal counted them."""
import os
import random
import re
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

from pentaiwatch import explore, report
from pentaiwatch.config import Config
from pentaiwatch.pipeline import run
from tests import kit, sample
from tests.test_timing import fired, pace

MAP = "cidr,name,type\n10.10.1.0/24,DMZ,on-prem\n10.10.2.0/24,Servers,on-prem\n"
FAILED, ANSWERED, RETURN, LATER, UNTIMED = (explore.SWEEP_FAILED, explore.SWEEP_ANSWERED, explore.RETURN,
                                            explore.LATER, explore.UNTIMED)


def micros(ts: float) -> int:
    """A session's start as the Zeek log holds it: microseconds, from the six decimals written."""
    return int(f"{ts:.6f}".replace(".", ""))


def plain_sessions(sessions, src, narrowed=sample.NARROWED):
    """What ``src`` did, read plainly from its sessions in time order: [ms after its first session,
    host, kind]. The first session to a service is a sweep attempt, answered or not; a later one is a
    return when the service is one it narrowed onto."""
    mine = sorted((s for s in sessions if s["src"] == src), key=lambda s: s["ts"])
    t0, seen, out = micros(mine[0]["ts"]) // 1000, set(), []
    for s in mine:
        service = (s["dst"], s["dport"])
        if service not in seen:
            kind = ANSWERED if s["state"] == "SF" else FAILED
        else:
            kind = RETURN if service in narrowed else LATER
        seen.add(service)
        out.append([micros(s["ts"]) // 1000 - t0, s["dst"], kind])
    return out


def plain_bursts(sessions, src, cfg=None):
    """The bursts of ``src``, read plainly from its start times: [first, last, sessions, the pause
    that follows (None after the last), how it counts], times in ms after its first session. A gap
    over ``burst_gap_seconds`` ends a burst. Counts 2: a short burst, then a pause in the band. 1:
    only the pause fits."""
    t = (cfg or Config()).timing
    starts = sorted(micros(s["ts"]) for s in sessions if s["src"] == src)
    bursts = [[starts[0]]]
    for before, after in zip(starts, starts[1:]):
        if (after - before) / 1e6 > t.burst_gap_seconds:
            bursts.append([])
        bursts[-1].append(after)
    out, t0 = [], starts[0] // 1000
    for burst, following in zip(bursts, bursts[1:] + [None]):
        pause = None if following is None else (following[0] - burst[-1]) / 1e6
        in_band = pause is not None and t.pause_min_seconds <= pause <= t.pause_max_seconds
        out.append([burst[0] // 1000 - t0, burst[-1] // 1000 - t0, len(burst), pause,
                    int(in_band) + int(in_band and len(burst) <= t.max_burst_sessions)])
    return out


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name
        self.n = 0

    def folder(self):
        self.n += 1
        d = os.path.join(self.dir, str(self.n))
        os.makedirs(d)
        return d

    def run_logs(self, sessions, zeek=True, firewall=None, settings=None):
        """Analyze ``sessions`` written as Zeek's conn.log, and as a firewall export when ``firewall``
        gives its options: (results, page data, output paths)."""
        src, out = self.folder(), self.folder()
        if zeek:
            kit.write_zeek_conn(os.path.join(src, "conn.log"), sessions)
        if firewall is not None:
            kit.write_paloalto(os.path.join(src, "traffic.csv"), sessions, **firewall)
        with open(os.path.join(src, "network_map.csv"), "w", encoding="utf-8") as fh:
            fh.write(MAP)
        if settings:
            with open(os.path.join(src, "pentaiwatch.json"), "w", encoding="utf-8") as fh:
                fh.write(settings)
        res, paths = run([src], out, workdir=self.dir)
        with open(paths[explore.FILENAME], encoding="utf-8") as fh:
            return res, explore.read_data(fh.read()), paths

    def assertBurstsEqual(self, got, plain):
        """The page's bursts are the plain reading's: same starts, sizes and standing, pauses to the ms."""
        self.assertEqual([b[:3] + b[4:] for b in got], [b[:3] + b[4:] for b in plain])
        for mine, theirs in zip(got, plain):
            if theirs[3] is None:
                self.assertIsNone(mine[3])
            else:
                self.assertAlmostEqual(mine[3], theirs[3], places=3)


class TimelineTests(Base):
    """The agent (level 1), a follower that swept and narrowed at another pace (not flagged), a plain
    scanner and an ordinary client."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        case = cls("run_logs")
        case.setUp()
        cls.addClassCleanup(case.tmp.cleanup)
        cls.sessions = sorted(sample.sessions() + sample.other_pace(), key=lambda s: s["ts"])
        cls.res, cls.data, cls.paths = case.run_logs(cls.sessions)
        cls.finding = cls.res["detection"]["findings"][0]
        cls.agent, cls.follower = cls.data["timelines"][sample.AGENT], cls.data["timelines"][sample.FOLLOWER]

    def test_the_sources_that_narrowed_have_one_flagged_first(self):
        self.assertEqual(list(self.data["timelines"]), [sample.AGENT, sample.FOLLOWER])
        self.assertEqual([s["ip"] for s in self.data["sources"] if s["narrowed"]], [sample.AGENT, sample.FOLLOWER])
        self.assertNotIn(sample.SCANNER, self.data["timelines"])       # it swept and did not narrow
        self.assertEqual(self.res["explorer"], {"file": "explorer.html", "sources_drawn": 3, "findings_drawn": 1,
                                                "timelines": [sample.AGENT, sample.FOLLOWER]})
        # the page is told the scoring window, which is one of the window lengths it offers
        self.assertEqual(self.data["window_hours"], self.res["settings"]["window_hours"])

    def test_sessions_are_the_sources_own_in_the_order_they_started(self):
        for src, t in ((sample.AGENT, self.agent), (sample.FOLLOWER, self.follower)):
            plain = plain_sessions(self.sessions, src)
            got = [[ms, t["hosts"][host][0], kind] for ms, host, kind in t["sessions"]]
            self.assertEqual(got, plain, src)
            self.assertEqual([ms for ms, _, _ in t["sessions"]], sorted(ms for ms, _, _ in t["sessions"]))
            self.assertEqual((t["sessions_total"], t["every"]), (len(plain), 1))
            # its first session is where the clock starts, and the span runs to its last
            first = min(s["ts"] for s in self.sessions if s["src"] == src)
            self.assertEqual(t["t0_ms"], micros(first) // 1000)
            self.assertEqual(t["t0"], datetime.fromtimestamp(int(first), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
            self.assertAlmostEqual(t["seconds"], plain[-1][0] / 1000, places=3)

    def test_the_sweep_and_the_returns_are_told_apart(self):
        kinds = [k for _, _, k in self.agent["sessions"]]
        # 300 services tried once each, 6 of them listening; every later session is a return to the
        # three services it narrowed onto
        self.assertEqual({k: kinds.count(k) for k in set(kinds)},
                         {FAILED: 294, ANSWERED: 6, RETURN: len(kinds) - 300})
        self.assertEqual(self.finding["services_probed"], 300)
        back = {(self.agent["hosts"][h][0]) for _, h, k in self.agent["sessions"] if k == RETURN}
        self.assertEqual(back, {host for host, _ in sample.NARROWED})
        self.assertEqual(kinds[:300].count(RETURN), 0)                 # the sweep comes first

    def test_a_later_session_to_a_service_it_did_not_narrow_onto_is_not_a_return(self):
        # the agent comes back twice, hours later, to a listening service it never worked on
        extra = [kit.session(sample.T0 + 3 * 3600 + i, sample.AGENT, "10.10.1.20", 443, "SF") for i in (0, 400)]
        sessions = sorted(sample.sessions() + extra, key=lambda s: s["ts"])
        t = self.run_logs(sessions)[1]["timelines"][sample.AGENT]
        self.assertEqual([[ms, t["hosts"][h][0], k] for ms, h, k in t["sessions"]], plain_sessions(sessions, sample.AGENT))
        self.assertEqual([t["hosts"][h][0] for _, h, k in t["sessions"] if k == LATER], ["10.10.1.20"] * 2)

    def test_bursts_are_the_ones_the_timing_signal_counted(self):
        for src, t in ((sample.AGENT, self.agent), (sample.FOLLOWER, self.follower)):
            plain = plain_bursts(self.sessions, src)
            self.assertBurstsEqual(t["bursts"], plain)
            self.assertEqual(t["bursts_total"], len(plain))
            self.assertEqual(sum(b[2] for b in t["bursts"]), t["sessions_total"])      # every session is in one burst
            # and they agree with the other plain reading, the one the timing tests use
            paced, all_bursts, _, windows = pace(self.sessions, src)
            self.assertEqual((sum(1 for b in t["bursts"] if b[4] == 2), len(t["bursts"])), (paced, all_bursts))
            step_ms = self.res["settings"]["window_hours"] * 3600 * 1000 / 2
            self.assertEqual({start: [cycles, pauses, in_band] for start, cycles, pauses, in_band in t["fired"]},
                             {int(k * step_ms - t["t0_ms"]): w for k, w in fired(windows).items()}, src)
        # the agent: what its finding says, and the sweep is one long burst that does not count
        timing = self.finding["timing"]
        self.assertEqual((timing["bursts"], timing["bursts_all"]),
                         (sum(1 for b in self.agent["bursts"] if b[4] == 2), len(self.agent["bursts"])))
        self.assertEqual((self.agent["bursts"][0][2], self.agent["bursts"][0][4]), (300, 0))
        self.assertGreaterEqual(len(self.agent["fired"]), 1)
        # the follower: its sweep, then one unbroken burst. Nothing fired.
        self.assertEqual(([b[2] for b in self.follower["bursts"]], self.follower["fired"]),
                         ([300, self.follower["sessions_total"] - 300], []))

    def test_a_long_burst_before_a_pause_in_the_band_counts_once(self):
        # with bursts of at most 5 sessions asked for, the agent's longer ones no longer count as short
        cfg = Config()
        cfg.timing.max_burst_sessions = 5
        res, data, _ = self.run_logs(sample.sessions(), settings='{"timing": {"max_burst_sessions": 5}}')
        self.assertEqual(res["settings"]["timing"]["max_burst_sessions"], 5)
        t, plain = data["timelines"][sample.AGENT], plain_bursts(sample.sessions(), sample.AGENT, cfg)
        self.assertBurstsEqual(t["bursts"], plain)
        counts = [sum(1 for b in t["bursts"] if b[4] == how) for how in (0, 1, 2)]
        self.assertTrue(all(counts), counts)                          # all three kinds of burst are there
        self.assertEqual(counts[2], pace(sample.sessions(), sample.AGENT, cfg)[0])

    def test_marks_are_the_findings_own_times(self):
        def when(ms):
            return datetime.fromtimestamp((self.agent["t0_ms"] + ms) // 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        marks = self.agent["marks"]
        self.assertEqual({k: when(v) for k, v in marks.items()},
                         {k: self.finding[k] for k in ("probe_start", "probe_end", "narrowing_start")})
        self.assertEqual(marks["probe_start"], 0)
        self.assertLess(marks["probe_end"], marks["narrowing_start"])

    def test_lanes_are_its_subnets_and_hosts_sit_in_address_order(self):
        self.assertEqual(self.agent["lanes"], [["10.10.1.0/24", "DMZ", 20], ["10.10.2.0/24", "Servers", 10]])
        self.assertEqual(self.agent["hosts"], [[h, 0] for h in sample.HOSTS[:20]] + [[h, 1] for h in sample.HOSTS[20:30]])
        # 10.10.1.9 would sort after 10.10.1.10 as text
        self.assertEqual(sorted(["10.0.0.10", "10.0.0.9", "2001:db8::2", "not an address"], key=explore._ip_order),
                         ["10.0.0.9", "10.0.0.10", "2001:db8::2", "not an address"])

    def test_the_report_links_to_the_flagged_sources_timeline(self):
        md = self.read(self.paths["report.md"])
        self.assertEqual(re.findall(r"explorer\.html#timeline=([0-9.]+)", md), [sample.AGENT])
        self.assertIn(f"| Timeline | [Replay its sessions in the order they started](explorer.html#timeline={sample.AGENT}) |", md)
        self.assertIn("Its Timeline replays a source's sessions in the order they started", md)
        self.assertIn(f'<a href="explorer.html#timeline={sample.AGENT}">Replay its sessions in the order they started</a>',
                      self.read(self.paths["report.html"]))

    @staticmethod
    def read(path):
        with open(path, encoding="utf-8") as fh:
            return fh.read()


class LimitTests(Base):
    """A page stays a size a browser can draw: the picture thins, the counts do not."""

    def timeline(self, **limits):
        with mock.patch.multiple(explore, **limits):
            sessions = sorted(sample.sessions() + sample.other_pace(), key=lambda s: s["ts"])
            res, data, _ = self.run_logs(sessions)
        return sessions, res, data

    def test_past_the_cap_every_nth_session_is_drawn(self):
        sessions, _, data = self.timeline(MAX_TIMELINE_SESSIONS=500)
        t, plain = data["timelines"][sample.AGENT], plain_sessions(sessions, sample.AGENT)
        every = -(-len(plain) // 500)
        self.assertGreater(every, 1)
        self.assertEqual((t["every"], t["sessions_total"]), (every, len(plain)))
        self.assertEqual([[ms, t["hosts"][h][0], k] for ms, h, k in t["sessions"]], plain[::every])
        self.assertLessEqual(len(t["sessions"]), 500)
        self.assertGreater(t["sessions"][-1][0], plain[-every][0] - 1)         # it still runs to the end
        # the bursts are counted from every session, drawn or not
        self.assertBurstsEqual(t["bursts"], plain_bursts(sessions, sample.AGENT))
        # the follower fits, and is drawn whole
        self.assertEqual(data["timelines"][sample.FOLLOWER]["every"], -(-len(plain_sessions(sessions, sample.FOLLOWER)) // 500))

    def test_past_the_cap_the_first_bursts_are_drawn_and_all_are_counted(self):
        sessions, _, data = self.timeline(MAX_TIMELINE_BURSTS=100)
        t, plain = data["timelines"][sample.AGENT], plain_bursts(sessions, sample.AGENT)
        self.assertGreater(len(plain), 100)
        self.assertBurstsEqual(t["bursts"], plain[:100])
        self.assertEqual(t["bursts_total"], len(plain))

    def test_only_the_first_sources_that_narrowed_get_one(self):
        _, res, data = self.timeline(MAX_TIMELINES=1)
        self.assertEqual(list(data["timelines"]), [sample.AGENT])              # the flagged one
        self.assertEqual([s["ip"] for s in data["sources"] if s["narrowed"]], [sample.AGENT, sample.FOLLOWER])
        self.assertEqual(res["explorer"]["timelines"], [sample.AGENT])

    def test_subnets_past_the_lanes_share_one(self):
        _, _, data = self.timeline(TIMELINE_LANES=1)
        t = data["timelines"][sample.AGENT]
        self.assertEqual(t["lanes"], [["10.10.1.0/24", "DMZ", 20], ["*", "other subnets", 10]])
        self.assertEqual(t["hosts"], [[h, 0] for h in sample.HOSTS[:20]] + [[h, 1] for h in sample.HOSTS[20:30]])


class StartTimeTests(Base):
    def test_sessions_with_only_an_end_time_are_marked_and_make_no_bursts(self):
        # a firewall export with neither a start time nor an elapsed time: tier 0, nothing to time
        res, data, _ = self.run_logs(sample.sessions(), zeek=False, firewall={"start": False})
        self.assertEqual([(f["source"], f["level"]) for f in res["detection"]["findings"]], [(sample.AGENT, 0)])
        t = data["timelines"][sample.AGENT]
        self.assertEqual((t["bursts"], t["bursts_total"], t["fired"]), ([], 0, []))
        self.assertEqual({k & UNTIMED for _, _, k in t["sessions"]}, {UNTIMED})
        kinds = [k & 7 for _, _, k in t["sessions"]]
        self.assertEqual((kinds.count(FAILED) + kinds.count(ANSWERED), len(kinds)), (300, t["sessions_total"]))
        self.assertGreater(kinds.count(RETURN), 0)

    def test_sessions_with_a_start_time_are_not_marked(self):
        for firewall in ({}, {"start": False, "elapsed": True}):
            t = self.run_logs(sample.sessions(), zeek=False, firewall=firewall)[1]["timelines"][sample.AGENT]
            self.assertEqual({k & UNTIMED for _, _, k in t["sessions"]}, {0}, firewall)
            self.assertGreater(len(t["bursts"]), 100)


class NothingTests(Base):
    def test_a_run_in_which_nothing_narrowed_has_no_timeline(self):
        rng = random.Random(3)
        res, data, paths = self.run_logs(sorted(sample.scanner(rng) + sample.client(rng), key=lambda s: s["ts"]))
        self.assertEqual((data["timelines"], res["explorer"]["timelines"]), ({}, []))
        with open(paths["report.md"], encoding="utf-8") as fh:
            self.assertNotIn("imeline", fh.read())
        self.assertEqual(explore.empty()["timelines"], {})


class ReportLinkTests(unittest.TestCase):
    FINDING = {"source": "203.0.113.9", "level": 1, "label": "x", "log_sources": ["zeek"], "start_times": {"zeek_ts": 1},
               "probe_start": "", "services_probed": 1, "hosts_probed": 1, "ports_probed": 1, "probe_end": "",
               "failed_share": 1.0, "services_answered": 0, "narrowing_start": "", "focus_share": 1.0, "hosts_hit": [],
               "timing": {"status": "unavailable", "reason": "none of its sessions has a start time"},
               "campaign_hours": 0.0, "first_seen": "", "last_seen": "", "sessions": 1,
               "threat_evidence": "", "services": [], "services_total": 0}

    def test_a_timeline_link_is_a_link_to_the_page_next_to_the_report(self):
        self.assertEqual(report._inline("[Replay](explorer.html#timeline=2001:db8::5)"),
                         '<a href="explorer.html#timeline=2001:db8::5">Replay</a>')
        for text in ("[x](explorer.html#timeline=1.2.3.4&x=<b>)", "[x](explorer.html#timeline=)",
                     "[x](http://example.com/explorer.html#timeline=1.2.3.4)", '[x](explorer.html#timeline=1" onclick="y)',
                     "[x](explorer.html#other=1.2.3.4)"):
            self.assertNotIn("<a", report._inline(text), text)

    def test_only_a_source_with_a_timeline_on_the_page_gets_the_link(self):
        st = Config().settings()
        lines = "\n".join
        self.assertNotIn("#timeline=", lines(report._finding_lines(self.FINDING, st, "explorer.html")))
        self.assertNotIn("#timeline=", lines(report._finding_lines(self.FINDING, st, "", True)))
        self.assertIn("(explorer.html#timeline=203.0.113.9)", lines(report._finding_lines(self.FINDING, st, "explorer.html", True)))


if __name__ == "__main__":
    unittest.main()
