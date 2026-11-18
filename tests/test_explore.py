"""The Explorer page: what it draws is what the report says, cut to a size a browser can draw, and
the page itself is one file that loads nothing from anywhere."""
import contextlib
import json
import os
import random
import re
import tempfile
import unittest
from unittest import mock

from pentaiwatch import explore, report
from pentaiwatch.config import Config
from pentaiwatch.detect import detect
from pentaiwatch.load import load
from pentaiwatch.pipeline import run
from tests import kit, sample

MAP = "cidr,name,type\n10.10.1.0/24,DMZ,on-prem\n10.10.2.0/24,Servers,on-prem\n"


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

    def run_logs(self, sessions, zeek=True, firewall=False, network_map=True):
        """Analyze ``sessions`` written as the logs asked for: (results, page data, output paths)."""
        src, out = self.folder(), self.folder()
        if zeek:
            kit.write_zeek_conn(os.path.join(src, "conn.log"), sessions)
        if firewall:
            kit.write_paloalto(os.path.join(src, "traffic.csv"), sessions)
        if network_map:
            with open(os.path.join(src, "network_map.csv"), "w", encoding="utf-8") as fh:
                fh.write(MAP)
        res, paths = run([src], out, workdir=self.dir)
        return res, explore.read_data(self.read(paths[explore.FILENAME])), paths

    @staticmethod
    def read(path):
        with open(path, encoding="utf-8") as fh:
            return fh.read()


class SceneTests(Base):
    """The three-source sample: the agent is flagged, the scanner swept only, the client did neither."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        case = cls("run_logs")
        case.setUp()
        cls.addClassCleanup(case.tmp.cleanup)
        cls.res, cls.data, cls.paths = case.run_logs(sample.sessions())
        cls.finding = cls.res["detection"]["findings"][0]
        cls.agent, cls.scanner = cls.data["sources"]

    def test_sources_drawn_are_those_that_swept_flagged_first(self):
        self.assertEqual([(s["ip"], s["flagged"], s["level"], s["label"]) for s in self.data["sources"]],
                         [(sample.AGENT, True, 1, self.finding["label"]), (sample.SCANNER, False, None, explore.SWEEP_ONLY)])
        self.assertEqual([s["narrowed"] for s in self.data["sources"]], [True, False])
        self.assertEqual(self.data["counts"], {
            "inbound_sessions": self.res["detection"]["inbound_sessions"], "outside_sources": 3, "sweeping": 2,
            "narrowed": 1, "flagged": 1, "sources_drawn": 2, "hosts_tried": 40, "hosts_drawn": 40, "subnets_tried": 2,
            "subnets_drawn": 2})
        # the page is told the timing settings of the run, so it can say what an agent's pace meant
        self.assertEqual(self.data["timing"], self.res["settings"]["timing"])
        self.assertEqual(self.data["window"], [self.res["detection"]["lookback_start"], self.res["detection"]["lookback_end"]])

    def test_a_flagged_source_carries_its_findings_numbers(self):
        f, s = self.finding, self.agent
        for key in ("probe_start", "probe_end", "services_probed", "hosts_probed", "ports_probed", "failed_share",
                    "services_answered", "narrowing_start", "focus_share", "start_times", "timing", "threat_evidence",
                    "sessions", "first_seen", "last_seen", "campaign_hours", "log_sources", "services_total"):
            self.assertEqual(s[key], f[key], key)
        self.assertEqual(s["hosts_hit"], len(f["hosts_hit"]))
        self.assertEqual(s["services"], [[v["host"], v["port"], v["proto"], v["sessions"], v["first_return"]]
                                         for v in f["services"]])

    def test_a_sources_sweep_adds_up_to_its_finding(self):
        hosts = self.data["hosts"]
        for s in self.data["sources"]:
            # every host it tried is in a drawn subnet here, and each is listed once
            self.assertEqual(sum(n[1] for n in s["nets"]) + s["hosts_elsewhere"], s["hosts_probed"])
            self.assertEqual(s["hosts_elsewhere"], 0)
            self.assertEqual(sum(n[2] for n in s["nets"]), s["services_probed"])
            self.assertEqual(sum(n[4] for n in s["nets"]), s["services_answered"])
            self.assertEqual(len(s["tried"]), s["hosts_probed"])
            self.assertEqual(len(set(s["tried"])), len(s["tried"]))
            by_net = {}
            for i in s["tried"]:
                by_net[hosts[i]["net"]] = by_net.get(hosts[i]["net"], 0) + 1
            self.assertEqual({n[0]: n[1] for n in s["nets"]}, by_net)
        # the scanner swept twice, twelve hours apart: only the sweep it is judged by is counted
        self.assertEqual((self.scanner["services_probed"], self.scanner["hosts_probed"]), (1000, 40))
        self.assertEqual((self.agent["services_probed"], self.agent["hosts_probed"]), (300, 30))

    def test_hosts_show_the_most_telling_thing_that_happened_to_them(self):
        state = {h["ip"]: h["state"] for h in self.data["hosts"]}
        narrowed = {h for h, _ in sample.NARROWED}
        answered = {h for h, _ in sample.OPEN} - narrowed
        self.assertEqual({ip for ip, s in state.items() if s == "narrowed"}, narrowed)
        self.assertEqual({ip for ip, s in state.items() if s == "answered"}, answered)
        self.assertEqual(sum(1 for s in state.values() if s == "tried"), 40 - len(narrowed) - len(answered))
        # drawn in that order, so the hosts that matter survive any cut
        order = [explore.STATES.index(h["state"]) for h in self.data["hosts"]]
        self.assertEqual(order, sorted(order))
        vpn = next(h for h in self.data["hosts"] if h["ip"] == "10.10.1.10")
        self.assertEqual((vpn["sources"], vpn["narrowed"]), (2, 1))
        self.assertEqual(vpn["sessions"], next(v["sessions"] for v in self.finding["services"] if v["host"] == "10.10.1.10"))

    def test_subnets_are_named_from_the_network_map_and_listed_by_what_happened(self):
        self.assertEqual([(n["id"], n["name"], n["tried"], n["answered"], n["narrowed"], n["drawn"])
                          for n in self.data["subnets"]],
                         [("10.10.1.0/24", "DMZ", 20, 4, 3, 20), ("10.10.2.0/24", "Servers", 20, 1, 0, 20)])
        answered = [[self.data["hosts"][i]["ip"], n] for i, n in self.agent["answered"]]
        self.assertEqual(sorted(answered), [["10.10.1.10", 2], ["10.10.1.11", 1], ["10.10.1.12", 1], ["10.10.1.20", 2]])

    def test_the_report_links_to_the_map_and_to_each_flagged_source_on_it(self):
        self.assertEqual(self.res["explorer"], {"file": "explorer.html", "sources_drawn": 2, "findings_drawn": 1,
                                                "timelines": [sample.AGENT]})
        md, page = self.read(self.paths["report.md"]), self.read(self.paths["report.html"])
        self.assertIn("[Open the Explorer](explorer.html)", md)
        self.assertIn(f"[Show this source on the map](explorer.html#source={sample.AGENT})", md)
        self.assertIn('<a href="explorer.html">Open the Explorer</a>', page)
        self.assertIn(f'<a href="explorer.html#source={sample.AGENT}">Show this source on the map</a>', page)
        # the report is still what the saved results give
        self.assertEqual(report.markdown(json.loads(self.read(self.paths["results.json"]))), md)


class ThreeWaysTests(Base):
    def test_the_map_is_the_same_whichever_log_it_was_built_from(self):
        seen = []
        for zeek, firewall in ((True, False), (False, True), (True, True)):
            _, data, _ = self.run_logs(sample.sessions(), zeek=zeek, firewall=firewall)
            agent = data["sources"][0]
            seen.append((agent["ip"], agent["flagged"], agent["services_probed"], agent["hosts_probed"],
                         sorted(v[:2] for v in agent["services"]),
                         sorted(h["ip"] for h in data["hosts"] if h["state"] == "narrowed"),
                         data["counts"]["hosts_tried"], [n["id"] for n in data["subnets"]]))
        self.assertEqual(seen[0], seen[1])
        self.assertEqual(seen[0], seen[2])
        self.assertEqual(seen[0][:4], (sample.AGENT, True, 300, 30))


class CutTests(Base):
    def collect(self, sessions, **limits):
        ds = load([kit.write_zeek_conn(os.path.join(self.folder(), "conn.log"), sessions)], workdir=self.dir)
        self.addCleanup(ds.close)
        scene = explore.empty()
        with mock.patch.multiple(explore, **limits) if limits else contextlib.nullcontext():
            found = detect(ds.flow_con(), Config(), while_scored=lambda con, det: scene.update(explore.collect(con, Config(), det)))
        return found, scene, ds

    def test_a_big_run_is_cut_and_the_counts_stay_whole(self):
        found, scene, _ = self.collect(sample.sessions(), MAX_SOURCES=1, MAX_SUBNETS=1, MAX_HOSTS=5)
        self.assertEqual([s["ip"] for s in scene["sources"]], [sample.AGENT])      # flagged sources come first
        self.assertEqual(scene["counts"]["sweeping"], 2)
        (net,), agent = scene["subnets"], scene["sources"][0]
        self.assertEqual((net["id"], net["tried"], net["narrowed"], net["drawn"]), ("10.10.1.0/24", 20, 3, 5))
        self.assertEqual([h["state"] for h in scene["hosts"]], ["narrowed"] * 3 + ["answered", "tried"])
        # 30 hosts tried: 20 in the subnet drawn (5 of them as dots), 10 in the one that is not
        self.assertEqual((agent["hosts_probed"], agent["nets"][0][1], agent["hosts_elsewhere"], len(agent["tried"])), (30, 20, 10, 5))
        self.assertEqual({k: scene["counts"][k] for k in ("hosts_tried", "hosts_drawn", "subnets_tried", "subnets_drawn")},
                         {"hosts_tried": 30, "hosts_drawn": 5, "subnets_tried": 2, "subnets_drawn": 1})
        self.assertEqual(len(agent["services"]), len(found.findings[0].services))

    def test_the_services_listed_per_source_are_capped_too(self):
        _, scene, _ = self.collect(sample.sessions(), MAX_SERVICES=2)
        agent = scene["sources"][0]
        self.assertEqual((len(agent["services"]), agent["services_total"]), (2, 3))
        sessions = [v[3] for v in agent["services"]]
        self.assertEqual(sessions, sorted(sessions, reverse=True))          # the busiest are the ones kept

    def test_the_working_tables_are_gone_afterwards(self):
        _, _, ds = self.collect(sample.sessions())
        left = [r[0] for r in ds.flow_con().execute(
            "SELECT table_name FROM information_schema.tables WHERE table_name LIKE 'pw_%'").fetchall()]
        self.assertEqual(left, [])

    def test_nothing_swept_gives_the_empty_scene_and_no_link_in_the_report(self):
        res, data, paths = self.run_logs(sample.client(random.Random(3)))
        self.assertEqual((data["sources"], data["hosts"], data["subnets"]), ([], [], []))
        self.assertEqual((data["counts"]["outside_sources"], data["counts"]["sweeping"]), (1, 0))
        self.assertEqual(res["explorer"], {"file": "explorer.html", "sources_drawn": 0, "findings_drawn": 0, "timelines": []})
        self.assertNotIn("explorer.html", self.read(paths["report.md"]))
        self.assertIn("<title>Explorer · PentAIWatch</title>", self.read(paths[explore.FILENAME]))

    def test_subnets_of_other_shapes(self):
        self.assertEqual(explore.subnet_of("10.47.23.82"), "10.47.23.0/24")
        self.assertEqual(explore.subnet_of("2001:db8:1:2:aaaa::5"), "2001:db8:1:2::/64")
        self.assertEqual(explore.subnet_of("not an address"), "other")


class PageTests(Base):
    SCENE = {**explore.empty(), "subnets": [{"id": "10.0.0.0/24", "name": "</script><script>alert(1)</script>",
                                             "cloud": False, "tried": 1, "answered": 0, "narrowed": 0, "drawn": 1}]}
    RES = {"sessions": 12, "log_sources": ["zeek"]}

    def test_the_data_comes_back_out_of_the_page(self):
        page = explore.html(self.SCENE, self.RES)
        self.assertEqual(explore.read_data(page), json.loads(json.dumps(explore.page_data(self.SCENE, self.RES))))
        self.assertEqual(explore.read_data(page)["limits"], {"sources": explore.MAX_SOURCES, "subnets": explore.MAX_SUBNETS,
                                                             "hosts": explore.MAX_HOSTS, "services": explore.MAX_SERVICES})

    def test_text_from_the_logs_cannot_end_the_data_block(self):
        page = explore.html(self.SCENE, self.RES)
        self.assertEqual(page.count("</script>"), 1 + len(explore.SCRIPTS))
        self.assertNotIn("alert(1)", page)
        self.assertEqual(explore.read_data(page)["subnets"][0]["name"], "</script><script>alert(1)</script>")

    def test_the_page_loads_nothing_from_anywhere(self):
        page = explore.html(self.SCENE, self.RES)
        self.assertEqual(re.findall(r"<script[^>]*\bsrc\s*=", page), [])
        self.assertEqual(re.findall(r"<(?:img|iframe|object|embed|video|audio|source)\b", page), [])
        self.assertEqual(re.findall(r"<link\b[^>]*>", page), ['<link rel="icon" href="data:,">'])
        for name in explore.STYLES:
            self.assertEqual(re.findall(r"@import|url\(\s*['\"]?(?!data:)", explore._read(name)), [], name)
        # the page's own markup links only to the report next to it
        self.assertEqual(re.findall(r'href="([^"]*)"', explore._read("explorer.html")), ["report.html"])
        for name in ("explorer.js", "explorer3d.js", "timeline3d.js"):
            for call in ("fetch(", "XMLHttpRequest", "WebSocket(", "sendBeacon", "importScripts", "EventSource", "window.open("):
                self.assertNotIn(call, explore._read(name), f"{call} in {name}")

    def test_the_same_scene_gives_the_same_bytes(self):
        self.assertEqual(explore.html(self.SCENE, self.RES), explore.html(self.SCENE, self.RES))
        a = self.run_logs(sample.sessions())[2][explore.FILENAME]
        b = self.run_logs(sample.sessions())[2][explore.FILENAME]
        self.assertEqual(self.read(a), self.read(b))

    def test_a_page_without_data_or_with_damaged_data_says_so(self):
        with self.assertRaisesRegex(ValueError, "no Explorer data"):
            explore.read_data("<html></html>")
        page = explore.html(self.SCENE, self.RES)
        start = page.index(explore.DATA_TAG) + len(explore.DATA_TAG)
        with self.assertRaisesRegex(ValueError, "damaged"):
            explore.read_data(page[:start] + "AAAA" + page[start + 4:])

    def test_a_script_that_would_end_its_own_block_is_refused(self):
        with mock.patch.object(explore, "STATIC", self.dir):
            with open(os.path.join(self.dir, "bad.js"), "w", encoding="utf-8") as fh:
                fh.write("const s = '</SCRIPT>';\n")
            with self.assertRaisesRegex(ValueError, "would end its <script> block"):
                explore._read("bad.js")

    def test_every_script_the_page_needs_is_in_the_package(self):
        for name in explore.SCRIPTS + explore.STYLES + ("explorer.html",):
            self.assertTrue(explore._read(name), name)
        self.assertIn("timeline3d.js", explore.SCRIPTS)
        # the Timeline starts after the map's controller, which it hands the other views back to
        self.assertLess(explore.SCRIPTS.index("explorer.js"), explore.SCRIPTS.index("timeline3d.js"))


class OtherPaceTests(Base):
    """A source that swept and narrowed, but not at an agent's pace: on the map, not flagged."""

    def test_it_is_drawn_unflagged_with_what_it_did_and_the_pace_it_kept(self):
        sessions = sorted(sample.sessions() + sample.other_pace(), key=lambda s: s["ts"])
        res, data, paths = self.run_logs(sessions)
        self.assertEqual([f["source"] for f in res["detection"]["findings"]], [sample.AGENT])
        # after the flagged source come those that narrowed, then the largest sweeps
        self.assertEqual([(s["ip"], s["flagged"], s["narrowed"], s["level"], s["label"]) for s in data["sources"]],
                         [(sample.AGENT, True, True, 1, "Agentic behaviour"),
                          (sample.FOLLOWER, False, True, None, explore.OTHER_PACE),
                          (sample.SCANNER, False, False, None, explore.SWEEP_ONLY)])
        counts = data["counts"]
        self.assertEqual((counts["sweeping"], counts["narrowed"], counts["flagged"]), (3, 2, 1))
        follower, scanner = data["sources"][1:]
        # why it is not flagged: three services it came back to, in two bursts with one pause, not in the band
        self.assertEqual(follower["pace"], {"services_total": 3, "bursts_all": 2, "pauses": 1, "pauses_in_band": 0})
        self.assertNotIn("pace", scanner)
        # solid beams and gold hosts belong to flagged sources only
        for s in (follower, scanner):
            self.assertNotIn("services", s)
        narrowed = {h["ip"]: (h["narrowed"], h["sources"]) for h in data["hosts"] if h["state"] == "narrowed"}
        self.assertEqual(narrowed, {h: (1, 3) for h, _ in sample.NARROWED})
        # and the report links to the flagged source alone
        self.assertEqual(re.findall(r"explorer\.html#source=([0-9.]+)", self.read(paths["report.md"])), [sample.AGENT])
        self.assertEqual(res["explorer"], {"file": "explorer.html", "sources_drawn": 3, "findings_drawn": 1,
                                           "timelines": [sample.AGENT, sample.FOLLOWER]})


class ReportLinkTests(unittest.TestCase):
    def test_only_a_page_in_the_same_folder_becomes_a_link(self):
        self.assertEqual(report._inline("[Map](explorer.html#source=2001:db8::5)"),
                         '<a href="explorer.html#source=2001:db8::5">Map</a>')
        for text in ("[x](javascript:alert(1))", "[x](http://example.com/a.html)", "[x](../up.html)", "[x](a/b.html)",
                     "[x](explorer.html#source=1.2.3.4&x=<b>)", '[x](explorer.html" onclick="y)'):
            self.assertNotIn("<a", report._inline(text), text)

    def test_a_finding_past_those_drawn_gets_no_link(self):
        f = {"source": "203.0.113.9", "level": 0, "label": "x", "log_sources": ["zeek"], "start_times": {"zeek_ts": 1},
             "probe_start": "", "services_probed": 1, "hosts_probed": 1, "ports_probed": 1, "probe_end": "",
             "failed_share": 1.0, "services_answered": 0, "narrowing_start": "", "focus_share": 1.0, "hosts_hit": [],
             "timing": {"status": "unavailable", "reason": "none of its sessions has a start time"},
             "campaign_hours": 0.0, "first_seen": "", "last_seen": "", "sessions": 1,
             "threat_evidence": "", "services": [], "services_total": 0}
        st = Config().settings()
        self.assertNotIn("explorer.html", "\n".join(report._finding_lines(f, st)))
        self.assertIn("(explorer.html#source=203.0.113.9)", "\n".join(report._finding_lines(f, st, "explorer.html")))


if __name__ == "__main__":
    unittest.main()
