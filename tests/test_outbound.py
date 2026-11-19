"""Your hosts reaching out to attacker infrastructure: an internal host's sessions to a published
attacker address are flagged; sessions to a command-and-control port (Cobalt Strike 50050, Adaptix
4321) on any other outside address are named as a hint and flag nothing. From Zeek and from a Palo
Alto export, and only from what those logs carry."""
import json
import os
import tempfile
import unittest

from pentaiwatch.errors import UserError
from pentaiwatch.pipeline import run
from tests import kit, sample

ARTEX_HOST = "38.244.50.120"         # CrowdStrike's ARTEX host (on the bundled list)
CS_SERVER = "1.14.104.208"           # Censys: Cobalt Strike and Adaptix on an ARTEX host (on the list)
ELSEWHERE = "198.51.100.200"         # not on any list
VICTIM, OTHER = "10.10.1.12", "10.10.2.40"


def calls_home(src=VICTIM, dst=ARTEX_HOST, port=443, n=12, start=16000, state="SF", every=60.0):
    return [kit.session(sample.T0 + start + every * i, src, dst, port, state) for i in range(n)]


class Outbound(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def analyze(self, sessions, zeek=True, firewall=False, settings=None, known_bad=None, inbound=True):
        src = os.path.join(self.tmp.name, f"in{len(os.listdir(self.tmp.name))}")
        os.makedirs(src)
        sessions = (sample.sessions() if inbound else []) + sessions
        if zeek:
            kit.write_zeek_conn(os.path.join(src, "conn.log"), sessions)
        if firewall:
            kit.write_paloalto(os.path.join(src, "traffic.csv"), sessions)
        if settings:
            with open(os.path.join(src, "pentaiwatch.json"), "w", encoding="utf-8") as fh:
                json.dump(settings, fh)
        if known_bad:
            with open(os.path.join(src, "known_bad.csv"), "w", encoding="utf-8") as fh:
                fh.write("address,name\n" + "".join(f"{ip},our incident\n" for ip in known_bad))
        res, paths = run([src], os.path.join(src, "out"))
        with open(paths["report.md"], encoding="utf-8") as fh:
            return res["detection"], fh.read()

    def test_a_host_calling_a_published_address_is_flagged_from_each_log(self):
        for zeek, firewall in ((True, False), (False, True)):
            with self.subTest(zeek=zeek, firewall=firewall):
                det, md = self.analyze(calls_home(), zeek, firewall)
                [c] = det["outbound_contacts"]
                self.assertEqual((c["host"], c["destination"], c["sessions"], c["answered"]),
                                 (VICTIM, ARTEX_HOST, 12, 12))
                self.assertEqual(c["ports"], ["443/tcp"])
                self.assertIn("CrowdStrike", c["name"] + c["reference"])
                self.assertIn("## Your hosts reaching out to attacker infrastructure", md)
                self.assertIn(f"| {VICTIM} | {ARTEX_HOST} | ", md)
                self.assertLess(md.index("## Your hosts reaching out"), md.index("## Agentic activity"))
                # the inbound findings are what they were
                self.assertEqual([f["source"] for f in det["findings"]], [sample.AGENT])

    def test_a_c2_port_on_a_published_address_is_named_on_the_contact(self):
        det, md = self.analyze(calls_home(dst=CS_SERVER, port=50050))
        [c] = det["outbound_contacts"]
        self.assertEqual(c["c2"], ["Cobalt Strike teamserver"])
        self.assertEqual(det["c2_hints"], [])
        self.assertIn("50050/tcp (Cobalt Strike teamserver port)", md)

    def test_a_c2_port_elsewhere_is_a_hint_only(self):
        det, md = self.analyze(calls_home(dst=ELSEWHERE, port=4321, src=OTHER))
        self.assertEqual(det["outbound_contacts"], [])
        [h] = det["c2_hints"]
        self.assertEqual((h["host"], h["destination"], h["port"], h["tool"]), (OTHER, ELSEWHERE, 4321, "Adaptix C2"))
        self.assertIn("### Command-and-control ports (hints, not flagged)", md)
        self.assertNotIn(f"| {OTHER} | {ELSEWHERE} | Published", md)

    def test_the_upload_page_lists_the_host(self):
        from pentaiwatch.web.jobs import summary
        src = os.path.join(self.tmp.name, "web")
        os.makedirs(src)
        kit.write_zeek_conn(os.path.join(src, "conn.log"), sample.sessions() + calls_home())
        res, _ = run([src], os.path.join(src, "out"))
        [entry] = [f for f in summary(res)["flagged"] if f["source"] == VICTIM]
        self.assertEqual(entry["tag"], "Reached attacker")
        self.assertIn(ARTEX_HOST, entry["label"])

    def test_ordinary_outbound_traffic_is_not_named(self):
        det, md = self.analyze(calls_home(dst=ELSEWHERE, port=443) + calls_home(dst=ELSEWHERE, port=8787))
        self.assertEqual((det["outbound_contacts"], det["c2_hints"]), ([], []))
        self.assertNotIn("## Your hosts reaching out", md)

    def test_your_own_list_and_a_log_with_only_outbound_traffic(self):
        det, md = self.analyze(calls_home(dst=ELSEWHERE), known_bad=[ELSEWHERE], inbound=False)
        [c] = det["outbound_contacts"]
        self.assertEqual((c["destination"], c["name"]), (ELSEWHERE, "our incident"))
        self.assertIn("## Your hosts reaching out", md)

    def test_unanswered_calls_still_count_and_say_so(self):
        det, _ = self.analyze(calls_home(state="S0"))
        [c] = det["outbound_contacts"]
        self.assertEqual((c["sessions"], c["answered"]), (12, 0))

    def test_allowlisted_destinations_and_the_switch(self):
        det, _ = self.analyze(calls_home(), settings={"allowlist": [ARTEX_HOST]})
        self.assertEqual(det["outbound_contacts"], [])
        det, md = self.analyze(calls_home(), settings={"outbound": {"check": False}})
        self.assertEqual(det["outbound_contacts"], [])
        self.assertIn("- Outbound: not checked", md)
        det, _ = self.analyze(calls_home(dst=ELSEWHERE, port=8787),
                              settings={"outbound": {"c2_ports": {"ARTEX console": [8787]}}})
        self.assertEqual([h["tool"] for h in det["c2_hints"]], ["ARTEX console"])
        with self.assertRaises(UserError):
            self.analyze([], settings={"outbound": {"c2_ports": {"x": [0]}}})


if __name__ == "__main__":
    unittest.main()
