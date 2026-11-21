"""Zeek http.log, dns.log and ssl.log beside conn.log: agentic tools' user agents (context, named on
sight) and internal hosts asking for watched names such as AI model APIs (hints). Connection logs
alone must give what they gave before."""
import json
import os
import tempfile
import unittest

from pentaiwatch.errors import UserError
from pentaiwatch.pipeline import run
from tests import kit, sample

ARTEX_SRC, HEX_SRC, BROWSER = "198.51.100.140", "198.51.100.141", "198.51.100.142"
WEB, SERVER, LAPTOP = "10.10.1.10", "10.10.1.12", "10.10.2.40"
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
T = sample.T0 + 5000


def http_rows():
    rows = [kit.http_row(T + i, ARTEX_SRC, WEB, "artex-enrich/1.0") for i in range(30)]
    rows += [kit.http_row(T + 40 + i, ARTEX_SRC, WEB, "Mozilla/5.0 (Spa-api-recon)") for i in range(5)]
    rows += [kit.http_row(T + 50 + i, ARTEX_SRC, "10.10.1.11", "Mozilla/5.0 ARTeX") for i in range(2)]
    rows += [kit.http_row(T + 60 + i, HEX_SRC, WEB, "HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)") for i in range(4)]
    rows += [kit.http_row(T + 70 + i, sample.AGENT, WEB, "Mozilla/5.0 (compatible; CyberStrikeAI-WebShell/1.0)") for i in range(3)]
    rows += [kit.http_row(T + 80 + i, BROWSER, WEB, CHROME) for i in range(50)]
    rows += [kit.http_row(T + 90 + i, BROWSER, WEB, "norma/0.4") for i in range(5)]              # shared SDK: left out
    rows += [kit.http_row(T + 100 + i, LAPTOP, "198.51.100.9", "HexStrike-BrowserAgent/1.0") for i in range(6)]
    rows += [kit.http_row(T + 110, SERVER, "198.51.100.9", "curl/8.5.0", host="webhook.site:80")]
    return rows


def dns_rows():
    return ([kit.dns_row(T + i, SERVER, "api.deepseek.com") for i in range(8)]
            + [kit.dns_row(T + 20, SERVER, "u6ud2s.dnslog.cn"), kit.dns_row(T + 21, LAPTOP, "API.Anthropic.com."),
               kit.dns_row(T + 22, LAPTOP, "max.ai"), kit.dns_row(T + 23, LAPTOP, "notapi.x.ai.example"),
               kit.dns_row(T + 24, SERVER, "updates.example"), kit.dns_row(T + 25, ARTEX_SRC, "api.x.ai")])


def ssl_rows():
    return [kit.ssl_row(T + 30 + i, SERVER, "198.51.100.9", "api.deepseek.com") for i in range(4)]


class WebLogs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def analyze(self, http=None, dns=None, ssl=None, settings=None, extra=()):
        src = os.path.join(self.tmp.name, f"in{len(os.listdir(self.tmp.name))}")
        os.makedirs(src)
        kit.write_zeek_conn(os.path.join(src, "conn.log"), sample.sessions() + list(extra))
        if http is not None:
            kit.write_zeek_log(os.path.join(src, "http.log"), "http", kit.HTTP_FIELDS, kit.HTTP_TYPES, http)
        if dns is not None:
            kit.write_zeek_log(os.path.join(src, "dns.log"), "dns", kit.DNS_FIELDS, kit.DNS_TYPES, dns)
        if ssl is not None:
            kit.write_zeek_log(os.path.join(src, "ssl.log"), "ssl", kit.SSL_FIELDS, kit.SSL_TYPES, ssl)
        if settings:
            with open(os.path.join(src, "pentaiwatch.json"), "w", encoding="utf-8") as fh:
                json.dump(settings, fh)
        res, paths = run([src], os.path.join(src, "out"))
        with open(paths["report.md"], encoding="utf-8") as fh:
            return res, res["detection"], fh.read()

    def coverage(self, det):
        return {c["detector"]: c["status"] for c in det["coverage"]}

    def test_tool_user_agents_are_named_on_sight(self):
        res, det, md = self.analyze(http=http_rows())
        got = {t["source"]: t for t in det["tool_clients"]}
        self.assertEqual(sorted(got), sorted([ARTEX_SRC, HEX_SRC, sample.AGENT, LAPTOP]))
        a = got[ARTEX_SRC]
        self.assertEqual((a["tools"], a["requests"], a["internal"], a["hosts"], a["also"]),
                         (["ARTEX"], 37, False, [WEB, "10.10.1.11"], ""))
        self.assertEqual(a["user_agents"], ["artex-enrich/1.0", "Mozilla/5.0 (Spa-api-recon)", "Mozilla/5.0 ARTeX"])
        self.assertEqual(got[HEX_SRC]["tools"], ["HexStrike AI"])
        self.assertEqual((got[LAPTOP]["internal"], got[LAPTOP]["requests"]), (True, 6))
        self.assertEqual([t["source"] for t in det["tool_clients"]][-1], LAPTOP)          # outside sources first
        # on the finding when the source is one; the finding itself is what it was
        [f] = det["findings"]
        self.assertEqual((f["source"], f["level"], got[sample.AGENT]["also"]), (sample.AGENT, 1, "finding"))
        self.assertEqual(f["user_agents"], ["CyberStrikeAI: Mozilla/5.0 (compatible; CyberStrikeAI-WebShell/1.0)"])
        self.assertTrue("| Agentic tool user agent | CyberStrikeAI: Mozilla/5.0 (compatible; CyberStrikeAI-WebShell/1.0) |" in md)
        self.assertTrue("## Context: agentic tools' user agents" in md)
        self.assertTrue(f"| {LAPTOP} (internal host) | HexStrike AI |" in md)
        # a browser and a shared SDK are not named; nothing became a lead or a finding because of a user agent
        self.assertFalse(BROWSER in md)
        self.assertEqual((det["steady_sources"], det["spray_sources"], det["login_sources"]), ([], [], []))
        self.assertEqual(det["web_logs"], {"http": len(http_rows())})
        self.assertEqual(self.coverage(det)["Agentic tools' user agents (Zeek http.log)"], "checked")
        [inp] = [i for i in res["inputs"] if i["file"] == "http.log"]
        self.assertEqual((inp["read"], inp["kept"]), (len(http_rows()), 51))

    def test_watched_names_are_hints_for_internal_hosts_only(self):
        _, det, md = self.analyze(http=http_rows(), dns=dns_rows(), ssl=ssl_rows())
        got = {(c["host"], c["kind"]): c for c in det["name_contacts"]}
        self.assertEqual(sorted(got), sorted([(SERVER, "AI model API"), (LAPTOP, "AI model API"),
                                              (SERVER, "Request-capture or callback service")]))
        api = got[(SERVER, "AI model API")]
        self.assertEqual((api["names"], api["records"], api["seen_in"]), (["api.deepseek.com"], 12, ["dns", "ssl"]))
        cb = got[(SERVER, "Request-capture or callback service")]
        self.assertEqual((sorted(cb["names"]), cb["records"], cb["seen_in"]), (["u6ud2s.dnslog.cn", "webhook.site"], 2, ["dns", "http"]))
        self.assertEqual(got[(LAPTOP, "AI model API")]["names"], ["api.anthropic.com"])     # case and the final dot
        self.assertEqual(det["name_contacts_total"], 3)
        self.assertTrue("### Watched names your hosts asked for (hints, not flagged)" in md)
        self.assertEqual(self.coverage(det)["Watched names such as AI model APIs (Zeek dns, http and ssl logs)"], "checked")
        self.assertEqual([f["source"] for f in det["findings"]], [sample.AGENT])

    def test_without_those_logs_nothing_changes_and_the_report_says_what_was_not_checked(self):
        _, det, md = self.analyze()
        self.assertEqual((det["tool_clients"], det["name_contacts"], det["web_logs"]), ([], [], {}))
        cov = self.coverage(det)
        self.assertEqual(cov["Agentic tools' user agents (Zeek http.log)"], "not checked")
        self.assertEqual(cov["Watched names such as AI model APIs (Zeek dns, http and ssl logs)"], "not checked")
        self.assertFalse("## Context: agentic tools' user agents" in md)
        _, det, _ = self.analyze(dns=dns_rows())
        self.assertEqual(self.coverage(det)["Watched names such as AI model APIs (Zeek dns, http and ssl logs)"], "partly checked")

    def test_json_logs_and_the_settings(self):
        src = os.path.join(self.tmp.name, "json")
        os.makedirs(src)
        kit.write_zeek_conn(os.path.join(src, "conn.log"), sample.sessions())
        with open(os.path.join(src, "http.log"), "w", encoding="utf-8") as fh:
            for row in http_rows():
                fh.write(json.dumps(dict(zip(kit.HTTP_FIELDS, row)) | {"ts": float(row[0]), "_path": "http"}) + "\n")
        res, _ = run([src], os.path.join(src, "out"))
        self.assertEqual(len(res["detection"]["tool_clients"]), 4)
        # your own entry, an entry dropped, and the switch
        _, det, _ = self.analyze(http=http_rows(), settings={"web": {"user_agents": {"Shared SDK": ["norma/"], "ARTEX": []}}})
        self.assertEqual({t["source"]: t["tools"] for t in det["tool_clients"] if not t["internal"]},
                         {BROWSER: ["Shared SDK"], HEX_SRC: ["HexStrike AI"], sample.AGENT: ["CyberStrikeAI"]})
        _, det, md = self.analyze(http=http_rows(), dns=dns_rows(), settings={"web": {"check": False}})
        self.assertEqual((det["tool_clients"], det["name_contacts"]), ([], []))
        self.assertTrue("- Zeek http, dns and ssl logs: not checked" in md)
        _, det, _ = self.analyze(http=http_rows(), settings={"allowlist": [ARTEX_SRC]})
        self.assertFalse(ARTEX_SRC in {t["source"] for t in det["tool_clients"]})
        for bad in ({"user_agents": {"x": ["ab"]}}, {"names": {"x": ["not a name"]}}, {"names": {"x": "api.x.ai"}}):
            with self.assertRaises(UserError):
                self.analyze(settings={"web": bad})

    def test_records_older_than_the_lookback_are_left_out(self):
        old = [kit.http_row(sample.T0 - 80 * 3600, ARTEX_SRC, WEB, "artex-enrich/1.0")]
        _, det, _ = self.analyze(http=old)
        self.assertEqual(det["tool_clients"], [])


if __name__ == "__main__":
    unittest.main()
