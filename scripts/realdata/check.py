#!/usr/bin/env python3
"""Check PentAIWatch on a real capture: Brim's public WRCCDC 2018 Zeek logs, a million sessions.

    python3 scripts/realdata/fetch.py DATA_DIR
    python3 scripts/realdata/check.py DATA_DIR WORK_DIR

The capture is 21 minutes of a cyber defence competition recorded in 2018. It holds scanners,
exploit attempts and ordinary traffic, and no agentic tool: there were none. Every address in it
is private, so the competition network 10.47.0.0/16 is set as internal and the rest is outside.

What is checked:

1. The counts PentAIWatch reports (sessions, inbound sessions, outside sources, sweeping sources)
   against the same counts worked out here by a separate, plain reader of conn.log that shares
   no code with PentAIWatch.
2. The TSV and JSON forms of the log give the same result.
3. The same sources are flagged from every form of the log. In the capture itself that is one
   source, an nmap run: a ping sweep, a port scan, then service detection on what answered. Sweep
   then narrow is what that looks like, so it is a tier 0 finding until the timing signal exists
   to tell it from an agentic tool.
4. The synthetic agentic source the unit tests use, added to the capture, IS flagged: from Zeek
   alone, from a Palo Alto form of the same sessions alone, and from both. With both logs every
   session is counted once.

The Palo Alto form is written by to_paloalto.py from the Zeek log. It is not a real firewall log,
so it checks that the two readers agree on the same sessions, not that the Palo Alto defaults fit
a real export.

The numbers in EXPECTED are facts about the pinned files under the default settings. A change to
a detection rule that moves one of them has to change it here, in the same pull request, where a
reviewer sees it.
"""
from __future__ import annotations

import gzip
import ipaddress
import json
import os
import random
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from tests import kit, sample          # noqa: E402  (the synthetic agent)
from to_paloalto import convert        # noqa: E402

INTERNAL = "10.47.0.0/16"
CAPTURE_START = 1521911720             # 2018-03-24 17:15:20 UTC, the first session
NMAP = "10.128.0.207"                  # a ping sweep, a port scan, then service detection
EXPECTED = {
    "sessions": 1_021_950,
    "inbound_sessions": 665_091,
    "outside_sources": 45,
    "sweeping_sources": 15,
    # 14 of the 15 sweeping sources never narrow. The nmap run does, and is flagged from every form
    # of the log. (Before pings were judged by their reply in Zeek logs too, only the Palo Alto
    # form saw its sweep.) When the timing signal lands, expect it to leave these lists.
    "zeek_flagged": [NMAP],
    "zeek_with_agent_flagged": [NMAP, sample.AGENT],
    "paloalto_with_agent_flagged": [NMAP, sample.AGENT],
    "both_with_agent_flagged": [NMAP, sample.AGENT],
    # Whole-second firewall times make 713 rows the same as another row (same second, addresses,
    # ports, protocol and action); each is kept once. 298 of them are pings, which have no ports
    # to tell two in one second apart.
    "paloalto_sessions_fewer": 713,
}
FAILED = {"S0", "REJ", "RSTOS0", "RSTR"}          # the default probing.zeek_failed_states
MIN_PORTS, MIN_HOSTS, MIN_FAILED = 50, 20, 0.70   # the default probing thresholds


def ground_truth(conn_log: str) -> dict:
    """The capture's counts from a plain reading of conn.log (TSV), sharing no code with PentAIWatch."""
    net = ipaddress.ip_network(INTERNAL)
    inside: dict[str, bool] = {}

    def internal(ip: str) -> bool:
        if ip not in inside:
            try:
                inside[ip] = ipaddress.ip_address(ip) in net
            except ValueError:
                inside[ip] = False
        return inside[ip]

    sessions = inbound = 0
    first: dict[tuple, tuple] = {}                 # (source, host, port, proto) -> (ts, line, state)
    fields: list[str] = []
    with gzip.open(conn_log, "rt", encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh):
            if line.startswith("#"):
                if line.startswith("#fields"):
                    fields = line.rstrip("\n").split("\t")[1:]
                continue
            r = dict(zip(fields, line.rstrip("\n").split("\t")))
            sessions += 1
            src, dst = r["id.orig_h"], r["id.resp_h"]
            if internal(src) or not internal(dst):
                continue
            inbound += 1
            icmp = r["proto"] == "icmp"
            # a ping has no ports (Zeek writes the ICMP type and code there) and no telling state
            # (always OTH): it failed when nothing came back
            key = (src, dst, "0" if icmp else r["id.resp_p"], r["proto"])
            failed = r["resp_pkts"] == "0" if icmp else r["conn_state"] in FAILED
            seen = (float(r["ts"]), n, failed)
            if key not in first or seen < first[key]:
                first[key] = seen
    per_source: dict[str, dict] = {}
    for (src, dst, port, proto), (_, _, failed) in first.items():
        s = per_source.setdefault(src, {"services": 0, "hosts": set(), "ports": set(), "failed": 0})
        s["services"] += 1
        s["hosts"].add(dst)
        if proto in ("tcp", "udp"):
            s["ports"].add(port)
        s["failed"] += failed
    sweeping = sorted(src for src, s in per_source.items()
                      if (len(s["ports"]) >= MIN_PORTS or len(s["hosts"]) >= MIN_HOSTS)
                      and s["failed"] >= MIN_FAILED * s["services"])
    return {"sessions": sessions, "inbound_sessions": inbound, "outside_sources": len(per_source),
            "sweeping_sources": len(sweeping)}


def analyze(name: str, inputs: list[str], work: str) -> dict:
    """Run the command line on ``inputs`` and return its results.json."""
    out = os.path.join(work, "runs", name)
    cfg = os.path.join(work, "pentaiwatch.json")
    started = time.time()
    done = subprocess.run([sys.executable, "-m", "pentaiwatch", "analyze", *inputs, "-o", out, "--config", cfg,
                           "--workdir", os.path.join(work, "tmp")], cwd=ROOT, capture_output=True, text=True)
    if done.returncode:
        sys.exit(f"PentAIWatch failed on {name}:\n{done.stdout}\n{done.stderr}")
    with open(os.path.join(out, "results.json"), encoding="utf-8") as fh:
        res = json.load(fh)
    res["seconds"] = round(time.time() - started, 1)
    return res


def summary(res: dict) -> dict:
    d = res["detection"]
    return {"sessions": res["sessions"], "inbound_sessions": d["inbound_sessions"],
            "outside_sources": d["outside_sources"], "sweeping_sources": d["probing_sources"],
            "flagged": sorted(f["source"] for f in d["findings"])}


def main(data: str, work: str) -> int:
    os.makedirs(os.path.join(work, "agent"), exist_ok=True)
    with open(os.path.join(work, "pentaiwatch.json"), "w", encoding="utf-8") as fh:
        json.dump({"internal_nets": [INTERNAL]}, fh)
    tsv = os.path.join(data, "wrccdc_tsv", "conn.log.gz")
    as_json = os.path.join(data, "wrccdc_json", "conn.json.gz")

    # the tests' agentic source, moved into the capture: it starts a minute in and targets 10.47.x
    shift = CAPTURE_START + 60 - (sample.T0 + 600)
    agent = [dict(s, ts=s["ts"] + shift, dst=s["dst"].replace("10.10.", "10.47."))
             for s in sample.agent(random.Random(7))]
    agent_zeek = kit.write_zeek_conn(os.path.join(work, "agent", "agent_conn.log"), agent)
    agent_fw = kit.write_paloalto(os.path.join(work, "agent", "agent_traffic.csv"), agent, elapsed=True, packets=True)
    firewall = os.path.join(work, "paloalto_traffic.csv")
    if not os.path.exists(firewall):
        convert(tsv, firewall)

    truth = ground_truth(tsv)
    runs = {
        "zeek_tsv": analyze("zeek_tsv", [tsv], work),
        "zeek_json": analyze("zeek_json", [as_json], work),
        "zeek_with_agent": analyze("zeek_with_agent", [tsv, agent_zeek], work),
        "paloalto_with_agent": analyze("paloalto_with_agent", [firewall, agent_fw], work),
        "both_with_agent": analyze("both_with_agent", [tsv, agent_zeek, firewall, agent_fw], work),
    }
    got = {name: summary(res) for name, res in runs.items()}
    counts = ("sessions", "inbound_sessions", "outside_sources", "sweeping_sources")
    checks = []           # (what, expected, got)
    for key in counts:
        checks.append((f"ground truth: {key}", EXPECTED[key], truth[key]))
        checks.append((f"Zeek TSV: {key}", truth[key], got["zeek_tsv"][key]))
    checks.append(("Zeek JSON gives what Zeek TSV gives", got["zeek_tsv"], got["zeek_json"]))
    checks.append(("Zeek: flagged in the capture itself", EXPECTED["zeek_flagged"], got["zeek_tsv"]["flagged"]))
    for name in ("zeek_with_agent", "paloalto_with_agent", "both_with_agent"):
        checks.append((f"{name}: flagged", sorted(EXPECTED[f"{name}_flagged"]), got[name]["flagged"]))
    with_agent = EXPECTED["sessions"] + len(agent)
    checks.append(("zeek_with_agent: sessions", with_agent, got["zeek_with_agent"]["sessions"]))
    fewer = with_agent - EXPECTED["paloalto_sessions_fewer"]
    checks.append(("paloalto_with_agent: sessions", fewer, got["paloalto_with_agent"]["sessions"]))
    checks.append(("both_with_agent: each session counted once", fewer, got["both_with_agent"]["sessions"]))
    checks.append(("both_with_agent: logs each finding was built from", [["paloalto", "zeek"]] * 2,
                   [f["log_sources"] for f in runs["both_with_agent"]["detection"]["findings"]]))
    checks.append(("both_with_agent: clock warning", [], [w for w in runs["both_with_agent"]["warnings"] if "clock" in w]))

    failed = 0
    for what, expected, value in checks:
        ok = expected == value
        failed += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  {what}: {value}" + ("" if ok else f"   (expected {expected})"))
    print()
    for name, res in runs.items():
        print(f"{name:22} {res['sessions']:>9,} sessions in {res['seconds']:>5} s, flagged {got[name]['flagged']}")
    print(f"\n{len(checks) - failed} of {len(checks)} checks passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])))
