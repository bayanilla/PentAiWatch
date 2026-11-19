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
3. Nothing in the capture itself is flagged as agentic, and the other signals (published
   addresses, machine-steady repetition, high-rate spray, rotating sources) find what EXPECTED
   says, from every form of the log. One source sweeps and then narrows, an nmap run: a
   ping sweep, a port scan, then service detection on what answered. Its pace is what tells it
   from an agentic tool, and the bursts and pauses PentAIWatch counts for it are the ones the
   plain reader counts: 6 bursts, 5 pauses, none of them 20 to 35 seconds long.
4. The synthetic agentic source the unit tests use, added to the capture, IS flagged, at level 1:
   from Zeek alone, from a Palo Alto form of the same sessions alone, and from both. Its bursts
   and pauses match the plain reader's too. With both logs every session is counted once.
5. The Explorer's Timeline of the nmap run and of the agentic source holds the sessions and the
   bursts the plain reader counts. The nmap run has more sessions than a Timeline draws, so every
   second one is drawn and all are counted.

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
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from pentaiwatch import explore        # noqa: E402  (to read the data inside explorer.html)
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
    # 14 of the 15 sweeping sources never narrow. The nmap run does, at a scanner's pace, so nothing
    # in the capture is flagged. (It was a tier 0 finding before the timing signal. And before pings
    # were judged by their reply in Zeek logs too, only the Palo Alto form saw its sweep.)
    "narrowing_sources": 1,
    "nmap_pace": {"sessions": 39_746, "bursts": 6, "pauses": 5, "pauses_in_band": 0},
    "flagged": [],
    # The other signals, the same from every form of the log. Two red-team sources hammer single
    # services with completed connections, well over one a second for minutes: a web server's port 80
    # (10.128.0.248, up to 179 a minute) and web and VNC ports on several hosts (10.164.94.120, up to
    # 411 a minute). That is the brute force the spray signal is for. Nothing is on the published
    # address lists, nothing keeps a machine-steady gap, and no sweep is followed by new addresses.
    "other_signals": {"known": [], "steady": [], "spray": ["10.128.0.248", "10.164.94.120"], "rotation": []},
    # with the synthetic agent added: [source, level], the same from every form of the log
    "with_agent_flagged": [[sample.AGENT, 1]],
    # Whole-second firewall times make 713 rows the same as another row (same second, addresses,
    # ports, protocol and action); each is kept once. 298 of them are pings, which have no ports
    # to tell two in one second apart.
    "paloalto_sessions_fewer": 713,
}
FAILED = {"S0", "REJ", "RSTOS0", "RSTR"}          # the default probing.zeek_failed_states
MIN_PORTS, MIN_HOSTS, MIN_FAILED = 50, 20, 0.70   # the default probing thresholds
BURST_GAP, MAX_BURST, PAUSE_MIN, PAUSE_MAX = 15, 15, 20, 35      # the default timing settings, in seconds


def records(conn_log: str):
    """(line number, {field: value}) for every record of a Zeek conn.log in TSV, plain or .gz."""
    opener = gzip.open if conn_log.endswith(".gz") else open
    fields: list[str] = []
    with opener(conn_log, "rt", encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh):
            if line.startswith("#"):
                if line.startswith("#fields"):
                    fields = line.rstrip("\n").split("\t")[1:]
                continue
            yield n, dict(zip(fields, line.rstrip("\n").split("\t")))


def micros(ts: str) -> int:
    """A Zeek ts ("1521911720.602122") in whole microseconds, without going through a float."""
    whole, _, part = ts.partition(".")
    return int(whole) * 1_000_000 + int((part + "000000")[:6])


def rhythm(starts: list[int]) -> dict:
    """The bursts and pauses in a source's session start times (microseconds), read plainly: a gap
    of more than BURST_GAP seconds ends a burst and is the pause that follows it."""
    starts = sorted(starts)
    sizes, pauses = [1], []
    for before, after in zip(starts, starts[1:]):
        if after - before > BURST_GAP * 1_000_000:
            pauses.append((after - before) / 1e6)
            sizes.append(1)
        else:
            sizes[-1] += 1
    in_band = [PAUSE_MIN <= p <= PAUSE_MAX for p in pauses]
    # the pauses that count towards the signal: in the band, after a burst that is short
    paced = [p for size, p, ok in zip(sizes, pauses, in_band) if ok and size <= MAX_BURST]
    return {"sessions": len(starts), "bursts": len(sizes), "pauses": len(pauses), "pauses_in_band": sum(in_band),
            "paced_bursts": len(paced), "typical_pause": round(statistics.median(paced), 1) if paced else None}


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
    nmap: list[int] = []                           # when each of the nmap run's inbound sessions started
    for n, r in records(conn_log):
        sessions += 1
        src, dst = r["id.orig_h"], r["id.resp_h"]
        if internal(src) or not internal(dst):
            continue
        inbound += 1
        if src == NMAP:
            nmap.append(micros(r["ts"]))
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
    pace = rhythm(nmap)
    return {"sessions": sessions, "inbound_sessions": inbound, "outside_sources": len(per_source),
            "sweeping_sources": len(sweeping), "nmap_pace": {k: pace[k] for k in EXPECTED["nmap_pace"]},
            "nmap_timeline": timeline_of(pace)}


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
    res["explorer_page"] = os.path.join(out, explore.FILENAME)
    return res


def summary(res: dict) -> dict:
    d = res["detection"]
    return {"sessions": res["sessions"], "inbound_sessions": d["inbound_sessions"],
            "outside_sources": d["outside_sources"], "sweeping_sources": d["probing_sources"],
            "narrowing_sources": d["narrowing_sources"],
            "flagged": sorted([f["source"], f["level"]] for f in d["findings"]),
            "other_signals": {"known": sorted(k["source"] for k in d.get("known_sources") or []),
                              "steady": sorted(v["source"] for v in d.get("steady_sources") or []),
                              "spray": sorted(v["source"] for v in d.get("spray_sources") or []),
                              "rotation": sorted(g["sweeper"] for g in d.get("rotations") or [])}}


def drawn_pace(res: dict, source: str) -> dict | None:
    """The pace the Explorer page gives for a source that narrowed and is not flagged."""
    with open(res["explorer_page"], encoding="utf-8") as fh:
        data = explore.read_data(fh.read())
    for s in data["sources"]:
        if s["ip"] == source and "pace" in s:
            return {"sessions": s["sessions"], "bursts": s["pace"]["bursts_all"], "pauses": s["pace"]["pauses"],
                    "pauses_in_band": s["pace"]["pauses_in_band"]}
    return None


def drawn_timeline(res: dict, source: str) -> dict | None:
    """What the Explorer page's Timeline holds for a source: its sessions, how many of them are
    drawn, its bursts, the pauses in the band, and the bursts the timing signal counted."""
    with open(res["explorer_page"], encoding="utf-8") as fh:
        t = explore.read_data(fh.read()).get("timelines", {}).get(source)
    if not t:
        return None
    return {"sessions": t["sessions_total"], "drawn": len(t["sessions"]), "bursts": t["bursts_total"],
            "pauses_in_band": sum(1 for b in t["bursts"] if b[4] >= 1),
            "paced_bursts": sum(1 for b in t["bursts"] if b[4] == 2)}


def timeline_of(pace: dict) -> dict:
    """The same, as the plain reader's bursts and pauses say it should be."""
    every = -(-pace["sessions"] // explore.MAX_TIMELINE_SESSIONS)
    return {"sessions": pace["sessions"], "drawn": -(-pace["sessions"] // every), "bursts": pace["bursts"],
            "pauses_in_band": pace["pauses_in_band"], "paced_bursts": pace["paced_bursts"]}


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
    checks.append(("Zeek: sources that swept and then narrowed", EXPECTED["narrowing_sources"],
                   got["zeek_tsv"]["narrowing_sources"]))
    checks.append(("ground truth: the nmap run's bursts and pauses", EXPECTED["nmap_pace"], truth["nmap_pace"]))
    checks.append(("Zeek: the nmap run's bursts and pauses", truth["nmap_pace"], drawn_pace(runs["zeek_tsv"], NMAP)))
    checks.append(("Zeek: the nmap run's Timeline (every second session drawn, all counted)", truth["nmap_timeline"],
                   drawn_timeline(runs["zeek_tsv"], NMAP)))
    checks.append(("Zeek: flagged in the capture itself", EXPECTED["flagged"], got["zeek_tsv"]["flagged"]))
    for name in ("zeek_tsv", "zeek_json", "zeek_with_agent", "paloalto_with_agent", "both_with_agent"):
        checks.append((f"{name}: published addresses, steady, spray and rotating sources",
                       EXPECTED["other_signals"], got[name]["other_signals"]))
    for name in ("zeek_with_agent", "paloalto_with_agent", "both_with_agent"):
        checks.append((f"{name}: flagged, with the level", EXPECTED["with_agent_flagged"], got[name]["flagged"]))
        checks.append((f"{name}: sources that swept and then narrowed", EXPECTED["narrowing_sources"] + 1,
                       got[name]["narrowing_sources"]))
    # the agent's bursts and pauses, from the Zeek log it was written to
    plain = rhythm([micros(r["ts"]) for _, r in records(agent_zeek)])
    timing = next((f["timing"] for f in runs["zeek_with_agent"]["detection"]["findings"]
                   if f["source"] == sample.AGENT), {})
    checks.append(("zeek_with_agent: the agent's short bursts with a pause in the band, all its bursts, typical pause",
                   [plain["paced_bursts"], plain["bursts"], plain["typical_pause"]],
                   [timing.get("bursts"), timing.get("bursts_all"), timing.get("typical_pause_seconds")]))
    checks.append(("zeek_with_agent: the agent's Timeline", timeline_of(plain), drawn_timeline(runs["zeek_with_agent"], sample.AGENT)))
    with_agent = EXPECTED["sessions"] + len(agent)
    checks.append(("zeek_with_agent: sessions", with_agent, got["zeek_with_agent"]["sessions"]))
    fewer = with_agent - EXPECTED["paloalto_sessions_fewer"]
    checks.append(("paloalto_with_agent: sessions", fewer, got["paloalto_with_agent"]["sessions"]))
    checks.append(("both_with_agent: each session counted once", fewer, got["both_with_agent"]["sessions"]))
    checks.append(("both_with_agent: logs the finding was built from", [["paloalto", "zeek"]],
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
