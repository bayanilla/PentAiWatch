"""Build PentAIWatch's two bundled samples and their Palo Alto versions.

The samples are VulnScope MAX's ARTEX and CyberStrikeAI stories (samples/artex_ai_agentic_intrusion
and samples/cyberstrike_ai_fortigate_intrusion at MAX commit cbdd106), fabricated and plain text.
MAX's versions have no sweep: every outside source goes straight to the one or two services it
uses, because MAX's story maps the targets through web requests, which a connection log does not
show. PentAIWatch's copies add one, made up: before its first session, each outside source with 30
or more sessions sweeps the target's address range on a handful of common ports, about one probe a
second, ending 90 seconds before that first session. What it later uses answers the sweep; nothing
else does. Nothing else in the logs is changed. The sweep is the only part that is not MAX's.

    python scripts/samples/build.py sweep MAX_CONN_LOG RANGE PORTS OUT_CONN_LOG
        Write MAX's conn.log with the sweeps added. RANGE is the first three octets of the swept /24
        (for example 10.50.1); PORTS is a comma-separated list.
    python scripts/samples/build.py paloalto CONN_LOG OUT_DIR
        Write the Palo Alto traffic versions of a conn.log into OUT_DIR, one folder each:
          paloalto/traffic.csv               with the session start time
          paloalto_elapsed_only/traffic.csv  no start time, with elapsed seconds (start = end - elapsed)
          paloalto_no_start/traffic.csv      neither: only the log (end) time
        The columns are those of MAX's sample export. A probe nothing answered (S0) is written as
        stopped by the firewall (deny); everything else as allowed, with the bytes Zeek saw coming
        back (60 bytes for a completed or refused handshake that carried no data). Times are cut to
        whole seconds, as a firewall logs them. Threat rows are not written: their layout waits for
        real sanitised rows.

Everything is deterministic: the same input gives the same files, byte for byte.
"""
from __future__ import annotations

import csv
import ipaddress
import os
import random
import sys
from datetime import datetime, timezone

MIN_SESSIONS = 30          # outside sources with this many sessions or more get a sweep
LEAD_SECONDS = 90          # the sweep ends this long before the source's first session
HEADER = ["Receive Time", "Serial #", "Type", "Threat/Content Type", "Source address", "Destination address",
          "Rule", "Application", "Source Zone", "Destination Zone", "Source Port", "Destination Port",
          "IP Protocol", "Action", "Bytes", "Bytes Sent", "Bytes Received", "Start Time",
          "Threat/Content Name", "Severity", "Elapsed Time (sec)"]
VARIANTS = {"paloalto": ("start",), "paloalto_elapsed_only": ("elapsed",), "paloalto_no_start": ()}


def read_conn(path: str) -> tuple[list[str], list[str], list[dict]]:
    """(header lines before #fields, field names, records) of a Zeek conn.log in TSV."""
    head, fields, rows = [], [], []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                head.append(line)
            elif line.startswith("#"):
                head.append(line)
            elif line:
                rows.append(dict(zip(fields, line.split("\t"))))
    return head, fields, rows


def _outside(ip: str) -> bool:
    return not ipaddress.ip_address(ip).is_private


def add_sweeps(rows: list[dict], prefix: str, ports: list[int]) -> list[dict]:
    """The sweep records for every outside source with MIN_SESSIONS or more sessions."""
    by_src: dict[str, list[dict]] = {}
    for r in rows:
        if _outside(r["id.orig_h"]):
            by_src.setdefault(r["id.orig_h"], []).append(r)
    open_svc = {(r["id.resp_h"], int(r["id.resp_p"])) for r in rows
                if _outside(r["id.orig_h"]) and r["conn_state"] == "SF"}
    hosts = [f"{prefix}.{i}" for i in range(1, 31)]
    out = []
    for n, (src, recs) in enumerate(sorted(by_src.items())):
        if len(recs) < MIN_SESSIONS:
            continue
        rng = random.Random(f"{src}/{prefix}")
        targets = [(h, p) for h in hosts for p in ports]
        # what the source uses later answers its sweep, even outside the range or the ports
        targets += sorted({(r["id.resp_h"], int(r["id.resp_p"])) for r in recs} - set(targets))
        rng.shuffle(targets)
        steps = [rng.uniform(0.6, 1.4) for _ in targets]
        t = min(float(r["ts"]) for r in recs) - LEAD_SECONDS - sum(steps)
        for i, ((host, port), step) in enumerate(zip(targets, steps)):
            answered = (host, port) in open_svc
            state = "SF" if answered else ("REJ" if rng.random() < 0.04 else "S0")
            history = {"SF": "ShAFaf", "REJ": "Sr", "S0": "S"}[state]
            out.append({"ts": f"{t:.6f}", "uid": f"W{n:02d}{i:06d}", "id.orig_h": src,
                        "id.orig_p": str(rng.randint(40000, 60999)), "id.resp_h": host, "id.resp_p": str(port),
                        "proto": "tcp", "service": "-", "duration": "0.051" if answered else "-",
                        "orig_bytes": "0", "resp_bytes": "0", "conn_state": state, "history": history})
            t += step
    return out


def write_conn(path: str, head: list[str], fields: list[str], rows: list[dict]) -> None:
    rows = sorted(rows, key=lambda r: (float(r["ts"]), r["uid"]))
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for line in head:
            if not line.startswith("#close"):
                fh.write(line + "\n")
        for r in rows:
            fh.write("\t".join(r.get(f, "-") for f in fields) + "\n")
        for line in head:
            if line.startswith("#close"):
                fh.write(line + "\n")


def _time(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y/%m/%d %H:%M:%S")


def _count(value: str) -> int:
    return int(float(value)) if value not in ("-", "", "(empty)") else 0


def paloalto(conn: str, outdir: str) -> dict[str, int]:
    """Write the three Palo Alto versions of ``conn``; returns rows written per folder."""
    _, _, rows = read_conn(conn)
    written = {}
    for folder, has in VARIANTS.items():
        header = [h for h in HEADER if (h != "Start Time" or "start" in has)
                  and (h != "Elapsed Time (sec)" or "elapsed" in has)]
        os.makedirs(os.path.join(outdir, folder), exist_ok=True)
        with open(os.path.join(outdir, folder, "traffic.csv"), "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerow(header)
            for r in rows:
                began = int(float(r["ts"]))
                dur = float(r["duration"]) if r["duration"] not in ("-", "") else 0.0
                ended = int(float(r["ts"]) + dur)
                denied = r["conn_state"] == "S0"
                back = _count(r["resp_bytes"])
                if not denied and back == 0 and r["conn_state"] in ("SF", "S1", "S2", "S3", "RSTO", "RSTR", "REJ"):
                    back = 60                     # the handshake or the reset that came back
                sent = _count(r["orig_bytes"]) + 60
                row = {"Receive Time": _time(ended), "Serial #": "016401000001", "Type": "TRAFFIC",
                       "Threat/Content Type": "deny" if denied else "end", "Source address": r["id.orig_h"],
                       "Destination address": r["id.resp_h"], "Rule": "any",
                       "Application": "incomplete" if denied else (r["service"] if r["service"] != "-" else "ssl"),
                       "Source Zone": "untrust" if _outside(r["id.orig_h"]) else "trust",
                       "Destination Zone": "untrust" if _outside(r["id.resp_h"]) else "dmz",
                       "Source Port": r["id.orig_p"], "Destination Port": r["id.resp_p"], "IP Protocol": r["proto"],
                       "Action": "deny" if denied else "allow", "Bytes": sent + (0 if denied else back),
                       "Bytes Sent": sent, "Bytes Received": 0 if denied else back, "Start Time": _time(began),
                       "Threat/Content Name": "", "Severity": "", "Elapsed Time (sec)": ended - began}
                w.writerow([row[h] for h in header])
        written[folder] = len(rows)
    return written


def main(argv: list[str]) -> int:
    if len(argv) == 5 and argv[0] == "sweep":
        src, prefix, ports, out = argv[1], argv[2], [int(p) for p in argv[3].split(",")], argv[4]
        head, fields, rows = read_conn(src)
        sweeps = add_sweeps(rows, prefix, ports)
        write_conn(out, head, fields, rows + sweeps)
        print(f"{len(rows):,} sessions from {src}, {len(sweeps):,} sweep probes added, written to {out}")
        return 0
    if len(argv) == 3 and argv[0] == "paloalto":
        for folder, n in paloalto(argv[1], argv[2]).items():
            print(f"{n:,} rows written to {os.path.join(argv[2], folder, 'traffic.csv')}")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
