"""Rewrite a Zeek conn.log (TSV, plain or .gz) as a Palo Alto traffic export, row for row.

Used by check.py to run both readers over the same real sessions. It is NOT a real firewall
log: every session is written as allowed (a tap cannot know the policy), times are cut to whole
seconds as a firewall logs them, and bytes and packets are Zeek's IP-level counts.

Usage: python3 to_paloalto.py CONN_LOG OUT_CSV
"""
import csv
import gzip
import sys
from datetime import datetime, timezone

HEADER = ["Receive Time", "Serial #", "Type", "Threat/Content Type", "Source address", "Destination address",
          "Rule", "Application", "Source Zone", "Destination Zone", "Source Port", "Destination Port",
          "IP Protocol", "Action", "Bytes", "Bytes Sent", "Bytes Received", "Start Time",
          "Threat/Content Name", "Severity", "Elapsed Time (sec)", "Packets Received"]


def _time(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y/%m/%d %H:%M:%S")


def _count(value: str) -> int:
    return int(float(value)) if value not in ("-", "", "(empty)") else 0


def convert(src: str, out: str) -> int:
    opener = gzip.open if src.endswith(".gz") else open
    fields, rows = None, 0
    with opener(src, "rt", encoding="utf-8", errors="replace") as fh, open(out, "w", newline="", encoding="utf-8") as oh:
        w = csv.writer(oh)
        w.writerow(HEADER)
        for line in fh:
            if line.startswith("#"):
                if line.startswith("#fields"):
                    fields = line.rstrip("\n").split("\t")[1:]
                continue
            r = dict(zip(fields or [], line.rstrip("\n").split("\t")))
            if r.get("ts", "-") in ("-", ""):
                continue
            start = float(r["ts"])
            began = int(start)
            ended = int(start + (float(r["duration"]) if r["duration"] not in ("-", "") else 0.0))
            sent, back = _count(r["orig_ip_bytes"]), _count(r["resp_ip_bytes"])
            w.writerow([_time(ended), "016401000001", "TRAFFIC", "end", r["id.orig_h"], r["id.resp_h"], "any", "",
                        "outside", "inside", r["id.orig_p"], r["id.resp_p"], r["proto"], "allow", sent + back,
                        sent, back, _time(began), "", "", ended - began, _count(r["resp_pkts"])])
            rows += 1
    return rows


if __name__ == "__main__":
    print(convert(sys.argv[1], sys.argv[2]), "rows written to", sys.argv[2])
