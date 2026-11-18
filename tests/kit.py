"""Writers for small synthetic logs used by the tests. Addresses are documentation ranges
(RFC 5737) for outside sources and 10.x for internal hosts."""
from __future__ import annotations

import csv
import gzip
from datetime import datetime, timezone

ZEEK_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
               "duration", "orig_bytes", "resp_bytes", "conn_state", "history", "orig_pkts", "resp_pkts"]
ZEEK_TYPES = ["time", "string", "addr", "port", "addr", "port", "enum", "string",
              "interval", "count", "count", "string", "string", "count", "count"]
# The header of the Palo Alto CSV export bundled with VulnScope MAX's samples.
PA_HEADER = ["Receive Time", "Serial #", "Type", "Threat/Content Type", "Source address",
             "Destination address", "Rule", "Application", "Source Zone", "Destination Zone",
             "Source Port", "Destination Port", "IP Protocol", "Action", "Bytes", "Bytes Sent",
             "Bytes Received", "Start Time", "Threat/Content Name", "Severity"]
# conn_state -> (history, orig_bytes, resp_bytes, orig_pkts, resp_pkts) for a plausible record
_STATE_SHAPE = {"S0": ("S", 0, 0, 1, 0), "REJ": ("Sr", 0, 0, 1, 1), "RSTOS0": ("SR", 0, 0, 2, 0),
                "RSTR": ("ShAr", 0, 0, 2, 2), "SF": ("ShADadFf", 420, 2600, 8, 7),
                "S1": ("ShADad", 380, 1900, 6, 5), "RSTO": ("ShADadR", 300, 1500, 6, 5)}


def session(ts: float, src: str, dst: str, dport: int, state: str = "SF", sport: int | None = None,
            proto: str = "tcp", duration: float = 0.4) -> dict:
    """One session as a plain dict; ``ts`` is the START in epoch seconds."""
    return {"ts": ts, "src": src, "dst": dst, "dport": dport, "state": state,
            "sport": sport if sport is not None else 20000 + int(ts * 7 + dport) % 40000,
            "proto": proto, "duration": duration}


def write_zeek_conn(path: str, sessions: list[dict]) -> str:
    """A Zeek conn.log in TSV form (plain, or gzip when the name ends in .gz)."""
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "wt", encoding="utf-8") as fh:
        fh.write("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n")
        fh.write("#fields\t" + "\t".join(ZEEK_FIELDS) + "\n#types\t" + "\t".join(ZEEK_TYPES) + "\n")
        for i, s in enumerate(sessions):
            hist, ob, rb, op, rp = _STATE_SHAPE.get(s["state"], ("S", 0, 0, 1, 0))
            fh.write("\t".join(str(v) for v in (
                f"{s['ts']:.6f}", f"C{i:08d}", s["src"], s["sport"], s["dst"], s["dport"], s["proto"], "-",
                f"{s['duration']:.6f}", ob, rb, s["state"], hist, op, rp)) + "\n")
    return path


def _pa_time(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y/%m/%d %H:%M:%S")


def write_paloalto(path: str, sessions: list[dict], denied=("S0",)) -> str:
    """A Palo Alto TRAFFIC export with the bundled sample's columns: sessions in ``denied`` states
    are logged as deny, completed ones as allow with bytes back, the rest as allow with none."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(PA_HEADER)
        for s in sessions:
            _, ob, rb, _, _ = _STATE_SHAPE.get(s["state"], ("S", 0, 0, 1, 0))
            action = "deny" if s["state"] in denied else "allow"
            end = s["ts"] + s["duration"]
            w.writerow([_pa_time(end), "016401000001", "TRAFFIC", "end", s["src"], s["dst"], "rule1",
                        "incomplete" if not rb else "web-browsing", "untrust", "dmz", s["sport"],
                        s["dport"], s["proto"], action, ob + rb, ob, rb, _pa_time(s["ts"]), "", ""])
    return path
