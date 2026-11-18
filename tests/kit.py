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


# What a Palo Alto firewall logs for a session Zeek would give each conn_state, when policy allows
# it: (bytes sent, bytes received, packets received). The firewall counts whole packets, headers
# included, so a lone reset from a closed port (Zeek REJ) is 60 bytes and one packet back.
_PA_SHAPE = {"S0": (74, 0, 0), "REJ": (74, 60, 1), "RSTOS0": (128, 0, 0), "RSTR": (414, 320, 3),
             "SF": (1160, 3340, 7), "S1": (980, 2440, 5), "RSTO": (900, 2040, 5)}


def paloalto_rows(sessions: list[dict], denied=("S0",), start: bool = True, elapsed: bool = False,
                  packets: bool = False, clock_offset: float = 0.0) -> tuple[list[str], list[list]]:
    """(header, rows) of a Palo Alto TRAFFIC export for ``sessions``.

    The columns are those of the export bundled with VulnScope MAX's samples. Sessions whose state
    is in ``denied`` were stopped by policy (action deny, nothing back); the rest were allowed.
    ``start=False`` leaves the Start Time column out, ``elapsed`` adds "Elapsed Time (sec)" and
    ``packets`` adds "Packets Received". Firewall times are whole seconds; ``clock_offset`` moves
    the firewall's clock by that many seconds."""
    header = [h for h in PA_HEADER if start or h != "Start Time"]
    header += (["Elapsed Time (sec)"] if elapsed else []) + (["Packets Received"] if packets else [])
    rows = []
    for s in sessions:
        sent, back, pkts = (74, 0, 0) if s["state"] in denied else _PA_SHAPE.get(s["state"], (74, 0, 0))
        began, ended = int(s["ts"] + clock_offset), int(s["ts"] + clock_offset + s["duration"])
        row = {"Receive Time": _pa_time(ended), "Serial #": "016401000001", "Type": "TRAFFIC",
               "Threat/Content Type": "deny" if s["state"] in denied else "end", "Source address": s["src"],
               "Destination address": s["dst"], "Rule": "inbound", "Application": "ssl" if back > 100 else "incomplete",
               "Source Zone": "untrust", "Destination Zone": "dmz", "Source Port": s["sport"],
               "Destination Port": s["dport"], "IP Protocol": s["proto"],
               "Action": "deny" if s["state"] in denied else "allow", "Bytes": sent + back, "Bytes Sent": sent,
               "Bytes Received": back, "Start Time": _pa_time(began), "Threat/Content Name": "", "Severity": "",
               "Elapsed Time (sec)": ended - began, "Packets Received": pkts}
        rows.append([row[h] for h in header])
    return header, rows


def write_paloalto(path: str, sessions: list[dict], rename: dict[str, str] | None = None, **kw) -> str:
    """A Palo Alto TRAFFIC export as CSV with a header row (see ``paloalto_rows`` for the options).
    ``rename`` gives columns other names, as an export from another tool would have."""
    header, rows = paloalto_rows(sessions, **kw)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow([(rename or {}).get(h, h) for h in header])
        w.writerows(rows)
    return path


def write_paloalto_syslog(path: str, sessions: list[dict], denied=("S0",)) -> str:
    """The same sessions as syslog lines without a header, in Palo Alto's published field order,
    each behind a syslog prefix."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        for i, s in enumerate(sessions):
            sent, back, pkts = (74, 0, 0) if s["state"] in denied else _PA_SHAPE.get(s["state"], (74, 0, 0))
            began, ended = int(s["ts"]), int(s["ts"] + s["duration"])
            stopped = s["state"] in denied
            w.writerow([
                "Nov 18 11:00:00 fw01 1", _pa_time(ended), "016401000001", "TRAFFIC", "deny" if stopped else "end",
                "2561", _pa_time(ended), s["src"], s["dst"], "0.0.0.0", "0.0.0.0", "inbound", "", "",
                "ssl" if back > 100 else "incomplete", "vsys1", "untrust", "dmz", "ethernet1/1", "ethernet1/2",
                "log-forwarding", _pa_time(ended), 100000 + i, 1, s["sport"], s["dport"], 0, 0, "0x19", s["proto"],
                "deny" if stopped else "allow", sent + back, sent, back, 1 + pkts, _pa_time(began), ended - began,
                "any", 0, 7000000 + i, "0x0", "United States", "10.0.0.0-10.255.255.255", 0, 1, pkts,
                "policy-deny" if stopped else "tcp-fin"])
    return path
