"""Palo Alto Networks TRAFFIC and THREAT log reader.

Taken from VulnScope MAX (vulnflow/parsers/paloalto.py) and reworked so that nothing about the
export's layout is fixed in code. The column names of a CSV export, the field positions of raw
syslog lines, the action words that mean "stopped" and the subtypes to leave out all come from
the settings (``paloalto`` in pentaiwatch.json; the defaults are in config.py).

Two layouts are read, plain or ``.gz``:

* a CSV export with a header row (web interface, Panorama), matched by column NAME;
* syslog lines without a header, matched by POSITION counted from the Type column.

Each TRAFFIC row becomes one session whose time is its START time, found in this order:

1. the start-time field                         -> start_method ``start_field``
2. end time minus elapsed (whole) seconds       -> ``end_minus_elapsed``
3. neither: the END time is kept, so the session still lands in the right scoring window, and it
   is marked ``none`` so that nothing ever works out timing from it.

A traffic row that lacks a field the detection cannot do without stops the run (MissingField):
scoring such a file as "nothing found" would look like a clean result.
"""
from __future__ import annotations

import csv
import re
from collections import Counter
from datetime import timedelta

from ..config import PA_REQUIRED, PaloAlto
from ..errors import MissingField
from ..schema import (START_END_MINUS_ELAPSED, START_FIELD, START_NONE, Flow, ParseStats, ThreatEvent)
from ._util import clean_ip, clean_port, clean_proto, count, open_text, parse_ts, to_int

LOG_TYPES = ("TRAFFIC", "THREAT", "SYSTEM", "CONFIG")
# How each field is named in messages to the person.
WORDS = {"source": "the source address", "destination": "the destination address",
         "destination_port": "the destination port", "protocol": "the protocol", "action": "the action",
         "bytes_received": "bytes received", "start": "the session start time", "end": "the log (end) time",
         "elapsed": "elapsed seconds", "packets_received": "packets received"}
MAX_ELAPSED = 366 * 86400          # a longer "session" is a damaged value, not a session


def canon(name) -> str:
    """A column name as it is compared: lower case, letters and digits only."""
    return re.sub(r"[^a-z0-9]", "", str(name or "").lower())


def _seconds(value) -> int | None:
    """Elapsed time as whole seconds, or None when the cell holds no usable number."""
    n = to_int(value)
    return n if n is not None and 0 <= n <= MAX_ELAPSED else None


class _Resolver:
    """Turns rows into sessions and alerts, and keeps count of how start times were found."""

    def __init__(self, stats: ParseStats, opt: PaloAlto):
        self.stats, self.opt = stats, opt
        self.deny = tuple(a.strip().lower() for a in opt.deny_actions)
        self.skip = {s.strip().lower() for s in opt.skip_subtypes}
        self.methods: Counter = Counter()
        self.sessions = 0
        self.no_packet_count = 0

    def flow(self, get) -> Flow | None:
        stats = self.stats
        if (get("subtype") or "").strip().lower() in self.skip:
            stats.drop("session-start record (each session is counted from its end record)")
            return None
        src, dst = clean_ip(get("source")), clean_ip(get("destination"))
        if not src or not dst:
            stats.drop("missing or invalid IP")
            return None
        action_raw = (get("action") or "").strip().lower()
        if not action_raw:
            stats.drop("no action")
            return None
        action = "deny" if action_raw.startswith(self.deny) else "allow"
        back = get("bytes_received")
        if action == "allow" and not (back or "").strip():
            stats.drop("allowed session with no bytes-received value")       # unknown is not zero
            return None
        b_out, b_in = count(get("bytes_sent")), count(back)
        packets = get("packets_received")
        pkts_in = count(packets, -1) if (packets or "").strip() else -1
        start = parse_ts(get("start"))
        if start is not None:
            ts, method = start, START_FIELD
        else:
            end, elapsed = parse_ts(get("end")), _seconds(get("elapsed"))
            if end is not None and elapsed is not None:
                ts, method = end - timedelta(seconds=elapsed), START_END_MINUS_ELAPSED
            else:
                ts, method = end, START_NONE          # an END time, or no time at all
        if ts is None:
            stats.note("some rows had no readable time (kept, untimed)")
        else:
            self.methods[method] += 1
        self.sessions += 1
        self.no_packet_count += pkts_in < 0
        return Flow(
            ts=ts, src_ip=src, dst_ip=dst,
            src_port=clean_port(get("source_port")), dst_port=clean_port(get("destination_port")),
            proto=clean_proto(get("protocol")), action=action,
            established=action == "allow" and b_in > 0,
            bytes_out=b_out, bytes_in=b_in, app=(get("application") or "").strip(),
            src_zone=(get("source_zone") or "").strip().lower(),
            dst_zone=(get("destination_zone") or "").strip().lower(),
            pkts_in=pkts_in if pkts_in >= 0 else None, start_method=method)

    def threat(self, get) -> ThreatEvent | None:
        src, dst = clean_ip(get("source")), clean_ip(get("destination"))
        if not src or not dst:
            self.stats.drop("missing or invalid IP")
            return None
        return ThreatEvent(ts=parse_ts(get("start")) or parse_ts(get("end")), src_ip=src, dst_ip=dst,
                           dst_port=clean_port(get("destination_port")),
                           name=(get("threat_name") or "unnamed threat").strip(),
                           severity=(get("severity") or "").strip().lower(),
                           action=(get("action") or "alert").strip().lower())

    def finish(self) -> None:
        """Say, once per file, how the start times were found and what stood in for what."""
        m, stats = self.methods, self.stats
        parts = []
        if m[START_FIELD]:
            parts.append(f"{m[START_FIELD]:,} from the start-time field")
        if m[START_END_MINUS_ELAPSED]:
            parts.append(f"{m[START_END_MINUS_ELAPSED]:,} from end time minus elapsed seconds")
        if m[START_NONE]:
            parts.append(f"{m[START_NONE]:,} had neither a start time nor an elapsed time: their end time "
                         "is kept and is never used for timing")
        if parts:
            stats.note("session start times: " + "; ".join(parts))
        if self.no_packet_count:
            stats.note(("no packets-received count" if self.no_packet_count == self.sessions else
                        f"{self.no_packet_count:,} rows had no packets-received count") +
                       ": zero bytes received stands in for 'no packets back'")


def _columns(header: list[str], fields: dict[str, list[str]]) -> dict[str, list[int]]:
    """Field -> the header positions that may hold it, in the order the settings list the names."""
    seen = [canon(h) for h in header]
    out: dict[str, list[int]] = {}
    for key, names in fields.items():
        found: list[int] = []
        for name in names:
            c = canon(name)
            if c and c in seen and seen.index(c) not in found:
                found.append(seen.index(c))
        out[key] = found
    return out


def _require_columns(cols: dict[str, list[int]], header: list[str], opt: PaloAlto) -> None:
    missing = [k for k in PA_REQUIRED if not cols.get(k)]
    if not cols.get("start") and not cols.get("end"):
        missing.append("start")
    if not missing:
        return
    wanted = "; ".join(f"{WORDS[k]} (looked for: {', '.join(opt.fields.get(k) or ['no name set'])})"
                       for k in missing)
    if "start" in missing:
        wanted += f", or {WORDS['end']} (looked for: {', '.join(opt.fields.get('end') or ['no name set'])})"
    shown = ", ".join(h.strip() for h in header if h.strip()) or "none"
    raise MissingField(
        f"this Palo Alto export has no column for {wanted}. Its columns are: {shown}. "
        "Put the right column name under paloalto.fields in pentaiwatch.json.")


def _require_positions(opt: PaloAlto) -> None:
    off = opt.syslog_offsets
    missing = [k for k in PA_REQUIRED if off.get(k) is None]
    if off.get("start") is None and off.get("end") is None:
        missing.append("start")
    if missing:
        raise MissingField(
            "paloalto.syslog_offsets in the settings has no position for "
            + ", ".join(WORDS[k] for k in missing)
            + ", which lines without a header row need. Positions are counted from the Type column.")


def parse(path: str, stats: ParseStats, options: PaloAlto | None = None):
    """Yield a Flow per TRAFFIC row and a ThreatEvent per THREAT row."""
    opt = options or PaloAlto()
    stats.note("firewall times are read as UTC")
    res = _Resolver(stats, opt)
    with open_text(path, newline="") as fh:
        first = fh.readline()
        while first and not first.strip():
            first = fh.readline()
        fh.seek(0)
        first_row = next(csv.reader([first.strip()]), [])
        if any(c.strip().upper() in LOG_TYPES for c in first_row):
            yield from _syslog_lines(fh, stats, opt, res)
        else:
            yield from _header_csv(fh, stats, opt, res)
    res.finish()


def _header_csv(fh, stats: ParseStats, opt: PaloAlto, res: _Resolver):
    reader = csv.reader(fh)
    header = next((row for row in reader if any(c.strip() for c in row)), [])
    cols = _columns(header, opt.fields)
    row: list[str] = []

    def get(key):
        # the first of the field's columns that has a value in this row (THREAT rows leave the
        # start time empty, so their time falls through to the next column that has one)
        return next((row[i] for i in cols.get(key, ()) if i < len(row) and row[i].strip()), None)

    checked = False
    for row in reader:
        if not any(c.strip() for c in row):
            continue
        stats.read += 1
        kind = (get("type") or "TRAFFIC").strip().upper()
        if kind == "THREAT":
            t = res.threat(get)
            if t:
                yield t
            continue
        if kind != "TRAFFIC":
            stats.drop(f"{kind} log type not used")
            continue
        if not checked:
            _require_columns(cols, header, opt)
            used = [f"{WORDS[k]} = {header[cols[k][0]].strip()}" if cols.get(k) else f"{WORDS[k]} = not in the export"
                    for k in ("start", "end", "elapsed", "packets_received")]
            stats.note("columns used: " + "; ".join(used))
            checked = True
        flow = res.flow(get)
        if flow:
            yield flow


def _syslog_lines(fh, stats: ParseStats, opt: PaloAlto, res: _Resolver):
    checked = False
    # THREAT lines share the TRAFFIC layout up to the action; what follows is laid out differently
    shared_until = opt.syslog_offsets.get("action")
    threat_offsets = {k: v for k, v in opt.syslog_offsets.items()
                      if v is not None and shared_until is not None and v <= shared_until}
    threat_offsets.update(opt.threat_syslog_offsets)
    for line in fh:
        if not line.strip():
            continue
        stats.read += 1
        row = next(csv.reader([line.strip()]), [])
        base = next((i for i, c in enumerate(row) if c.strip().upper() in LOG_TYPES), None)
        if base is None:
            stats.drop("unrecognized line")
            continue
        kind = row[base].strip().upper()
        if kind not in ("TRAFFIC", "THREAT"):
            stats.drop(f"{kind} log type not used")
            continue
        offsets = threat_offsets if kind == "THREAT" else opt.syslog_offsets

        def get(key, row=row, base=base, offsets=offsets):
            off = offsets.get(key)
            i = base + off if off is not None else -1
            return row[i] if 0 <= i < len(row) and row[i].strip() else None

        if kind == "THREAT":
            t = res.threat(get)
            if t:
                yield t
            continue
        if not checked:
            _require_positions(opt)
            checked = True
        if max(base + (opt.syslog_offsets.get(k) or 0) for k in PA_REQUIRED) >= len(row):
            stats.drop("line too short to hold the fields needed")
            continue
        flow = res.flow(get)
        if flow:
            yield flow
