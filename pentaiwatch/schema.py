"""Common shape every input format is normalized into.

Taken from VulnScope MAX (vulnflow/schema.py) and extended with what the detector needs: the raw
connection state, packets back from the responder, and how the session's START time was found.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

# How a session's start time was found (Flow.start_method). Timing is only ever worked out from
# start times, so each session records where its time came from.
START_ZEEK_TS = "zeek_ts"                # Zeek ts: always the start, though conn.log is written at close
START_FIELD = "start_field"              # the firewall export's own start-time field
START_END_MINUS_ELAPSED = "end_minus_elapsed"   # firewall end time minus elapsed seconds
START_NONE = "none"                      # no start time could be found (the time, if any, is an END time)
START_UNKNOWN = ""                       # the parser does not say (formats not yet covered)


@dataclass(slots=True)          # slots: millions of these can be in memory at once
class Flow:
    """One network connection/session, regardless of which sensor saw it."""
    ts: datetime | None
    src_ip: str
    dst_ip: str
    dst_port: int | None
    proto: str                   # tcp | udp | icmp | other
    src_port: int | None = None
    action: str = "allow"        # allow | deny (firewall/IPS) | reject (host refused, Zeek REJ)
    established: bool = True     # handshake completed / data flowed both ways
    bytes_out: int = 0           # originator -> responder
    bytes_in: int = 0            # responder -> originator
    app: str = ""
    src_zone: str = ""
    dst_zone: str = ""
    source: str = ""             # input file the record came from
    state: str = ""              # Zeek conn_state as logged (S0, REJ, SF, ...); empty for other sensors
    pkts_in: int | None = None   # packets responder -> originator, when the log has them
    start_method: str = START_UNKNOWN    # one of the START_* values above

    def key(self):
        return (self.ts, self.src_ip, self.src_port, self.dst_ip, self.dst_port,
                self.proto, self.action)


@dataclass(slots=True)
class ThreatEvent:
    """An IPS/IDS alert (Palo Alto THREAT log, Zeek notice, Suricata alert)."""
    ts: datetime | None
    src_ip: str
    dst_ip: str
    dst_port: int | None
    name: str                    # signature / threat name, often with a vendor ID or CVE
    severity: str = ""
    action: str = "alert"        # alert/allow (traffic passed) or block (traffic stopped)
    source: str = ""

    @property
    def blocked(self) -> bool:
        return self.action.lower().startswith(("block", "drop", "deny", "reset", "reject"))

    def key(self):
        return (self.ts, self.src_ip, self.dst_ip, self.dst_port, self.name)


@dataclass(slots=True)
class ZeekEvent:
    """A Zeek record from a stream other than conn or notice (dns, ssl, http, ...). Read so the
    file is accounted for; not used by the inbound detection."""
    ts: datetime | None
    stream: str
    uid: str
    src_ip: str | None
    dst_ip: str | None
    fields: dict
    source: str = ""


@dataclass(slots=True)
class WebHit:
    """One Zeek http, dns or ssl record that matched a list in the ``web`` settings: an agentic
    tool's user agent (kind "agent", http only), or a watched name such as an AI model API (kind
    "name": the http Host, the dns query or the ssl server name). Only matching records are kept."""
    ts: datetime | None
    kind: str                    # "agent" | "name"
    label: str                   # the tool, or the kind of name, as the settings call it
    stream: str                  # http | dns | ssl
    src_ip: str
    dst_ip: str
    dst_port: int | None
    text: str                    # the user agent, or the name
    source: str = ""


@dataclass
class ParseStats:
    """Data-quality bookkeeping for one input file."""
    file: str
    fmt: str
    read: int = 0
    kept: int = 0
    dropped: Counter = field(default_factory=Counter)
    notes: list[str] = field(default_factory=list)
    web_rows: Counter = field(default_factory=Counter)   # Zeek http/dns/ssl records checked, by stream

    def drop(self, reason: str):
        self.dropped[reason] += 1

    def note(self, msg: str):
        if msg not in self.notes:
            self.notes.append(msg)
