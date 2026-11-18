"""Every setting of the detection, with its default, and the optional JSON file that changes them.

A file named ``pentaiwatch.json`` in an input folder is used automatically (it is not read as a
log), or pass one with ``--config``. It only needs the settings you want to change:

    {
      "lookback_hours": 48,
      "allowlist": ["198.51.100.0/28"],
      "probing": {"min_ports": 80},
      "narrowing": {"min_sessions_per_service": 8},
      "paloalto": {"fields": {"elapsed": ["Session Duration"]}}
    }

A name that is not a setting is refused, so a typo cannot silently leave a default in place.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import json
import os
from dataclasses import dataclass, field

from .errors import UserError

FILENAME = "pentaiwatch.json"
DEFAULT_INTERNAL_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]      # RFC 1918


@dataclass
class Probing:
    """Signal 1: one source tries many ports or hosts and most attempts fail."""
    min_ports: int = 50                  # distinct destination ports, or ...
    min_hosts: int = 20                  # ... distinct internal hosts
    min_failed_share: float = 0.70       # share of the sweep's attempts that failed
    # Zeek conn_state values that count as a failed attempt.
    zeek_failed_states: list[str] = field(default_factory=lambda: ["S0", "REJ", "RSTOS0", "RSTR"])


@dataclass
class Narrowing:
    """Signal 2: afterwards the source keeps returning, to the services that answered only."""
    max_answered_share: float = 0.10     # answered services are at most this share of those probed
    min_sessions_per_service: int = 5    # completed sessions that make a service "narrowed onto"
    max_start_delay_minutes: float = 15  # the returns begin within this long of the sweep
    # After the returns begin, at least this share of the source's sessions (over one window)
    # go to services that answered: it went back to what answered, not on sweeping.
    min_focus_share: float = 0.60
    # Zeek conn_state values that count as a completed session.
    zeek_answered_states: list[str] = field(default_factory=lambda: ["SF", "S1", "S2", "S3", "RSTO"])


# -- Palo Alto logs: nothing about the export's layout is fixed in code ----------------------
# CSV exports with a header row: the column names that may hold each field. The first one the
# file has is used. Names are compared ignoring case, spaces and punctuation, so "Source address",
# "source_address" and "SOURCE ADDRESS" are the same name.
#
# Where these defaults come from: the columns of the Palo Alto export bundled with VulnScope MAX's
# samples, plus the other spellings MAX's reader accepts. That export has no generated time, no
# elapsed time and no packet count; for those three the names are the ones in Palo Alto's
# published log format (and the "(sec)" spelling of the web export). A name the file does not
# have is simply not used, and the report lists which column each time was read from.
PA_FIELDS: dict[str, list[str]] = {
    "type": ["Type"],                                    # TRAFFIC or THREAT
    "subtype": ["Threat/Content Type"],                  # start, end, drop, deny (traffic rows)
    "start": ["Start Time"],                             # when the session started
    "end": ["Generate Time", "Generated Time", "Receive Time", "Time Logged"],   # when it was logged (its end)
    "elapsed": ["Elapsed Time (sec)", "Elapsed Time", "elapsed"],                # whole seconds it lasted
    "source": ["Source address", "Source IP", "src_ip"],                         # the address BEFORE any NAT
    "destination": ["Destination address", "Destination IP", "dst_ip"],
    "source_port": ["Source Port", "src_port"],
    "destination_port": ["Destination Port", "dst_port"],
    "protocol": ["IP Protocol", "Protocol"],
    "action": ["Action"],
    "bytes_sent": ["Bytes Sent"],
    "bytes_received": ["Bytes Received"],                # server to client
    "packets_received": ["Packets Received", "pkts_received"],                   # server to client
    "application": ["Application"],
    "source_zone": ["Source Zone", "From Zone"],
    "destination_zone": ["Destination Zone", "To Zone"],
    "threat_name": ["Threat/Content Name", "Threat Name", "Threat ID", "Name"],  # threat rows
    "severity": ["Severity"],                                                    # threat rows
}
# Syslog lines (no header row): where each field sits, counted from the Type column (the one that
# holds TRAFFIC or THREAT), so a syslog prefix of any length in front does not matter. These follow
# Palo Alto's published field order; MAX's reader uses the same positions.
PA_SYSLOG_OFFSETS: dict[str, int | None] = {
    "subtype": 1, "end": 3, "source": 4, "destination": 5, "application": 11, "source_zone": 13,
    "destination_zone": 14, "source_port": 21, "destination_port": 22, "protocol": 26, "action": 27,
    "bytes_sent": 29, "bytes_received": 30, "start": 32, "elapsed": 33, "packets_received": 42,
}
# THREAT lines share that layout up to the action, then differ.
PA_THREAT_SYSLOG_OFFSETS: dict[str, int | None] = {"threat_name": 29, "severity": 31}
# What a traffic row cannot do without (see parsers/paloalto.py); "a time" is start or end.
PA_REQUIRED = ("source", "destination", "destination_port", "protocol", "action", "bytes_received")


@dataclass
class PaloAlto:
    """How Palo Alto traffic and threat logs are read, and when a firewall session counts as
    failed or answered."""
    fields: dict[str, list[str]] = field(
        default_factory=lambda: {k: list(v) for k, v in PA_FIELDS.items()}, metadata={"kind": "names"})
    syslog_offsets: dict[str, int | None] = field(
        default_factory=lambda: dict(PA_SYSLOG_OFFSETS), metadata={"kind": "positions"})
    threat_syslog_offsets: dict[str, int | None] = field(
        default_factory=lambda: dict(PA_THREAT_SYSLOG_OFFSETS), metadata={"kind": "positions"})
    # An action that starts with one of these means the firewall stopped the session.
    deny_actions: list[str] = field(default_factory=lambda: ["deny", "drop", "reset", "block"])
    # Traffic rows with one of these subtypes are left out: a "start" row is written when a session
    # opens, before any reply could be counted, and the same session is logged again when it ends.
    skip_subtypes: list[str] = field(default_factory=lambda: ["start"])
    # An allowed session FAILED when at most this many packets came back. 0 is "no packets back".
    # 1 also counts a lone reset from a closed port, which is what Zeek calls REJ. Where the export
    # has no packet count, zero bytes received stands in for "no packets back".
    failed_max_packets_received: int = 0
    # An allowed session was ANSWERED when at least this many bytes came back.
    answered_min_bytes_received: int = 1


@dataclass
class Config:
    # Your own address ranges. Ranges in network_map.csv are added to these.
    internal_nets: list[str] = field(default_factory=lambda: list(DEFAULT_INTERNAL_NETS))
    # Sources never flagged (addresses or ranges), on top of known_scanners.csv.
    allowlist: list[str] = field(default_factory=list)
    lookback_hours: float = 72           # how far back from the last session in the run to look (24-72)
    window_hours: float = 2              # length of the scoring window
    # Clock difference tolerated when matching one session seen by Zeek and by the firewall.
    dedup_skew_seconds: float = 2.0
    probing: Probing = field(default_factory=Probing)
    narrowing: Narrowing = field(default_factory=Narrowing)
    paloalto: PaloAlto = field(default_factory=PaloAlto)
    # Filled by the pipeline from network_map.csv and known_scanners.csv (not settings).
    networks: list[dict] = field(default_factory=list, metadata={"runtime": True})
    known_scanners: list[dict] = field(default_factory=list, metadata={"runtime": True})

    def settings(self) -> dict:
        """The settings as plain data (what a pentaiwatch.json may hold), for results.json."""
        out = dataclasses.asdict(self)
        for f in dataclasses.fields(self):
            if f.metadata.get("runtime"):
                out.pop(f.name)
        return out


def is_config_file(path: str) -> bool:
    return os.path.basename(path).lower() == FILENAME


def read(path: str) -> Config:
    """A Config with the file's settings over the defaults. Raises UserError on anything wrong."""
    name = os.path.basename(path)
    try:
        with open(path, encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise UserError(f"{name}: cannot be read ({exc.strerror or exc})") from None
    except json.JSONDecodeError as exc:
        raise UserError(f"{name}: not valid JSON (line {exc.lineno}: {exc.msg})") from None
    if not isinstance(data, dict):
        raise UserError(f"{name}: expected one JSON object of settings")
    cfg = Config()
    _apply(cfg, data, name, "")
    check(cfg, name)
    return cfg


def _apply(target, data: dict, name: str, where: str) -> None:
    known = {f.name: f for f in dataclasses.fields(target) if not f.metadata.get("runtime")}
    for key, value in data.items():
        if key not in known:
            raise UserError(f"{name}: '{where}{key}' is not a setting. Settings here: {', '.join(sorted(known))}")
        current = getattr(target, key)
        kind = known[key].metadata.get("kind")
        if kind:
            _apply_map(current, value, kind, name, f"{where}{key}")
        elif dataclasses.is_dataclass(current):
            if not isinstance(value, dict):
                raise UserError(f"{name}: '{where}{key}' must be an object of settings")
            _apply(current, value, name, f"{where}{key}.")
        elif isinstance(current, list):
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise UserError(f"{name}: '{where}{key}' must be a list of text values")
            setattr(target, key, [v.strip() for v in value])
        else:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise UserError(f"{name}: '{where}{key}' must be a number")
            setattr(target, key, type(current)(value) if isinstance(current, int) and value == int(value) else value)


def _apply_map(current: dict, value, kind: str, name: str, where: str) -> None:
    """Merge an object setting into its defaults: only the entries given are replaced. ``names``
    maps a field to the column names that may hold it; ``positions`` maps a field to a position
    (null: this log does not have the field)."""
    if not isinstance(value, dict):
        raise UserError(f"{name}: '{where}' must be an object")
    for key, item in value.items():
        if key not in current:
            raise UserError(f"{name}: '{where}.{key}' is not a field. Fields here: {', '.join(sorted(current))}")
        if kind == "names":
            names = [item] if isinstance(item, str) else item
            if not isinstance(names, list) or not all(isinstance(v, str) for v in names):
                raise UserError(f"{name}: '{where}.{key}' must be a column name or a list of column names")
            current[key] = [v.strip() for v in names if v.strip()]
        else:
            if item is not None and (isinstance(item, bool) or not isinstance(item, int)):
                raise UserError(f"{name}: '{where}.{key}' must be a whole number, or null when the log "
                                "does not have the field")
            current[key] = item


def check(cfg: Config, name: str = "settings") -> None:
    """Refuse values that cannot work, before any log is read."""
    for label, nets in (("internal_nets", cfg.internal_nets), ("allowlist", cfg.allowlist)):
        for net in nets:
            try:
                ipaddress.ip_network(net, strict=False)
            except ValueError:
                raise UserError(f"{name}: {label}: '{net}' is not an address or address range") from None
    positive = {"lookback_hours": cfg.lookback_hours, "window_hours": cfg.window_hours,
                "probing.min_ports": cfg.probing.min_ports, "probing.min_hosts": cfg.probing.min_hosts,
                "narrowing.min_sessions_per_service": cfg.narrowing.min_sessions_per_service,
                "narrowing.max_start_delay_minutes": cfg.narrowing.max_start_delay_minutes}
    for key, value in positive.items():
        if not value > 0:
            raise UserError(f"{name}: {key} must be more than 0")
    shares = {"probing.min_failed_share": cfg.probing.min_failed_share,
              "narrowing.max_answered_share": cfg.narrowing.max_answered_share,
              "narrowing.min_focus_share": cfg.narrowing.min_focus_share}
    for key, value in shares.items():
        if not 0 <= value <= 1:
            raise UserError(f"{name}: {key} must be between 0 and 1 (0.7 means 70%)")
    if cfg.window_hours > cfg.lookback_hours:
        raise UserError(f"{name}: window_hours cannot be longer than lookback_hours")
    for key, states in (("probing.zeek_failed_states", cfg.probing.zeek_failed_states),
                        ("narrowing.zeek_answered_states", cfg.narrowing.zeek_answered_states)):
        if not states or not all(s.isalnum() for s in states):
            raise UserError(f"{name}: {key} must list Zeek conn_state names such as S0 or SF")
    pa = cfg.paloalto
    if not pa.deny_actions or not all(a.strip() for a in pa.deny_actions):
        raise UserError(f"{name}: paloalto.deny_actions must list at least one action, such as deny")
    if pa.failed_max_packets_received < 0:
        raise UserError(f"{name}: paloalto.failed_max_packets_received cannot be less than 0")
    if pa.answered_min_bytes_received < 1:
        raise UserError(f"{name}: paloalto.answered_min_bytes_received must be 1 or more: a session with "
                        "nothing back was not answered")
    for label, offsets in (("syslog_offsets", pa.syslog_offsets), ("threat_syslog_offsets", pa.threat_syslog_offsets)):
        for key, value in offsets.items():
            if value is not None and not -3 <= value <= 400:
                raise UserError(f"{name}: paloalto.{label}.{key} is a position counted from the Type column; "
                                f"{value} cannot be right")
