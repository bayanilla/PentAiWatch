"""Every setting of the detection, with its default, and the optional JSON file that changes them.

A file named ``pentaiwatch.json`` in an input folder is used automatically (it is not read as a
log), or pass one with ``--config``. It only needs the settings you want to change:

    {
      "lookback_hours": 48,
      "allowlist": ["198.51.100.0/28"],
      "probing": {"min_ports": 80},
      "narrowing": {"min_sessions_per_service": 8}
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
        if dataclasses.is_dataclass(current):
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
