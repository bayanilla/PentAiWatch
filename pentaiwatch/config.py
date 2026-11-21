"""Every setting of the detection, with its default, and the optional JSON file that changes them.

A file named ``pentaiwatch.json`` in an input folder is used automatically (it is not read as a
log), or pass one with ``--config``. It only needs the settings you want to change:

    {
      "lookback_hours": 48,
      "allowlist": ["198.51.100.0/28"],
      "probing": {"min_ports": 80},
      "narrowing": {"min_sessions_per_service": 8},
      "timing": {"pause_max_seconds": 40},
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
    # Zeek gives every ICMP record the conn_state OTH whatever happened, so the lists of states
    # cannot tell an unanswered ping from an answered one. With this on, an ICMP session in a Zeek
    # log is judged by what came back, as it is on the firewall: nothing back is a failed attempt,
    # a reply is an answer. Off: ICMP in a Zeek log is neither.
    zeek_icmp_by_reply: bool = True


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
    # Protocols whose services a source can narrow onto. A host that answers pings is not a service
    # to come back to, so ICMP counts in the sweep and is never listed as narrowed onto.
    protocols: list[str] = field(default_factory=lambda: ["tcp", "udp"])


@dataclass
class Timing:
    """Signal 3: the source works in short bursts of sessions separated by pauses the length of a
    model's think time. Only session START times are used."""
    burst_gap_seconds: float = 15        # a gap longer than this between two session starts ends a burst
    max_burst_sessions: int = 15         # a burst is short when it has at most this many sessions
    pause_min_seconds: float = 20        # the band a pause must fall in: at least this long ...
    pause_max_seconds: float = 35        # ... and at most this long
    min_cycles: int = 5                  # short bursts, each followed by a pause in the band, in one window
    # "Mostly": of ALL the pauses between the source's bursts in that window, at least this share
    # is in the band. It keeps a source whose pauses are every length from passing by chance.
    min_pause_share: float = 0.60
    # Timing can only clear a source when it saw nearly all of it. When timing does not fire and
    # less than this share of the source's sessions has a usable start time, the result is
    # "timing unavailable" (tier 0), not "no agentic pace".
    min_timed_share: float = 0.90


@dataclass
class Steady:
    """Fixed-interval cadence: one source hits one service over and over at an almost constant gap,
    as a scripted login brute force does (CyberStrikeAI's FortiGate runs retried every 1.5 seconds
    with no jitter). A person, or an agent that stops to think, never keeps a gap that even.

    It is the second timing pattern: a source that swept and narrowed is Level 1 when either this
    or the burst-and-pause pattern fires. On its own (no sweep and narrowing) it is a lead, because a
    health check or a monitoring probe keeps a gap just as even; another behaviour of the same source
    flags it. Only logged session START times are used (Zeek, or a firewall start field): a start
    worked out from whole elapsed seconds is too coarse for a 1 or 2-second step."""
    min_sessions: int = 30               # sessions in one unbroken run to the same service
    max_gap_seconds: float = 10          # a longer gap between two starts ends the run
    # How even the gaps are: their standard deviation divided by their mean. 0.10 means the gaps
    # stay within about a tenth of their typical length.
    max_jitter: float = 0.10


@dataclass
class Spray:
    """High-rate repeated connections: one source sends a flood of completed connections to one service,
    minute after minute, as a password spray against a VPN portal, webmail or remote access does
    (Microsoft saw up to 2,900 failed logins a minute from one Storm-0940 address). Unlike the
    fixed-interval cadence, the gaps need not be even. A completed connection reached the service;
    whether it was a login, and whether the login failed, only that service's own log can say. A
    busy integration looks the same, so on its own this is a lead; another behaviour of the same
    source (a sweep, or a fixed-interval cadence) flags it. Counted per minute, so it works from
    session start or end times."""
    # Sessions in one minute from the source to one TCP service: one a second. A person, or a tool
    # following up on what it found, stays well under that for minutes on end.
    min_per_minute: int = 60
    min_minutes: int = 5                 # minutes at that rate in the lookback
    min_answered_share: float = 0.50     # share of those sessions that completed
    # A service more outside addresses than this used in the lookback is public: a busy client of it
    # (or many people behind one NAT address) is expected there, so it is left out.
    max_service_sources: int = 20


@dataclass
class LoginSpray:
    """Repeated failed-login pattern: one source keeps sending short sessions to one TCP service, minute
    after minute for a quarter of an hour or more, and the service answers each with a small reply of
    nearly the same size, as a login page refusing one password after another does (ARTEX sprayed
    an SSO page at about one attempt a second for 40 minutes). A connection log cannot see accounts
    or passwords, so this reads the shape: sustained, mostly answered, small same-size replies, and
    most of the service's traffic in those minutes. Unlike high-rate repeated connections it also
    looks at a public service, such as your SSO or webmail, because that is where sprays go. A
    monitor or an integration that posts small requests all day looks the same, so on its own this
    is a lead; a sweep, or another behaviour of the source on another service, flags it."""
    check: bool = True
    min_per_minute: int = 20             # sessions in a minute that count it
    min_minutes: int = 15                # such minutes in one stretch (gaps of up to 2 minutes allowed)
    min_answered_share: float = 0.50     # share of the stretch's sessions that completed
    max_reply_bytes: int = 16384         # median bytes back per completed session (a refusal page, not a download)
    max_reply_spread: float = 0.6        # (90th - 10th percentile of those bytes) / their median
    min_service_share: float = 0.5       # its share of all sessions to the service in the stretch


@dataclass
class Parallel:
    """Several attack paths at once: once a flagged source has narrowed, its bursts work more than one
    service, switching back and forth between them, as an agent that runs several attack paths side by
    side does (ARTEX did). A tool that finishes one service before it starts the next switches once
    and does not count. This raises a finding's confidence; it never flags a source on its own. Only
    answered sessions with a known START time are used, so the sweep itself never counts."""
    min_services: int = 2                # services one burst works, switching back to one it left
    min_bursts: int = 5                  # such bursts after narrowing


@dataclass
class Rotation:
    """Rotating sources: one address sweeps, and other, new addresses come straight back to what the
    sweep found answering, as an operator who rotates through proxies does (CrowdStrike lists nine
    for one ARTEX operator). Each address alone can stay under the thresholds; together they are one
    campaign. The narrowing settings decide what "came back" means (completed sessions per service,
    how soon after the sweep, and the share of sessions that go to what answered)."""
    min_joiners: int = 2                 # other addresses that came back to what the sweep found
    # A service more outside addresses than this used in the lookback is public (a web site, a mail
    # relay): new visitors to it are expected, so it never ties addresses together.
    max_service_sources: int = 20
    # A joiner must have had no session at all in this many hours before the sweep began: an address
    # that was already using the service is not new. A sweep that begins sooner than this after the
    # start of the data cannot be checked, so it anchors a rotation only when it is a finding itself.
    quiet_before_hours: float = 2


@dataclass
class SharedSweep:
    """Shared sweeps: several addresses split one sweep between them, each too small to fire the
    probing signal, and then an address that was quiet before comes back to a service they found.
    Ordinary internet scanning hits the same popular ports from many addresses; a split sweep
    hardly repeats itself, so the addresses' first attempts must cover ``min_split_share`` or more
    distinct services. Together they must pass the probing thresholds, against one /24. The
    narrowing settings decide what "came back" means and how soon; rotation.quiet_before_hours
    what "quiet before" means; rotation.max_service_sources what a public service is. A lead,
    flagged only when an address in it is a finding of its own."""
    check: bool = True
    min_sources: int = 3                 # addresses that share the sweep
    min_probes_per_source: int = 5       # first attempts each, in the window, mostly failed
    min_split_share: float = 0.8         # distinct services / first attempts, over all of them


@dataclass
class Baseline:
    """Regular clients: a fixed-interval or high-rate lead from a source that already repeated to the
    same service well before, such as a health check or a partner integration that runs every day.
    Such a lead is marked as a regular client and listed last. It is still listed, never dropped, and
    a lead that another behaviour backs is flagged whatever its history: a sweep first is not what a
    regular client does. A service is a regular one for a source when the source had ``min_sessions``
    or more sessions to it at least ``before_hours`` before the end of its latest run there, anywhere
    in the data read (sessions older than the lookback count here too): it has been a client of
    that service for half a day or more, as a health check that runs for days or a job that runs
    every day has."""
    check: bool = True
    before_hours: float = 12
    min_sessions: int = 30


@dataclass
class Outbound:
    """Your hosts reaching out to attacker infrastructure. Inbound traffic shows the attack;
    outbound shows whether it worked. An internal host with a session to an address on a list of
    published attacker addresses is flagged (the bundled list and your known_bad.csv). A session out
    to a command-and-control port below, to any outside address, is named as a hint: these ports
    are the defaults of the tools the reporting found on ARTEX hosts, but anything can listen on
    them, so a hint never flags on its own.

    Calls back: the agentic frameworks' own servers listen on default ports too (``tool_ports``, and
    ``tool_port_ranges`` for a first and last port), and the reporting says a compromised host calls
    back to the operator's server on them. Ordinary services use these ports far more often than the
    command-and-control ones, so a session out on one is named only when the outside address had
    already connected IN to one of your hosts before it: a call back to a source. It is a hint and
    flags nothing."""
    check: bool = True
    c2_ports: dict[str, list[int]] = field(
        default_factory=lambda: {"Cobalt Strike teamserver": [50050], "Adaptix C2": [4321]},
        metadata={"kind": "targets"})
    # Default listener ports of the frameworks' own servers (Threat Landscape, 10 Nov 2026; Elastic
    # Security Labs, 13 Nov 2026).
    tool_ports: dict[str, list[int]] = field(
        default_factory=lambda: {"ARTEX console": [8787], "Cairn server": [8000], "HexStrike AI server": [8888]},
        metadata={"kind": "targets"})
    # First and last port of a range: compromised hosts connect to a PentAGI host on TCP 28000 to
    # 29999 (Elastic); its worker ports are bound in 28000 to 30000 (Threat Landscape).
    tool_port_ranges: dict[str, list[int]] = field(
        default_factory=lambda: {"PentAGI worker": [28000, 30000]}, metadata={"kind": "targets"})


@dataclass
class Beacon:
    """Fixed-interval calls out: an internal host connects out to one outside service over and over
    at an almost constant gap, as an implant checking in with its server does (Elastic Security Labs:
    CyberStrikeAI's implant checks in every five seconds with no jitter). It is the fixed-interval
    cadence of ``steady``, read on sessions going OUT. Update agents, monitoring and sync clients keep
    a gap just as even, so on its own this is a lead. It is flagged when the address it goes to is a
    published attacker address or a finding or flagged lead in the same report, or the port is a
    command-and-control or agentic-tool port (``outbound``). Only logged session START times are
    used, as for ``steady``."""
    check: bool = True
    min_sessions: int = 60               # sessions in one unbroken run to the same outside service
    max_gap_seconds: float = 10          # a longer gap between two starts ends the run
    max_jitter: float = 0.10             # standard deviation of the gaps over their mean


@dataclass
class Nonstop:
    """No overnight break: a source that stays active for most of a day or longer with no break as
    long as a night's, or even a meal's. An agent does not sleep: AWS watched Cairn agents work one
    target for about 16 hours in 148 sequential actions, and Unit 42 saw operations run from 20
    minutes to more than 50 hours. A monitor or an integration runs around the clock too, so this
    never flags a source and never backs a lead. It is named, as extra evidence, on a source that is
    already a finding, a lead or a published address. Read from any session time."""
    check: bool = True
    min_hours: float = 16                # a stretch of activity at least this long ...
    max_quiet_hours: float = 2           # ... in which no gap between two sessions is longer than this


@dataclass
class Web:
    """What Zeek's http.log, dns.log and ssl.log add, when they are given with conn.log. Connection
    logs carry no user agent and no name, so two things the reporting describes cannot be seen
    without them:

    * ``user_agents``: the frameworks name themselves in the User-Agent header of their requests
      (http.log). A request whose user agent CONTAINS one of these texts, ignoring case, is a match.
      An outside source that sent one is named on sight, like a published address: context, kept
      apart from the behaviour, and never backing a lead. An internal host that sent one is named
      too: the tool is running inside. A user agent is whatever the sender writes, so a match can
      be faked and a miss proves nothing; plain HTTP only, since http.log does not see inside TLS.
      Left out on purpose: norma/0.4, which ARTEX sends but other tools share.
    * ``names``: an internal host that looked up or connected to one of these names (the dns.log
      query, the http.log Host, the ssl.log server name; a listed name or anything under it). A
      hint only, never a flag: an AI model API is ordinary traffic from a developer's machine and
      worth a look from a server. In dns.log the asker is often your resolver, not the host itself.

    Only matching records are kept; everything else in those logs is counted and set aside."""
    check: bool = True
    user_agents: dict[str, list[str]] = field(
        default_factory=lambda: {
            "ARTEX": ["artex", "spa-api-recon"],
            "CyberStrikeAI": ["CyberStrikeAI", "cyberstrike-ai/"],
            "HexStrike AI": ["HexStrike"],
        }, metadata={"kind": "lists"})
    names: dict[str, list[str]] = field(
        default_factory=lambda: {
            "AI model API": ["api.anthropic.com", "api.deepseek.com", "open.bigmodel.cn", "api.x.ai"],
            "AI model reseller named in ARTEX reporting": ["xcai.pro"],
            "Request-capture or callback service": ["webhook.site", "dnslog.cn"],
        }, metadata={"kind": "lists"})


# Kinds of service the ARTEX and CyberStrikeAI reporting names as what the agents went for, by TCP or
# UDP port. A flagged source's services on these ports are named in the report; they do not change
# whether it is flagged. Port 443 is left out: too much else answers on it to name anything.
DEFAULT_TARGETS = {
    "Edge device admin or VPN": [541, 4443, 8443, 9443, 10443],   # FortiGate and other firewall consoles
    "AI model gateway": [4000, 11434],                             # LiteLLM, Ollama
    "Database": [1433, 1521, 3306, 5432, 6379, 9200, 27017],
    "Remote access": [22, 3389, 5985, 5986],                       # SSH, RDP, WinRM
}


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
    # Use the list of published addresses of ARTEX, CyberStrikeAI, Cairn and other AI-assisted intrusions
    # that comes with PentAIWatch (data/known_bad.csv). Your own known_bad.csv is used either way.
    known_bad_bundled: bool = True
    # Clock difference tolerated when matching one session seen by Zeek and by the firewall.
    dedup_skew_seconds: float = 2.0
    probing: Probing = field(default_factory=Probing)
    narrowing: Narrowing = field(default_factory=Narrowing)
    timing: Timing = field(default_factory=Timing)
    steady: Steady = field(default_factory=Steady)
    spray: Spray = field(default_factory=Spray)
    login_spray: LoginSpray = field(default_factory=LoginSpray)
    parallel: Parallel = field(default_factory=Parallel)
    rotation: Rotation = field(default_factory=Rotation)
    baseline: Baseline = field(default_factory=Baseline)
    shared_sweep: SharedSweep = field(default_factory=SharedSweep)
    outbound: Outbound = field(default_factory=Outbound)
    beacon: Beacon = field(default_factory=Beacon)
    nonstop: Nonstop = field(default_factory=Nonstop)
    web: Web = field(default_factory=Web)
    # Named kinds of target: name -> ports. Your names are added; giving a default name replaces its
    # ports, and an empty list drops it.
    targets: dict[str, list[int]] = field(
        default_factory=lambda: {k: list(v) for k, v in DEFAULT_TARGETS.items()}, metadata={"kind": "targets"})
    paloalto: PaloAlto = field(default_factory=PaloAlto)
    # Filled by the pipeline from network_map.csv and known_scanners.csv (not settings).
    networks: list[dict] = field(default_factory=list, metadata={"runtime": True})
    known_scanners: list[dict] = field(default_factory=list, metadata={"runtime": True})
    known_bad: list[dict] = field(default_factory=list, metadata={"runtime": True})

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
        elif isinstance(current, bool):
            if not isinstance(value, bool):
                raise UserError(f"{name}: '{where}{key}' must be true or false")
            setattr(target, key, value)
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
    if kind == "lists":                      # name -> texts; a name given replaces its texts, [] drops it
        for key, item in value.items():
            if not isinstance(item, list) or not all(isinstance(v, str) and v.strip() for v in item):
                raise UserError(f"{name}: '{where}.{key}' must be a list of text values, none of them empty")
            label = key.strip()
            if not label:
                raise UserError(f"{name}: '{where}' has an entry with no name")
            current.pop(key, None)
            current.pop(label, None)
            if item:
                current[label] = [v.strip() for v in item]
        return
    if kind == "targets":
        for key, item in value.items():
            if not isinstance(item, list) or not all(isinstance(v, int) and not isinstance(v, bool) for v in item):
                raise UserError(f"{name}: '{where}.{key}' must be a list of port numbers")
            label = key.strip()
            if not label:
                raise UserError(f"{name}: '{where}' has a target with no name")
            current.pop(key, None)
            if item:
                current[label] = list(item)
            else:
                current.pop(label, None)
        return
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
                "narrowing.max_start_delay_minutes": cfg.narrowing.max_start_delay_minutes,
                "timing.burst_gap_seconds": cfg.timing.burst_gap_seconds,
                "timing.max_burst_sessions": cfg.timing.max_burst_sessions,
                "timing.pause_min_seconds": cfg.timing.pause_min_seconds,
                "timing.pause_max_seconds": cfg.timing.pause_max_seconds,
                "timing.min_cycles": cfg.timing.min_cycles,
                "steady.max_gap_seconds": cfg.steady.max_gap_seconds,
                "beacon.max_gap_seconds": cfg.beacon.max_gap_seconds,
                "nonstop.min_hours": cfg.nonstop.min_hours,
                "nonstop.max_quiet_hours": cfg.nonstop.max_quiet_hours}
    for key, value in positive.items():
        if not value > 0:
            raise UserError(f"{name}: {key} must be more than 0")
    shares = {"probing.min_failed_share": cfg.probing.min_failed_share,
              "narrowing.max_answered_share": cfg.narrowing.max_answered_share,
              "narrowing.min_focus_share": cfg.narrowing.min_focus_share,
              "timing.min_pause_share": cfg.timing.min_pause_share,
              "timing.min_timed_share": cfg.timing.min_timed_share,
              "steady.max_jitter": cfg.steady.max_jitter,
              "beacon.max_jitter": cfg.beacon.max_jitter,
              "spray.min_answered_share": cfg.spray.min_answered_share,
              "shared_sweep.min_split_share": cfg.shared_sweep.min_split_share,
              "login_spray.min_answered_share": cfg.login_spray.min_answered_share,
              "login_spray.min_service_share": cfg.login_spray.min_service_share}
    for key, value in shares.items():
        if not 0 <= value <= 1:
            raise UserError(f"{name}: {key} must be between 0 and 1 (0.7 means 70%)")
    if cfg.steady.min_sessions < 3:
        raise UserError(f"{name}: steady.min_sessions must be 3 or more: two sessions have one gap, which is "
                        "always even")
    if cfg.beacon.min_sessions < 3:
        raise UserError(f"{name}: beacon.min_sessions must be 3 or more: two sessions have one gap, which is "
                        "always even")
    for tool, patterns in cfg.web.user_agents.items():
        for pattern in patterns:
            if len(pattern.strip()) < 4:
                raise UserError(f"{name}: web.user_agents.{tool}: '{pattern}' is too short to tell a tool by; "
                                "give 4 characters or more")
    for label, names in cfg.web.names.items():
        for item in names:
            if "." not in item.strip(". ") or " " in item.strip() or "/" in item:
                raise UserError(f"{name}: web.names.{label}: '{item}' is not a host name such as api.example.com")
    if cfg.nonstop.max_quiet_hours >= cfg.nonstop.min_hours:
        raise UserError(f"{name}: nonstop.max_quiet_hours must be less than nonstop.min_hours")
    if cfg.parallel.min_services < 2 or cfg.parallel.min_bursts < 1:
        raise UserError(f"{name}: parallel.min_services must be 2 or more, and parallel.min_bursts 1 or more")
    if min(cfg.spray.min_per_minute, cfg.spray.min_minutes, cfg.spray.max_service_sources) < 1:
        raise UserError(f"{name}: spray.min_per_minute, spray.min_minutes and spray.max_service_sources must be 1 or more")
    if cfg.rotation.quiet_before_hours < 0:
        raise UserError(f"{name}: rotation.quiet_before_hours cannot be less than 0")
    ls = cfg.login_spray
    if min(ls.min_per_minute, ls.min_minutes, ls.max_reply_bytes) < 1 or ls.max_reply_spread < 0:
        raise UserError(f"{name}: login_spray.min_per_minute, login_spray.min_minutes and login_spray.max_reply_bytes "
                        "must be 1 or more, and login_spray.max_reply_spread 0 or more")
    if cfg.shared_sweep.min_sources < 2 or cfg.shared_sweep.min_probes_per_source < 1:
        raise UserError(f"{name}: shared_sweep.min_sources must be 2 or more, and shared_sweep.min_probes_per_source 1 or more")
    if cfg.baseline.before_hours < 0 or cfg.baseline.min_sessions < 1:
        raise UserError(f"{name}: baseline.before_hours cannot be less than 0, and baseline.min_sessions must be 1 or more")
    if cfg.rotation.min_joiners < 1 or cfg.rotation.max_service_sources < 1:
        raise UserError(f"{name}: rotation.min_joiners and rotation.max_service_sources must be 1 or more")
    if cfg.window_hours > cfg.lookback_hours:
        raise UserError(f"{name}: window_hours cannot be longer than lookback_hours")
    t = cfg.timing
    if t.pause_max_seconds < t.pause_min_seconds:
        raise UserError(f"{name}: timing.pause_max_seconds cannot be less than timing.pause_min_seconds")
    if t.pause_min_seconds < t.burst_gap_seconds:
        raise UserError(f"{name}: timing.pause_min_seconds cannot be less than timing.burst_gap_seconds: a gap "
                        "that short does not end a burst, so it is never a pause")
    for key, states in (("probing.zeek_failed_states", cfg.probing.zeek_failed_states),
                        ("narrowing.zeek_answered_states", cfg.narrowing.zeek_answered_states)):
        if not states or not all(s.isalnum() for s in states):
            raise UserError(f"{name}: {key} must list Zeek conn_state names such as S0 or SF")
    known = ("tcp", "udp", "icmp")
    cfg.narrowing.protocols = [p.lower() for p in cfg.narrowing.protocols]
    if not cfg.narrowing.protocols or not all(p in known for p in cfg.narrowing.protocols):
        raise UserError(f"{name}: narrowing.protocols must list one or more of {', '.join(known)}")
    pa = cfg.paloalto
    if not pa.deny_actions or not all(a.strip() for a in pa.deny_actions):
        raise UserError(f"{name}: paloalto.deny_actions must list at least one action, such as deny")
    if pa.failed_max_packets_received < 0:
        raise UserError(f"{name}: paloalto.failed_max_packets_received cannot be less than 0")
    if pa.answered_min_bytes_received < 1:
        raise UserError(f"{name}: paloalto.answered_min_bytes_received must be 1 or more: a session with "
                        "nothing back was not answered")
    for key, group in (("c2_ports", cfg.outbound.c2_ports), ("tool_ports", cfg.outbound.tool_ports),
                       ("tool_port_ranges", cfg.outbound.tool_port_ranges)):
        for label, ports in group.items():
            for port in ports:
                if not 1 <= port <= 65535:
                    raise UserError(f"{name}: outbound.{key}.{label}: {port} is not a port number (1 to 65535)")
    for label, ports in cfg.outbound.tool_port_ranges.items():
        if len(ports) != 2 or ports[0] > ports[1]:
            raise UserError(f"{name}: outbound.tool_port_ranges.{label} must be a first and a last port, "
                            "such as [28000, 29999]")
    seen: dict[int, str] = {}
    for label, ports in cfg.targets.items():
        for port in ports:
            if not 1 <= port <= 65535:
                raise UserError(f"{name}: targets.{label}: {port} is not a port number (1 to 65535)")
            if seen.get(port, label) != label:
                raise UserError(f"{name}: targets: port {port} is in both '{seen[port]}' and '{label}'; "
                                "give each port one name")
            seen[port] = label
    for label, offsets in (("syslog_offsets", pa.syslog_offsets), ("threat_syslog_offsets", pa.threat_syslog_offsets)):
        for key, value in offsets.items():
            if value is not None and not -3 <= value <= 400:
                raise UserError(f"{name}: paloalto.{label}.{key} is a position counted from the Type column; "
                                f"{value} cannot be right")
