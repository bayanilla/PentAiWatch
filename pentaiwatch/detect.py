"""Detection of outside sources that behave like agentic, AI-driven pentest tools.

One entry point: ``detect(con, cfg)``. It reads the clean ``flows`` table (see store.py) through
the DuckDB connection and returns a ``Detection``: the flagged sources, most serious first, and
the warnings a reader needs to judge them.

How it works, in order:

1. ``_classify_addresses``  which addresses are internal, and which sources are allowlisted.
1b. ``_outbound``           internal hosts with sessions OUT to a published attacker address
                            (flagged) or to a command-and-control port on any other outside
                            address (a hint only). Everything after this reads inbound sessions.
2. ``_common_sessions``     inbound sessions (outside source -> internal host) inside the lookback,
                            in ONE shape whatever sensor logged them: start time, how that time
                            was found, and an outcome of failed / answered / other. Every signal
                            below reads only this table, so each is written once.
3. ``_services``            per source and service (host, port, protocol): the first attempt and
                            the completed sessions.
4. ``_probing``             signal 1, per scoring window.
5. ``_narrowing``           signal 2, for the windows where probing fired.
6. ``_timing``              signal 3, for the sources where narrowing fired: their sessions cut
                            into bursts, and whether the bursts and pauses keep an agent's pace.
7. ``_sweeps``              per source, the one window it is judged by, and whether it is flagged.
8. ``_findings``            one finding per flagged source.
9. ``_known_sources``       sources on a list of published attacker addresses (knownbad.py) that
                            were not flagged by their traffic: flagged and named all the same.
10. ``_steady``             fixed-interval cadence: sources that hit one service over and over
                            at an almost constant gap, as a scripted login brute force does. It
                            is run before step 6, because it is the second timing pattern.
11. ``_spray``              sources that sent a flood of completed connections to one service,
                            minute after minute, as a password spray does.
12. ``_backing``            fixed-interval repetition, high-rate repeated connections and rotating
                            sources on their own are leads. One is flagged only when evidence from
                            other sessions of the same source backs it (see there). A
                            published-address match is context, never backing.
Within step 8, ``_parallel`` (several attack paths at once) raises a finding's confidence, and
``_rotation`` ties new addresses that came straight back to what one sweep found to that sweep.

A source is flagged when probing and narrowing fired and timing either fired too (level 1) or
could not be judged because its sessions have no start time (tier 0). Timing fires on either
pattern: short bursts separated by think-time pauses, or a fixed-interval cadence. A source that swept and
narrowed at some other pace is not flagged; ``Detection.narrowing_sources`` counts it.

The scoring tables (``pw_sessions``, ``pw_svc``, ``pw_probe``, ``pw_narrow_svc``, ``pw_narrow``,
``pw_burst``, ``pw_timing``, ``pw_pace``, ``pw_sweep``) exist only while ``detect`` runs. A caller
that needs more than the findings, such as the Explorer (explore.py), passes ``while_scored``: it
is called with the connection and the finished ``Detection`` just before the tables are dropped.

Scoring is per source address. A campaign that rotates through proxies is split across several
findings; each finding carries the services, hosts and times a later grouping step (by targeted
service, time window or network owner) needs, so that step can be added on top without changing
the signals.

Zeek conn.log and Palo Alto traffic logs are scored alone or together: step 2 turns each into the
same shape, and a session both recorded has already been counted once by the de-duplication in
store.py, with Zeek's start time. The threat-log levels (2 and 3) are not built yet.
"""
from __future__ import annotations

import csv
import ipaddress
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from . import engine
from .config import Config
from .knownbad import KnownBad
from .netmap import NetMap
from .scanners import Known
from .schema import START_END_MINUS_ELAPSED, START_FIELD, START_ZEEK_TS

TIER_0 = "Sweep and narrow seen, timing unavailable"
LEVEL_1 = "Agentic behaviour"
MAX_SERVICES_LISTED = 25
# The start times that are known to be session STARTS. Timing reads these and nothing else.
TIMED = (START_ZEEK_TS, START_FIELD, START_END_MINUS_ELAPSED)
# Fixed-interval cadence needs start times finer than the whole seconds an elapsed time gives: a
# 1.5-second step cannot be told from a 1-or-2-second jitter when the start is end minus elapsed.
CADENCE_TIMED = (START_ZEEK_TS, START_FIELD)
PATTERN_BURSTS = "burst and pause"
PATTERN_CADENCE = "fixed-interval cadence"
# What a standalone behaviour is called where it backs another one.
BEHAVIOUR_SWEEP = "sweep"
BEHAVIOUR_STEADY = "fixed-interval repetition"
BEHAVIOUR_SPRAY = "high-rate repeated connections"


def target_ports(cfg: Config) -> dict[int, str]:
    """Port -> the name of the kind of target it is (the ``targets`` setting)."""
    return {port: name for name, ports in cfg.targets.items() for port in ports}


def target_of(ports: dict[int, str], port, proto) -> str:
    """The kind of target a service is ('' when none): TCP and UDP only, a ping has no port."""
    return ports.get(port, "") if port is not None and proto in ("tcp", "udp") else ""


def _names(ports: dict[int, str], services) -> list[str]:
    """The kinds of target among (port, proto) pairs, in the order they first appear."""
    return list(dict.fromkeys(t for port, proto in services if (t := target_of(ports, port, proto))))


@dataclass
class Service:
    """A service the source narrowed onto."""
    host: str
    port: int | None
    proto: str
    network: str                 # name from network_map.csv, '' when unmapped
    sessions: int                # completed sessions from this source
    first_return: str            # when the source first came back to it (UTC)
    target: str = ""             # the kind of target its port is (the targets setting), '' when none


@dataclass
class Pace:
    """What the timing signal found for a flagged source."""
    status: str                  # 'agentic': signal 3 fired. 'unavailable': it could not be judged
    reason: str                  # why it could not be judged ('' when it fired)
    sessions_timed: int          # its sessions whose START time is known; only these are ever timed
    bursts: int                  # short bursts, each followed by a pause in the band, in the lookback
    bursts_all: int              # all its bursts in the lookback
    typical_pause_seconds: float | None      # median of the pauses that follow those short bursts
    window_start: str            # the scoring window in which signal 3 fired with the most such bursts
    window_bursts: int           # how many of them that window holds
    window_pause_share: float | None         # the share of ALL that window's pauses that are in the band
    patterns: list[str] = field(default_factory=list)   # which timing patterns fired (PATTERN_*)
    cadence_seconds: float | None = None     # the fixed interval, when that pattern fired (longest run)
    cadence_service: str = ""                # the service of that run, "host:port/proto"
    cadence_whole_seconds: bool = False      # that run's times are whole seconds (a firewall start field)


@dataclass
class Finding:
    source: str
    level: int                   # 0 = tier 0, 1 = agentic behaviour; 2 and 3 arrive with the threat logs
    label: str
    log_sources: list[str]       # kinds of log the finding was built from
    start_times: dict[str, int]  # how session start times were found -> sessions
    probe_start: str
    probe_end: str
    services_probed: int
    hosts_probed: int
    ports_probed: int
    failed_share: float          # share of the sweep's attempts that failed
    services_answered: int
    narrowing_start: str
    focus_share: float           # share of sessions that went to answered services once it narrowed
    services: list[Service]      # the services it narrowed onto, most sessions first
    services_total: int          # how many there are (the list is capped)
    hosts_hit: list[str]         # hosts of those services
    sessions: int                # all its inbound sessions in the lookback
    first_seen: str
    last_seen: str
    campaign_hours: float
    timing: Pace
    threat_evidence: str
    notes: list[str] = field(default_factory=list)    # what a reader should know about this finding's data
    known: dict | None = None    # its entry in a list of published attacker addresses, if any
    steady: list[SteadyRun] = field(default_factory=list)   # fixed-interval repetition, if any
    spray: list[SprayRun] = field(default_factory=list)     # high-rate repeated connections, if any
    targets: list[str] = field(default_factory=list)  # kinds of target among all the services it narrowed onto
    parallel: ParallelPaths | None = None   # several attack paths at once, if seen: higher confidence
    confidence: str = "standard"            # "higher" when several attack paths at once were seen
    rotation: Rotation | None = None        # new addresses that came back to what its sweep found


@dataclass
class SteadyRun:
    """One unbroken run of sessions from a source to one service at an almost constant gap."""
    service: str                 # "host:port/proto"
    sessions: int
    answered: int
    gap_seconds: float           # the typical (mean) gap between session starts
    jitter: float                # standard deviation of the gaps over their mean
    whole_seconds: bool          # its times are whole seconds (as on the firewall), so the gaps are too
    first: str
    last: str
    target: str = ""             # the kind of target the service is, '' when none


@dataclass
class ParallelPaths:
    """A flagged source that, after narrowing, worked several services in the same burst."""
    bursts: int                  # bursts that worked min_services+ services, switching back and forth
    bursts_total: int            # all its bursts with answered sessions after narrowing
    most_services: int           # the most services one of those bursts worked
    services: list[str]          # "host:port/proto" in those bursts, most sessions first (capped)
    first: str
    last: str


@dataclass
class Joiner:
    """An address that came straight back to what another address's sweep found."""
    source: str
    sessions: int                # its sessions in the window from its first one
    answered: int                # of those, completed sessions to what the sweep found
    services: list[str]          # "host:port/proto" of those, most sessions first (capped)
    first: str
    last: str


@dataclass
class Rotation:
    """Rotating sources: one sweep, and new addresses that came back to what it found."""
    sweeper: str
    flagged: bool                # the sweeper is a finding of its own as well
    probe_start: str
    probe_end: str
    services_probed: int
    services_found: int          # of those, the ones that answered and are not public
    joiners: list[Joiner]
    services: list[str]          # what the sweep found that the joiners came back to
    log_sources: list[str]
    # "flagged" when the sweeper is a finding, or an address in it also shows fixed-interval
    # repetition or high-rate repeated connections; else "lead"
    status: str = "lead"
    backed_by: list[str] = field(default_factory=list)


@dataclass
class SprayRun:
    """A source's flood of completed connections to one service."""
    service: str                 # "host:port/proto"
    minutes: int                 # minutes at the spray rate or above
    sessions: int                # sessions in those minutes
    answered: int
    peak_per_minute: int
    first: str                   # start of the first such minute
    last: str                    # end of the last such minute
    target: str = ""             # the kind of target the service is, '' when none


@dataclass
class SpraySource:
    """A source with high-rate repeated connections that is not a finding: a lead, or flagged when backed."""
    source: str
    log_sources: list[str]
    runs: list[SprayRun]         # most sessions first (capped)
    runs_total: int
    sessions: int                # all its inbound sessions in the lookback
    status: str = "lead"         # "flagged" when another behaviour of the source backs it, else "lead"
    backed_by: list[str] = field(default_factory=list)   # those behaviours (BEHAVIOUR_*)


@dataclass
class OutboundContact:
    """An internal host that had sessions out to a published attacker address."""
    host: str
    network: str                 # name from network_map.csv, '' when unmapped
    destination: str
    name: str                    # what the list says about the destination
    confidence: str
    reference: str
    list_name: str
    sessions: int
    answered: int                # sessions the destination answered
    ports: list[str]             # "port/proto", most sessions first (capped)
    first: str
    last: str
    log_sources: list[str]
    c2: list[str] = field(default_factory=list)   # command-and-control port names among those ports


@dataclass
class C2Hint:
    """An internal host's sessions out to a command-and-control port on an outside address that is
    not on a published list. A hint only: it never flags."""
    host: str
    network: str
    destination: str
    port: int
    tool: str                    # whose default port it is
    sessions: int
    answered: int
    first: str
    last: str
    log_sources: list[str]


@dataclass
class SteadySource:
    """A source with fixed-interval repetition that is not a finding: a lead, or flagged when backed."""
    source: str
    log_sources: list[str]
    runs: list[SteadyRun]        # longest first (capped)
    runs_total: int
    sessions: int                # all its inbound sessions in the lookback
    status: str = "lead"         # "flagged" when another behaviour of the source backs it, else "lead"
    backed_by: list[str] = field(default_factory=list)   # those behaviours (BEHAVIOUR_*)


@dataclass
class KnownSource:
    """A source on a list of published attacker addresses that its traffic alone did not flag."""
    source: str
    name: str                    # what the list says about it
    confidence: str              # high / medium / low, as the publisher put it ('' when not given)
    reference: str               # where it was published
    list_name: str               # which list: "bundled list" or the file name
    log_sources: list[str]
    sessions: int                # its inbound sessions in the lookback
    answered: int                # of those, the ones a host answered
    hosts: int
    services: list[str]          # "host:port/proto", most sessions first (capped)
    services_total: int
    first_seen: str
    last_seen: str
    targets: list[str] = field(default_factory=list)  # kinds of target among all the services it reached


@dataclass
class Detection:
    findings: list[Finding] = field(default_factory=list)
    known_sources: list[KnownSource] = field(default_factory=list)
    steady_sources: list[SteadySource] = field(default_factory=list)
    spray_sources: list[SpraySource] = field(default_factory=list)
    rotations: list[Rotation] = field(default_factory=list)
    outbound_contacts: list[OutboundContact] = field(default_factory=list)
    c2_hints: list[C2Hint] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    lookback_start: str | None = None
    lookback_end: str | None = None
    inbound_sessions: int = 0    # outside -> internal sessions scored
    outside_sources: int = 0
    candidates: int = 0          # sources that tried enough services to be worth scoring
    probing_sources: int = 0     # sources where signal 1 fired (with or without narrowing)
    narrowing_sources: int = 0   # sources where signals 1 and 2 fired (whatever their timing)
    # outside sources the allowlist or known_scanners.csv kept out of the scoring, and the inbound
    # sessions they had inside the lookback: a list that hides a source does not do it quietly
    never_flagged_sources: int = 0
    never_flagged_sessions: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


SCORING_TABLES = ("pw_ip", "pw_sessions", "pw_svc", "pw_probe", "pw_narrow_svc", "pw_narrow", "pw_burst",
                  "pw_timing", "pw_cadence", "pw_pace", "pw_sweep", "pw_out")


def detect(con, cfg: Config, *, while_scored=None) -> Detection:
    """Flag outside sources whose sessions in ``flows`` show a sweep, then narrowing, at the pace of
    an agentic tool (or at a pace that cannot be known, because the sessions have no start time).

    ``while_scored(con, detection)``, when given, is called once the findings are built and before
    the scoring tables are dropped. It is not called when there was nothing to score."""
    engine.check()               # a faulty DuckDB version would quietly find nothing
    out = Detection()
    total, untimed, last = con.execute(
        "SELECT count(*), count(*) FILTER (ts IS NULL), max(ts) FROM flows").fetchone()
    if not total:
        out.warnings.append("No sessions were read, so nothing could be scored.")
        return out
    if untimed:
        out.warnings.append(f"{untimed:,} session(s) had no readable time and were left out.")
    if last is None:
        return out
    start = last - timedelta(hours=cfg.lookback_hours)
    out.lookback_start, out.lookback_end = _iso(start), _iso(last)
    older = con.execute("SELECT count(*) FROM flows WHERE ts < ?", [start]).fetchone()[0]
    if older:
        out.warnings.append(f"{older:,} session(s) are older than the {cfg.lookback_hours:g}-hour lookback, which "
                            f"ends at the last session in the run ({_iso(last)}), and were left out. Raise "
                            "lookback_hours to include them.")
    nm = NetMap(cfg.networks)
    try:
        bad = _classify_addresses(con, cfg)
        if cfg.outbound.check:
            out.outbound_contacts, out.c2_hints = _outbound(con, cfg, bad, start, nm)
        _common_sessions(con, cfg, start)
        out.inbound_sessions, out.outside_sources = con.execute(
            "SELECT count(*), count(DISTINCT src_ip) FROM pw_sessions").fetchone()
        out.never_flagged_sources, out.never_flagged_sessions = _never_flagged(con, start)
        if not out.inbound_sessions and out.never_flagged_sessions:
            out.warnings.append(f"Nothing was scored: all {out.never_flagged_sessions:,} session(s) from outside "
                                f"addresses to internal hosts came from {out.never_flagged_sources:,} source(s) on "
                                "the allowlist or in known_scanners.csv.")
            return out
        if not out.inbound_sessions:
            out.warnings.append("No sessions from outside addresses to internal hosts were found. Check that "
                                "internal_nets (or network_map.csv) covers your address ranges.")
            return out
        out.warnings += _data_quality(con, cfg)
        out.candidates = _services(con, cfg)
        out.probing_sources = _probing(con, cfg)
        _narrowing(con, cfg)
        steady = _steady(con, cfg)
        _timing(con, cfg, steady)
        out.narrowing_sources = _sweeps(con)
        out.warnings += _cadence_unchecked(con, cfg)
        out.findings = _findings(con, cfg, nm, steady)
        for f in out.findings:
            f.known = bad.get(f.source)
        out.known_sources = _known_sources(con, bad, {f.source for f in out.findings}, target_ports(cfg))
        for f in out.findings:
            f.steady = steady.pop(f.source, [])
        out.steady_sources = [
            SteadySource(source=src, log_sources=log_sources(con, src), runs=runs[:MAX_STEADY_RUNS],
                         runs_total=len(runs), sessions=int(con.execute(
                             "SELECT count(*) FROM pw_sessions WHERE src_ip = ?", [src]).fetchone()[0]))
            for src, runs in sorted(steady.items(), key=lambda kv: (-kv[1][0].sessions, kv[0]))]
        out.rotations = _rotation(con, cfg, {f.source for f in out.findings})
        for g in out.rotations:
            for f in out.findings:
                if f.source == g.sweeper:
                    f.rotation = g
        spray = _spray(con, cfg)
        for f in out.findings:
            f.spray = spray.pop(f.source, [])
        steady_only = {v.source for v in out.steady_sources}
        spray_any = dict(spray)
        out.spray_sources = [
            SpraySource(source=src, log_sources=log_sources(con, src), runs=runs[:MAX_SPRAY_RUNS],
                        runs_total=len(runs), sessions=int(con.execute(
                            "SELECT count(*) FROM pw_sessions WHERE src_ip = ?", [src]).fetchone()[0]))
            for src, runs in sorted(spray.items(), key=lambda kv: (-kv[1][0].sessions, kv[0]))
            if src not in steady_only]
        _backing(con, out, spray_any)
        listed_but_allowed = sorted(ip for ip in bad if ip in _allowed(con))
        if listed_but_allowed:
            out.warnings.append(f"{len(listed_but_allowed)} source(s) on a list of published attacker addresses are "
                                "also on your allowlist or in known_scanners.csv, so they were not flagged: "
                                + ", ".join(listed_but_allowed[:10]) + (" and more" if len(listed_but_allowed) > 10 else "")
                                + ".")
        if while_scored is not None:
            while_scored(con, out)
    finally:
        for table in SCORING_TABLES:
            con.execute(f"DROP TABLE IF EXISTS {table}")
    return out


# -- 1. addresses ---------------------------------------------------------------------------
def _classify_addresses(con, cfg: Config) -> dict[str, dict]:
    """Table pw_ip(ip, internal, allowed) for every address in the flows. Internal: inside
    ``internal_nets`` or a network_map.csv range. Allowed: in the allowlist or known_scanners.csv.
    Returns the outside addresses on a list of published attacker addresses, with their entry."""
    internal = [ipaddress.ip_network(c, strict=False)
                for c in list(cfg.internal_nets) + [e["cidr"] for e in cfg.networks]]
    allowed = Known([{"cidr": str(ipaddress.ip_network(c, strict=False)), "name": ""} for c in cfg.allowlist]
                    + list(cfg.known_scanners))

    def is_internal(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr.version == n.version and addr in n for n in internal)

    ips = [r[0] for r in con.execute("SELECT src_ip FROM flows UNION SELECT dst_ip FROM flows").fetchall()]
    lists = KnownBad(cfg.known_bad)
    bad = {ip: hit for ip in ips if not is_internal(ip) and (hit := lists.match(ip)) is not None}
    fd, path = tempfile.mkstemp(prefix="pw-ip-", suffix=".csv")
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerows((ip, is_internal(ip), allowed.label(ip) is not None) for ip in ips)
        con.execute("CREATE OR REPLACE TEMP TABLE pw_ip (ip VARCHAR, internal BOOLEAN, allowed BOOLEAN)")
        if ips:
            con.execute("INSERT INTO pw_ip SELECT * FROM read_csv(?, header = false, auto_detect = false, "
                        "columns = {'ip': 'VARCHAR', 'internal': 'BOOLEAN', 'allowed': 'BOOLEAN'})", [path])
    finally:
        os.remove(path)
    return bad


def _allowed(con) -> set[str]:
    return {r[0] for r in con.execute("SELECT ip FROM pw_ip WHERE allowed").fetchall()}


# -- 1b. your hosts reaching out to attacker infrastructure ----------------------------------
MAX_OUTBOUND_PORTS = 10


def _outbound(con, cfg: Config, bad: dict[str, dict], start: datetime,
              nm: NetMap) -> tuple[list[OutboundContact], list[C2Hint]]:
    """Sessions since ``start`` from an internal host to an outside address: per (host, address),
    those to a published attacker address, and per (host, address, port) those to a command-and-
    control port (``outbound.c2_ports``) on any other outside address. A destination on the
    allowlist or in known_scanners.csv is left out, as it is for sources."""
    c2 = {port: tool for tool, ports in cfg.outbound.c2_ports.items() for port in ports}
    args = {"zeek_failed": list(cfg.probing.zeek_failed_states),
            "zeek_answered": list(cfg.narrowing.zeek_answered_states),
            "zeek_icmp": bool(cfg.probing.zeek_icmp_by_reply),
            "pa_failed_packets": int(cfg.paloalto.failed_max_packets_received),
            "pa_answered_bytes": int(cfg.paloalto.answered_min_bytes_received), "start": start}
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE pw_out AS
        SELECT f.src_ip AS host, f.dst_ip AS dest, f.dst_port, f.proto, f.ts, f.sensor,
               {_OUTCOME_SQL} AS outcome
        FROM flows f JOIN pw_ip s ON s.ip = f.src_ip JOIN pw_ip d ON d.ip = f.dst_ip
        WHERE s.internal AND NOT d.internal AND NOT d.allowed AND f.ts IS NOT NULL AND f.ts >= $start
          AND (list_contains($bad, f.dst_ip) OR (f.proto = 'tcp' AND list_contains($c2, f.dst_port)))""",
                {**args, "bad": sorted(bad), "c2": sorted(c2)})
    contacts = []
    for host, dest, n, answered, first, last, sensors in con.execute("""
            SELECT host, dest, count(*), count(*) FILTER (outcome = 'answered'), min(ts), max(ts), list(DISTINCT sensor)
            FROM pw_out WHERE list_contains($bad, dest) GROUP BY ALL ORDER BY host, dest""",
                                                                       {"bad": sorted(bad)}).fetchall():
        ports = con.execute("""
            SELECT dst_port, proto, count(*) AS n FROM pw_out WHERE host = ? AND dest = ?
            GROUP BY ALL ORDER BY n DESC, dst_port""", [host, dest]).fetchall()
        entry = bad[dest]
        contacts.append(OutboundContact(
            host=host, network=nm.name(host), destination=dest, name=entry["name"], confidence=entry["confidence"],
            reference=entry["reference"], list_name=entry["list_name"], sessions=int(n), answered=int(answered),
            ports=[f"{p}/{pr}" if p is not None else pr for p, pr, _ in ports[:MAX_OUTBOUND_PORTS]],
            first=_iso(first), last=_iso(last), log_sources=sorted(sensors),
            c2=list(dict.fromkeys(c2[p] for p, pr, _ in ports if pr == "tcp" and p in c2))))
    hints = [C2Hint(host=host, network=nm.name(host), destination=dest, port=int(port), tool=c2[port],
                    sessions=int(n), answered=int(answered), first=_iso(first), last=_iso(last),
                    log_sources=sorted(sensors))
             for host, dest, port, n, answered, first, last, sensors in con.execute("""
                SELECT host, dest, dst_port, count(*), count(*) FILTER (outcome = 'answered'), min(ts), max(ts),
                       list(DISTINCT sensor)
                FROM pw_out WHERE proto = 'tcp' AND list_contains($c2, dst_port) AND NOT list_contains($bad, dest)
                GROUP BY ALL ORDER BY host, dest, dst_port""", {"c2": sorted(c2), "bad": sorted(bad)}).fetchall()]
    rank = {c: i for i, c in enumerate(("high", "medium", "low", ""))}
    contacts.sort(key=lambda c: (rank.get(c.confidence, 3), -c.answered, -c.sessions, c.host, c.destination))
    hints.sort(key=lambda h: (-h.answered, -h.sessions, h.host, h.destination))
    return contacts, hints


# -- 2. the common session shape ------------------------------------------------------------
# A session's outcome (failed / answered / other), per kind of sensor. The state lists and the
# firewall thresholds are bound from the settings when the query runs.
#   Zeek       by conn_state. ICMP is the exception (probing.zeek_icmp_by_reply): Zeek gives every
#              ICMP record the state OTH, so a ping is judged by what came back, as on the
#              firewall. Nothing back: failed. A reply: answered. "Nothing back" is resp_pkts
#              where the log has it, else zero resp_bytes.
#   Palo Alto  stopped by the firewall, or allowed with nothing back: failed. Allowed with bytes
#              back: answered. "Nothing back" is the packets-received count where the export has
#              one, else zero bytes received.
_OUTCOME_SQL = """CASE f.sensor
            WHEN 'zeek' THEN CASE WHEN $zeek_icmp AND f.proto = 'icmp' AND coalesce(f.pkts_in, f.bytes_in) = 0 THEN 'failed'
                                  WHEN $zeek_icmp AND f.proto = 'icmp' THEN 'answered'
                                  WHEN list_contains(CAST($zeek_failed AS VARCHAR[]), f.state) THEN 'failed'
                                  WHEN list_contains(CAST($zeek_answered AS VARCHAR[]), f.state) THEN 'answered'
                                  ELSE 'other' END
            WHEN 'paloalto' THEN CASE WHEN f.action = 'deny' THEN 'failed'
                                      WHEN f.pkts_in IS NOT NULL AND f.pkts_in <= $pa_failed_packets THEN 'failed'
                                      WHEN f.pkts_in IS NULL AND f.bytes_in = 0 THEN 'failed'
                                      WHEN f.bytes_in >= $pa_answered_bytes THEN 'answered'
                                      ELSE 'other' END
            ELSE 'other' END"""


def _common_sessions(con, cfg: Config, start: datetime) -> None:
    """Table pw_sessions: inbound sessions since ``start`` from sources that are not allowlisted,
    one row each: seq, start_ts, start_method, sensor, src_ip, src_port, dst_ip, dst_port, proto,
    outcome, and stand_in (true where zero bytes received stood in for "no packets back")."""
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE pw_sessions AS
        SELECT f.seq, f.ts AS start_ts, f.start_method, f.sensor, f.src_ip, f.src_port, f.dst_ip,
               f.dst_port, f.proto, {_OUTCOME_SQL} AS outcome,
               f.sensor = 'paloalto' AND f.action <> 'deny' AND f.pkts_in IS NULL AS stand_in
        FROM flows f JOIN pw_ip s ON s.ip = f.src_ip JOIN pw_ip d ON d.ip = f.dst_ip
        WHERE NOT s.internal AND NOT s.allowed AND d.internal
          AND f.ts IS NOT NULL AND f.ts >= $start""",
                {"zeek_failed": list(cfg.probing.zeek_failed_states),
                 "zeek_answered": list(cfg.narrowing.zeek_answered_states),
                 "zeek_icmp": bool(cfg.probing.zeek_icmp_by_reply),
                 "pa_failed_packets": int(cfg.paloalto.failed_max_packets_received),
                 "pa_answered_bytes": int(cfg.paloalto.answered_min_bytes_received), "start": start})


def _never_flagged(con, start: datetime) -> tuple[int, int]:
    """(sources, sessions): the outside sources that the allowlist and known_scanners.csv keep out of
    pw_sessions, and the inbound sessions they had since ``start``."""
    sources, sessions = con.execute("""
        SELECT count(DISTINCT f.src_ip), count(*)
        FROM flows f JOIN pw_ip s ON s.ip = f.src_ip JOIN pw_ip d ON d.ip = f.dst_ip
        WHERE NOT s.internal AND s.allowed AND d.internal
          AND f.ts IS NOT NULL AND f.ts >= ?""", [start]).fetchone()
    return int(sources), int(sessions)


# How many sessions both sensors must have recorded before their clocks are compared.
MIN_CLOCK_PAIRS = 10


def _data_quality(con, cfg: Config) -> list[str]:
    """Warnings about the scored sessions that change how far the findings can be trusted."""
    out = []
    no_start, firewall, zeek = con.execute("""
        SELECT count(*) FILTER (start_method = 'none'), count(*) FILTER (sensor = 'paloalto'),
               count(*) FILTER (sensor = 'zeek') FROM pw_sessions""").fetchone()
    if no_start:
        out.append(f"{no_start:,} Palo Alto session(s) had neither a start time nor an elapsed time. They are "
                   "scored by their end time, so a sweep and narrowing can still be seen, and they are never "
                   "used for timing.")
        if zeek:
            out.append("Those sessions were not matched to a Zeek record. Where Zeek saw the same session, the "
                       "two times differ by the session's length, so some sessions may be counted twice.")
    if firewall and zeek:
        # A session both sensors recorded is normally kept once. Where both copies are still here,
        # their start times were further apart than the de-duplication tolerates: a clock problem.
        pairs, median = con.execute("""
            WITH once AS (
                SELECT sensor, src_ip, src_port, dst_ip, dst_port, proto, min(start_ts) AS ts
                FROM pw_sessions WHERE start_method <> 'none' AND src_port IS NOT NULL
                GROUP BY ALL HAVING count(*) = 1)
            SELECT count(*), median(epoch(p.ts) - epoch(z.ts))
            FROM once p JOIN once z USING (src_ip, src_port, dst_ip, dst_port, proto)
            WHERE p.sensor = 'paloalto' AND z.sensor = 'zeek'""").fetchone()
        if pairs >= MIN_CLOCK_PAIRS and abs(median) > cfg.dedup_skew_seconds:
            out.append(f"The Palo Alto and Zeek clocks disagree: for {pairs:,} sessions both recorded, the "
                       f"firewall's start time is {_gap(abs(median))} {'later' if median > 0 else 'earlier'} "
                       "than Zeek's (median). Those sessions are counted twice and the order of events across "
                       "the two logs cannot be trusted. Check that both are in UTC and that the clocks are "
                       "in step, or analyze one log at a time.")
    return out


def _gap(seconds: float) -> str:
    if seconds >= 5400:
        return f"{seconds / 3600:.1f} hours"
    return f"{seconds / 60:.0f} minutes" if seconds >= 90 else f"{seconds:.0f} seconds"


# -- 3. services ----------------------------------------------------------------------------
def _services(con, cfg: Config) -> int:
    """Table pw_svc: per source and service, the first attempt (time, outcome), how many sessions
    completed, and when the source first came back after that first attempt with a completed
    session (``return_ts``). ``bucket`` is the half window the first attempt fell in: windows start
    every half window and window k covers buckets k and k + 1, so a first attempt in bucket b
    belongs to windows b and b - 1. Only sources that tried enough services to possibly pass
    signal 1 are kept. Returns how many such sources there are."""
    con.execute("""
        CREATE OR REPLACE TEMP TABLE pw_svc AS
        WITH first AS MATERIALIZED (
            SELECT src_ip, dst_ip, dst_port, proto, min(seq) AS first_seq, min(start_ts) AS first_ts,
                   arg_min(outcome, seq) AS first_outcome, count(*) AS sessions,
                   count(*) FILTER (outcome = 'answered') AS answered
            FROM pw_sessions GROUP BY ALL),
        busy AS (SELECT src_ip FROM first GROUP BY src_ip HAVING count(*) >= $floor)
        SELECT v.*, CAST(floor(epoch(v.first_ts) / $step) AS BIGINT) AS bucket,
                    (SELECT min(s.start_ts) FROM pw_sessions s
                     WHERE s.src_ip = v.src_ip AND s.dst_ip = v.dst_ip AND s.proto = v.proto
                       AND s.dst_port IS NOT DISTINCT FROM v.dst_port
                       AND s.outcome = 'answered' AND s.seq > v.first_seq) AS return_ts
        FROM first v WHERE v.src_ip IN (SELECT src_ip FROM busy)""",
                {"floor": int(min(cfg.probing.min_ports, cfg.probing.min_hosts)),
                 "step": cfg.window_hours * 3600 / 2})
    return con.execute("SELECT count(DISTINCT src_ip) FROM pw_svc").fetchone()[0]


# -- 4. signal 1: probing -------------------------------------------------------------------
def _probing(con, cfg: Config) -> int:
    """Table pw_probe: the scoring windows in which a source's sweep fired signal 1.

    A sweep is made of first attempts: the first session from the source to each service. Counting
    only those keeps the later, repeated sessions of the narrowing phase from diluting the failed
    share. Windows are ``window_hours`` long and start every half window, so a sweep that crosses
    a window edge still falls whole inside one window. Returns how many sources fired."""
    p = cfg.probing
    con.execute("""
        CREATE OR REPLACE TEMP TABLE pw_probe AS
        SELECT v.src_ip, k, min(v.first_ts) AS probe_start, max(v.first_ts) AS probe_end,
               count(*) AS services, count(DISTINCT v.dst_ip) AS hosts,
               count(DISTINCT v.dst_port) FILTER (v.proto IN ('tcp', 'udp')) AS ports,
               count(*) FILTER (v.first_outcome = 'failed') AS failed,
               count(*) FILTER (v.answered > 0) AS answered
        FROM pw_svc v, unnest([v.bucket, v.bucket - 1]) AS w(k)
        GROUP BY v.src_ip, k
        HAVING (ports >= $min_ports OR hosts >= $min_hosts) AND failed >= $min_failed_share * count(*)""",
                {"min_ports": int(p.min_ports), "min_hosts": int(p.min_hosts),
                 "min_failed_share": float(p.min_failed_share)})
    return con.execute("SELECT count(DISTINCT src_ip) FROM pw_probe").fetchone()[0]


# -- 5. signal 2: narrowing -----------------------------------------------------------------
def _narrowing(con, cfg: Config) -> None:
    """Tables pw_narrow_svc and pw_narrow: the services a source narrowed onto after a sweep, and
    the probing windows after which it narrowed.

    For a window where probing fired: few of the probed services answered
    (``max_answered_share``); the source came back with ``min_sessions_per_service`` or more
    completed sessions to at least one of them; those returns began no later than
    ``max_start_delay_minutes`` after the sweep's last first attempt; and from then on, for one
    window, at least ``min_focus_share`` of its sessions went to services that had answered.

    Only services of the protocols in ``narrowing.protocols`` (TCP and UDP) can be narrowed onto:
    a host that keeps answering pings is not a service the source came back to."""
    n = cfg.narrowing
    con.execute("""
        CREATE OR REPLACE TEMP TABLE pw_narrow_svc AS
        SELECT p.src_ip, p.k, v.dst_ip, v.dst_port, v.proto, v.answered, v.return_ts
        FROM pw_probe p JOIN pw_svc v ON v.src_ip = p.src_ip AND v.bucket IN (p.k, p.k + 1)
        WHERE v.answered >= $min_sessions
          AND list_contains(CAST($protocols AS VARCHAR[]), v.proto)
          AND v.return_ts <= p.probe_end + to_seconds($max_delay)
          AND p.answered <= $max_answered_share * p.services""",
                {"min_sessions": int(n.min_sessions_per_service),
                 "protocols": [p.lower() for p in n.protocols],
                 "max_delay": float(n.max_start_delay_minutes) * 60,
                 "max_answered_share": float(n.max_answered_share)})
    con.execute("""
        CREATE OR REPLACE TEMP TABLE pw_narrow AS
        WITH narrowed AS (
            SELECT n.src_ip, n.k, min(n.return_ts) AS narrowing_start,
                   greatest(min(n.return_ts), any_value(p.probe_end)) AS focus_from
            FROM pw_narrow_svc n JOIN pw_probe p USING (src_ip, k) GROUP BY n.src_ip, n.k),
        focus AS (
            SELECT w.src_ip, w.k, count(*) FILTER (v.answered > 0) / count(*)::DOUBLE AS focus_share
            FROM narrowed w JOIN pw_sessions s ON s.src_ip = w.src_ip
             AND s.start_ts >= w.focus_from AND s.start_ts < w.focus_from + to_seconds($window)
            JOIN pw_svc v ON v.src_ip = s.src_ip AND v.dst_ip = s.dst_ip AND v.proto = s.proto
             AND v.dst_port IS NOT DISTINCT FROM s.dst_port
            GROUP BY w.src_ip, w.k)
        SELECT w.src_ip, w.k, w.narrowing_start, f.focus_share
        FROM narrowed w JOIN focus f USING (src_ip, k)
        WHERE f.focus_share >= $min_focus_share""",
                {"window": cfg.window_hours * 3600.0, "min_focus_share": float(n.min_focus_share)})


# -- 6. signal 3: timing --------------------------------------------------------------------
def _timing(con, cfg: Config, steady: dict[str, list[SteadyRun]] | None = None) -> None:
    """Tables pw_burst, pw_timing, pw_cadence and pw_pace, for the sources where narrowing fired.

    Signal 3 fires on either of two patterns: short bursts separated by think-time pauses
    (pw_timing), or a fixed-interval cadence (pw_cadence: the sources ``_steady`` found a run for,
    passed in as ``steady``).

    pw_burst   The source's sessions with a known START time, in order, cut into bursts: a gap of
               more than ``burst_gap_seconds`` between two starts ends a burst. One row per burst:
               its first and last start, its sessions, the pause that follows it (from its last
               start to the next burst's first; none after the last burst) and the half window
               that pause begins in.
    pw_timing  The scoring windows in which signal 3 fired: ``min_cycles`` or more short bursts
               (``max_burst_sessions`` sessions at most), each followed by a pause of
               ``pause_min_seconds`` to ``pause_max_seconds``, and at least ``min_pause_share`` of
               ALL the window's pauses inside that band. Nothing is asked of the spacing inside a
               burst, and the pauses need not be alike.
    pw_cadence The sources with a fixed-interval run: to one service (``steady``), or across the
               services it narrowed onto, from narrowing on (``_narrowed_cadence``).
    pw_pace    One row per source. 'agentic': signal 3 fired, either pattern. 'unavailable': it did
               not, and fewer than ``min_timed_share`` of the source's sessions have a known
               start time (none at all, in the usual case), so the pace could not be judged.
               'other': the source was seen nearly whole and does not keep that pace.

    A session whose time is an END time (start_method 'none') is never timed: long and aged-out
    sessions would smear the bursts."""
    t = cfg.timing
    con.execute("""
        CREATE OR REPLACE TEMP TABLE pw_burst AS
        WITH timed AS (
            SELECT src_ip, start_ts, seq, epoch(start_ts) - epoch(lag(start_ts) OVER w) AS gap
            FROM pw_sessions
            WHERE list_contains(CAST($timed AS VARCHAR[]), start_method)
              AND src_ip IN (SELECT src_ip FROM pw_narrow)
            WINDOW w AS (PARTITION BY src_ip ORDER BY start_ts, seq)),
        numbered AS (
            SELECT src_ip, start_ts,
                   sum(CASE WHEN gap IS NULL OR gap > $burst_gap THEN 1 ELSE 0 END)
                       OVER (PARTITION BY src_ip ORDER BY start_ts, seq ROWS UNBOUNDED PRECEDING) AS burst
            FROM timed),
        bursts AS (
            SELECT src_ip, burst, min(start_ts) AS first_ts, max(start_ts) AS last_ts, count(*) AS sessions
            FROM numbered GROUP BY src_ip, burst)
        SELECT src_ip, burst, first_ts, last_ts, sessions,
               epoch(lead(first_ts) OVER (PARTITION BY src_ip ORDER BY burst)) - epoch(last_ts) AS pause,
               CAST(floor(epoch(last_ts) / $step) AS BIGINT) AS bucket
        FROM bursts""",
                {"timed": list(TIMED), "burst_gap": float(t.burst_gap_seconds), "step": cfg.window_hours * 3600 / 2})
    con.execute("""
        CREATE OR REPLACE TEMP TABLE pw_timing AS
        SELECT b.src_ip, k, count(*) AS pauses,
               count(*) FILTER (b.pause BETWEEN $lo AND $hi) AS in_band,
               count(*) FILTER (b.sessions <= $max_burst AND b.pause BETWEEN $lo AND $hi) AS cycles
        FROM pw_burst b, unnest([b.bucket, b.bucket - 1]) AS w(k)
        WHERE b.pause IS NOT NULL
        GROUP BY b.src_ip, k
        HAVING cycles >= $min_cycles AND in_band >= $min_pause_share * count(*)""",
                {"lo": float(t.pause_min_seconds), "hi": float(t.pause_max_seconds),
                 "max_burst": int(t.max_burst_sessions), "min_cycles": int(t.min_cycles),
                 "min_pause_share": float(t.min_pause_share)})
    con.execute("CREATE OR REPLACE TEMP TABLE pw_cadence (src_ip VARCHAR)")
    cadence = sorted(set(steady or {}) | set(_narrowed_cadence(con, cfg)))
    if cadence:
        con.executemany("INSERT INTO pw_cadence VALUES (?)", [[ip] for ip in cadence])
    con.execute("""
        CREATE OR REPLACE TEMP TABLE pw_pace AS
        WITH seen AS (
            SELECT src_ip, count(*) AS sessions,
                   count(*) FILTER (list_contains(CAST($timed AS VARCHAR[]), start_method)) AS timed
            FROM pw_sessions WHERE src_ip IN (SELECT src_ip FROM pw_narrow) GROUP BY src_ip)
        SELECT src_ip, sessions, timed,
               CASE WHEN src_ip IN (SELECT src_ip FROM pw_timing) OR src_ip IN (SELECT src_ip FROM pw_cadence)
                    THEN 'agentic'
                    WHEN timed = 0 OR timed < $min_timed_share * sessions THEN 'unavailable'
                    ELSE 'other' END AS status
        FROM seen""", {"timed": list(TIMED), "min_timed_share": float(t.min_timed_share)})


def _pace(con, cfg: Config, src: str, status: str, sessions: int, timed: int,
          runs: list[SteadyRun] | None = None) -> Pace:
    """The timing evidence of one flagged source, for its finding."""
    t = cfg.timing
    bursts_all, cycles, typical = con.execute("""
        SELECT count(*), count(*) FILTER (sessions <= $max_burst AND pause BETWEEN $lo AND $hi),
               median(pause) FILTER (sessions <= $max_burst AND pause BETWEEN $lo AND $hi)
        FROM pw_burst WHERE src_ip = $src""",
                                              {"src": src, "max_burst": int(t.max_burst_sessions),
                                               "lo": float(t.pause_min_seconds),
                                               "hi": float(t.pause_max_seconds)}).fetchone()
    best = con.execute("SELECT k, cycles, pauses, in_band FROM pw_timing WHERE src_ip = ? "
                       "ORDER BY cycles DESC, k LIMIT 1", [src]).fetchone()
    if status == "agentic":
        reason = ""
    elif not timed:
        reason = "none of its sessions has a start time"
    else:
        reason = (f"only {timed:,} of its {sessions:,} sessions have a start time, and those do not show "
                  "the bursts and pauses")
    step = cfg.window_hours * 3600 / 2
    burst_fired = con.execute("SELECT count(*) FROM pw_timing WHERE src_ip = ?", [src]).fetchone()[0] > 0
    if not runs:
        across = _narrowed_cadence(con, cfg).get(src)
        runs = [across] if across else []
    patterns = ([PATTERN_BURSTS] if burst_fired else []) + ([PATTERN_CADENCE] if runs else [])
    longest = runs[0] if runs else None
    return Pace(status=status, reason=reason, sessions_timed=int(timed), bursts=int(cycles),
                bursts_all=int(bursts_all), typical_pause_seconds=round(typical, 1) if typical is not None else None,
                window_start=_iso(datetime.fromtimestamp(best[0] * step, tz=timezone.utc)) if best else "",
                window_bursts=int(best[1]) if best else 0,
                window_pause_share=round(best[3] / best[2], 3) if best else None,
                patterns=patterns if status == "agentic" else [],
                cadence_seconds=longest.gap_seconds if longest and status == "agentic" else None,
                cadence_service=longest.service if longest and status == "agentic" else "",
                cadence_whole_seconds=bool(longest and longest.whole_seconds and status == "agentic"))


# -- 7. the window each source is judged by -------------------------------------------------
def _sweeps(con) -> int:
    """Table pw_sweep(src_ip, k, narrowed, flagged): for every source where probing fired, the one
    window it is judged by. Windows overlap, so a sweep can fire in two of them. A window where
    narrowing fired too comes first; then the window that holds most of the sweep; then the
    earliest. ``flagged``: narrowing fired there and the source's pace is agentic or could not be
    judged. Returns how many sources narrowed."""
    con.execute("""
        CREATE OR REPLACE TEMP TABLE pw_sweep AS
        SELECT p.src_ip, p.k, w.src_ip IS NOT NULL AS narrowed,
               w.src_ip IS NOT NULL AND coalesce(t.status IN ('agentic', 'unavailable'), false) AS flagged
        FROM pw_probe p LEFT JOIN pw_narrow w USING (src_ip, k) LEFT JOIN pw_pace t ON t.src_ip = p.src_ip
        QUALIFY row_number() OVER (PARTITION BY p.src_ip ORDER BY narrowed DESC, p.services DESC, p.k) = 1""")
    return con.execute("SELECT count(*) FROM pw_sweep WHERE narrowed").fetchone()[0]


# -- 8. findings ----------------------------------------------------------------------------
def _findings(con, cfg: Config, nm: NetMap, steady: dict[str, list[SteadyRun]] | None = None) -> list[Finding]:
    """One finding per flagged source: the window where probing and narrowing both fired that holds
    the largest sweep (the earliest such window on a tie), plus everything it did in the lookback
    (so a campaign that pauses and resumes stays one finding)."""
    rows = con.execute("""
        SELECT p.src_ip, p.k, p.probe_start, p.probe_end, p.services, p.hosts, p.ports, p.failed,
               p.answered, w.narrowing_start, w.focus_share, t.status, t.sessions, t.timed
        FROM pw_sweep s JOIN pw_probe p USING (src_ip, k) JOIN pw_narrow w USING (src_ip, k)
        JOIN pw_pace t USING (src_ip)
        WHERE s.flagged ORDER BY p.src_ip""").fetchall()
    out = []
    threat_text = _threat_text(con)
    tports = target_ports(cfg)
    for src, k, p_start, p_end, services, hosts, ports, failed, answered, n_start, focus, status, n, timed in rows:
        svc_rows = con.execute("""
            SELECT dst_ip, dst_port, proto, answered, return_ts FROM pw_narrow_svc
            WHERE src_ip = ? AND k = ? ORDER BY answered DESC, dst_ip, dst_port""", [src, k]).fetchall()
        first, last = con.execute(
            "SELECT min(start_ts), max(start_ts) FROM pw_sessions WHERE src_ip = ?", [src]).fetchone()
        sensors = log_sources(con, src)
        stand_in = con.execute(
            "SELECT count(*) FROM pw_sessions WHERE src_ip = ? AND stand_in", [src]).fetchone()[0]
        notes = []
        if stand_in:
            notes.append(f"{stand_in:,} of its Palo Alto sessions come from an export without a packets-received "
                         "count, so zero bytes received stood in for 'no packets back'.")
        methods = dict(con.execute(
            "SELECT start_method, count(*) FROM pw_sessions WHERE src_ip = ? GROUP BY 1 ORDER BY 1", [src]).fetchall())
        listed = [Service(host=h, port=port, proto=proto, network=nm.name(h), sessions=int(c),
                          first_return=_iso(ts), target=target_of(tports, port, proto))
                  for h, port, proto, c, ts in svc_rows[:MAX_SERVICES_LISTED]]
        agentic = status == "agentic"
        parallel = _parallel(con, cfg, src, n_start)
        out.append(Finding(
            source=src, level=1 if agentic else 0, label=LEVEL_1 if agentic else TIER_0, log_sources=sensors,
            start_times=methods, probe_start=_iso(p_start), probe_end=_iso(p_end), services_probed=int(services),
            hosts_probed=int(hosts), ports_probed=int(ports), failed_share=round(failed / services, 3),
            services_answered=int(answered), narrowing_start=_iso(n_start), focus_share=round(focus, 3),
            services=listed, services_total=len(svc_rows), hosts_hit=sorted({r[0] for r in svc_rows}),
            sessions=int(n), first_seen=_iso(first), last_seen=_iso(last),
            campaign_hours=round((last - first).total_seconds() / 3600, 2),
            timing=_pace(con, cfg, src, status, int(n), int(timed), (steady or {}).get(src)),
            threat_evidence=threat_text, notes=notes, targets=_names(tports, [(r[1], r[2]) for r in svc_rows]),
            parallel=parallel, confidence="higher" if parallel else "standard"))
    return sorted(out, key=lambda f: (-f.level, -f.sessions, f.source))


# -- 8b. several attack paths at once --------------------------------------------------------
MAX_PARALLEL_SERVICES = 10
# One flagged source's answered TCP and UDP sessions from narrowing on, with a known START time, each
# numbered with its burst (a gap longer than the timing setting's burst gap starts a new one).
_PARALLEL_BURSTS = """
        WITH s AS (
            SELECT start_ts, seq, dst_ip, dst_port, proto,
                   epoch(start_ts) - epoch(lag(start_ts) OVER (ORDER BY start_ts, seq)) AS gap
            FROM pw_sessions
            WHERE src_ip = $src AND start_ts >= $since AND outcome = 'answered' AND proto IN ('tcp', 'udp')
              AND list_contains(CAST($timed AS VARCHAR[]), start_method)),
        b AS (
            SELECT *, sum(CASE WHEN gap IS NULL OR gap > $burst_gap THEN 1 ELSE 0 END)
                          OVER (ORDER BY start_ts, seq ROWS UNBOUNDED PRECEDING) AS burst
            FROM s)
"""


def _parallel(con, cfg: Config, src: str, since) -> ParallelPaths | None:
    """Several attack paths at once, for one flagged source: from narrowing on, its answered TCP and
    UDP sessions with a known START time, cut into bursts by the timing setting's burst gap. A burst
    counts when it works ``min_services`` or more services and switches between them more often
    than finishing one before starting the next would (it goes back to a service it left)."""
    p = cfg.parallel
    args = {"src": src, "since": since, "timed": list(TIMED), "burst_gap": float(cfg.timing.burst_gap_seconds)}
    rows = con.execute(_PARALLEL_BURSTS + """,
        sw AS (
            SELECT *, CASE WHEN lag(dst_ip) OVER w IS DISTINCT FROM dst_ip
                             OR lag(dst_port) OVER w IS DISTINCT FROM dst_port
                             OR lag(proto) OVER w IS DISTINCT FROM proto THEN 1 ELSE 0 END AS change
            FROM b WINDOW w AS (PARTITION BY burst ORDER BY start_ts, seq)),
        per AS (
            SELECT burst, min(start_ts) AS first_ts, max(start_ts) AS last_ts,
                   count(DISTINCT (dst_ip, dst_port, proto)) AS services, sum(change) AS changes
            FROM sw GROUP BY burst)
        SELECT burst, first_ts, last_ts, services, services >= $min_services AND changes > services AS hit
        FROM per ORDER BY burst""", {**args, "min_services": int(p.min_services)}).fetchall()
    hits = [r for r in rows if r[4]]
    if len(hits) < p.min_bursts:
        return None
    svc = con.execute(_PARALLEL_BURSTS + """
        SELECT dst_ip, dst_port, proto, count(*) AS n FROM b WHERE list_contains($bursts, burst)
        GROUP BY ALL ORDER BY n DESC, dst_ip, dst_port""", {**args, "bursts": [int(r[0]) for r in hits]}).fetchall()
    return ParallelPaths(
        bursts=len(hits), bursts_total=len(rows), most_services=max(int(r[3]) for r in hits),
        services=[f"{h}:{port}/{proto}" for h, port, proto, _ in svc[:MAX_PARALLEL_SERVICES]],
        first=_iso(min(r[1] for r in hits)), last=_iso(max(r[2] for r in hits)))


# -- 8c. rotating sources ----------------------------------------------------------------------
MAX_JOINER_SERVICES = 10


def _rotation(con, cfg: Config, flagged: set[str]) -> list[Rotation]:
    """Rotating sources. For each window where a source's sweep fired signal 1 and few of the probed
    services answered (as narrowing asks): the answered TCP and UDP services it found that are not
    public (``max_service_sources``). A joiner is another address first seen in the lookback between
    the sweep's start and ``max_start_delay_minutes`` after its end that, for one window from its
    first session, sent ``min_focus_share`` or more of its sessions to those services, with
    ``min_sessions_per_service`` or more completed sessions to at least one. A sweep with
    ``min_joiners`` or more joiners is a rotation (the window with the most joiners, per sweeper). An
    address that fits two sweeps joins the one that started last before it came."""
    n, r = cfg.narrowing, cfg.rotation
    rows = con.execute("""
        WITH sweep AS (
            SELECT src_ip, k, probe_start, probe_end, services FROM pw_probe
            WHERE answered > 0 AND answered <= $max_answered_share * services),
        public AS (
            SELECT dst_ip, dst_port, proto FROM pw_sessions
            GROUP BY ALL HAVING count(DISTINCT src_ip) > $max_sources),
        found AS (
            SELECT DISTINCT w.src_ip AS sweeper, w.k, v.dst_ip, v.dst_port, v.proto
            FROM sweep w JOIN pw_svc v ON v.src_ip = w.src_ip AND v.bucket IN (w.k, w.k + 1)
            WHERE v.answered > 0 AND list_contains(CAST($protocols AS VARCHAR[]), v.proto)
              AND NOT EXISTS (SELECT 1 FROM public p WHERE p.dst_ip = v.dst_ip AND p.proto = v.proto
                              AND p.dst_port IS NOT DISTINCT FROM v.dst_port)),
        seen AS (
            SELECT src_ip, min(start_ts) AS first_ts FROM pw_sessions
            WHERE src_ip NOT IN (SELECT src_ip FROM pw_probe) GROUP BY src_ip),
        cand AS (
            SELECT w.src_ip AS sweeper, w.k, w.probe_start, s.src_ip, s.dst_ip, s.dst_port, s.proto, s.outcome, s.start_ts,
                   f.sweeper IS NOT NULL AS on_found
            FROM sweep w
            JOIN seen j ON j.src_ip <> w.src_ip AND j.first_ts >= w.probe_start
                       AND j.first_ts <= w.probe_end + to_seconds($max_delay)
            JOIN pw_sessions s ON s.src_ip = j.src_ip AND s.start_ts < j.first_ts + to_seconds($window)
            LEFT JOIN found f ON f.sweeper = w.src_ip AND f.k = w.k AND f.dst_ip = s.dst_ip
                             AND f.proto = s.proto AND f.dst_port IS NOT DISTINCT FROM s.dst_port),
        per_svc AS (
            SELECT sweeper, k, src_ip, dst_ip, dst_port, proto, count(*) FILTER (outcome = 'answered') AS answered
            FROM cand WHERE on_found GROUP BY sweeper, k, src_ip, dst_ip, dst_port, proto),
        returned AS (
            SELECT DISTINCT sweeper, k, src_ip FROM per_svc WHERE answered >= $min_sessions),
        joiner AS (
            SELECT c.sweeper, c.k, c.src_ip, count(*) AS sessions,
                   count(*) FILTER (c.on_found AND c.outcome = 'answered') AS answered,
                   min(c.start_ts) AS first_ts, max(c.start_ts) AS last_ts
            FROM cand c JOIN returned USING (sweeper, k, src_ip)
            GROUP BY c.sweeper, c.k, c.src_ip
            HAVING count(*) FILTER (c.on_found) >= $min_focus * count(*)
            -- an address joins one sweep only: the latest to start before it came
            QUALIFY row_number() OVER (PARTITION BY c.src_ip ORDER BY max(c.probe_start) DESC, c.sweeper, c.k) = 1),
        best AS (
            SELECT sweeper, k FROM joiner GROUP BY sweeper, k HAVING count(*) >= $min_joiners
            QUALIFY row_number() OVER (PARTITION BY sweeper ORDER BY count(*) DESC, k) = 1)
        SELECT j.sweeper, j.k, j.src_ip, j.sessions, j.answered, j.first_ts, j.last_ts,
               w.probe_start, w.probe_end, w.services,
               (SELECT count(*) FROM found f WHERE f.sweeper = j.sweeper AND f.k = j.k),
               (SELECT list(p.dst_ip || coalesce(':' || p.dst_port, '') || '/' || p.proto
                            ORDER BY p.answered DESC, p.dst_ip, p.dst_port)
                FROM per_svc p WHERE p.sweeper = j.sweeper AND p.k = j.k AND p.src_ip = j.src_ip AND p.answered > 0)
        FROM joiner j JOIN best USING (sweeper, k) JOIN sweep w ON w.src_ip = j.sweeper AND w.k = j.k
        ORDER BY j.sweeper, j.first_ts, j.src_ip""",
                       {"max_answered_share": float(n.max_answered_share), "max_sources": int(r.max_service_sources),
                        "protocols": [p.lower() for p in n.protocols], "max_delay": float(n.max_start_delay_minutes) * 60,
                        "window": cfg.window_hours * 3600, "min_focus": float(n.min_focus_share),
                        "min_sessions": int(n.min_sessions_per_service), "min_joiners": int(r.min_joiners)}).fetchall()
    groups: dict[str, Rotation] = {}
    for sweeper, _k, src, sessions, answered, first, last, p_start, p_end, probed, found, svc in rows:
        g = groups.get(sweeper)
        if g is None:
            g = groups[sweeper] = Rotation(
                sweeper=sweeper, flagged=sweeper in flagged, probe_start=_iso(p_start), probe_end=_iso(p_end),
                services_probed=int(probed), services_found=int(found), joiners=[], services=[], log_sources=[])
        svc = list(svc or [])
        g.joiners.append(Joiner(source=src, sessions=int(sessions), answered=int(answered),
                                services=svc[:MAX_JOINER_SERVICES], first=_iso(first), last=_iso(last)))
        g.services += [s for s in svc if s not in g.services]
    for g in groups.values():
        g.log_sources = sorted({x for ip in [g.sweeper] + [j.source for j in g.joiners] for x in log_sources(con, ip)})
    return sorted(groups.values(), key=lambda g: (-len(g.joiners), g.sweeper))


# -- 9. published attacker addresses ---------------------------------------------------------
MAX_KNOWN_SERVICES = 10


def _known_sources(con, bad: dict[str, dict], flagged: set[str], tports: dict[int, str]) -> list[KnownSource]:
    """Sources with inbound sessions that are on a list of published attacker addresses and were
    not already flagged by their traffic (those findings carry the entry themselves)."""
    out = []
    for src in sorted(set(bad) - flagged):
        sessions, answered, hosts, first, last = con.execute("""
            SELECT count(*), count(*) FILTER (outcome = 'answered'), count(DISTINCT dst_ip), min(start_ts),
                   max(start_ts) FROM pw_sessions WHERE src_ip = ?""", [src]).fetchone()
        if not sessions:
            continue
        svc = con.execute("""
            SELECT dst_ip, dst_port, proto, count(*) AS n FROM pw_sessions WHERE src_ip = ?
            GROUP BY ALL ORDER BY n DESC, dst_ip, dst_port""", [src]).fetchall()
        entry = bad[src]
        out.append(KnownSource(
            source=src, name=entry["name"], confidence=entry["confidence"], reference=entry["reference"],
            list_name=entry["list_name"], log_sources=log_sources(con, src), sessions=int(sessions), answered=int(answered),
            hosts=int(hosts), services=[f"{h}:{p}/{pr}" if p is not None else f"{h}/{pr}" for h, p, pr, _ in
                                        svc[:MAX_KNOWN_SERVICES]],
            services_total=len(svc), first_seen=_iso(first), last_seen=_iso(last),
            targets=_names(tports, [(p, pr) for _, p, pr, _ in svc])))
    rank = {c: i for i, c in enumerate(("high", "medium", "low", ""))}
    return sorted(out, key=lambda k: (rank.get(k.confidence, 3), -k.sessions, k.source))


# -- 11. high-rate repeated connections----------------------------------------------------------
MAX_SPRAY_RUNS = 10


def _spray(con, cfg: Config) -> dict[str, list[SprayRun]]:
    """Per source, the TCP services it sent ``spray.min_per_minute`` or more sessions a minute in
    ``spray.min_minutes`` or more minutes, with ``spray.min_answered_share`` of those sessions
    completed. Services more than ``spray.max_service_sources`` outside addresses used are left
    out. Most sessions first."""
    s = cfg.spray
    rows = con.execute("""
        WITH public AS (
            SELECT dst_ip, dst_port FROM pw_sessions WHERE proto = 'tcp'
            GROUP BY ALL HAVING count(DISTINCT src_ip) > $max_sources),
        per_min AS (
            SELECT src_ip, dst_ip, dst_port, date_trunc('minute', start_ts) AS m, count(*) AS n,
                   count(*) FILTER (outcome = 'answered') AS a
            FROM pw_sessions WHERE proto = 'tcp' AND dst_port IS NOT NULL
            GROUP BY ALL HAVING count(*) >= $rate)
        SELECT p.src_ip, p.dst_ip, p.dst_port, count(*) AS minutes, sum(p.n) AS sessions, sum(p.a) AS answered,
               max(p.n) AS peak, min(p.m) AS first, max(p.m) + INTERVAL 1 MINUTE AS last
        FROM per_min p
        WHERE NOT EXISTS (SELECT 1 FROM public u WHERE u.dst_ip = p.dst_ip AND u.dst_port = p.dst_port)
        GROUP BY p.src_ip, p.dst_ip, p.dst_port
        HAVING count(*) >= $min_minutes AND sum(p.a) >= $share * sum(p.n)
        ORDER BY p.src_ip, sessions DESC, p.dst_ip, p.dst_port""",
                       {"max_sources": int(s.max_service_sources), "rate": int(s.min_per_minute),
                        "min_minutes": int(s.min_minutes), "share": float(s.min_answered_share)}).fetchall()
    out: dict[str, list[SprayRun]] = {}
    tports = target_ports(cfg)
    for src, host, port, minutes, n, answered, peak, first, last in rows:
        out.setdefault(src, []).append(SprayRun(
            service=f"{host}:{port}/tcp", minutes=int(minutes), sessions=int(n), answered=int(answered),
            peak_per_minute=int(peak), first=_iso(first), last=_iso(last), target=target_of(tports, port, "tcp")))
    return out


# -- 10. fixed-interval repetition --------------------------------------------------------------
MAX_STEADY_RUNS = 10


def _steady(con, cfg: Config) -> dict[str, list[SteadyRun]]:
    """Per source, its runs of ``steady.min_sessions`` or more sessions to one service, each started
    no more than ``steady.max_gap_seconds`` after the one before, whose gaps vary by no more than
    ``steady.max_jitter`` of their mean. Longest run first. Only sessions whose START time was logged
    (Zeek's ts or the firewall's start field): a start worked out from whole elapsed seconds blurs a
    1 or 2-second interval, so those sessions are never used here.

    Where every time in a run is a whole second (Palo Alto logs), a steady 1.5-second gap shows up
    as 1, 2, 1, 2...: the rounding alone spreads the gaps, so a run whose gaps are all one of two
    neighbouring whole seconds counts as steady too. A pace that really varies shows gaps of 0, 1,
    2 and 3 there. Below a typical gap of one second many sessions share a second and the rounding
    hides the pace, so no such allowance is made."""
    s = cfg.steady
    rows = con.execute("""
        WITH t AS (
            SELECT src_ip, dst_ip, dst_port, proto, start_ts, outcome,
                   epoch(start_ts) - epoch(lag(start_ts) OVER w) AS gap
            FROM pw_sessions WHERE list_contains(CAST($timed AS VARCHAR[]), start_method)
            WINDOW w AS (PARTITION BY src_ip, dst_ip, dst_port, proto ORDER BY start_ts, seq)),
        r AS (
            SELECT *, sum(CASE WHEN gap IS NULL OR gap > $max_gap THEN 1 ELSE 0 END) OVER (
                PARTITION BY src_ip, dst_ip, dst_port, proto ORDER BY start_ts ROWS UNBOUNDED PRECEDING) AS run
            FROM t),
        runs AS (
            SELECT src_ip, dst_ip, dst_port, proto, run, count(*) AS n,
                   count(*) FILTER (outcome = 'answered') AS answered, min(start_ts) AS first_ts,
                   max(start_ts) AS last_ts, avg(gap) FILTER (gap <= $max_gap) AS mean_gap,
                   stddev_pop(gap) FILTER (gap <= $max_gap) AS sd_gap,
                   min(gap) FILTER (gap <= $max_gap) AS lo_gap, max(gap) FILTER (gap <= $max_gap) AS hi_gap,
                   bool_and(epoch(start_ts) = floor(epoch(start_ts))) AS whole
            FROM r GROUP BY ALL)
        SELECT src_ip, dst_ip, dst_port, proto, n, answered, mean_gap, sd_gap / mean_gap, whole, first_ts, last_ts
        FROM runs WHERE n >= $min_sessions AND mean_gap > 0
          AND (sd_gap <= $max_jitter * mean_gap OR (whole AND mean_gap >= 1 AND hi_gap - lo_gap <= 1))
        ORDER BY src_ip, n DESC, first_ts""",
                       {"timed": list(CADENCE_TIMED), "max_gap": float(s.max_gap_seconds),
                        "min_sessions": int(s.min_sessions), "max_jitter": float(s.max_jitter)}).fetchall()
    out: dict[str, list[SteadyRun]] = {}
    tports = target_ports(cfg)
    for src, host, port, proto, n, answered, gap, jitter, whole, first, last in rows:
        out.setdefault(src, []).append(SteadyRun(
            service=f"{host}:{port}/{proto}" if port is not None else f"{host}/{proto}", sessions=int(n),
            answered=int(answered), gap_seconds=round(gap, 2), jitter=round(jitter, 3), whole_seconds=bool(whole),
            first=_iso(first), last=_iso(last), target=target_of(tports, port, proto)))
    return out


def _narrowed_cadence(con, cfg: Config) -> dict[str, SteadyRun]:
    """Per source where narrowing fired, its longest fixed-interval run ACROSS services, from the end
    of the sweep it narrowed after (its last first attempt): ``steady.min_sessions`` or more sessions in a row, whatever service each
    went to, each started within ``steady.max_gap_seconds`` of the one before, gaps varying by no
    more than ``steady.max_jitter`` of their mean (the same whole-second allowance as ``_steady``).
    A tool that steps through what answered at a fixed rate (CyberStrikeAI fingerprinted management
    ports every 2 seconds, a few sessions per port) keeps no one service busy long enough for a
    per-service run. The sweep itself is left out: a scanner probing at a fixed rate is not this.
    It starts at the sweep's end rather than at the first return, because the first steps can go to
    services that answered but were not returned to five times."""
    s = cfg.steady
    rows = con.execute("""
        WITH since AS (SELECT n.src_ip, min(p.probe_end) AS t0 FROM pw_narrow n JOIN pw_probe p USING (src_ip, k)
                       GROUP BY n.src_ip),
        t AS (
            SELECT p.src_ip, p.start_ts, p.dst_ip, p.dst_port, p.proto, p.outcome,
                   epoch(p.start_ts) - epoch(lag(p.start_ts) OVER w) AS gap
            FROM pw_sessions p JOIN since USING (src_ip)
            WHERE p.start_ts >= since.t0 AND list_contains(CAST($timed AS VARCHAR[]), p.start_method)
            WINDOW w AS (PARTITION BY p.src_ip ORDER BY p.start_ts, p.seq)),
        r AS (
            SELECT *, sum(CASE WHEN gap IS NULL OR gap > $max_gap THEN 1 ELSE 0 END) OVER (
                PARTITION BY src_ip ORDER BY start_ts ROWS UNBOUNDED PRECEDING) AS run
            FROM t),
        runs AS (
            SELECT src_ip, run, count(*) AS n, count(*) FILTER (outcome = 'answered') AS answered,
                   count(DISTINCT (dst_ip, dst_port, proto)) AS services,
                   min(start_ts) AS first_ts, max(start_ts) AS last_ts,
                   avg(gap) FILTER (gap <= $max_gap) AS mean_gap, stddev_pop(gap) FILTER (gap <= $max_gap) AS sd_gap,
                   min(gap) FILTER (gap <= $max_gap) AS lo_gap, max(gap) FILTER (gap <= $max_gap) AS hi_gap,
                   bool_and(epoch(start_ts) = floor(epoch(start_ts))) AS whole
            FROM r GROUP BY src_ip, run)
        SELECT src_ip, n, answered, services, mean_gap, sd_gap / mean_gap, whole, first_ts, last_ts
        FROM runs WHERE n >= $min_sessions AND mean_gap > 0
          AND (sd_gap <= $max_jitter * mean_gap OR (whole AND mean_gap >= 1 AND hi_gap - lo_gap <= 1))
        QUALIFY row_number() OVER (PARTITION BY src_ip ORDER BY n DESC, first_ts) = 1""",
                       {"timed": list(CADENCE_TIMED), "max_gap": float(s.max_gap_seconds),
                        "min_sessions": int(s.min_sessions), "max_jitter": float(s.max_jitter)}).fetchall()
    return {src: SteadyRun(service=f"{services} services in turn", sessions=int(n), answered=int(answered),
                           gap_seconds=round(gap, 2), jitter=round(jitter, 3), whole_seconds=bool(whole),
                           first=_iso(first), last=_iso(last))
            for src, n, answered, services, gap, jitter, whole, first, last in rows}


def _cadence_unchecked(con, cfg: Config) -> list[str]:
    """A warning when sources swept and narrowed but their start times came from elapsed seconds, so
    the burst pattern was checked and the fixed-interval cadence could not be."""
    n = con.execute("""
        SELECT count(*) FROM pw_pace p
        WHERE p.status = 'other' AND p.src_ip IN (SELECT src_ip FROM pw_sweep WHERE narrowed)
          AND (SELECT count(*) FILTER (list_contains(CAST($cadence AS VARCHAR[]), start_method))
               FROM pw_sessions s WHERE s.src_ip = p.src_ip) < $share * p.sessions""",
                    {"cadence": list(CADENCE_TIMED), "share": float(cfg.timing.min_timed_share)}).fetchone()[0]
    if not n:
        return []
    return [f"{n:,} source(s) swept and narrowed, and their start times were worked out from whole elapsed "
            "seconds. Their bursts and pauses were checked and did not fit; a fixed-interval cadence cannot be "
            "checked at that precision, so a tool stepping every 1 or 2 seconds would not be flagged. A "
            "firewall export with the session start time, or Zeek, settles it."]


def _backing(con, out: Detection, spray_any: dict[str, list[SprayRun]] | None = None) -> None:
    """Set ``status`` and ``backed_by`` on the standalone behaviours: fixed-interval repetition,
    high-rate repeated connections and rotating sources. Each alone is a lead, because a health
    check, a busy integration or ordinary clients near a sweep can look the same. One is flagged only
    when evidence from OTHER sessions of the same source backs it:

    * fixed-interval repetition or high-rate repeated connections: the source swept (signal 1
      fired), or it shows the other of the two on a different service. On the same service the two
      are one stream of sessions measured twice (a fast health check is both), so they do not count.
    * rotating sources: the sweeping address is a finding, or it shows fixed-interval repetition or
      high-rate repeated connections itself. A joiner's own repetition is what made it a joiner, so
      it never backs the rotation, and a rotation never backs a joiner's repetition.

    A finding of its own carries its runs already and is not listed here. ``spray_any``: every source
    with high-rate repeated connections that is not a finding, with its runs, including those listed
    only under fixed-interval repetition. A published-address match never backs anything."""
    swept = {r[0] for r in con.execute("SELECT DISTINCT src_ip FROM pw_probe").fetchall()}
    steady = {v.source: {r.service for r in v.runs} for v in out.steady_sources}
    spray = {src: {r.service for r in runs} for src, runs in (spray_any or {}).items()}
    for v in out.spray_sources:
        spray.setdefault(v.source, {r.service for r in v.runs})

    def backed(src: str, own: dict[str, set], other: dict[str, set], other_name: str) -> list[str]:
        out_ = [BEHAVIOUR_SWEEP] if src in swept else []
        if other.get(src, set()) - own.get(src, set()):
            out_.append(other_name)
        return out_

    for v in out.steady_sources:
        v.backed_by = backed(v.source, steady, spray, BEHAVIOUR_SPRAY)
        v.status = "flagged" if v.backed_by else "lead"
    for w in out.spray_sources:
        w.backed_by = backed(w.source, spray, steady, BEHAVIOUR_STEADY)
        w.status = "flagged" if w.backed_by else "lead"
    for g in out.rotations:
        g.backed_by = ((["the sweeping address is a finding"] if g.flagged else [])
                       + ([f"the sweeping address shows {BEHAVIOUR_STEADY}"] if g.sweeper in steady else [])
                       + ([f"the sweeping address shows {BEHAVIOUR_SPRAY}"] if g.sweeper in spray else []))
        g.status = "flagged" if g.backed_by else "lead"


def _has_table(con, name: str) -> bool:
    return con.execute("SELECT count(*) FROM information_schema.tables WHERE table_name = ?",
                       [name]).fetchone()[0] > 0


def log_sources(con, src: str) -> list[str]:
    """The kinds of log that recorded the source. Read from before the de-duplication where the
    store kept that (a session seen by both sensors is kept once, under one sensor's name)."""
    if _has_table(con, "source_sensors"):
        found = [r[0] for r in con.execute(
            "SELECT DISTINCT sensor FROM source_sensors WHERE src_ip = ? ORDER BY 1", [src]).fetchall()]
        if found:
            return found
    return [r[0] for r in con.execute(
        "SELECT DISTINCT sensor FROM pw_sessions WHERE src_ip = ? ORDER BY 1", [src]).fetchall()]


def _threat_text(con) -> str:
    """What a finding says about exploit evidence until the threat-log levels are built."""
    events = con.execute("SELECT count(*) FROM threats WHERE sensor = 'paloalto'").fetchone()[0] \
        if _has_table(con, "threats") else 0
    if not events:
        return "threat logs not provided"
    return (f"threat logs were read ({events:,} event{'' if events == 1 else 's'}) but are not scored yet: "
            "this says nothing either way about exploit attempts")


def _iso(ts: datetime | None) -> str:
    """A DuckDB TIMESTAMP (naive, always UTC here) as ISO text ending in Z."""
    return ts.replace(tzinfo=None).isoformat(timespec="seconds") + "Z" if ts is not None else ""
