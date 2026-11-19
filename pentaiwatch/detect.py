"""Detection of outside sources that behave like agentic, AI-driven pentest tools.

One entry point: ``detect(con, cfg)``. It reads the clean ``flows`` table (see store.py) through
the DuckDB connection and returns a ``Detection``: the flagged sources, most serious first, and
the warnings a reader needs to judge them.

How it works, in order:

1. ``_classify_addresses``  which addresses are internal, and which sources are allowlisted.
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
10. ``_steady``             sources that hit one service over and over at an almost constant gap,
                            as a scripted login brute force does: flagged on their own, and
                            attached to a finding when the source is flagged already.

A source is flagged when probing and narrowing fired and timing either fired too (level 1) or
could not be judged because its sessions have no start time (tier 0). A source that swept and
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


@dataclass
class Service:
    """A service the source narrowed onto."""
    host: str
    port: int | None
    proto: str
    network: str                 # name from network_map.csv, '' when unmapped
    sessions: int                # completed sessions from this source
    first_return: str            # when the source first came back to it (UTC)


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
    steady: list[SteadyRun] = field(default_factory=list)   # machine-steady repetition, if any


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


@dataclass
class SteadySource:
    """A source whose only evidence is machine-steady repetition (it was not flagged otherwise)."""
    source: str
    log_sources: list[str]
    runs: list[SteadyRun]        # longest first (capped)
    runs_total: int
    sessions: int                # all its inbound sessions in the lookback


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


@dataclass
class Detection:
    findings: list[Finding] = field(default_factory=list)
    known_sources: list[KnownSource] = field(default_factory=list)
    steady_sources: list[SteadySource] = field(default_factory=list)
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
                  "pw_timing", "pw_pace", "pw_sweep")


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
        _timing(con, cfg)
        out.narrowing_sources = _sweeps(con)
        out.findings = _findings(con, cfg, nm)
        for f in out.findings:
            f.known = bad.get(f.source)
        out.known_sources = _known_sources(con, bad, {f.source for f in out.findings})
        steady = _steady(con, cfg)
        for f in out.findings:
            f.steady = steady.pop(f.source, [])
        out.steady_sources = [
            SteadySource(source=src, log_sources=log_sources(con, src), runs=runs[:MAX_STEADY_RUNS],
                         runs_total=len(runs), sessions=int(con.execute(
                             "SELECT count(*) FROM pw_sessions WHERE src_ip = ?", [src]).fetchone()[0]))
            for src, runs in sorted(steady.items(), key=lambda kv: (-kv[1][0].sessions, kv[0]))]
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
def _timing(con, cfg: Config) -> None:
    """Tables pw_burst, pw_timing and pw_pace, for the sources where narrowing fired.

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
    pw_pace    One row per source. 'agentic': signal 3 fired in a window. 'unavailable': it did
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
    con.execute("""
        CREATE OR REPLACE TEMP TABLE pw_pace AS
        WITH seen AS (
            SELECT src_ip, count(*) AS sessions,
                   count(*) FILTER (list_contains(CAST($timed AS VARCHAR[]), start_method)) AS timed
            FROM pw_sessions WHERE src_ip IN (SELECT src_ip FROM pw_narrow) GROUP BY src_ip)
        SELECT src_ip, sessions, timed,
               CASE WHEN src_ip IN (SELECT src_ip FROM pw_timing) THEN 'agentic'
                    WHEN timed = 0 OR timed < $min_timed_share * sessions THEN 'unavailable'
                    ELSE 'other' END AS status
        FROM seen""", {"timed": list(TIMED), "min_timed_share": float(t.min_timed_share)})


def _pace(con, cfg: Config, src: str, status: str, sessions: int, timed: int) -> Pace:
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
    return Pace(status=status, reason=reason, sessions_timed=int(timed), bursts=int(cycles),
                bursts_all=int(bursts_all), typical_pause_seconds=round(typical, 1) if typical is not None else None,
                window_start=_iso(datetime.fromtimestamp(best[0] * step, tz=timezone.utc)) if best else "",
                window_bursts=int(best[1]) if best else 0,
                window_pause_share=round(best[3] / best[2], 3) if best else None)


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
def _findings(con, cfg: Config, nm: NetMap) -> list[Finding]:
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
                          first_return=_iso(ts)) for h, port, proto, c, ts in svc_rows[:MAX_SERVICES_LISTED]]
        agentic = status == "agentic"
        out.append(Finding(
            source=src, level=1 if agentic else 0, label=LEVEL_1 if agentic else TIER_0, log_sources=sensors,
            start_times=methods, probe_start=_iso(p_start), probe_end=_iso(p_end), services_probed=int(services),
            hosts_probed=int(hosts), ports_probed=int(ports), failed_share=round(failed / services, 3),
            services_answered=int(answered), narrowing_start=_iso(n_start), focus_share=round(focus, 3),
            services=listed, services_total=len(svc_rows), hosts_hit=sorted({r[0] for r in svc_rows}),
            sessions=int(n), first_seen=_iso(first), last_seen=_iso(last),
            campaign_hours=round((last - first).total_seconds() / 3600, 2),
            timing=_pace(con, cfg, src, status, int(n), int(timed)),
            threat_evidence=threat_text, notes=notes))
    return sorted(out, key=lambda f: (-f.level, -f.sessions, f.source))


# -- 9. published attacker addresses ---------------------------------------------------------
MAX_KNOWN_SERVICES = 10


def _known_sources(con, bad: dict[str, dict], flagged: set[str]) -> list[KnownSource]:
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
            services_total=len(svc), first_seen=_iso(first), last_seen=_iso(last)))
    rank = {c: i for i, c in enumerate(("high", "medium", "low", ""))}
    return sorted(out, key=lambda k: (rank.get(k.confidence, 3), -k.sessions, k.source))


# -- 10. machine-steady repetition ------------------------------------------------------------
MAX_STEADY_RUNS = 10


def _steady(con, cfg: Config) -> dict[str, list[SteadyRun]]:
    """Per source, its runs of ``steady.min_sessions`` or more sessions to one service, each started
    no more than ``steady.max_gap_seconds`` after the one before, whose gaps vary by no more than
    ``steady.max_jitter`` of their mean. Longest run first. Only sessions with a known START time.

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
                       {"timed": list(TIMED), "max_gap": float(s.max_gap_seconds),
                        "min_sessions": int(s.min_sessions), "max_jitter": float(s.max_jitter)}).fetchall()
    out: dict[str, list[SteadyRun]] = {}
    for src, host, port, proto, n, answered, gap, jitter, whole, first, last in rows:
        out.setdefault(src, []).append(SteadyRun(
            service=f"{host}:{port}/{proto}" if port is not None else f"{host}/{proto}", sessions=int(n),
            answered=int(answered), gap_seconds=round(gap, 2), jitter=round(jitter, 3), whole_seconds=bool(whole),
            first=_iso(first),
            last=_iso(last)))
    return out


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
