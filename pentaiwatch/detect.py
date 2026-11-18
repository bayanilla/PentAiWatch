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
6. ``_findings``            one finding per source, from the window where both fired.

Scoring is per source address. A campaign that rotates through proxies is split across several
findings; each finding carries the services, hosts and times a later grouping step (by targeted
service, time window or network owner) needs, so that step can be added on top without changing
the signals.

The timing signal and the threat-log levels are not built yet, so every finding is tier 0.
"""
from __future__ import annotations

import csv
import ipaddress
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from . import engine
from .config import Config
from .netmap import NetMap
from .scanners import Known

TIER_0 = "Sweep and narrow seen, timing unavailable"
MAX_SERVICES_LISTED = 25


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
class Finding:
    source: str
    level: int                   # 0 = tier 0; 1-3 arrive with the timing signal and threat logs
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
    timing: str                  # why the timing signal has no result
    threat_evidence: str


@dataclass
class Detection:
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    lookback_start: str | None = None
    lookback_end: str | None = None
    inbound_sessions: int = 0    # outside -> internal sessions scored
    outside_sources: int = 0
    candidates: int = 0          # sources that tried enough services to be worth scoring
    probing_sources: int = 0     # sources where signal 1 fired (with or without narrowing)

    def to_dict(self) -> dict:
        return asdict(self)


def detect(con, cfg: Config) -> Detection:
    """Flag outside sources whose sessions in ``flows`` show a sweep followed by narrowing."""
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
        _classify_addresses(con, cfg)
        _common_sessions(con, cfg, start)
        out.inbound_sessions, out.outside_sources = con.execute(
            "SELECT count(*), count(DISTINCT src_ip) FROM pw_sessions").fetchone()
        if not out.inbound_sessions:
            out.warnings.append("No sessions from outside addresses to internal hosts were found. Check that "
                                "internal_nets (or network_map.csv) covers your address ranges.")
            return out
        out.candidates = _services(con, cfg)
        out.probing_sources = _probing(con, cfg)
        _narrowing(con, cfg)
        out.findings = _findings(con, nm)
    finally:
        for table in ("pw_ip", "pw_sessions", "pw_svc", "pw_probe", "pw_narrow_svc", "pw_narrow"):
            con.execute(f"DROP TABLE IF EXISTS {table}")
    return out


# -- 1. addresses ---------------------------------------------------------------------------
def _classify_addresses(con, cfg: Config) -> None:
    """Table pw_ip(ip, internal, allowed) for every address in the flows. Internal: inside
    ``internal_nets`` or a network_map.csv range. Allowed: in the allowlist or known_scanners.csv."""
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


# -- 2. the common session shape ------------------------------------------------------------
# A session's outcome (failed / answered / other), per kind of sensor. The state lists are bound
# from the settings when the query runs.
_OUTCOME_SQL = """CASE f.sensor
            WHEN 'zeek' THEN CASE WHEN list_contains(CAST($zeek_failed AS VARCHAR[]), f.state) THEN 'failed'
                                  WHEN list_contains(CAST($zeek_answered AS VARCHAR[]), f.state) THEN 'answered'
                                  ELSE 'other' END
            ELSE 'other' END"""


def _common_sessions(con, cfg: Config, start: datetime) -> None:
    """Table pw_sessions: inbound sessions since ``start`` from sources that are not allowlisted,
    one row each: seq, start_ts, start_method, sensor, src_ip, dst_ip, dst_port, proto, outcome."""
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE pw_sessions AS
        SELECT f.seq, f.ts AS start_ts, f.start_method, f.sensor, f.src_ip, f.dst_ip,
               f.dst_port, f.proto, {_OUTCOME_SQL} AS outcome
        FROM flows f JOIN pw_ip s ON s.ip = f.src_ip JOIN pw_ip d ON d.ip = f.dst_ip
        WHERE NOT s.internal AND NOT s.allowed AND d.internal
          AND f.ts IS NOT NULL AND f.ts >= $start""",
                {"zeek_failed": list(cfg.probing.zeek_failed_states),
                 "zeek_answered": list(cfg.narrowing.zeek_answered_states), "start": start})


# -- 3. services ----------------------------------------------------------------------------
def _services(con, cfg: Config) -> int:
    """Table pw_svc: per source and service, the first attempt (time, outcome), how many sessions
    completed, and when the source first came back after that first attempt with a completed
    session (``return_ts``). Only sources that tried enough services to possibly pass signal 1 are
    kept. Returns how many such sources there are."""
    con.execute("""
        CREATE OR REPLACE TEMP TABLE pw_svc AS
        WITH first AS MATERIALIZED (
            SELECT src_ip, dst_ip, dst_port, proto, min(seq) AS first_seq, min(start_ts) AS first_ts,
                   arg_min(outcome, seq) AS first_outcome, count(*) AS sessions,
                   count(*) FILTER (outcome = 'answered') AS answered
            FROM pw_sessions GROUP BY ALL),
        busy AS (SELECT src_ip FROM first GROUP BY src_ip HAVING count(*) >= $floor)
        SELECT v.*, (SELECT min(s.start_ts) FROM pw_sessions s
                     WHERE s.src_ip = v.src_ip AND s.dst_ip = v.dst_ip AND s.proto = v.proto
                       AND s.dst_port IS NOT DISTINCT FROM v.dst_port
                       AND s.outcome = 'answered' AND s.seq > v.first_seq) AS return_ts
        FROM first v WHERE v.src_ip IN (SELECT src_ip FROM busy)""",
                {"floor": int(min(cfg.probing.min_ports, cfg.probing.min_hosts))})
    return con.execute("SELECT count(DISTINCT src_ip) FROM pw_svc").fetchone()[0]


# -- 4. signal 1: probing -------------------------------------------------------------------
# Windows start every half window: window k covers the half-window buckets k and k + 1, so a first
# attempt in bucket b belongs to windows b and b - 1.
_BUCKET = "CAST(floor(epoch(v.first_ts) / $step) AS BIGINT)"


def _step(cfg: Config) -> float:
    """Seconds between window starts (half a window)."""
    return cfg.window_hours * 3600 / 2


def _probing(con, cfg: Config) -> int:
    """Table pw_probe: the scoring windows in which a source's sweep fired signal 1.

    A sweep is made of first attempts: the first session from the source to each service. Counting
    only those keeps the later, repeated sessions of the narrowing phase from diluting the failed
    share. Windows are ``window_hours`` long and start every half window, so a sweep that crosses
    a window edge still falls whole inside one window. Returns how many sources fired."""
    p = cfg.probing
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE pw_probe AS
        SELECT v.src_ip, k, min(v.first_ts) AS probe_start, max(v.first_ts) AS probe_end,
               count(*) AS services, count(DISTINCT v.dst_ip) AS hosts,
               count(DISTINCT v.dst_port) FILTER (v.proto IN ('tcp', 'udp')) AS ports,
               count(*) FILTER (v.first_outcome = 'failed') AS failed,
               count(*) FILTER (v.answered > 0) AS answered
        FROM pw_svc v, unnest([{_BUCKET}, {_BUCKET} - 1]) AS w(k)
        GROUP BY v.src_ip, k
        HAVING (ports >= $min_ports OR hosts >= $min_hosts) AND failed >= $min_failed_share * count(*)""",
                {"step": _step(cfg), "min_ports": int(p.min_ports), "min_hosts": int(p.min_hosts),
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
    window, at least ``min_focus_share`` of its sessions went to services that had answered."""
    n = cfg.narrowing
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE pw_narrow_svc AS
        SELECT p.src_ip, p.k, v.dst_ip, v.dst_port, v.proto, v.answered, v.return_ts
        FROM pw_probe p JOIN pw_svc v ON v.src_ip = p.src_ip AND {_BUCKET} IN (p.k, p.k + 1)
        WHERE v.answered >= $min_sessions
          AND v.return_ts <= p.probe_end + to_seconds($max_delay)
          AND p.answered <= $max_answered_share * p.services""",
                {"step": _step(cfg), "min_sessions": int(n.min_sessions_per_service),
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


# -- 6. findings ----------------------------------------------------------------------------
def _findings(con, nm: NetMap) -> list[Finding]:
    """One finding per source: the window where probing and narrowing both fired that holds the
    largest sweep (the earliest such window on a tie), plus everything it did in the lookback (so a campaign that pauses and resumes stays one finding)."""
    rows = con.execute("""
        SELECT p.src_ip, p.k, p.probe_start, p.probe_end, p.services, p.hosts, p.ports, p.failed,
               p.answered, w.narrowing_start, w.focus_share
        FROM pw_narrow w JOIN pw_probe p USING (src_ip, k)
        -- windows overlap, so a sweep can fire in two of them: keep the one that holds most of it
        QUALIFY row_number() OVER (PARTITION BY p.src_ip ORDER BY p.services DESC, p.k) = 1
        ORDER BY p.src_ip""").fetchall()
    out = []
    for src, k, p_start, p_end, services, hosts, ports, failed, answered, n_start, focus in rows:
        svc_rows = con.execute("""
            SELECT dst_ip, dst_port, proto, answered, return_ts FROM pw_narrow_svc
            WHERE src_ip = ? AND k = ? ORDER BY answered DESC, dst_ip, dst_port""", [src, k]).fetchall()
        n, first, last = con.execute(
            "SELECT count(*), min(start_ts), max(start_ts) FROM pw_sessions WHERE src_ip = ?", [src]).fetchone()
        sensors = [r[0] for r in con.execute(
            "SELECT DISTINCT sensor FROM pw_sessions WHERE src_ip = ? ORDER BY 1", [src]).fetchall()]
        methods = dict(con.execute(
            "SELECT start_method, count(*) FROM pw_sessions WHERE src_ip = ? GROUP BY 1 ORDER BY 1", [src]).fetchall())
        listed = [Service(host=h, port=port, proto=proto, network=nm.name(h), sessions=int(c),
                          first_return=_iso(ts)) for h, port, proto, c, ts in svc_rows[:MAX_SERVICES_LISTED]]
        out.append(Finding(
            source=src, level=0, label=TIER_0, log_sources=sensors, start_times=methods,
            probe_start=_iso(p_start), probe_end=_iso(p_end), services_probed=int(services),
            hosts_probed=int(hosts), ports_probed=int(ports), failed_share=round(failed / services, 3),
            services_answered=int(answered), narrowing_start=_iso(n_start), focus_share=round(focus, 3),
            services=listed, services_total=len(svc_rows), hosts_hit=sorted({r[0] for r in svc_rows}),
            sessions=int(n), first_seen=_iso(first), last_seen=_iso(last),
            campaign_hours=round((last - first).total_seconds() / 3600, 2),
            timing="not evaluated: the timing signal is not built yet",
            threat_evidence="threat logs not provided"))
    return sorted(out, key=lambda f: (-f.level, -f.sessions, f.source))


def _iso(ts: datetime | None) -> str:
    """A DuckDB TIMESTAMP (naive, always UTC here) as ISO text ending in Z."""
    return ts.replace(tzinfo=None).isoformat(timespec="seconds") + "Z" if ts is not None else ""
