"""The Explorer: explorer.html, one self-contained page that draws the outside sources that swept
the network on an arc above it, each with its sweep and the services it kept coming back to.

Two steps:

``collect``  reads the scoring tables while they exist (it is detect()'s ``while_scored`` hook)
             and returns the scene as plain data: the sources drawn, the internal subnets and
             hosts they tried, and what each source did to each of them.
``write``    packs that data into the page together with the scripts and styles in
             ``pentaiwatch/static``, so the page opens offline and straight from disk.

What is drawn is what the report says. A source is drawn when the probing signal fired for it:
the flagged ones with their finding, the others as "swept, did not narrow" or, when they narrowed
at some other pace, as "swept and narrowed, not at an agent's pace". Every number about a source's
sweep is counted over the same window its finding uses (``pw_sweep`` in detect.py).

Big runs are cut to what a browser draws comfortably: the ``MAX_SOURCES`` largest sweeps (flagged
sources first), the ``MAX_SUBNETS`` subnets that matter most and ``MAX_HOSTS`` hosts in them. The
counts in the page stay complete; it says how many subnets and hosts were tried and how many of
them are drawn.

A source that narrowed also gets a Timeline (``_timelines``): its sessions in order, each with the
host it went to and what it was (a first attempt of the sweep, a return to a service it narrowed
onto, anything else), and its bursts and pauses as the timing signal cut them (``pw_burst``). The
page replays that in a tunnel with time along it (timeline3d.js).

The renderer (explorer3d.js), the data unpacker (vf_data.js) and Three.js come from VulnScope
MAX; see README.md. The controller (explorer.js) and the Timeline (timeline3d.js, after MAX's time
tunnel) are written for this tool.
"""
from __future__ import annotations

import base64
import csv
import io
import ipaddress
import json
import os
import re
import tempfile
import zlib
from collections import Counter
from dataclasses import asdict
from html import escape

from . import __version__, csp
from .config import Config
from .detect import TIMED, Detection, log_sources
from .netmap import NetMap

FILENAME = "explorer.html"
MAX_SOURCES = 48        # outside sources on the arc
MAX_SUBNETS = 120       # subnets drawn as rings
MAX_HOSTS = 2000        # hosts drawn as dots
MAX_SERVICES = 200      # narrowed services listed per source
MAX_TIMELINES = 12              # sources given a Timeline: those that narrowed, flagged ones first
MAX_TIMELINE_SESSIONS = 20000   # sessions drawn on one source's Timeline (evenly thinned beyond that)
MAX_TIMELINE_BURSTS = 20000     # bursts drawn on one source's Timeline (the earliest beyond that)
TIMELINE_LANES = 14             # subnets given a lane of their own on a Timeline; the rest share one
# What a session on a Timeline is. Add UNTIMED when its time is an END time (it has no start time).
SWEEP_FAILED, SWEEP_ANSWERED, SWEEP_OTHER, RETURN, LATER, UNTIMED = 0, 1, 2, 3, 4, 8
SWEEP_ONLY = "Swept, did not narrow"
OTHER_PACE = "Swept and narrowed, not at an agent's pace"
VIEW_TABLES = ("pw_view_src", "pw_view_sh", "pw_view_nsvc", "pw_view_host", "pw_view_h", "pw_view_net",
               "pw_view_drawn")
STATES = ("narrowed", "answered", "tried")          # a drawn host's state, most telling first


def subnet_of(ip: str) -> str:
    """The /24 (IPv4) or /64 (IPv6) an address is in. Hosts are grouped this way on the map, as in
    VulnScope MAX."""
    if ":" not in ip:
        head, dot, _ = ip.rpartition(".")
        if dot and head.count(".") == 2:
            return head + ".0/24"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "other"
    return str(ipaddress.ip_network(f"{ip}/{24 if addr.version == 4 else 64}", strict=False))


def empty() -> dict:
    """The scene of a run in which no source swept (or nothing could be scored)."""
    return {"window": [None, None], "subnets": [], "hosts": [], "sources": [], "timelines": {},
            "counts": {"inbound_sessions": 0, "outside_sources": 0, "sweeping": 0, "narrowed": 0, "flagged": 0,
                       "sources_drawn": 0, "hosts_tried": 0, "hosts_drawn": 0, "subnets_tried": 0,
                       "subnets_drawn": 0}}


def _iso(ts) -> str:
    return ts.replace(tzinfo=None).isoformat(timespec="seconds") + "Z" if ts is not None else ""


def _ip_order(ip: str) -> tuple:
    """Sort key that puts addresses in numeric order (10.0.0.9 before 10.0.0.10)."""
    try:
        addr = ipaddress.ip_address(ip)
        return (addr.version, int(addr), ip)
    except ValueError:
        return (9, 0, ip)


def _timelines(con, cfg: Config, nm: NetMap) -> dict[str, dict]:
    """What the Timeline replays, for the drawn sources that narrowed (flagged ones first).

    Per source, with every time in milliseconds after its first session (``t0``):
      sessions  [ms, index into hosts, kind] in time order. kind: SWEEP_FAILED, SWEEP_ANSWERED or
                SWEEP_OTHER for the first attempt on a service, by its outcome; RETURN for a later
                session to a service the source narrowed onto; LATER for any other later session.
                UNTIMED is added when the time is an end time. Beyond MAX_TIMELINE_SESSIONS every
                n-th session is kept, so the picture thins evenly and never loses its end.
      hosts     [address, index into lanes], in address order inside each lane.
      lanes     [subnet, its name in network_map.csv, hosts]: the TIMELINE_LANES subnets with the
                most hosts the source went to, then one lane for all the others.
      bursts    [first start, last start, sessions, the pause that follows in seconds or None, how
                it counts], exactly as the timing signal cut them. How it counts: 2 when it is one
                of the signal's cycles (a short burst, then a pause in the band), 1 when only its
                pause is in the band, else 0. Empty for a source with no start times.
      marks     where its sweep starts and ends and where narrowing starts.
      fired     the scoring windows in which the timing signal fired: [start, such bursts, all
                pauses, pauses in the band]."""
    out: dict[str, dict] = {}
    step_ms = cfg.window_hours * 3600 * 1000 / 2
    for src, k in con.execute("SELECT src_ip, k FROM pw_view_src WHERE narrowed ORDER BY pos LIMIT ?",
                              [MAX_TIMELINES]).fetchall():
        first, t0, t1, total = con.execute(
            "SELECT min(start_ts), epoch_ms(min(start_ts)), epoch_ms(max(start_ts)), count(*) "
            "FROM pw_sessions WHERE src_ip = ?", [src]).fetchone()
        every = max(1, -(-total // MAX_TIMELINE_SESSIONS))
        rows = con.execute("""
            WITH mine AS (
                SELECT s.start_ts, s.seq, s.dst_ip, epoch_ms(s.start_ts) - $t0 AS ms,
                       CASE WHEN s.seq = v.first_seq
                            THEN CASE s.outcome WHEN 'failed' THEN $failed WHEN 'answered' THEN $answered
                                                ELSE $other END
                            WHEN n.dst_ip IS NOT NULL THEN $return ELSE $later END
                       + CASE WHEN list_contains(CAST($timed AS VARCHAR[]), s.start_method) THEN 0
                              ELSE $untimed END AS kind
                FROM pw_sessions s
                JOIN pw_svc v ON v.src_ip = s.src_ip AND v.dst_ip = s.dst_ip AND v.proto = s.proto
                             AND v.dst_port IS NOT DISTINCT FROM s.dst_port
                LEFT JOIN pw_narrow_svc n ON n.src_ip = s.src_ip AND n.k = $k AND n.dst_ip = s.dst_ip
                             AND n.proto = s.proto AND n.dst_port IS NOT DISTINCT FROM s.dst_port
                WHERE s.src_ip = $src)
            SELECT ms, dst_ip, kind FROM mine
            QUALIFY (row_number() OVER (ORDER BY start_ts, seq) - 1) % $every = 0
            ORDER BY start_ts, seq""",
                           {"src": src, "k": k, "t0": t0, "every": every, "timed": list(TIMED),
                            "failed": SWEEP_FAILED, "answered": SWEEP_ANSWERED, "other": SWEEP_OTHER,
                            "return": RETURN, "later": LATER, "untimed": UNTIMED}).fetchall()
        subnet = {ip: subnet_of(ip) for ip in {r[1] for r in rows}}
        per_subnet = Counter(subnet.values())
        own = sorted(sorted(per_subnet, key=lambda s: (-per_subnet[s], s))[:TIMELINE_LANES])
        lane_of = {s: i for i, s in enumerate(own)}
        lanes = [[s, nm.name(next(ip for ip in sorted(subnet, key=_ip_order) if subnet[ip] == s)), per_subnet[s]]
                 for s in own]
        if len(per_subnet) > len(own):
            lanes.append(["*", "other subnets", sum(n for s, n in per_subnet.items() if s not in lane_of)])
        hosts = sorted(subnet, key=lambda ip: (lane_of.get(subnet[ip], len(own)), _ip_order(ip)))
        at = {ip: i for i, ip in enumerate(hosts)}
        bursts_total = con.execute("SELECT count(*) FROM pw_burst WHERE src_ip = ?", [src]).fetchone()[0]
        bursts = con.execute("""
            SELECT epoch_ms(first_ts) - $t0, epoch_ms(last_ts) - $t0, sessions, round(pause, 3),
                   coalesce(CAST(pause BETWEEN $lo AND $hi AS INTEGER), 0)
                   + coalesce(CAST(sessions <= $max_burst AND pause BETWEEN $lo AND $hi AS INTEGER), 0)
            FROM pw_burst WHERE src_ip = $src ORDER BY burst LIMIT $limit""",
                             {"src": src, "t0": t0, "limit": MAX_TIMELINE_BURSTS,
                              "lo": float(cfg.timing.pause_min_seconds), "hi": float(cfg.timing.pause_max_seconds),
                              "max_burst": int(cfg.timing.max_burst_sessions)}).fetchall()
        marks = con.execute("""
            SELECT epoch_ms(p.probe_start) - $t0, epoch_ms(p.probe_end) - $t0, epoch_ms(w.narrowing_start) - $t0
            FROM pw_probe p JOIN pw_narrow w USING (src_ip, k) WHERE p.src_ip = $src AND p.k = $k""",
                            {"src": src, "k": k, "t0": t0}).fetchone()
        fired = con.execute("SELECT k, cycles, pauses, in_band FROM pw_timing WHERE src_ip = ? ORDER BY k",
                            [src]).fetchall()
        out[src] = {
            "t0": _iso(first), "t0_ms": int(t0), "seconds": round((t1 - t0) / 1000, 3),
            "sessions_total": int(total), "every": int(every),
            "lanes": lanes, "hosts": [[ip, lane_of.get(subnet[ip], len(own))] for ip in hosts],
            "sessions": [[int(ms), at[ip], int(kind)] for ms, ip, kind in rows],
            "bursts": [[int(a), int(b), int(n), None if pause is None else float(pause), int(how)]
                       for a, b, n, pause, how in bursts],
            "bursts_total": int(bursts_total),
            "marks": {"probe_start": int(marks[0]), "probe_end": int(marks[1]), "narrowing_start": int(marks[2])},
            "fired": [[int(w * step_ms - t0), int(c), int(p), int(b)] for w, c, p, b in fired]}
    return out


def _load(con, table: str, columns: dict[str, str], rows) -> None:
    """Fill a temp table from Python rows through a CSV file (quick for any number of rows)."""
    fd, path = tempfile.mkstemp(prefix="pw-view-", suffix=".csv")
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerows(rows)
        spec = ", ".join(f"{name} {kind}" for name, kind in columns.items())
        con.execute(f"CREATE OR REPLACE TEMP TABLE {table} ({spec})")
        if os.path.getsize(path):
            con.execute(f"INSERT INTO {table} SELECT * FROM read_csv(?, header = false, auto_detect = false, "
                        f"columns = {{{', '.join(repr(n) + ': ' + repr(k) for n, k in columns.items())}}})", [path])
    finally:
        os.remove(path)


def collect(con, cfg: Config, detection: Detection) -> dict:
    """The scene for the Explorer, read from the scoring tables of the detection that just ran."""
    out = empty()
    out["window"] = [detection.lookback_start, detection.lookback_end]
    out["counts"].update(inbound_sessions=detection.inbound_sessions, outside_sources=detection.outside_sources,
                         sweeping=detection.probing_sources, narrowed=detection.narrowing_sources,
                         flagged=len(detection.findings))
    findings = {f.source: f for f in detection.findings}
    drawn = [f.source for f in detection.findings[:MAX_SOURCES]]          # most serious first, as in the report
    # then the sources that are not flagged: those that narrowed first, then the largest sweeps
    drawn += [r[0] for r in con.execute("""
        SELECT s.src_ip FROM pw_sweep s JOIN pw_probe p USING (src_ip, k)
        WHERE NOT s.flagged ORDER BY s.narrowed DESC, p.services DESC, s.src_ip LIMIT ?""",
                                        [MAX_SOURCES - len(drawn)]).fetchall()]
    if not drawn:
        return out
    nm = NetMap(cfg.networks)
    try:
        _tables(con, drawn)
        out["counts"].update(_draw(con, out, nm))
        out["sources"] = _sources(con, cfg, findings)
        out["counts"]["sources_drawn"] = len(out["sources"])
        out["timelines"] = _timelines(con, cfg, nm)
    finally:
        for table in VIEW_TABLES:
            con.execute(f"DROP TABLE IF EXISTS {table}")
    return out


def _tables(con, drawn: list[str]) -> None:
    """The working tables: the sources drawn (pw_view_src), what each did to each host inside its
    window (pw_view_sh), the services the flagged ones narrowed onto (pw_view_nsvc), each host's
    subnet (pw_view_host) and one row per host over all drawn sources (pw_view_h)."""
    con.execute("""
        CREATE OR REPLACE TEMP TABLE pw_view_src AS
        SELECT s.src_ip, s.k, s.narrowed, s.flagged, list_position(CAST($ips AS VARCHAR[]), s.src_ip) - 1 AS pos
        FROM pw_sweep s WHERE list_contains(CAST($ips AS VARCHAR[]), s.src_ip)""", {"ips": drawn})
    con.execute("""
        CREATE OR REPLACE TEMP TABLE pw_view_sh AS
        SELECT d.src_ip, v.dst_ip, count(*) AS services,
               count(*) FILTER (v.first_outcome = 'failed') AS failed,
               count(*) FILTER (v.answered > 0) AS answered
        FROM pw_view_src d JOIN pw_svc v ON v.src_ip = d.src_ip AND v.bucket IN (d.k, d.k + 1)
        GROUP BY ALL""")
    con.execute("""
        CREATE OR REPLACE TEMP TABLE pw_view_nsvc AS
        SELECT n.src_ip, n.dst_ip, n.dst_port, n.proto, n.answered AS sessions, n.return_ts
        FROM pw_narrow_svc n JOIN pw_view_src d USING (src_ip, k) WHERE d.flagged""")
    hosts = [r[0] for r in con.execute("SELECT DISTINCT dst_ip FROM pw_view_sh").fetchall()]
    _load(con, "pw_view_host", {"ip": "VARCHAR", "subnet": "VARCHAR"}, ((ip, subnet_of(ip)) for ip in hosts))
    con.execute("""
        CREATE OR REPLACE TEMP TABLE pw_view_h AS
        WITH nar AS (SELECT dst_ip, count(*) AS narrowed, sum(sessions) AS sessions
                     FROM pw_view_nsvc GROUP BY dst_ip)
        SELECT a.dst_ip AS ip, any_value(h.subnet) AS subnet, count(*) AS sources,
               sum(a.services) AS services, sum(a.answered) AS answered,
               coalesce(any_value(nar.narrowed), 0) AS narrowed, coalesce(any_value(nar.sessions), 0) AS sessions,
               -- 0 a source narrowed onto it, 1 it answered a sweep, 2 it was only tried
               CASE WHEN coalesce(any_value(nar.narrowed), 0) > 0 THEN 0
                    WHEN sum(a.answered) > 0 THEN 1 ELSE 2 END AS cls
        FROM pw_view_sh a JOIN pw_view_host h ON h.ip = a.dst_ip LEFT JOIN nar ON nar.dst_ip = a.dst_ip
        GROUP BY a.dst_ip""")


def _draw(con, out: dict, nm: NetMap) -> dict:
    """Choose the subnets and hosts that are drawn, write them into ``out`` and return the counts.

    Subnets: those with hosts a source narrowed onto first, then by hosts that answered, then by
    hosts tried. Hosts inside them: every host a source narrowed onto, then those that answered,
    then those only tried, each subnet taking its turn so none is left empty. The pick among equals
    follows md5 of the address, so the same logs always draw the same hosts."""
    con.execute("""
        CREATE OR REPLACE TEMP TABLE pw_view_net AS
        SELECT subnet, count(*) AS tried, count(*) FILTER (cls <= 1) AS answered,
               count(*) FILTER (cls = 0) AS narrowed,
               row_number() OVER (ORDER BY count(*) FILTER (cls = 0) DESC, count(*) FILTER (cls <= 1) DESC,
                                           count(*) DESC, subnet) - 1 AS pos
        FROM pw_view_h GROUP BY subnet""")
    con.execute("""
        CREATE OR REPLACE TEMP TABLE pw_view_drawn AS
        WITH ranked AS (
            SELECT h.*, n.pos AS net,
                   row_number() OVER (PARTITION BY h.subnet, h.cls ORDER BY md5(h.ip)) AS turn
            FROM pw_view_h h JOIN pw_view_net n USING (subnet) WHERE n.pos < $subnets)
        SELECT ip, net, cls, sources, services, answered, narrowed, sessions,
               row_number() OVER (ORDER BY cls, turn, md5(ip)) - 1 AS pos
        FROM ranked QUALIFY pos < $hosts""", {"subnets": MAX_SUBNETS, "hosts": MAX_HOSTS})
    in_subnet = dict(con.execute("SELECT net, count(*) FROM pw_view_drawn GROUP BY net").fetchall())
    for subnet, tried, answered, narrowed, pos in con.execute(
            "SELECT subnet, tried, answered, narrowed, pos FROM pw_view_net WHERE pos < ? ORDER BY pos",
            [MAX_SUBNETS]).fetchall():
        # the subnet's name and kind come from network_map.csv, by its first drawn host
        first = con.execute("SELECT min(ip) FROM pw_view_drawn WHERE net = ?", [pos]).fetchone()[0]
        entry = nm.entries[nm.index(first)] if first and nm.index(first) is not None else None
        out["subnets"].append({"id": subnet, "name": entry["name"] if entry else "",
                               "cloud": bool(entry and entry.get("cloud")), "tried": int(tried),
                               "answered": int(answered), "narrowed": int(narrowed),
                               "drawn": int(in_subnet.get(pos, 0))})
    for ip, net, cls, sources, services, answered, narrowed, sessions in con.execute("""
            SELECT ip, net, cls, sources, services, answered, narrowed, sessions
            FROM pw_view_drawn ORDER BY pos""").fetchall():
        out["hosts"].append({"ip": ip, "net": int(net), "state": STATES[cls], "sources": int(sources),
                             "services": int(services), "answered": int(answered), "narrowed": int(narrowed),
                             "sessions": int(sessions)})
    hosts_tried, subnets_tried = con.execute("SELECT count(*), count(DISTINCT subnet) FROM pw_view_h").fetchone()
    return {"hosts_tried": int(hosts_tried), "hosts_drawn": len(out["hosts"]),
            "subnets_tried": int(subnets_tried), "subnets_drawn": len(out["subnets"])}


def _other_pace(con, cfg: Config) -> dict[str, dict]:
    """For the drawn sources that narrowed and are not flagged: what they narrowed onto and the pace
    they kept, which is why they are not flagged."""
    t = cfg.timing
    return {src: {"services_total": int(services), "bursts_all": int(bursts), "pauses": int(pauses),
                  "pauses_in_band": int(in_band)}
            for src, services, bursts, pauses, in_band in con.execute("""
                SELECT d.src_ip, (SELECT count(*) FROM pw_narrow_svc n WHERE n.src_ip = d.src_ip AND n.k = d.k),
                       count(b.burst), count(b.pause), count(*) FILTER (b.pause BETWEEN $lo AND $hi)
                FROM pw_view_src d LEFT JOIN pw_burst b USING (src_ip)
                WHERE d.narrowed AND NOT d.flagged GROUP BY d.src_ip, d.k""",
                                                               {"lo": float(t.pause_min_seconds),
                                                                "hi": float(t.pause_max_seconds)}).fetchall()}


def _sources(con, cfg: Config, findings: dict) -> list[dict]:
    """One entry per drawn source: the evidence the report gives for it, and what the map needs to
    draw it (its sweep per drawn subnet, the drawn hosts it tried, the services it narrowed onto)."""
    nets: dict[int, list] = {}
    for src, net, in_net, tried_there, failed_there, answered_there in con.execute("""
            SELECT d.pos, n.pos, count(*), sum(a.services), sum(a.failed), sum(a.answered)
            FROM pw_view_sh a JOIN pw_view_src d USING (src_ip) JOIN pw_view_host h ON h.ip = a.dst_ip
            JOIN pw_view_net n ON n.subnet = h.subnet
            WHERE n.pos < ? GROUP BY ALL ORDER BY ALL""", [MAX_SUBNETS]).fetchall():
        nets.setdefault(src, []).append([int(net), int(in_net), int(tried_there), int(failed_there), int(answered_there)])
    tried: dict[int, list] = {}
    answered_hosts: dict[int, list] = {}
    for src, host, answered in con.execute("""
            SELECT d.pos, w.pos, a.answered
            FROM pw_view_sh a JOIN pw_view_src d USING (src_ip) JOIN pw_view_drawn w ON w.ip = a.dst_ip
            ORDER BY ALL""").fetchall():
        tried.setdefault(src, []).append(int(host))
        if answered:
            answered_hosts.setdefault(src, []).append([int(host), int(answered)])
    services: dict[int, list] = {}
    for src, host, port, proto, sessions, ts in con.execute("""
            SELECT d.pos, n.dst_ip, n.dst_port, n.proto, n.sessions, n.return_ts
            FROM pw_view_nsvc n JOIN pw_view_src d USING (src_ip)
            ORDER BY d.pos, n.sessions DESC, n.dst_ip, n.dst_port""").fetchall():
        services.setdefault(src, []).append([host, port, proto, int(sessions), _iso(ts)])
    seen = {src: (int(n), first, last) for src, n, first, last in con.execute("""
        SELECT src_ip, count(*), min(start_ts), max(start_ts) FROM pw_sessions
        WHERE src_ip IN (SELECT src_ip FROM pw_view_src) GROUP BY src_ip""").fetchall()}
    other_pace = _other_pace(con, cfg)
    out = []
    for pos, src, narrowed, p_start, p_end, n_services, n_hosts, n_ports, failed, answered in con.execute("""
            SELECT d.pos, d.src_ip, d.narrowed, p.probe_start, p.probe_end, p.services, p.hosts, p.ports, p.failed,
                   p.answered
            FROM pw_view_src d JOIN pw_probe p USING (src_ip, k) ORDER BY d.pos""").fetchall():
        f = findings.get(src)
        sessions, first, last = seen[src]
        item = {"ip": src, "flagged": f is not None, "narrowed": bool(narrowed), "level": f.level if f else None,
                "label": f.label if f else OTHER_PACE if narrowed else SWEEP_ONLY,
                "log_sources": f.log_sources if f else log_sources(con, src),
                "probe_start": _iso(p_start), "probe_end": _iso(p_end), "services_probed": int(n_services),
                "hosts_probed": int(n_hosts), "ports_probed": int(n_ports),
                "failed_share": round(failed / n_services, 3), "services_answered": int(answered),
                "sessions": sessions, "first_seen": _iso(first), "last_seen": _iso(last),
                "campaign_hours": round((last - first).total_seconds() / 3600, 2)}
        if f is not None:
            mine = services.get(pos, [])
            evidence = asdict(f)
            item.update({k: evidence[k] for k in ("narrowing_start", "focus_share", "start_times", "timing",
                                                  "threat_evidence", "notes")})
            item.update(services=mine[:MAX_SERVICES], services_total=len(mine), hosts_hit=len(f.hosts_hit))
        elif narrowed:
            item["pace"] = other_pace[src]
        item["nets"] = nets.get(pos, [])
        # hosts it tried in subnets that are not drawn
        item["hosts_elsewhere"] = int(n_hosts) - sum(n[1] for n in item["nets"])
        item["tried"] = tried.get(pos, [])
        item["answered"] = answered_hosts.get(pos, [])
        out.append(item)
    return out


# -- the page -------------------------------------------------------------------------------
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
# In page order: the data unpacker, Three.js, the map's renderer and controller, the Timeline.
SCRIPTS = ("vf_data.js", "vendor/three.min.js", "explorer3d.js", "explorer.js", "timeline3d.js")
STYLES = ("explorer.css", "timeline3d.css")
DATA_TAG = '<script id="vf-data" type="application/octet-stream" data-encoding="gzip-base64">'
_DATA = re.compile(re.escape(DATA_TAG) + r"(.*?)</script>", re.S)
MAX_DATA = 1024 ** 3            # unpacked bytes read_data accepts, the same limit the page has


def _read(name: str) -> str:
    with open(os.path.join(STATIC, *name.split("/")), encoding="utf-8") as fh:
        text = fh.read()
    if name.endswith(".js") and "</script" in text.lower():
        raise ValueError(f"static/{name} contains '</script', which would end its <script> block early")
    return text


def write_data(fh, data: dict) -> None:
    """``data`` as gzip in base64. The page unpacks it with the browser's own gzip decoder
    (vf_data.js), so nothing in it can be read as markup or script. No timestamp goes into the
    gzip header: the same data always gives the same bytes."""
    comp = zlib.compressobj(6, zlib.DEFLATED, 31)
    packed = comp.compress(json.dumps(data, separators=(",", ":")).encode()) + comp.flush()
    fh.write(base64.b64encode(packed).decode("ascii"))


def read_data(page: str) -> dict:
    """The data inside a page this module wrote. Raises ValueError when there is none or it is damaged."""
    m = _DATA.search(page)
    if not m:
        raise ValueError("no Explorer data in the page")
    try:
        d = zlib.decompressobj(31)
        text = d.decompress(base64.b64decode(m.group(1).strip(), validate=True), MAX_DATA)
        if d.unconsumed_tail:
            raise ValueError("it unpacks to more than 1 GB")
        return json.loads(text)
    except (ValueError, zlib.error) as exc:
        raise ValueError(f"the Explorer data is damaged ({exc})") from None


def page_data(scene: dict, res: dict) -> dict:
    """What goes into the page: the scene plus what the header needs from the results."""
    return {"tool": {"name": "PentAIWatch", "version": __version__}, "sessions": res.get("sessions", 0),
            "log_sources": res.get("log_sources", []), "limits": {"sources": MAX_SOURCES, "subnets": MAX_SUBNETS,
                                                                  "hosts": MAX_HOSTS, "services": MAX_SERVICES},
            # the timing settings, so the page can say what "an agent's pace" meant in this run
            "timing": (res.get("settings") or {}).get("timing") or {},
            "window_hours": (res.get("settings") or {}).get("window_hours") or 2,
            # the analyst's report name and description, shown in the header
            "report": res.get("report") or {"name": "", "description": ""},
            **scene}


def html(scene: dict, res: dict) -> str:
    buf = io.StringIO()
    write_html(buf, scene, res)
    return buf.getvalue()


def _title(res: dict) -> str:
    name = (res.get("report") or {}).get("name")
    return (escape(name) + " · " if name else "") + "Explorer · PentAIWatch"


def write_html(fh, scene: dict, res: dict) -> None:
    """Write the Explorer page: styles, the page's fixed markup, the packed data, then the scripts
    inline. It loads nothing from the network, and its policy (csp.py) lets it run these scripts
    only and contact nothing."""
    scripts = [_read(name) for name in SCRIPTS]
    fh.write('<!doctype html>\n<html lang="en"><head><meta charset="utf-8">' + csp.meta(scripts)
             + '<meta name="viewport" content="width=device-width,initial-scale=1">'
             f'<title>{_title(res)}</title><link rel="icon" href="data:,">'
             "<style>" + "".join(_read(name) for name in STYLES) + "</style></head><body>" + _read("explorer.html"))
    fh.write(DATA_TAG)
    write_data(fh, page_data(scene, res))
    fh.write("</script>" + "".join("<script>" + text + "</script>" for text in scripts)
             + "</body></html>\n")


def write(scene: dict, res: dict, outdir: str) -> str:
    """Write explorer.html into ``outdir`` and return its path."""
    os.makedirs(outdir, mode=0o700, exist_ok=True)
    path = os.path.join(outdir, FILENAME)
    with open(path, "w", encoding="utf-8") as fh:
        write_html(fh, scene, res)
    return path
