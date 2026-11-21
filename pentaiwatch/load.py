"""Load every input file, normalize it into the common shape and clean it.

Taken from VulnScope MAX (vulnflow/normalize.py), trimmed to sessions and IPS alerts.
"""
from __future__ import annotations

import os
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass, field
from multiprocessing import get_context

from . import resources
from .errors import MissingField, UserError
from .parsers import FORMATS, detect
from .schema import Flow, ParseStats, ThreatEvent, WebHit
from .store import DEFAULT_BATCH, DEFAULT_SKEW_SECONDS, FlowView, PartWriter, Store


@dataclass
class Dataset:
    """Normalized inputs. ``flows`` is a disk-backed view of the clean DuckDB ``flows`` table, so
    memory stays flat as inputs grow."""
    flows: list[Flow] | FlowView = field(default_factory=list)
    threats: list[ThreatEvent] = field(default_factory=list)      # IPS/IDS alerts
    stats: list[ParseStats] = field(default_factory=list)
    sensors: list[str] = field(default_factory=list)              # kinds of log that held sessions
    duplicate_flows: int = 0
    cross_sensor_duplicates: int = 0
    store: Store | None = field(default=None, repr=False, compare=False)

    def flow_con(self):
        """The DuckDB connection holding the clean ``flows`` table."""
        if self.store is None:
            raise RuntimeError("this dataset has no store")
        return self.store.con

    def close(self):
        """Delete the working directory (Parquet and the DuckDB file)."""
        if self.store is not None:
            self.store.close()


def load(paths: list[str], overrides: dict[str, str] | None = None, *,
         workdir: str | None = None, skew_seconds: float | None = DEFAULT_SKEW_SECONDS,
         batch_size: int = DEFAULT_BATCH, budget: resources.Budget | None = None,
         options: dict | None = None) -> Dataset:
    """overrides maps a file path or basename to a format name. ``options`` maps a format name to
    that reader's settings (``{"paloalto": cfg.paloalto}``); a format without an entry uses its
    defaults.

    Files are parsed in parallel worker processes (see ``parse_workers``). Sessions stream from
    each parser in batches to Parquet under ``workdir`` and are de-duplicated with DuckDB.
    ``skew_seconds`` is the clock-skew tolerance used to recognise the same session seen by two
    sensors (None disables cross-sensor matching). A file that is neither a Zeek log nor a Palo
    Alto log is left out and listed as such.
    """
    overrides = overrides or {}
    store = Store(workdir, budget=budget)
    try:
        return _load(store, paths, overrides, skew_seconds, batch_size, options or {})
    except Exception as exc:
        store.close()
        friendly = None if isinstance(exc, resources.ResourceError) else resources.explain(exc, store.budget)
        if friendly is not None:
            raise friendly from exc
        raise


def _load(store, paths, overrides, skew_seconds, batch_size, options) -> Dataset:
    ds = Dataset(store=store)
    jobs = []
    for fid, path in enumerate(paths):
        name = os.path.basename(path)
        fmt = overrides.get(path) or overrides.get(name) or detect(path)
        if fmt is None:
            skipped = ParseStats(file=name, fmt="unknown")
            skipped.note("not a Zeek or Palo Alto log; left out")
            ds.stats.append(skipped)
            continue
        if fmt not in FORMATS:
            raise UserError(f"{name}: unknown format '{fmt}' (choose from {', '.join(FORMATS)})")
        jobs.append((fid, path, fmt, store.dir, batch_size, options.get(fmt)))
    threats: dict[tuple, ThreatEvent] = {}
    kinds: dict[tuple, str] = {}             # alert -> the kind of log it came from
    sensors: set[str] = set()
    web: dict[tuple, list] = {}              # matching http/dns/ssl records, counted per hour
    for stats, threat_list, n_flows, fatal, web_rows in _parse_all(jobs, store.budget):
        if fatal:
            raise RuntimeError(fatal)       # out of memory or disk in a worker: resources.explain words it
        for key, (n, first, last) in web_rows.items():
            have = web.get(key)
            web[key] = [n, first, last] if have is None else [have[0] + n, min(have[1], first), max(have[2], last)]
        for t in threat_list:
            threats[t.key()] = t
            kinds[t.key()] = stats.fmt
        if n_flows:
            sensors.add(stats.fmt)
        ds.stats.append(stats)
    ds.sensors = sorted(sensors)

    # Exact duplicates are removed; a session seen by two sensors (Zeek and the firewall) is
    # counted once. Both steps run in DuckDB over the Parquet batches.
    ds.duplicate_flows, ds.cross_sensor_duplicates = store.finalize_flows(skew_seconds)
    ds.flows = FlowView(store)
    ds.threats = sorted(threats.values(), key=lambda t: (t.ts is None, t.ts))
    store.save_threats((kinds[t.key()], t) for t in ds.threats)
    checked: dict[str, int] = {}
    for stats in ds.stats:
        for stream, n in stats.web_rows.items():
            checked[stream] = checked.get(stream, 0) + n
    store.save_web(web, checked)
    return ds


# Inputs smaller than this are parsed in the main process: starting worker processes would take
# longer than the parsing itself.
PARALLEL_MIN_BYTES = 64 * 1024 * 1024


def parse_workers(jobs: list, budget: resources.Budget | None) -> int:
    """How many processes parse files at once: one per CPU, at most one per input file and one
    per GiB of the analysis' memory ceiling (each worker holds about half a GiB at peak).
    PENTAIWATCH_PARSE_WORKERS overrides it (1 parses everything in the main process). Small inputs
    are parsed in the main process unless the variable is set."""
    raw = os.environ.get("PENTAIWATCH_PARSE_WORKERS", "").strip()
    if raw:
        try:
            return max(1, min(int(raw), len(jobs)))
        except ValueError:
            raise UserError(f"PENTAIWATCH_PARSE_WORKERS must be a whole number, not '{raw}'.") from None
    size = 0
    for job in jobs:
        try:
            size += os.path.getsize(job[1])
        except OSError:
            pass
    if len(jobs) < 2 or size < PARALLEL_MIN_BYTES:
        return 1
    cpus = budget.machine.cpus if budget else resources.cpu_count()
    by_memory = max(1, (budget.ceiling if budget else resources.GiB) // resources.GiB)
    return max(1, min(cpus, len(jobs), by_memory))


def _parse_all(jobs: list, budget):
    """Parse every file, yielding results in input order. Files are spread over worker
    processes when there is more than one worker (see ``parse_workers``)."""
    workers = parse_workers(jobs, budget)
    if workers == 1:
        for job in jobs:
            yield parse_file(job)
        return
    # "spawn" (not fork): the main process has DuckDB threads running, and spawn is what macOS
    # and Windows use anyway, so every platform behaves the same.
    pool = ProcessPoolExecutor(max_workers=workers, mp_context=get_context("spawn"))
    try:
        # map() keeps input order; results are small (findings, alerts, counts), since flows and
        # events go straight to Parquet in the worker.
        yield from pool.map(parse_file, jobs)
    except BrokenProcessPool:
        raise resources.ResourceError(
            "A file-parsing process stopped unexpectedly, most likely because the machine ran out of "
            "memory. Set PENTAIWATCH_PARSE_WORKERS to a lower number (1 parses one file at a time).") from None
    finally:
        pool.shutdown(wait=True, cancel_futures=True)


def parse_file(job):
    """Parse one input file (in a worker process or the main one). Sessions are written to Parquet
    in the run's working directory; IPS/IDS alerts, which are few, are returned.
    Matching http/dns/ssl records (WebHits) are counted per hour and returned too.
    Returns (stats, alerts, sessions written, fatal error or None, web counts)."""
    fid, path, fmt, workdir, batch_size, options = job
    name = os.path.basename(path)
    parser = FORMATS[fmt]
    stats = ParseStats(file=name, fmt=fmt)
    writer = PartWriter(workdir, fid, batch_size)
    alerts = []
    web: dict[tuple, list] = {}
    kept = 0
    try:
        try:
            for r in (parser(path, stats, options) if options is not None else parser(path, stats)):
                r.source = name
                if isinstance(r, Flow):
                    writer.add_flow(r, fmt)
                    kept += 1
                elif isinstance(r, ThreatEvent):
                    alerts.append(r)
                    kept += 1
                elif isinstance(r, WebHit):
                    if r.ts is not None:     # counted per hour, so the lookback can be applied later
                        hour = r.ts.replace(minute=0, second=0, microsecond=0)
                        key = (r.kind, r.label, r.stream, r.src_ip, r.dst_ip, r.dst_port, r.text, hour)
                        have = web.get(key)
                        web[key] = [1, r.ts, r.ts] if have is None else [have[0] + 1, min(have[1], r.ts), max(have[2], r.ts)]
                        kept += 1
                # other Zeek streams are read and set aside
        except MissingField as exc:      # a required field is missing: stop, naming the file
            raise MissingField(f"{name}: {exc}") from None
        except Exception as exc:  # a broken file should not sink the whole run
            if resources.explain(exc, None) is not None:
                raise                    # out of memory or disk: stop, don't report a "broken file"
            # Records parsed before the error (e.g. a truncated .gz) are kept.
            stats.note(f"file could not be parsed: {exc}"
                       + (f" (kept {kept} record(s) read before the error)" if kept else ""))
        writer.close()
    except MissingField:
        writer.close()
        raise
    except Exception as exc:
        if resources.explain(exc, None) is None:
            raise
        writer.con = None
        return stats, [], 0, str(exc) or repr(exc), {}
    stats.kept = kept
    return stats, alerts, writer.n_flows, None, web
