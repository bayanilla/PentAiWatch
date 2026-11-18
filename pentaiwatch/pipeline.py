"""One call that runs the whole tool: load -> de-duplicate -> detect -> report."""
from __future__ import annotations

import os
import sys

from . import __version__, config, engine, netmap, resources, scanners
from .config import Config
from .detect import detect
from .errors import UserError
from .load import load
from .report import write_all

# Version of the results.json layout. Raise it when a field changes meaning or shape.
RESULTS_SCHEMA_VERSION = 1
NOTES = ("readme.md", "readme.txt")
LIMITATIONS = [
    "Scoring is per source address. These tools rotate through residential, datacenter and free "
    "proxies or Tor when blocked, so one campaign can be split across several sources, each below "
    "the thresholds or each reported separately.",
    "Only connection metadata is read. A source that is not flagged has not been cleared.",
]


def _why_empty(stats: list) -> str:
    """What the files said about themselves when no session came out of any of them."""
    reasons = [f"{s.file}: {why} ({n:,} rows)" for s in stats for why, n in s.dropped.most_common(2)]
    reasons += [f"{s.file}: {note}" for s in stats for note in s.notes if "could not be parsed" in note]
    return " What was read: " + "; ".join(reasons[:6]) + "." if reasons else ""


def input_files(paths: list[str], outdir: str) -> list[str]:
    """Expand input folders recursively, ignoring hidden files and the output folder."""
    files = []
    output = os.path.abspath(outdir)
    for path in paths:
        if not os.path.isdir(path):
            if not os.path.exists(path):
                raise UserError(f"{path}: no such file or folder")
            files.append(path)
            continue
        for root, dirs, names in os.walk(path):
            dirs[:] = sorted(d for d in dirs if not d.startswith(".") and
                             os.path.abspath(os.path.join(root, d)) != output)
            files.extend(os.path.join(root, name) for name in sorted(names)
                         if not name.startswith(".") and os.path.isfile(os.path.join(root, name)))
    return files


def run(paths: list[str], outdir: str, cfg: Config | None = None, *, config_path: str | None = None,
        network_map: str | None = None, known_scanners: str | None = None,
        workdir: str | None = None) -> tuple[dict, dict[str, str]]:
    """Analyze ``paths`` (files or folders) and write the report into ``outdir``.

    Settings come from ``cfg``, else ``config_path``, else a pentaiwatch.json found in the input,
    else the defaults. network_map.csv and known_scanners.csv found in the input are used too.
    ``workdir`` holds the run's Parquet batches and DuckDB file (default: system temp, or
    $PENTAIWATCH_WORKDIR); it is deleted when the run finishes.
    Returns (results, {output name: path})."""
    engine.check()                                    # before any log is read
    files = input_files(paths, outdir)
    config_files = [f for f in files if config.is_config_file(f)]
    if cfg is None:
        chosen = config_path or (config_files[0] if config_files else None)
        cfg = config.read(chosen) if chosen else Config()
    config.check(cfg)
    maps = [f for f in files if netmap.is_map_file(f)] + ([network_map] if network_map else [])
    cfg.networks = [e for path in maps for e in netmap.read(path)]          # read first: a bad map fails fast
    lists = [f for f in files if scanners.is_list_file(f)] + ([known_scanners] if known_scanners else [])
    cfg.known_scanners = [e for path in lists for e in scanners.read(path)]
    logs = [f for f in files if not (config.is_config_file(f) or netmap.is_map_file(f)
                                     or scanners.is_list_file(f) or os.path.basename(f).lower() in NOTES)]
    if not logs:
        raise UserError("No log files were given. Point PentAIWatch at Zeek conn.log files, Palo Alto "
                        "traffic logs, or a folder of them.")
    with resources.job_slot():
        budget = resources.plan(workdir=workdir)
        for warning in budget.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        ds = load(logs, workdir=workdir, skew_seconds=cfg.dedup_skew_seconds, budget=budget,
                  options={"paloalto": cfg.paloalto})
        try:
            if not ds.flows:
                raise UserError("No sessions could be read from the input. PentAIWatch needs Zeek conn.log "
                                "(TSV or JSON) or Palo Alto traffic logs (CSV export or syslog lines), "
                                "plain or .gz." + _why_empty(ds.stats))
            warnings = []
            unknown = [s.file for s in ds.stats if s.fmt == "unknown"]
            if unknown:
                warnings.append(f"{len(unknown)} file(s) are neither Zeek nor Palo Alto logs and were left out: "
                                + ", ".join(unknown[:5]) + (" and more" if len(unknown) > 5 else "") + ".")
            detection = detect(ds.flow_con(), cfg)
            res = {
                "schema_version": RESULTS_SCHEMA_VERSION,
                "tool": {"name": "PentAIWatch", "version": __version__},
                "inputs": [{"file": s.file, "format": s.fmt, "read": s.read, "kept": s.kept,
                            "dropped": dict(s.dropped), "notes": list(s.notes)} for s in ds.stats],
                "log_sources": ds.sensors,
                "sessions": len(ds.flows),
                "duplicates_removed": {"exact": ds.duplicate_flows, "seen_by_two_sensors": ds.cross_sensor_duplicates},
                # IPS/IDS alerts read, by kind of log (not scored yet)
                "threat_events": dict(ds.flow_con().execute(
                    "SELECT sensor, count(*) FROM threats GROUP BY 1 ORDER BY 1").fetchall()),
                "settings": cfg.settings(),
                "networks": cfg.networks,
                "known_scanners": cfg.known_scanners,
                "warnings": warnings + detection.warnings,
                "detection": detection.to_dict(),
                "limitations": LIMITATIONS,
            }
            return res, write_all(res, outdir)
        except Exception as exc:
            friendly = resources.explain(exc, budget)
            if friendly is not None:
                raise friendly from exc
            raise
        finally:
            ds.close()
