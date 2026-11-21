"""One call that runs the whole tool: load -> de-duplicate -> detect -> report and Explorer."""
from __future__ import annotations

import os
import sys

from . import __version__, config, details, engine, explore, knownbad, netmap, resources, scanners
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
    "proxies or Tor when blocked. New addresses that come straight back to what one sweep found are "
    "tied to it (rotating sources). A sweep split across addresses against one /24 is tied together "
    "when a new address comes back to what it found (shared sweeps); one spread over many networks, "
    "or slower than one scoring window, can still be split across several sources, each below the "
    "thresholds.",
    "Timing reads when sessions start and nothing inside them. A tool that sends many requests over "
    "one connection it keeps open, or runs several jobs at once from one address, shows fewer pauses "
    "and can go unflagged.",
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
        network_map: str | None = None, known_scanners: str | None = None, known_bad: str | None = None,
        workdir: str | None = None, internal_nets: list[str] | None = None,
        report: dict | None = None) -> tuple[dict, dict[str, str]]:
    """Analyze ``paths`` (files or folders) and write the report and the Explorer into ``outdir``.

    Settings come from ``cfg``, else ``config_path``, else a pentaiwatch.json found in the input,
    else the defaults. network_map.csv and known_scanners.csv found in the input are used too.
    Every such file that was read is listed in the results (``settings_files``) and in the report,
    with whether it was named or found among the input files.
    ``workdir`` holds the run's Parquet batches and DuckDB file (default: system temp, or
    $PENTAIWATCH_WORKDIR); it is deleted when the run finishes.
    ``internal_nets``, typed on the upload page, replaces the settings' internal_nets; the results
    say so (``typed_settings``), and so does the report.
    ``report`` is the optional {"name", "description"} the analyst gave the run (details.py); it is
    shown at the top of the report and in the Explorer.
    Returns (results, {output name: path})."""
    engine.check()                                    # before any log is read
    files = input_files(paths, outdir)
    config_files = [f for f in files if config.is_config_file(f)]
    setup = []                                        # warnings about how the run was set up
    chosen = None
    if cfg is None:
        chosen = config_path or (config_files[0] if config_files else None)
        cfg = config.read(chosen) if chosen else Config()
        if not config_path and len(config_files) > 1:
            setup.append(f"{len(config_files)} settings files ({config.FILENAME}) were found among the input "
                         f"files. Only {config_files[0]} was used; ignored: {', '.join(config_files[1:])}. "
                         "Name the one to use with --config.")
    typed = []                                        # settings typed on the upload page
    if internal_nets:
        cfg.internal_nets = list(internal_nets)
        typed.append("internal_nets")
    config.check(cfg, "internal networks" if typed else "settings")
    found_maps = [f for f in files if netmap.is_map_file(f)]
    maps = found_maps + ([network_map] if network_map else [])
    cfg.networks = [e for path in maps for e in netmap.read(path)]          # read first: a bad map fails fast
    found_lists = [f for f in files if scanners.is_list_file(f)]
    lists = found_lists + ([known_scanners] if known_scanners else [])
    cfg.known_scanners = [e for path in lists for e in scanners.read(path)]
    found_bad = [f for f in files if knownbad.is_list_file(f)]
    bad_lists = found_bad + ([known_bad] if known_bad else [])
    cfg.known_bad = ((knownbad.bundled() if cfg.known_bad_bundled else [])
                     + [e for path in bad_lists for e in knownbad.read(path)])
    # The files that decide what counts as internal and what is never flagged. One left in a log
    # folder is used without being asked for, so each is named in the results and the report.
    settings_files = ([{"kind": "settings", "file": chosen, "found_in_input": not config_path}] if chosen else [])
    settings_files += [{"kind": "network_map", "file": f, "found_in_input": True} for f in found_maps]
    settings_files += [{"kind": "network_map", "file": network_map, "found_in_input": False}] if network_map else []
    settings_files += [{"kind": "known_scanners", "file": f, "found_in_input": True} for f in found_lists]
    settings_files += ([{"kind": "known_scanners", "file": known_scanners, "found_in_input": False}]
                       if known_scanners else [])
    settings_files += [{"kind": "known_bad", "file": f, "found_in_input": True} for f in found_bad]
    settings_files += [{"kind": "known_bad", "file": known_bad, "found_in_input": False}] if known_bad else []
    logs = [f for f in files if not (config.is_config_file(f) or netmap.is_map_file(f) or scanners.is_list_file(f)
                                     or knownbad.is_list_file(f) or os.path.basename(f).lower() in NOTES)]
    if not logs:
        raise UserError("No log files were given. Point PentAIWatch at Zeek conn.log files, Palo Alto "
                        "traffic logs, or a folder of them.")
    with resources.job_slot():
        budget = resources.plan(workdir=workdir)
        for warning in budget.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        ds = load(logs, workdir=workdir, skew_seconds=cfg.dedup_skew_seconds, budget=budget,
                  options={"paloalto": cfg.paloalto, **({"zeek": cfg.web} if cfg.web.check else {})})
        try:
            if not ds.flows:
                raise UserError("No sessions could be read from the input. PentAIWatch needs Zeek conn.log "
                                "(TSV or JSON) or Palo Alto traffic logs (CSV export or syslog lines), "
                                "plain or .gz." + _why_empty(ds.stats))
            warnings = list(setup)
            unknown = [s.file for s in ds.stats if s.fmt == "unknown"]
            if unknown:
                warnings.append(f"{len(unknown)} file(s) are neither Zeek nor Palo Alto logs and were left out: "
                                + ", ".join(unknown[:5]) + (" and more" if len(unknown) > 5 else "") + ".")
            scene = explore.empty()
            # the Explorer's picture is read while the scoring tables exist
            detection = detect(ds.flow_con(), cfg,
                               while_scored=lambda con, found: scene.update(explore.collect(con, cfg, found)))
            res = {
                "schema_version": RESULTS_SCHEMA_VERSION,
                "tool": {"name": "PentAIWatch", "version": __version__},
                "report": details.clean((report or {}).get("name"), (report or {}).get("description")),
                "inputs": [{"file": s.file, "format": s.fmt, "read": s.read, "kept": s.kept,
                            "dropped": dict(s.dropped), "notes": list(s.notes)} for s in ds.stats],
                "log_sources": ds.sensors,
                "sessions": len(ds.flows),
                "duplicates_removed": {"exact": ds.duplicate_flows, "seen_by_two_sensors": ds.cross_sensor_duplicates},
                # IPS/IDS alerts read, by kind of log (not scored yet)
                "threat_events": dict(ds.flow_con().execute(
                    "SELECT sensor, count(*) FROM threats GROUP BY 1 ORDER BY 1").fetchall()),
                "settings": cfg.settings(),
                "settings_files": settings_files,
                "typed_settings": typed,
                "networks": cfg.networks,
                "known_scanners": cfg.known_scanners,
                "known_bad_lists": {"bundled": sum(1 for e in cfg.known_bad if e["list_name"] == "bundled list"),
                                    "yours": sum(1 for e in cfg.known_bad if e["list_name"] != "bundled list")},
                "warnings": warnings + detection.warnings,
                "detection": detection.to_dict(),
                "limitations": LIMITATIONS,
                # the map written next to the report, and how much of the detection is drawn on it
                "explorer": {"file": explore.FILENAME, "sources_drawn": len(scene["sources"]),
                             "findings_drawn": sum(1 for s in scene["sources"] if s["flagged"]),
                             # the sources whose sessions the page can replay on its Timeline
                             "timelines": list(scene["timelines"])},
            }
            paths = write_all(res, outdir)
            paths[explore.FILENAME] = explore.write(scene, res, outdir)
            return res, paths
        except Exception as exc:
            friendly = resources.explain(exc, budget)
            if friendly is not None:
                raise friendly from exc
            raise
        finally:
            ds.close()
