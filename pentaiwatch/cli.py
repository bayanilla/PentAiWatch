"""Command line: ``python -m pentaiwatch analyze <folder or files> -o <output folder>``, or
``python -m pentaiwatch serve`` for the upload page."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .errors import UserError
from .pipeline import run


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="pentaiwatch",
        description="Flag outside addresses that behave like agentic, AI-driven pentest tools.")
    ap.add_argument("--version", action="version", version=f"PentAIWatch {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="read logs and write the report")
    a.add_argument("files", nargs="+", metavar="PATH",
                   help="Zeek conn.log files, Palo Alto traffic logs, or folders that hold them")
    a.add_argument("-o", "--out", default="pentaiwatch_out", help="output folder (default pentaiwatch_out)")
    a.add_argument("--config", metavar="JSON",
                   help="settings file (default: pentaiwatch.json in an input folder, else built-in defaults)")
    a.add_argument("--network-map", metavar="CSV",
                   help="your address ranges with names: cidr,name,type (default: network_map.csv in an input folder)")
    a.add_argument("--known-scanners", metavar="CSV",
                   help="sources never to flag: address,name (default: known_scanners.csv in an input folder)")
    a.add_argument("--name", default="", help="report name, shown at the top of the report and in the Explorer")
    a.add_argument("--description", default="",
                   help="a few lines about the run (scope, case number), shown under the report name")
    a.add_argument("--workdir", metavar="DIR",
                   help="where temporary files go while the logs are processed (default: system temp)")
    s = sub.add_parser("serve", help="start the upload page in this computer's browser")
    s.add_argument("--host", default="127.0.0.1",
                   help="address to listen on (default 127.0.0.1: this computer only)")
    s.add_argument("--port", type=int, help="port (default 8770, or the next free one)")
    s.add_argument("--allow-remote", action="store_true",
                   help="allow a --host other computers can reach; every request then needs a printed access token")
    s.add_argument("--data-dir", default="pentaiwatch_runs",
                   help="where each run's uploads and results are kept (default pentaiwatch_runs)")
    s.add_argument("--max-upload-gb", type=float, default=20, help="largest upload in GB (default 20)")
    s.add_argument("--open", action="store_true", help="open the page in the default browser")
    args = ap.parse_args(argv)
    if args.cmd == "serve":
        from .web.server import serve
        if args.max_upload_gb <= 0:
            ap.error("--max-upload-gb must be more than 0")
        serve(args.host, args.port, args.data_dir, int(args.max_upload_gb * 1024 ** 3), args.allow_remote, args.open)
        return 0
    try:
        res, paths = run(args.files, args.out, config_path=args.config, network_map=args.network_map,
                         known_scanners=args.known_scanners, workdir=args.workdir,
                         report={"name": args.name, "description": args.description})
    except UserError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for warning in res["warnings"]:
        print(f"warning: {warning}", file=sys.stderr)
    found = res["detection"]["findings"]
    print(f"{res['sessions']:,} sessions read; {len(found)} source{'' if len(found) == 1 else 's'} flagged.")
    for f in found:
        tier = "tier 0" if f["level"] == 0 else f"level {f['level']}"
        hosts = len(f["hosts_hit"])
        print(f"  {f['source']}  {tier}: {f['label']}  ({hosts} host{'' if hosts == 1 else 's'} hit)")
    print(f"Report:   {paths['report.html']}")
    print(f"Explorer: {paths['explorer.html']}")
    return 0
