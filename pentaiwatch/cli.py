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
    a.add_argument("--known-bad", metavar="CSV",
                   help="attacker addresses to flag on sight: address,name,confidence,reference "
                        "(default: known_bad.csv in an input folder, plus the bundled published list)")
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
                         known_scanners=args.known_scanners, known_bad=args.known_bad, workdir=args.workdir,
                         report={"name": args.name, "description": args.description})
    except UserError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for warning in res["warnings"]:
        print(f"warning: {warning}", file=sys.stderr)
    found = res["detection"]["findings"]
    known = res["detection"].get("known_sources") or []
    steady = res["detection"].get("steady_sources") or []
    spray = res["detection"].get("spray_sources") or []
    rotations = res["detection"].get("rotations") or []
    flagged = lambda items: [x for x in items if x.get("status") == "flagged"]
    shared = res["detection"].get("shared_sweeps") or []
    logins = res["detection"].get("login_sources") or []
    total = len({x["source"] for x in found + known + flagged(steady) + flagged(spray) + flagged(logins)}
                | {ip for g in flagged(rotations) for ip in [g["sweeper"]] + [j["source"] for j in g["joiners"]]}
                | {ip for g in flagged(shared) for r in g["returns"] for ip in r["sources"]})
    regular = {x["source"] for x in steady + spray + logins if x.get("status") == "regular"}
    leads = len({x["source"] for x in steady + spray + logins if x.get("status") == "lead"}
                | {g["sweeper"] for g in rotations if g.get("status") != "flagged"}
                | {ip for g in shared if g.get("status") != "flagged" for r in g["returns"] for ip in r["sources"]})
    regular -= {x["source"] for x in steady + spray + logins if x.get("status") != "regular"}
    authorized = len(res["detection"].get("authorized") or [])
    reached = len({c["host"] for c in res["detection"].get("outbound_contacts") or []})
    print(f"{res['sessions']:,} sessions read; {total} source{'' if total == 1 else 's'} flagged"
          + (f"; {reached} internal host{'' if reached == 1 else 's'} reached attacker addresses" if reached else "")
          + (f"; {leads} lead{'' if leads == 1 else 's'} to look at (not flagged)" if leads else "")
          + (f"; {len(regular)} regular client{'' if len(regular) == 1 else 's'}" if regular else "")
          + (f"; {authorized} authorized source{'' if authorized == 1 else 's'} (not flagged)" if authorized else "")
          + ".")
    for f in found:
        tier = "tier 0" if f["level"] == 0 else f"level {f['level']}"
        hosts = len(f["hosts_hit"])
        also = ("  [several attack paths at once]" if f.get("parallel") else "") + \
               ("  [published attacker address]" if f.get("known") else "")
        print(f"  {f['source']}  {tier}: {f['label']}  ({hosts} host{'' if hosts == 1 else 's'} hit){also}")
    for k in known:
        print(f"  {k['source']}  published attacker address: {k['name'] or 'listed'}  "
              f"({k['hosts']} host{'' if k['hosts'] == 1 else 's'} reached)")
    for v in steady:
        r = v["runs"][0]
        print(f"  {v['source']}  fixed-interval repetition ({v['status']}): {r['sessions']} sessions to {r['service']}, "
              f"one every {r['gap_seconds']:g} s")
    for v in spray:
        r = v["runs"][0]
        print(f"  {v['source']}  high-rate repeated connections ({v['status']}): {r['sessions']} sessions to {r['service']}, "
              f"up to {r['peak_per_minute']} a minute")
    for v in logins:
        r = v["runs"][0]
        print(f"  {v['source']}  repeated failed-login pattern ({v['status']}): {r['sessions']} sessions to {r['service']} "
              f"in {r['minutes']} minutes, replies of about {r['reply_bytes']} bytes")
    for g in rotations:
        print(f"  {g['sweeper']}  rotating sources ({g['status']}): {', '.join(j['source'] for j in g['joiners'])} came back to "
              "what it swept")
    for g in res["detection"].get("shared_sweeps") or []:
        for r in g["returns"]:
            print(f"  {', '.join(r['sources'])}  shared sweep ({g['status']}): came back to {r['service']} after "
                  f"{len(g['sweepers'])} addresses split a sweep of {g['network']}")
    for a in res["detection"].get("authorized") or []:
        print(f"  {a['source']}  authorized: {a['name'] or 'listed'}" + (f" ({a['owner']})" if a["owner"] else "")
              + f", would have been {', '.join(a['behaviours'])}")
    for c in res["detection"].get("outbound_contacts") or []:
        print(f"  {c['host']}  reached attacker address {c['destination']}: {c['name'] or 'listed'}  "
              f"({c['sessions']} sessions, {c['answered']} answered)")
    hints = res["detection"].get("c2_hints") or []
    if hints:
        print(f"  {len(hints)} outbound session group(s) to command-and-control ports (hints, see the report)")
    for b in res["detection"].get("beacons") or []:
        print(f"  {b['host']}  fixed-interval calls out ({b['status']}): {b['sessions']} sessions to {b['service']}, "
              f"one every {b['gap_seconds']:g} s")
    calls = res["detection"].get("callbacks_total") or 0
    if calls:
        print(f"  {calls} outbound session group(s) back to a source on an agentic tool's port (hints, see the report)")
    for row in res["detection"].get("coverage") or []:
        if row["status"] != "checked" and not row["detector"].startswith("Levels 2 and 3"):
            print(f"  {row['status']}: {row['detector']} ({row['detail']})")
    print(f"Report:   {paths['report.html']}")
    print(f"Explorer: {paths['explorer.html']}")
    return 0
