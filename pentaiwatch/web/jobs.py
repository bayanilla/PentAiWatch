"""Analyses started from the upload page. Each runs in a background thread, so a run of an hour
never depends on one browser request staying open: the run's page asks how it is going and opens
the results when it is done, and the tab can be closed meanwhile.

How a run is going is kept in its folder, in STATUS.json: "running", then "done" (with a short
summary for its page) or "failed" (with the message to show). A run that says "running" while this
server is not running it was cut short when an earlier server stopped; its page says so.

As on the command line, only ``resources.max_jobs()`` analyses run at once (one by default). The
check is made here, under a lock, before a run is started, and ``pipeline.run`` holds its job slot
as it always does.
"""
from __future__ import annotations

import json
import os
import threading
import time
import traceback
from datetime import datetime, timezone

from .. import pipeline, resources
from ..errors import UserError

STATUS = "STATUS.json"
MAX_STATUS = 1024 * 1024           # a status file is a few hundred bytes; anything larger is not ours
FAILED = "The analysis failed; the console that started the upload page has the details."


def now() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds") + "Z"


def write_status(root: str, status: dict) -> None:
    """Replace the run's STATUS.json in one step, so a reader never sees half of it."""
    tmp = os.path.join(root, STATUS + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(status, fh)
    os.replace(tmp, os.path.join(root, STATUS))


def read_status(root: str) -> dict | None:
    path = os.path.join(root, STATUS)
    try:
        if os.path.getsize(path) > MAX_STATUS:
            return None
        with open(path, encoding="utf-8") as fh:
            status = json.load(fh)
    except (OSError, ValueError):
        return None
    return status if isinstance(status, dict) and isinstance(status.get("state"), str) else None


def summary(res: dict) -> dict:
    """What a finished run's page shows without opening its results.json."""
    timelines = set((res.get("explorer") or {}).get("timelines") or [])
    return {"sessions": res["sessions"], "warnings": len(res["warnings"]),
            "flagged": [{"source": f["source"], "level": f["level"], "label": f["label"],
                         "hosts": len(f["hosts_hit"]), "timeline": f["source"] in timelines,
                         "known": bool(f.get("known")), "parallel": bool(f.get("parallel"))}
                        for f in res["detection"]["findings"]]
                       + [{"source": k["source"], "level": None, "label": k["name"] or "listed",
                           "hosts": k["hosts"], "timeline": False, "known": True, "tag": "Published address"}
                          for k in res["detection"].get("known_sources") or []]
                       + [{"source": v["source"], "level": None, "label": f"{v['runs'][0]['sessions']:,} sessions "
                           f"to {v['runs'][0]['service']}, one every {v['runs'][0]['gap_seconds']:g} s",
                           "hosts": len({r["service"].split(":")[0].split("/")[0] for r in v["runs"]}),
                           "timeline": False, "tag": "Machine-steady"}
                          for v in res["detection"].get("steady_sources") or []]
                       + _rotation_entries(res)}


def _rotation_entries(res: dict) -> list[dict]:
    """The rotating sources not already listed: each sweep, then the addresses that came back to it."""
    det = res["detection"]
    listed = {x["source"] for x in det["findings"] + (det.get("known_sources") or [])
              + (det.get("steady_sources") or [])}
    out = []
    for g in det.get("rotations") or []:
        members = [(g["sweeper"], f"swept {g['services_probed']:,} services; {len(g['joiners'])} new addresses "
                    "came back to what it found", 0)]
        members += [(j["source"], f"came back to what {g['sweeper']} swept", len(j["services"])) for j in g["joiners"]]
        for ip, label, hosts in members:
            if ip not in listed:
                listed.add(ip)
                out.append({"source": ip, "level": None, "label": label, "hosts": hosts or g["services_found"],
                            "timeline": False, "tag": "Rotating sources"})
    return out


class Jobs:
    """The runs this server started that are still going."""

    def __init__(self):
        self._lock = threading.Lock()
        self._live: dict[str, float] = {}           # run id -> when it started (time.monotonic)

    def running(self) -> int:
        with self._lock:
            return len(self._live)

    def is_live(self, run_id: str) -> bool:
        with self._lock:
            return run_id in self._live

    def elapsed(self, run_id: str) -> float | None:
        with self._lock:
            started = self._live.get(run_id)
        return None if started is None else time.monotonic() - started

    def start(self, run_id: str, root: str, files: list[str], internal_nets: list[str] | None, source: str,
              run=None, report: dict | None = None) -> None:
        """Start analyzing ``files`` into ``root``/out in the background. Raises BusyError when as
        many analyses as may run at once are already running. ``run`` stands in for pipeline.run
        (tests). ``report`` is the report name and description (details.clean)."""
        with self._lock:
            if len(self._live) >= resources.max_jobs() or resources.busy():
                raise resources.BusyError("Another analysis is already running on this computer. Wait for it to "
                                          "finish and try again; the upload page lists it under Recent reports.")
            write_status(root, {"state": "running", "started": now(), "source": source, "files": len(files),
                                "report": report or {}})
            self._live[run_id] = time.monotonic()
        thread = threading.Thread(target=self._run, name=f"pentaiwatch-run-{run_id}", daemon=True,
                                  args=(run_id, root, files, internal_nets, report, run or pipeline.run))
        thread.start()

    def _run(self, run_id: str, root: str, files: list[str], internal_nets, report, run) -> None:
        status = read_status(root) or {}
        began = time.monotonic()
        try:
            res, _ = run(files, os.path.join(root, "out"), workdir=root, internal_nets=internal_nets, report=report)
            status.update(state="done", summary=summary(res))
        except UserError as exc:
            status.update(state="failed", message=str(exc))
        except Exception:
            traceback.print_exc()          # the run folder is kept for a look at what went wrong
            status.update(state="failed", message=FAILED)
        finally:
            status.update(finished=now(), seconds=round(time.monotonic() - began, 1))
            try:
                write_status(root, status)
            finally:
                with self._lock:
                    self._live.pop(run_id, None)
