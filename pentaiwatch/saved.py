"""Reopen a finished report from its output folder, without reading the logs again (after VulnScope
MAX 6a7ac93, vulnflow/saved.py).

The folder is an earlier run's output folder: results.json next to report.md, report.html and
explorer.html. results.json holds everything the report is written from, so the report is written
again with this version's code. The Explorer is drawn from data that results.json does not keep;
that data is packed inside explorer.html, so it is lifted out and drawn again with this version's
Explorer. Nothing in the folder is changed: the pages are written into a new run folder.

Its files are treated as untrusted: size capped, read as data only (the old pages are never served,
only the data inside explorer.html is used), checked for the fields the pages read, and the new
pages are served in the same sandbox as any run's (web/runs.py).
"""
from __future__ import annotations

import json
import os

from . import explore
from .errors import UserError
from .pipeline import RESULTS_SCHEMA_VERSION
from .report import write_all

MAX_SAVED_FILE = 256 * 1024 * 1024       # results.json is read into memory (several times its size)
SCENE_KEYS = ("window", "subnets", "hosts", "sources", "timelines", "counts")   # explore.empty()


class SavedRunError(UserError):
    """The folder is not a usable saved report; the message is shown to the user."""


def _json(text: str, what: str):
    try:
        return json.loads(text)
    except RecursionError:
        raise SavedRunError(f"{what} is nested too deeply to be a PentAIWatch file.") from None
    except ValueError as exc:
        raise SavedRunError(f"{what} is not valid JSON ({exc}).") from None


def _need(obj: dict, key: str, kind, where: str = "results.json"):
    value = obj.get(key)
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        name = {dict: "an object", list: "a list", str: "text", int: "a number"}.get(kind, kind.__name__)
        raise SavedRunError(f"This doesn't look like a PentAIWatch {where}: \"{key}\" is missing or is not {name}.")
    return value


def check_results(res) -> dict:
    """A parsed results.json, checked for what the report reads. Raises SavedRunError with a reason."""
    if not isinstance(res, dict):
        raise SavedRunError("This doesn't look like a PentAIWatch results.json: the top level is not an object.")
    tool = res.get("tool") if isinstance(res.get("tool"), dict) else {}
    if tool.get("name") != "PentAIWatch":
        raise SavedRunError("This results.json was not written by PentAIWatch.")
    version = res.get("schema_version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise SavedRunError("results.json has an unreadable \"schema_version\".")
    if version > RESULTS_SCHEMA_VERSION:
        raise SavedRunError(f"This results.json was written by a newer PentAIWatch (results format {version}; "
                            f"this copy reads up to {RESULTS_SCHEMA_VERSION}). Update PentAIWatch and try again.")
    _need(res, "sessions", int)
    for key in ("warnings", "log_sources", "inputs"):
        _need(res, key, list)
    det = _need(res, "detection", dict)
    found = _need(det, "findings", list, "results.json detection")
    if not all(isinstance(f, dict) and isinstance(f.get("source"), str) for f in found):
        raise SavedRunError("This doesn't look like a PentAIWatch results.json: a finding has no source.")
    if "report" in res and not isinstance(res["report"], dict):
        raise SavedRunError("results.json \"report\" must be an object.")
    return res


def explorer_scene(text: str, res: dict) -> dict:
    """The Explorer's scene packed inside a saved explorer.html, checked against its results.json."""
    try:
        data = explore.read_data(text)
    except RecursionError:
        raise SavedRunError("The Explorer data in explorer.html is nested too deeply to be a PentAIWatch file.") from None
    except ValueError as exc:
        raise SavedRunError(f"explorer.html in that folder cannot be read: {exc}.") from None
    if not isinstance(data, dict):
        raise SavedRunError("The Explorer data in explorer.html is not an object.")
    for key, kind in (("sources", list), ("hosts", list), ("subnets", list), ("timelines", dict), ("counts", dict),
                      ("window", list)):
        _need(data, key, kind, "explorer.html")
    if data.get("sessions") != res["sessions"]:
        raise SavedRunError("explorer.html is from a different analysis than results.json (they count "
                            f"{data.get('sessions')} and {res['sessions']} sessions). The folder mixes files from two runs.")
    flagged = {s.get("ip") for s in data["sources"] if isinstance(s, dict) and s.get("flagged")}
    if not flagged <= {f["source"] for f in res["detection"]["findings"]}:
        raise SavedRunError("explorer.html is from a different analysis than results.json (it flags other sources). "
                            "The folder mixes files from two runs.")
    return {k: data[k] for k in SCENE_KEYS}


def is_report_folder(folder: str) -> bool:
    """An earlier run's output folder: results.json next to the pages it wrote."""
    return os.path.isfile(os.path.join(folder, "results.json")) and any(
        os.path.isfile(os.path.join(folder, n)) for n in ("explorer.html", "report.md", "report.html"))


def read_text(path: str, what: str) -> str:
    if os.path.getsize(path) > MAX_SAVED_FILE:
        raise SavedRunError(f"{what} is larger than {MAX_SAVED_FILE // 1048576} MB, too large to reopen.")
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def load_folder(folder: str) -> tuple[dict, dict | None]:
    """results.json (required) and the Explorer's scene in explorer.html (when there is one)."""
    path = os.path.join(folder, "results.json")
    if not os.path.isfile(path):
        raise SavedRunError("There's no results.json in that folder. Choose a finished report's output folder "
                            "(the one with results.json, report.html and explorer.html).")
    res = check_results(_json(read_text(path, "results.json"), "results.json"))
    page = os.path.join(folder, explore.FILENAME)
    scene = explorer_scene(read_text(page, "explorer.html"), res) if os.path.isfile(page) else None
    return res, scene


def write(res: dict, scene: dict | None, outdir: str) -> dict[str, str]:
    """Write the report (and the Explorer, when there is a scene) again into ``outdir``. Missing or
    mistyped fields become a SavedRunError."""
    if scene is None:
        res = {**res, "explorer": None}          # no map to link to
    try:
        paths = write_all(res, outdir)
        if scene is not None:
            paths[explore.FILENAME] = explore.write(scene, res, outdir)
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
        detail = f"missing field {exc}" if isinstance(exc, KeyError) else str(exc)[:200]
        raise SavedRunError("This results.json can't be written out by this version of PentAIWatch "
                            f"({detail}). It may be from a much older version, or edited.") from None
    return paths
