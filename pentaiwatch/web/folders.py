"""Finding a folder on this computer for the upload page (after VulnScope MAX 6a7ac93,
vulnflow/web/folders.py): the macOS Choose Folder dialog, or the in-page folder list elsewhere.

Both give back a path only. The folder list shows folder names and how many files a folder holds,
never a file's name or contents. MAX's container mode (finding a folder picked in the browser among
the folders shared with a Docker container) is left out: PentAIWatch has no container yet.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

NATIVE_PICKER = sys.platform == "darwin" and shutil.which("osascript") is not None


def list_folder(raw: str) -> dict:
    """Subfolders of ``raw`` (default: the home folder), skipping hidden ones; falls back to the
    nearest folder above that exists."""
    path = os.path.realpath(os.path.expanduser(raw.strip().strip('"').strip("'") or "~"))
    while not os.path.isdir(path) and os.path.dirname(path) != path:
        path = os.path.dirname(path)
    try:
        entries = list(os.scandir(path))
    except OSError as exc:
        return {"error": f"Cannot open {path}: {exc.strerror or exc}"}
    dirs, files = [], 0
    for e in entries:
        if e.name.startswith("."):
            continue
        try:
            if e.is_dir():
                dirs.append(e.name)
            elif e.is_file():
                files += 1
        except OSError:
            continue
    parent = os.path.dirname(path)
    return {"path": path, "parent": None if parent == path else parent, "sep": os.sep,
            "dirs": sorted(dirs, key=str.lower), "files": files}


def native_pick(start: str) -> dict:
    """Show the macOS Choose Folder dialog in front of the browser and return the chosen path. The
    start folder reaches the script as a JSON string, so it is never read as AppleScript."""
    start = os.path.realpath(os.path.expanduser(start.strip() or "~"))
    script = ['tell application (path to frontmost application as text)',
              'activate',
              'POSIX path of (choose folder with prompt "Choose a folder of Zeek or Palo Alto logs"'
              + (' default location (POSIX file %s)' % json.dumps(start) if os.path.isdir(start) else "") + ")",
              'end tell']
    try:
        out = subprocess.run(["osascript"] + sum((["-e", line] for line in script), []),
                             capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired):
        return {"error": "The folder dialog could not be opened."}
    if out.returncode != 0:
        return {"cancelled": True} if "-128" in out.stderr else {"error": "The folder dialog could not be opened."}
    return {"path": out.stdout.strip().rstrip("/") or "/"}


def resolve(raw: str) -> str:
    """The real path of a folder typed or pasted on the page ("" when nothing was given)."""
    raw = raw.strip().strip('"').strip("'")
    return os.path.realpath(os.path.expanduser(raw)) if raw else ""


def path_example() -> str:
    return "C:\\Users\\you\\Documents\\case-logs" if os.name == "nt" else "~/Documents/case-logs"


# -- views ------------------------------------------------------------------------------------
def browse(req):
    """POST /browse: the subfolders of a folder on this computer, for the in-page folder list."""
    body = req.read_json()
    if body is None:
        return req.send_json(403, {"error": "Forbidden"})
    return req.send_json(200, list_folder(str(body.get("path") or "")))


def pick(req):
    """POST /pick-folder: the operating system's own folder dialog (macOS), on the computer running
    the server."""
    body = req.read_json()
    if body is None:
        return req.send_json(403, {"error": "Forbidden"})
    if not NATIVE_PICKER:
        return req.send_json(200, {"unsupported": True})
    return req.send_json(200, native_pick(str(body.get("path") or "")))
