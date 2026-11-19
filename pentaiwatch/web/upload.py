"""The upload page and the two ways to start an analysis from it (after VulnScope MAX 6a7ac93,
vulnflow/web/upload.py): reading a folder on this computer in place, or uploading files. Both end
in ``_start``, which starts the run in the background (jobs.py) and opens its page.
"""
from __future__ import annotations

import html
import ipaddress
import os
import re
import shutil

from .. import resources
from ..errors import UserError
from ..pipeline import input_files
from . import folders, multipart, runname, runs
from .pages import MARK, asset, busy_overlay, error_html, page

START_HINT = "The analysis runs in the background; its page opens in a moment."
UPLOAD_HINT = "The files are copied to this computer's runs folder first. Keep this tab open until the upload is done."
BUSY_MESSAGE = ("Another analysis is already running on this computer. Wait for it to finish and try again; "
                "it is listed under Recent reports.")
DISK_RESERVE = 2 * 1024 ** 3      # room left for the run's own working files besides an upload

FORM = """<h1><img class="mark" src="{mark}" alt="">Analyze logs with PentAIWatch</h1>
<p>Point PentAIWatch at a folder of Zeek <code>conn.log</code> files or Palo Alto traffic logs, or upload them. It flags
outside addresses that behave like agentic, AI-driven pentest tools, and writes a report and an Explorer: a map of what
each source swept and came back to, with a Timeline of its bursts and pauses.</p>
{error}
<form method="post" action="/analyze-folder" data-busy="Starting…" data-busy-hint="{start_hint}">
<input type="hidden" name="csrf" value="{csrf}">
<label for="path">Folder on this computer</label>
<div class="pathrow"><input id="path" type="text" name="path" value="{path}" placeholder="{path_example}" autocomplete="off" spellcheck="false">
<button type="button" id="browse" class="secondary">Browse&hellip;</button></div>
<div id="pick-msg" class="hint error" role="status" aria-live="polite"></div>
<div id="picker" hidden><div class="pk-head"><button type="button" id="pk-up" class="secondary" title="Parent folder">&uarr; Up</button>
<code id="pk-where"></code></div><ul id="pk-list"></ul>
<div class="pk-foot"><span id="pk-info" class="hint"></span><button type="button" id="pk-cancel" class="secondary">Cancel</button>
<button type="button" id="pk-use">Use this folder</button></div></div>
<div class="hint">The files are read where they are, including subfolders; nothing is copied or uploaded. Hidden files are
skipped. A <code>pentaiwatch.json</code>, <code>network_map.csv</code> or <code>known_scanners.csv</code> in the folder is used,
and the report names it.</div>
<label for="nets1">Internal networks (optional)</label>
<input id="nets1" type="text" name="internal_nets" value="{nets}" placeholder="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16" autocomplete="off" spellcheck="false">
<div class="hint">Anything outside these ranges counts as the internet. Leave blank to use the settings file's, or else the
private ranges.</div>
<div class="btnrow"><button type="submit" id="analyze-folder">Analyze folder</button></div>
</form>
<h2>Or upload files</h2>
<form method="post" action="/analyze" enctype="multipart/form-data" data-busy="Uploading…" data-busy-hint="{upload_hint}">
<input type="hidden" name="csrf" value="{csrf}">
<label for="folder">Folder of logs</label>
<input id="folder" type="file" name="folder" webkitdirectory directory multiple>
<div class="hint">Choose one folder to include its files and subfolders.</div>
<label for="files">Log files</label>
<input id="files" type="file" name="files" multiple>
<div class="hint">Zeek <code>conn.log</code> (TSV or JSON) and Palo Alto traffic logs (CSV export or syslog lines), plain or
<code>.gz</code>, with a <code>pentaiwatch.json</code>, <code>network_map.csv</code> or <code>known_scanners.csv</code> if you
use one.</div>
<label for="nets2">Internal networks (optional)</label>
<input id="nets2" type="text" name="internal_nets" value="{nets}" placeholder="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16" autocomplete="off" spellcheck="false">
<div class="btnrow"><button type="submit" id="analyze-upload">Analyze</button></div>
<div class="hint">Up to {max_upload} in all. For more, use Folder on this computer, which reads the logs in place.</div>
</form>
<p class="hint">Formats are detected automatically. Folder selection is supported by Chrome and other current browsers.
Files stay on this computer: an upload goes to this server only, and PentAIWatch makes no network connections.</p>
{recent}
{busy}"""


def show(req, error: str = ""):
    """GET / and every refusal of the two forms (the form keeps what was typed)."""
    app = req.app
    body = FORM.format(
        mark=MARK, error=error_html(error), csrf=html.escape(app.csrf), path=html.escape(app.last_path),
        path_example=html.escape(folders.path_example()), nets=html.escape(app.last_nets),
        start_hint=html.escape(START_HINT), upload_hint=html.escape(UPLOAD_HINT),
        max_upload=html.escape(resources.fmt_size(app.max_upload)),
        recent=runs.recent_html(app), busy=busy_overlay())
    config = {"csrf": app.csrf, "native": folders.NATIVE_PICKER and not app.access_token}
    req.send_page(200, page("PentAIWatch", body, [asset("busy.js"), asset("folder_picker.js")], config))


def page_view(req):
    return show(req)


def _nets(text: str) -> list[str] | None:
    """The internal networks typed on the form, or None when the field was left blank. Raises
    UserError on anything that is not an address or a range."""
    nets = [n for n in re.split(r"[,\s]+", text.strip()) if n]
    for net in nets:
        try:
            ipaddress.ip_network(net, strict=False)
        except ValueError:
            raise UserError(f"Internal networks: '{net}' is not an address or address range "
                            "(for example 10.0.0.0/8).") from None
    return nets or None


def _start(req, run_id: str, files: list[str], nets: list[str] | None, source: str):
    """Start the run in the background and open its page."""
    app = req.app
    root = app.run_root(run_id)
    try:
        app.jobs.start(run_id, root, files, nets, source)
    except UserError as exc:
        shutil.rmtree(root, ignore_errors=True)
        return show(req, str(exc))
    app.last_path = app.last_nets = ""          # the next analysis starts with an empty form
    req.redirect(f"/runs/{run_id}/")


def _busy(app) -> bool:
    return app.jobs.running() >= resources.max_jobs() or resources.busy()


def _placer(in_dir: str):
    """Where each uploaded file goes: its path inside an uploaded folder is kept (each part made
    safe, at most 8 deep), and so is its name, which is how settings files are found. A second
    file with the same path gets "-2", "-3"... before its extension."""
    root = os.path.realpath(in_dir)

    def place(index: int, filename: str) -> str:
        parts = [re.sub(r"[^A-Za-z0-9._-]", "_", p)[:120] for p in filename.replace("\\", "/").split("/")]
        parts = [p for p in parts if p not in ("", ".", "..")][-8:] or [f"upload-{index + 1}"]
        path = os.path.join(root, *parts)
        stem, ext = os.path.splitext(path)
        n = 1
        while os.path.exists(path):
            n += 1
            path = f"{stem}-{n}{ext}"
        where = os.path.realpath(os.path.dirname(path))
        if where != root and not where.startswith(root + os.sep):
            raise multipart.MultipartError("An uploaded file name points outside the upload folder.")
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        return path
    return place


def analyze_upload(req):
    """POST /analyze: files uploaded from the browser, streamed to disk, then analyzed."""
    app = req.app
    if _busy(app):                                # refuse before reading a large upload
        req.close_connection = True
        return show(req, BUSY_MESSAGE)
    length = req.length()
    if length <= 0 or length > app.max_upload:
        req.close_connection = True               # don't read an oversized body at all
        return show(req, f"An upload can be up to {resources.fmt_size(app.max_upload)}; this one is "
                         f"{resources.fmt_size(max(length, 0))}. For more, use Folder on this computer.")
    os.makedirs(app.data_dir, mode=0o700, exist_ok=True)
    free = shutil.disk_usage(app.data_dir).free
    if free < length + DISK_RESERVE:
        req.close_connection = True
        return show(req, f"There is not enough free disk space for this upload: it is {resources.fmt_size(length)}, "
                         f"the run needs about {resources.fmt_size(DISK_RESERVE)} more to work in, and "
                         f"{resources.fmt_size(free)} is free where runs are kept ({app.data_dir}).")
    run_id = runname.new_run(app.data_dir)
    root = app.run_root(run_id)
    in_dir = os.path.join(root, "in")
    os.makedirs(in_dir, mode=0o700)
    try:
        fields, parts = multipart.parse(req.rfile, length, req.headers.get("Content-Type", ""), _placer(in_dir))
    except multipart.MultipartError as exc:
        shutil.rmtree(root, ignore_errors=True)
        req.close_connection = True
        return show(req, str(exc))
    except OSError as exc:                        # the disk filled up, or a name the system refuses
        shutil.rmtree(root, ignore_errors=True)
        req.close_connection = True
        return show(req, f"The upload could not be saved: {exc.strerror or exc}.")
    if not app.csrf_ok(fields.get("csrf", "")):
        shutil.rmtree(root, ignore_errors=True)
        return req.send_text(403, "Forbidden")
    app.last_nets = fields.get("internal_nets", "")
    try:
        nets = _nets(app.last_nets)
    except UserError as exc:
        shutil.rmtree(root, ignore_errors=True)
        return show(req, str(exc))
    if not parts:
        shutil.rmtree(root, ignore_errors=True)
        return show(req, "Choose a folder of logs or at least one log file to upload.")
    files = [path for _, path in parts]
    return _start(req, run_id, files, nets, f"Upload of {len(files):,} file{'' if len(files) == 1 else 's'}")


def analyze_folder(req):
    """POST /analyze-folder: a folder on the computer running the server, read in place."""
    app = req.app
    form = req.read_form()
    if form is None:
        return req.send_text(400, "Bad request")
    if not app.csrf_ok(form.get("csrf", "")):
        return req.send_text(403, "Forbidden")
    raw = form.get("path", "").strip().strip('"').strip("'")
    folder = folders.resolve(raw)
    app.last_path, app.last_nets = raw, form.get("internal_nets", "")
    if not raw:
        return show(req, "Choose a folder first: click Browse… and pick one, or type its full path.")
    if not os.path.isdir(folder):
        return show(req, f"Folder not found: {raw}. Use the full path, for example {folders.path_example()}.")
    try:
        nets = _nets(app.last_nets)
    except UserError as exc:
        return show(req, str(exc))
    if _busy(app):
        return show(req, BUSY_MESSAGE)
    runs_dir = os.path.realpath(app.data_dir) + os.sep
    try:
        files = [f for f in input_files([folder], app.data_dir) if not os.path.realpath(f).startswith(runs_dir)]
    except (UserError, OSError) as exc:
        return show(req, str(exc))
    if not files:
        return show(req, f"No files found in {folder} (hidden files and the runs folder are skipped).")
    run_id = runname.new_run(app.data_dir)
    in_dir = os.path.join(app.run_root(run_id), "in")
    os.makedirs(in_dir, mode=0o700)
    with open(os.path.join(in_dir, "SOURCE.txt"), "w", encoding="utf-8") as fh:
        fh.write(f"Read in place from {folder}\n" + "\n".join(files) + "\n")
    return _start(req, run_id, files, nets, f"Folder {folder}")
