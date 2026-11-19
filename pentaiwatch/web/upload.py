"""The upload page and the two ways to start an analysis from it (after VulnScope MAX 6a7ac93,
vulnflow/web/upload.py): reading a folder on this computer in place, or uploading files. Both end
in ``_start``, which starts the run in the background (jobs.py) and opens its page. A folder that is
a finished report's output folder is reopened instead (saved.py), without reading the logs again.
"""
from __future__ import annotations

import html
import ipaddress
import os
import re
import shutil
import traceback

from .. import details, resources, saved
from ..errors import UserError
from ..pipeline import input_files
from . import folders, jobs, multipart, runname, runs
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
<section id="report-details" aria-labelledby="rd-title"><h2 id="rd-title">Report details <span class="hint">(optional)</span></h2>
<label for="report_name">Report name</label>
<input id="report_name" type="text" name="report_name" value="{report_name}" maxlength="{name_max}" placeholder="e.g. DMZ sweep review, November" autocomplete="off">
<label for="report_description">Description</label>
<textarea id="report_description" name="report_description" maxlength="{description_max}" rows="3" placeholder="Scope, case number, who asked for it&hellip;">{report_description}</textarea>
<div class="hint">Shown at the top of the report and in the Explorer. The run is saved in a folder named after the report plus
the date and time (for example <code>DMZ-sweep-review_2026-11-19_10-19-14</code>); without a name, a random name plus the date
and time.</div></section>
<form method="post" action="/analyze-folder" data-busy="Starting…" data-busy-hint="{start_hint}">
<input type="hidden" name="csrf" value="{csrf}">
<label for="path">Folder on this computer</label>
<div class="pathrow"><input id="path" type="text" name="path" value="{path}" placeholder="{path_example}" autocomplete="off" spellcheck="false">
<button type="button" id="browse" class="secondary">Browse&hellip;</button></div>
<div id="pick-msg" class="hint error" role="status" aria-live="polite"></div>
<div id="kind-msg" class="hint" role="status" aria-live="polite"></div>
<div id="picker" hidden><div class="pk-head"><button type="button" id="pk-up" class="secondary" title="Parent folder">&uarr; Up</button>
<code id="pk-where"></code></div><ul id="pk-list"></ul>
<div class="pk-foot"><span id="pk-info" class="hint"></span><button type="button" id="pk-cancel" class="secondary">Cancel</button>
<button type="button" id="pk-use">Use this folder</button></div></div>
<div class="hint">The files are read where they are, including subfolders; nothing is copied or uploaded. Hidden files are
skipped. A <code>pentaiwatch.json</code>, <code>network_map.csv</code> or <code>known_scanners.csv</code> in the folder is used,
and the report names it. A finished report's output folder (with its <code>results.json</code>) is opened again instead.</div>
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
        mark=MARK, error=error_html(error),
        report_name=html.escape(app.last_report.get("name", "")), name_max=details.NAME_MAX,
        report_description=html.escape(app.last_report.get("description", "")),
        description_max=details.DESCRIPTION_MAX, csrf=html.escape(app.csrf), path=html.escape(app.last_path),
        path_example=html.escape(folders.path_example()), nets=html.escape(app.last_nets),
        start_hint=html.escape(START_HINT), upload_hint=html.escape(UPLOAD_HINT),
        max_upload=html.escape(resources.fmt_size(app.max_upload)),
        recent=runs.recent_html(app), busy=busy_overlay())
    config = {"csrf": app.csrf, "native": folders.NATIVE_PICKER and not app.access_token}
    req.send_page(200, page("PentAIWatch", body, [asset("busy.js"), asset("folder_picker.js"), asset("details.js"),
                                                  asset("folder_kind.js")], config))


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


def _report(fields: dict) -> dict:
    return details.clean(fields.get("report_name"), fields.get("report_description"))


def _start(req, run_id: str, files: list[str], nets: list[str] | None, source: str, report: dict):
    """Start the run in the background and open its page."""
    app = req.app
    root = app.run_root(run_id)
    try:
        app.jobs.start(run_id, root, files, nets, source, report=report)
    except UserError as exc:
        shutil.rmtree(root, ignore_errors=True)
        return show(req, str(exc))
    app.last_path = app.last_nets = ""          # the next analysis starts with an empty form
    app.last_report = {}
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
    # the report name is a field of the same upload, read after its files: the folder gets the
    # name once the upload is in
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
    app.last_nets, app.last_report = fields.get("internal_nets", ""), _report(fields)
    try:
        nets = _nets(app.last_nets)
    except UserError as exc:
        shutil.rmtree(root, ignore_errors=True)
        return show(req, str(exc))
    if not parts:
        shutil.rmtree(root, ignore_errors=True)
        return show(req, "Choose a folder of logs or at least one log file to upload.")
    if app.last_report["name"]:
        named = runname.new_run(app.data_dir, app.last_report["name"])
        os.rmdir(app.run_root(named))
        os.replace(root, app.run_root(named))
        parts = [(field, os.path.join(app.run_root(named), os.path.relpath(path, root))) for field, path in parts]
        run_id = named
    files = [path for _, path in parts]
    return _start(req, run_id, files, nets, f"Upload of {len(files):,} file{'' if len(files) == 1 else 's'}",
                  app.last_report)


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
    app.last_path, app.last_nets, app.last_report = raw, form.get("internal_nets", ""), _report(form)
    if not raw:
        return show(req, "Choose a folder first: click Browse… and pick one, or type its full path.")
    if not os.path.isdir(folder):
        return show(req, f"Folder not found: {raw}. Use the full path, for example {folders.path_example()}.")
    if saved.is_report_folder(folder):
        return _open_report(req, folder)
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
    run_id = runname.new_run(app.data_dir, app.last_report["name"])
    in_dir = os.path.join(app.run_root(run_id), "in")
    os.makedirs(in_dir, mode=0o700)
    with open(os.path.join(in_dir, "SOURCE.txt"), "w", encoding="utf-8") as fh:
        fh.write(f"Read in place from {folder}\n" + "\n".join(files) + "\n")
    return _start(req, run_id, files, nets, f"Folder {folder}", app.last_report)


def _open_report(req, folder: str):
    """Write a finished report's pages again from its output folder, without reading the logs.
    The new run gets the saved report's name; details typed on the page are not used."""
    app, root = req.app, None
    try:
        res, scene = saved.load_folder(folder)
        report = res.get("report") or {}
        run_id = runname.new_run(app.data_dir, str(report.get("name") or ""))
        root = app.run_root(run_id)
        os.makedirs(os.path.join(root, "in"), mode=0o700)
        with open(os.path.join(root, "in", "SOURCE.txt"), "w", encoding="utf-8") as fh:
            fh.write(f"Reopened from {folder}\n")
        saved.write(res, scene, os.path.join(root, "out"))
        jobs.write_status(root, {"state": "done", "started": jobs.now(), "finished": jobs.now(), "seconds": 0,
                                 "source": f"Reopened from {folder}", "reopened": True, "files": 0,
                                 "report": details.clean(report.get("name"), report.get("description")),
                                 "summary": jobs.summary(res)})
    except saved.SavedRunError as exc:
        if root:
            shutil.rmtree(root, ignore_errors=True)
        return show(req, str(exc))
    except Exception:
        traceback.print_exc()
        if root:
            shutil.rmtree(root, ignore_errors=True)
        return show(req, "The saved report could not be opened; the console that started the upload page has the details.")
    app.last_path, app.last_nets, app.last_report = "", "", {}
    req.redirect(f"/runs/{run_id}/")


def folder_kind(req):
    """POST /folder-kind: whether a folder is a finished report's output folder (the page then
    labels its button Open report)."""
    body = req.read_json()
    if body is None:
        return req.send_json(403, {"error": "Forbidden"})
    folder = folders.resolve(str(body.get("path") or ""))
    return req.send_json(200, {"report": bool(folder) and os.path.isdir(folder) and saved.is_report_folder(folder)})
