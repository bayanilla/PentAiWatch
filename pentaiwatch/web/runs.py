"""A run of the upload page: its page (the progress overlay while it runs, then its results), its
state for that overlay, its files (read only), and the list of recent runs on the upload page.

A run's files are sent in a sandbox (``RUN_FILES_POLICY``): the report and the Explorer run in an
opaque origin, so even a page built from crafted logs could not read this server's pages or post
to it (a post from an opaque origin carries "Origin: null", which handler.py refuses). Their own
policy (csp.py) still applies on top and names the scripts that may run: the header adds nothing
to it, it only takes away.
"""
from __future__ import annotations

import html
import os
import re
from datetime import datetime, timezone
from urllib.parse import quote

from .jobs import read_status
from .pages import MARK, asset, busy_overlay, page
from .runname import RUN_ID

RUN_FILES_POLICY = ("sandbox allow-scripts allow-popups allow-popups-to-escape-sandbox allow-downloads; "
                    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; "
                    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
RECENT = 10                        # runs listed on the upload page
RUNNING_HINT = ("Large folders can take several minutes. You can close this tab: the analysis carries on, and "
                "the upload page lists it under Recent reports.")
_RUN = re.compile(RUN_ID)
STATE_TEXT = {"running": "Running", "done": "Done", "failed": "Failed", "stopped": "Stopped"}


def read_run(app, run_id: str) -> tuple[dict | None, bool]:
    """The run's STATUS.json and whether this server was running it just before the file was read.

    The order matters: a job writes its final status before it leaves the live list, so a run that
    was live before the read and has since finished is read as finished, never as cut short."""
    live = app.jobs.is_live(run_id)
    return read_status(app.run_root(run_id)), live


def state(status: dict, live: bool) -> str:
    """running, done, failed, or stopped: a run that says "running" but that this server was not
    running (``live``, from read_run) was cut short when an earlier server stopped."""
    st = status.get("state")
    if st == "running" and not live:
        return "stopped"
    return st if st in STATE_TEXT else "failed"


def _local(iso) -> str:
    """A time from STATUS.json (UTC) in this computer's time zone."""
    try:
        when = datetime.fromisoformat(str(iso).rstrip("Z")).replace(tzinfo=timezone.utc).astimezone()
    except ValueError:
        return ""
    return when.strftime("%Y-%m-%d %H:%M")


def _took(seconds) -> str:
    try:
        s = int(round(float(seconds)))
    except (TypeError, ValueError):
        return ""
    return f"{s // 3600} h {s // 60 % 60} min" if s >= 3600 else f"{s // 60} min {s % 60} s" if s >= 60 else f"{s} s"


def _name(status: dict) -> str:
    report = status.get("report") if isinstance(status.get("report"), dict) else {}
    return str(report.get("name") or "")


def _about(status: dict) -> str:
    """The report name and description, as the top of a run's page."""
    report = status.get("report") if isinstance(status.get("report"), dict) else {}
    paras = [p for p in str(report.get("description") or "").split("\n\n") if p.strip()]
    return "".join(f'<p class="about">{html.escape(p).replace(chr(10), "<br>")}</p>' for p in paras)


def _plural(n: int, word: str) -> str:
    return f"{n:,} {word}{'' if n == 1 else 's'}"


# -- views ------------------------------------------------------------------------------------
def status_view(req, run_id: str):
    """GET /runs/<id>/status: {state, elapsed} for the progress overlay."""
    app = req.app
    status, live = read_run(app, run_id)
    if status is None:
        return req.send_json(404, {"error": "No such run."})
    elapsed = app.jobs.elapsed(run_id)
    return req.send_json(200, {"state": state(status, live),
                               "elapsed": round(elapsed, 1) if elapsed is not None else status.get("seconds")})


def slash(req, run_id: str):
    req.redirect(f"/runs/{run_id}/")


def get(req, run_id: str, rest: str):
    """GET /runs/<id>/<rest>: the run's page, or one of its files."""
    app = req.app
    if not rest:
        return index(req, run_id)
    out = app.run_out(run_id)
    target = os.path.realpath(os.path.join(out, rest))
    if not (target.startswith(out + os.sep) and os.path.isfile(target)):
        return req.send_text(404, "Not found")
    req.send_file(target, RUN_FILES_POLICY)


def index(req, run_id: str):
    app = req.app
    status, live = read_run(app, run_id)
    if status is None:
        return req.send_text(404, "Not found")
    st = state(status, live)
    source = html.escape(str(status.get("source") or ""))
    started = _local(status.get("started"))
    name = _name(status)
    heading = f": {html.escape(name)}" if name else ""
    tab = f"{name} · " if name else ""
    if st == "running":
        elapsed = app.jobs.elapsed(run_id) or 0.0
        extra = ('<p class="hint"><a href="/">Back to the upload page</a></p>'
                 '<p class="hint error" id="busy-note" role="status" aria-live="polite"></p>')
        body = (f"<h1>Analyzing{heading}</h1><p class=\"hint\">{source} · started {started}</p>"
                + busy_overlay("Analyzing…", RUNNING_HINT, shown=True, extra=extra))
        return req.send_page(200, page(f"{tab}Analyzing · PentAIWatch", body, [asset("run.js")],
                                       {"status": f"/runs/{run_id}/status", "elapsed": round(elapsed, 1)}))
    where = (f'<p class="hint">{source} · started {started}'
             + (f" · took {_took(status.get('seconds'))}" if status.get("seconds") is not None
                and not status.get("reopened") else "")
             + f' · saved as <code>{html.escape(run_id)}</code></p>' + _about(status))
    if st == "stopped":
        body = (f"<h1>The analysis stopped{heading}</h1>" + where
                + "<p>It was still running when the upload page's server stopped, so it has no results. "
                  "Start it again from the upload page.</p><p><a href=\"/\">Back to the upload page</a></p>")
        return req.send_page(200, page(f"{tab}Stopped · PentAIWatch", body))
    if st == "failed":
        body = (f"<h1>The analysis did not finish{heading}</h1>" + where
                + f'<p class="error" role="alert"><strong>{html.escape(str(status.get("message") or ""))}</strong></p>'
                  "<p><a href=\"/\">Back to the upload page</a></p>")
        return req.send_page(200, page(f"{tab}Failed · PentAIWatch", body))
    return req.send_page(200, page(f"{tab}Results · PentAIWatch", _done(app, run_id, status, where, heading)))


def _done(app, run_id: str, status: dict, where: str, heading: str) -> str:
    summary = status.get("summary") if isinstance(status.get("summary"), dict) else {}
    flagged = [f for f in summary.get("flagged") or [] if isinstance(f, dict)]
    out = app.run_out(run_id)
    have = lambda name: os.path.isfile(os.path.join(out, name))
    reached = {str(f.get("source")) for f in flagged if f.get("tag") == "Reached attacker"}
    sources = {str(f.get("source")) for f in flagged if f.get("tag") != "Reached attacker"}
    lines = [f'<h1><img class="mark" src="{MARK}" alt="">Results{heading}</h1>', where,
             f"<p><strong>{_plural(int(summary.get('sessions') or 0), 'session')} read; "
             f"{_plural(len(sources), 'source')} flagged"
             + (f"; {_plural(len(reached), 'internal host')} reached attacker addresses" if reached else "")
             + ".</strong></p>"]
    if flagged:
        items = []
        for f in flagged:
            ip = str(f.get("source") or "")
            level = f.get("level")
            tag = (str(f.get("tag") or "Published address") if level is None
                   else "Tier 0" if level == 0 else f"Level {level}")
            link = quote(ip, safe=":.")
            extras = ([] if level is None else
                      [f'<a href="explorer.html#source={link}" target="_blank" rel="noopener">on the map</a>'])
            if f.get("known") and level is not None:
                extras.append("published attacker address")
            if f.get("parallel"):
                extras.append("several attack paths at once")
            if f.get("timeline"):
                extras.append(f'<a href="explorer.html#timeline={link}" target="_blank" rel="noopener">Timeline</a>')
            items.append(f'<li><code>{html.escape(ip)}</code> <span class="level{" t0" if level == 0 else ""}">'
                         f"{tag}</span>: {html.escape(str(f.get('label') or ''))}, "
                         + ("internal host" if f.get("tag") == "Reached attacker"
                            else f"{_plural(int(f.get('hosts') or 0), 'host')} hit")
                         + (f" · {' · '.join(extras)}" if extras else "") + "</li>")
        lines.append('<ul class="flagged">' + "".join(items) + "</ul>")
    opens = [f'<a href="{n}" target="_blank" rel="noopener">{t}</a>'
             for t, n in (("Open the report", "report.html"), ("Open the Explorer", "explorer.html")) if have(n)]
    if opens:
        lines.append('<p class="open">' + " · ".join(opens) + "</p>")
    files = [f'<li><a href="{n}" target="_blank" rel="noopener">{t}</a></li>'
             for t, n in (("Report (Markdown)", "report.md"), ("Full results (JSON)", "results.json")) if have(n)]
    if files:
        lines.append("<ul>" + "".join(files) + "</ul>")
    warnings = int(summary.get("warnings") or 0)
    if warnings:
        lines.append(f"<p>The report lists {_plural(warnings, 'warning')} about the input or the settings; "
                     "read them before relying on the result.</p>")
    lines.append(f'<p class="hint">The run\'s files are in <code>{html.escape(app.run_root(run_id))}</code>.</p>'
                 '<p><a href="/">New analysis</a></p>')
    return "\n".join(lines)


# -- the upload page's list -----------------------------------------------------------------
def recent(app, limit: int = RECENT) -> list[tuple[str, dict, bool]]:
    """The newest runs in the runs folder, as (run id, status, live) from read_run, newest first."""
    try:
        names = os.listdir(app.data_dir)
    except OSError:
        return []
    rows = []
    for name in names:
        if not _RUN.fullmatch(name):
            continue
        status, live = read_run(app, name)
        if status is not None:
            rows.append((str(status.get("started") or ""), name, status, live))
    rows.sort(key=lambda row: row[:2], reverse=True)
    return [(name, status, live) for _, name, status, live in rows[:limit]]


def recent_html(app) -> str:
    rows = recent(app)
    if not rows:
        return ""
    body = []
    for run_id, status, live in rows:
        st = state(status, live)
        summary = status.get("summary") if isinstance(status.get("summary"), dict) else {}
        flagged = (len({str(f.get("source")) for f in summary.get("flagged") or [] if isinstance(f, dict)})
                   if st == "done" else None)
        body.append(f'<tr><td class="when"><a href="/runs/{quote(run_id)}/">{_local(status.get("started")) or html.escape(run_id)}</a></td>'
                    f"<td>{f'<strong>{html.escape(_name(status))}</strong><br>' if _name(status) else ''}"
                    f"{html.escape(str(status.get('source') or ''))}</td>"
                    f'<td class="state-{st}">{STATE_TEXT[st]}</td>'
                    f"<td>{'' if flagged is None else (_plural(flagged, 'source') if flagged else 'None')}</td></tr>")
    return ("<h2>Recent reports</h2><table><thead><tr><th>Started</th><th>From</th><th>Status</th><th>Flagged</th>"
            "</tr></thead><tbody>" + "".join(body) + "</tbody></table>"
            f'<p class="hint">Runs are kept in <code>{html.escape(os.path.abspath(app.data_dir))}</code>, one folder each.</p>')
