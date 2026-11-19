"""Pieces the upload server's pages share: the page shell, PentAIWatch's mark, the "working"
overlay, files from static/web/ and the policy each page is sent with.

A page inlines everything it uses (it loads nothing else), and its Content-Security-Policy names
each of its inline scripts by SHA-256, as the report and the Explorer do (csp.py): text that
reached a page any other way cannot run. The page's settings for its scripts (the CSRF token,
whether a folder dialog is available) travel in a JSON block, which is data and never runs.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import os
from collections.abc import Iterable

STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "web")

# PentAIWatch's mark: the diamond the Explorer draws for a flagged source, in level 1's colour.
MARK_SVG = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><path d="M32 3 61 32 32 61 3 32Z" '
            'fill="#d98845" stroke="#7a4512" stroke-width="2.5"/><path d="M32 17 47 32 32 47 17 32Z" '
            'fill="#f3c18f" opacity=".55"/></svg>')
MARK = "data:image/svg+xml;base64," + base64.b64encode(MARK_SVG.encode()).decode()


def asset(name: str) -> str:
    """A file from pentaiwatch/static/web, to inline into a page."""
    with open(os.path.join(STATIC, name), encoding="utf-8") as fh:
        return fh.read()


def policy(scripts: Iterable[str] = ()) -> str:
    """The Content-Security-Policy for a page whose inline scripts are ``scripts``. It may run those,
    talk to this server (the folder list, a run's progress) and post its forms here; nothing else."""
    hashes = " ".join("'sha256-" + base64.b64encode(hashlib.sha256(s.encode("utf-8")).digest()).decode() + "'"
                      for s in scripts)
    return ("default-src 'none'; " + (f"script-src {hashes}; " if hashes else "")
            + "style-src 'unsafe-inline'; img-src data:; connect-src 'self'; form-action 'self'; "
              "base-uri 'none'; frame-ancestors 'none'")


def config_block(values: dict) -> str:
    """Values a page's scripts read, as a JSON block that is safe inside HTML and never runs."""
    blob = json.dumps(values).replace("<", "\\u003c")
    return f'<script type="application/json" id="pw-page">{blob}</script>'


def page(title: str, body: str, scripts: Iterable[str] = (), config: dict | None = None) -> tuple[str, str]:
    """(HTML, policy) for a complete page in PentAIWatch's look, with ``scripts`` inlined at the end."""
    scripts = list(scripts)
    doc = ('<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
           '<meta name="viewport" content="width=device-width,initial-scale=1">'
           f'<title>{html.escape(title)}</title><link rel="icon" href="{MARK}">'
           f'<style>{asset("web.css")}</style></head>\n<body><main>\n{body}\n</main>'
           + (config_block(config) if config is not None else "")
           + "".join(f"<script>{s}</script>" for s in scripts) + "</body></html>\n")
    return doc, policy(scripts)


def error_html(message: str) -> str:
    return f'<p class="error" role="alert"><strong>{html.escape(message)}</strong></p>' if message else ""


BUSY = """<div id="busy" role="alertdialog" aria-modal="true" aria-labelledby="busy-title" aria-describedby="busy-hint"{hidden}>
<div class="busy-card"><div class="busy-stage"><img class="busy-logo" src="{mark}" alt=""></div>
<p class="busy-title" role="status"><span id="busy-title">{title}</span> <span class="busy-time" id="busy-time">0:00</span></p>
<p class="hint" id="busy-hint">{hint}</p>{extra}</div></div>"""


def busy_overlay(title: str = "Working…", hint: str = "", shown: bool = False, extra: str = "") -> str:
    """The overlay MAX shows while a long job runs: the mark turns and a timer counts."""
    return BUSY.format(hidden="" if shown else " hidden", mark=MARK, title=html.escape(title),
                       hint=html.escape(hint), extra=extra)
