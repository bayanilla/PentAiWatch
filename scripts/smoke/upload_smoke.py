#!/usr/bin/env python3
"""Browser check for the upload page (python -m pentaiwatch serve).

Starts the upload page on a free loopback port with a fresh runs folder, writes the tests' sample logs, and
in headless Chromium:

  * opens the upload page, light and dark, and fails on any page or console error;
  * opens the in-page folder list with Browse…, goes into the sample folder and uses it;
  * analyzes that folder: the run's page must show the progress overlay while it runs and then the result,
    with the sample agent flagged;
  * follows the agent's Timeline link: the Explorer must open on its Timeline and draw, inside the sandbox
    a run's files are sent in, where it must have no origin of its own, no cookies and no way to read
    the upload page;
  * uploads the same log as a file and checks the run finishes with the agent flagged.

Usage:
  python scripts/smoke/upload_smoke.py WORKDIR     screenshots go to WORKDIR/upload-shots/

It needs `pip install playwright` and a Chromium (`python -m playwright install chromium`).
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from pentaiwatch.web.server import make_handler  # noqa: E402
from tests import kit, sample  # noqa: E402

failures: list[str] = []


def check(ok: bool, what: str) -> None:
    print(("ok    " if ok else "FAIL  ") + what)
    if not ok:
        failures.append(what)


def poll(page, js: str, seconds: float = 60) -> bool:
    """Wait for ``js`` to be true in the page (page.evaluate, not wait_for_function: the pages'
    policy refuses the eval that wait_for_function needs)."""
    end = time.time() + seconds
    while time.time() < end:
        try:
            if page.evaluate(js):
                return True
        except Exception:
            pass                       # the page is navigating
        time.sleep(0.2)
    return False


def watch(page, errors: list[str]) -> None:
    page.on("console", lambda m: m.type == "error" and errors.append(m.text))
    page.on("pageerror", lambda e: errors.append(str(e)))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("workdir")
    args = ap.parse_args()
    work = Path(args.workdir).resolve()
    shutil.rmtree(work / "upload-runs", ignore_errors=True)
    logs, shots = work / "upload-logs", work / "upload-shots"
    for d in (logs, shots):
        d.mkdir(parents=True, exist_ok=True)
    kit.write_zeek_conn(str(logs / "conn.log"), sample.sessions())

    handler = make_handler(str(work / "upload-runs"))
    handler.log_message = lambda *a: None
    os.makedirs(handler.app.data_dir, mode=0o700, exist_ok=True)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/"

    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for scheme in ("light", "dark"):
            ctx = browser.new_context(viewport={"width": 1200, "height": 900}, color_scheme=scheme)
            page, errors = ctx.new_page(), []
            watch(page, errors)
            page.goto(url)
            check(page.title() == "PentAIWatch" and page.locator("#analyze-folder").is_visible(),
                  f"upload page opens ({scheme})")
            page.screenshot(path=str(shots / f"upload-{scheme}.png"), full_page=True)
            if scheme == "dark":
                check(not errors, f"no page errors ({scheme}): {errors}")
                ctx.close()
                continue

            # Browse…: the in-page folder list (headless Chromium is never on a Mac's dialog path)
            page.fill("#path", str(logs.parent))
            page.click("#browse")
            page.locator("#pk-list li", has_text="upload-logs").click()
            check(poll(page, f"document.getElementById('pk-where').textContent === {str(logs)!r}", 10),
                  "folder list goes into a folder")
            page.screenshot(path=str(shots / "picker.png"), full_page=True)
            page.click("#pk-use")
            check(page.input_value("#path") == str(logs), "Use this folder fills in the path")

            # Analyze the folder; the run page shows the overlay, then the result
            page.click("#analyze-folder")
            page.wait_for_url("**/runs/*/", timeout=30000)
            check(poll(page, "document.querySelector('h1') && /Results/.test(document.querySelector('h1').textContent)"),
                  "the folder's run finishes and shows its result")
            body = page.inner_text("main")
            check("1 source flagged" in body and sample.AGENT in body, "the sample agent is flagged")
            page.screenshot(path=str(shots / "results.png"), full_page=True)

            # The agent's Timeline, inside the sandbox
            with page.expect_popup() as pop:
                page.click("a:text('Timeline')")
            ex, ex_errors = pop.value, []
            watch(ex, ex_errors)
            check(poll(ex, "!!window.PWExplorer && PWExplorer.stats().sources > 0"), "the Explorer draws")
            check(poll(ex, f"!!window.PWTimeline && PWTimeline.isOpen() && "
                           f"decodeURIComponent(location.hash) === '#timeline={sample.AGENT}'", 15),
                  "it opens on the agent's Timeline")
            ex.wait_for_timeout(1500)
            ex.screenshot(path=str(shots / "explorer-timeline.png"))
            check(not ex_errors, f"no Explorer errors: {ex_errors}")      # before the probes, which the policy blocks
            check(ex.evaluate("window.origin") == "null", "a run's files have no origin of their own")
            check(ex.evaluate("(() => { try { document.cookie; return false } catch (e) { return true } })()"),
                  "and no cookies")
            check(ex.evaluate("fetch('/').then(() => false, () => true)"), "and cannot read the upload page")
            ex.close()

            # Upload the same log as a file
            page.goto(url)
            page.set_input_files("#files", str(logs / "conn.log"))
            page.click("#analyze-upload")
            page.wait_for_url("**/runs/*/", timeout=30000)
            check(poll(page, "document.querySelector('h1') && /Results/.test(document.querySelector('h1').textContent)"),
                  "the upload's run finishes")
            check("1 source flagged" in page.inner_text("main"), "and flags the sample agent")
            page.goto(url)
            check(page.locator("table tbody tr").count() == 2, "Recent reports lists both runs")
            page.screenshot(path=str(shots / "recent.png"), full_page=True)
            check(not errors, f"no page errors ({scheme}): {errors}")
            ctx.close()
        browser.close()
    srv.shutdown()
    print(f"Screenshots: {shots}")
    if failures:
        print(f"{len(failures)} check(s) failed.")
        return 1
    print("Upload page: all checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
