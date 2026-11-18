#!/usr/bin/env python3
"""Browser check for the Explorer page (explorer.html).

Opens each run's explorer.html in headless Chromium and walks what the page offers: the 3D overview, a
source, a host, the Flat view and back to 3D, then the report's link to a source. A page fails when

  * it throws or logs a console error at any step, or cannot unpack its data, or
  * 3D draws fewer bodies than the data has sources and hosts, or three.js would draw fewer than it
    holds (the more-than-1,024-bodies bug VulnScope MAX fixed in the renderer this page uses), or
  * a selected source does not get one dashed beam per subnet it swept and one solid beam per drawn
    host it kept coming back to, in 3D and in Flat alike, or
  * the report's "Show this source on the map" link does not open the map on that source, or
  * a run in which nothing swept does not say so.

What the page should draw is worked out here from the data packed inside it, not asked of the page.

Usage:
  python scripts/smoke/explorer_smoke.py --samples WORKDIR   write the tests' sample logs four ways into
                                                             WORKDIR, analyze them, then check the pages
  python scripts/smoke/explorer_smoke.py RUN [RUN ...]       check existing output folders (or explorer.html files)
  python scripts/smoke/explorer_smoke.py --samples WORKDIR --build-only
                                                             only write and analyze the samples, to open by hand

The check needs `pip install playwright` and a Chromium (`python -m playwright install chromium`); --build-only
needs neither. WebGL comes from Chromium's software renderer, so no GPU is needed; a page that cannot start 3D
fails rather than skipping it. Screenshots of every step go to <WORKDIR or the first RUN's parent>/smoke-shots/
for looking at by eye.
"""
from __future__ import annotations

import argparse
import random
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from pentaiwatch import explore  # noqa: E402
from tests import kit, sample  # noqa: E402

SETTLE_MS = 1500      # time for a step to settle and draw a few frames
NETWORK_MAP = "cidr,name,type\n10.10.1.0/24,DMZ,on-prem\n10.10.2.0/24,Servers,on-prem\n"
BIG_SCANNER = "198.51.100.200"


def big_sweep() -> list[dict]:
    """One more scanner that tries 1,500 hosts once each: more bodies than fit in the renderer's first
    buffer of 1,024, so the page has to grow it."""
    hosts = [f"10.20.{net}.{i}" for net in range(6) for i in range(1, 251)]
    return [kit.session(sample.T0 + 900 + i * 0.5, BIG_SCANNER, host, 445, "S0") for i, host in enumerate(hosts)]


def build_samples(work: Path) -> list[Path]:
    """The tests' three-source sample as Zeek only and as both logs, the same with a 1,500-host sweep added,
    and a run in which nothing swept. Each is analyzed with the command line, as an analyst would."""
    cases = {
        "zeek_only": (sample.sessions(), False),
        "both_logs": (sample.sessions(), True),
        "many_hosts": (sorted(sample.sessions() + big_sweep(), key=lambda s: s["ts"]), False),
        "nothing_swept": (sample.client(random.Random(3)), False),
    }
    runs = []
    for name, (sessions, firewall) in cases.items():
        src, out = work / "input" / name, work / name
        if not (out / explore.FILENAME).exists():
            src.mkdir(parents=True, exist_ok=True)
            kit.write_zeek_conn(str(src / "conn.log"), sessions)
            if firewall:
                kit.write_paloalto(str(src / "traffic.csv"), sessions)
            (src / "network_map.csv").write_text(NETWORK_MAP, encoding="utf-8")
            subprocess.run([sys.executable, "-m", "pentaiwatch", "analyze", str(src), "-o", str(out)],
                           check=True, cwd=ROOT, stdout=subprocess.DEVNULL)
        runs.append(out)
    return runs


def explorer_file(run: Path) -> Path:
    page = run if run.suffix == ".html" else run / explore.FILENAME
    if not page.is_file():
        raise SystemExit(f"no {explore.FILENAME} in {run}")
    return page


def expected(data: dict) -> dict:
    """What the page should draw, from the data inside it: per source, a sweep beam for each subnet it
    swept that has a ring, and a solid beam for each drawn host it kept coming back to."""
    drawn = {h["ip"] for h in data["hosts"]}
    beams = {}
    for s in data["sources"]:
        beams[s["ip"]] = {"sweep": sum(1 for n in s["nets"] if data["subnets"][n[0]]["drawn"]),
                          "narrowed": len({v[0] for v in s.get("services", [])} & drawn)}
    return {"sources": len(data["sources"]), "hosts": len(data["hosts"]),
            "subnets": sum(1 for n in data["subnets"] if n["drawn"]), "beams": beams,
            "narrowed": sum(b["narrowed"] for b in beams.values())}


def check(page_path: Path, browser, shots: Path) -> list[str]:
    """Every problem found in one page. A step the page cannot take (it threw) is a problem too."""
    problems: list[str] = []
    try:
        walk(page_path, browser, shots, problems)
    except Exception as exc:                       # a script error inside the page, or a timeout
        problems.append(f"the walk stopped: {str(exc).splitlines()[0]}")
    return problems


def walk(page_path: Path, browser, shots: Path, problems: list[str]) -> None:
    label = page_path.parent.name
    want = expected(explore.read_data(page_path.read_text(encoding="utf-8")))
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(f"uncaught: {e}"))
    page.on("console", lambda m: errors.append(f"console.error: {m.text}") if m.type == "error" else None)

    def step(name: str, wait: int = SETTLE_MS) -> dict:
        page.wait_for_timeout(wait)
        page.screenshot(path=str(shots / f"{label}__{name}.png"))
        while errors:
            problems.append(f"{name}: {errors.pop(0)}")
        return page.evaluate("window.PWExplorer ? PWExplorer.stats() : null") or {}

    def bodies(name: str, s: dict) -> None:
        if not s.get("is3d"):
            problems.append(f"{name}: the page is not in 3D ({s})")
        elif s["bodies"] != want["sources"] + want["hosts"] or s["bodiesDrawable"] < s["bodies"]:
            problems.append(f"{name}: {want['sources']} sources and {want['hosts']} hosts in the data, "
                            f"{s['bodies']} bodies added, {s['bodiesDrawable']} drawable")

    def selected(name: str, s: dict, ip: str, beams: dict | None = None) -> None:
        if s.get("selected") != ip:
            problems.append(f"{name}: {ip} was picked but {s.get('selected')} is selected")
        if page.evaluate("document.getElementById('panel').hidden") or page.inner_text("#panel h2") != ip:
            problems.append(f"{name}: the panel does not show {ip}")
        got = s.get("beams", {})
        if beams and (got.get("selSweep"), got.get("selNarrowed")) != (beams["sweep"], beams["narrowed"]):
            problems.append(f"{name}: {ip} should have {beams['sweep']} sweep and {beams['narrowed']} solid beams, "
                            f"drew {got.get('selSweep')} and {got.get('selNarrowed')}")

    page.goto(page_path.resolve().as_uri())
    # the data is unpacked in the background (vf_data.js); the map starts once it is there
    page.wait_for_function("document.documentElement.dataset.vf !== 'loading'", timeout=120_000)
    if page.evaluate("document.documentElement.dataset.vf") == "failed":
        problems.append(f"page could not unpack its data: {page.evaluate('window.VF_ERROR')}")
        page.close()
        return
    s = step("3d-overview", 2500)
    if not s:
        problems.append("page did not start (window.PWExplorer missing)")
        page.close()
        return
    if (s["sources"], s["hosts"], s["subnets"]) != (want["sources"], want["hosts"], want["subnets"]):
        problems.append(f"3d-overview: the page holds {s['sources']} sources, {s['hosts']} hosts, {s['subnets']} subnets; "
                        f"the data has {want['sources']}, {want['hosts']}, {want['subnets']}")
    if not want["sources"]:
        if page.evaluate("document.getElementById('empty').hidden") or "Nothing to draw" not in page.inner_text("#empty"):
            problems.append("nothing swept, and the page does not say so")
        page.close()
        return
    if not page.evaluate("PWExplorer.can3d"):
        problems.append("3D unavailable in this browser (WebGL missing), so 3D was not checked")
    else:
        bodies("3d-overview", s)
        if s.get("beams", {}).get("narrowed") != want["narrowed"]:
            problems.append(f"3d-overview: {want['narrowed']} solid beams expected, {s.get('beams', {}).get('narrowed')} drawn")

    first = next(iter(want["beams"]))
    page.evaluate("ip => PWExplorer.select(ip)", first)
    selected("3d-source", step("3d-source"), first, want["beams"][first])
    host = page.evaluate("window.VF_DATA.hosts[0].ip")
    page.evaluate("ip => PWExplorer.select(ip)", host)
    selected("3d-host", step("3d-host"), host)
    page.keyboard.press("Escape")
    s = step("3d-escape", 600)
    if s.get("selected") is not None:
        problems.append(f"3d-escape: Esc left {s.get('selected')} selected")

    page.evaluate("PWExplorer.set3d(false)")
    s = step("flat")
    if s.get("is3d"):
        problems.append("flat: the page stayed in 3D")
    page.evaluate("ip => PWExplorer.select(ip)", first)
    selected("flat-source", step("flat-source"), first, want["beams"][first])
    page.evaluate("PWExplorer.overview()")

    if page.evaluate("PWExplorer.can3d"):
        before = s.get("frames", 0)
        page.evaluate("PWExplorer.set3d(true)")
        s = step("back-to-3d")
        bodies("back-to-3d", s)
        if s.get("frames", 0) <= before:
            problems.append("back-to-3d: the page stopped drawing")
    page.close()

    # the report's link to a flagged source opens the map on it
    report = page_path.parent / "report.html"
    if report.is_file():
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.on("pageerror", lambda e: errors.append(f"uncaught: {e}"))
        page.goto(report.resolve().as_uri())
        link = page.query_selector('a[href^="explorer.html#source="]')
        if link:
            ip = link.get_attribute("href").split("=", 1)[1]
            link.click()
            page.wait_for_function("!!window.PWExplorer", timeout=120_000)
            s = step("from-report", 2500)
            if s.get("selected") != ip:
                problems.append(f"from-report: the report's link to {ip} opened the map with {s.get('selected')} selected")
        elif any(v["narrowed"] for v in want["beams"].values()):
            problems.append("from-report: the report has no link to a flagged source on the map")
        page.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("runs", nargs="*", type=Path, help="output folders or explorer.html files")
    ap.add_argument("--samples", type=Path, metavar="WORKDIR", help="write and analyze the sample logs in WORKDIR first")
    ap.add_argument("--build-only", action="store_true", help="with --samples: stop once the samples are analyzed")
    args = ap.parse_args()
    runs = list(args.runs)
    if args.samples:
        runs += build_samples(args.samples)
    if not runs:
        ap.error("give output folders or --samples WORKDIR")
    pages = [explorer_file(r) for r in runs]
    if args.build_only:
        print("\n".join(str(p) for p in pages))
        return 0
    shots = (args.samples or pages[0].parent.parent) / "smoke-shots"
    shots.mkdir(parents=True, exist_ok=True)

    from playwright.sync_api import sync_playwright
    failed = 0
    with sync_playwright() as pw:
        # newer Chromium only gives a page software WebGL when asked to
        browser = pw.chromium.launch(args=["--enable-unsafe-swiftshader"])
        for p in pages:
            problems = check(p, browser, shots)
            print(("FAIL " if problems else "ok   ") + str(p))
            for line in problems:
                print("     - " + line)
            failed += bool(problems)
        browser.close()
    print(f"\n{len(pages) - failed} of {len(pages)} Explorer pages passed; screenshots in {shots}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
