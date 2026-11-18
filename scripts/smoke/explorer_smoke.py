#!/usr/bin/env python3
"""Browser check for the Explorer page (explorer.html).

Opens each run's explorer.html in headless Chromium and walks what the page offers: the 3D overview, every
source, a host, the Timeline of the sources that have one, the Flat view and back to 3D, then the report's
links to a source. A page fails when

  * it throws or logs a console error at any step, or cannot unpack its data, or
  * 3D draws fewer bodies than the data has sources and hosts, or three.js would draw fewer than it
    holds (the more-than-1,024-bodies bug VulnScope MAX fixed in the renderer this page uses), or
  * a selected source does not get one dashed beam per subnet it swept and one solid beam per drawn
    host it kept coming back to, in 3D and in Flat alike, or
  * a source's panel does not give its tier or level, or the reason it is not flagged, or
  * a source that narrowed has no Timeline, or its Timeline does not draw, window by window, the
    sessions, bursts and pauses the data holds, or pointing at a burst, zooming to it, replaying and
    leaving do not work, or
  * the report's "Show this source on the map" link does not open the map on that source, or its
    Timeline link does not open that source's Timeline, or
  * a run in which nothing swept does not say so.

What the page should draw is worked out here from the data packed inside it, not asked of the page.

Usage:
  python scripts/smoke/explorer_smoke.py --samples WORKDIR   write the tests' sample logs five ways into
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
    the same with a source that sweeps and narrows at another pace than an agent's (drawn, not flagged), and
    a run in which nothing swept. Each is analyzed with the command line, as an analyst would."""
    cases = {
        "zeek_only": (sample.sessions(), False),
        "both_logs": (sample.sessions(), True),
        "many_hosts": (sorted(sample.sessions() + big_sweep(), key=lambda s: s["ts"]), False),
        "other_pace": (sorted(sample.sessions() + sample.other_pace(), key=lambda s: s["ts"]), False),
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
    swept that has a ring, and a solid beam for each drawn host it kept coming back to (flagged sources
    only: a source that is not flagged has no solid beams). And what each source's panel should say."""
    drawn = {h["ip"] for h in data["hosts"]}
    beams, says = {}, {}
    for s in data["sources"]:
        beams[s["ip"]] = {"sweep": sum(1 for n in s["nets"] if data["subnets"][n[0]]["drawn"]),
                          "narrowed": len({v[0] for v in s.get("services", [])} & drawn)}
        if s["flagged"]:
            verdict = f"Level {s['level']}" if s["level"] else "Tier 0"
            body = ["Timing", "Not evaluated" if s["timing"]["status"] != "agentic" else "Typical pause"]
        else:
            # the reason is checked by words only its paragraph has (the verdict line repeats the label)
            verdict = "Not flagged"
            body = ["Why it is not flagged", "The timing signal asks for" if s["narrowed"] else "looks like plain scanning"]
        says[s["ip"]] = {"verdict": [verdict, s["label"]], "body": body}
    return {"sources": len(data["sources"]), "hosts": len(data["hosts"]),
            "subnets": sum(1 for n in data["subnets"] if n["drawn"]), "beams": beams, "says": says,
            "narrowed": sum(b["narrowed"] for b in beams.values()),
            # every drawn source that narrowed has a Timeline (the first few, when there are many)
            "timelines": [s["ip"] for s in data["sources"] if s["narrowed"]][:explore.MAX_TIMELINES]}


# -- the Timeline (timeline3d.js) ---------------------------------------------------------------
TL_LEN, TL_PAD = 900.0, 27.0                             # the tunnel's length and the margin at each end
TL_WINDOWS = (43_200_000, 1_800_000, 300_000, 60_000)    # window lengths on offer in ms, with the scoring window
TL_ZOOM = 300_000                                        # a click on a burst goes to the longest window not over this


def tl_windows(t: dict, data: dict) -> list[float]:
    """The window lengths a source's Timeline should offer: all of it, then the shorter ones that fit."""
    span = max(1000.0, t["seconds"] * 1000)
    offered = sorted({*TL_WINDOWS, int(data.get("window_hours", 2) * 3_600_000)}, reverse=True)
    return [span] + [w for w in offered if w < span * 0.75]


def tl_window(t: dict, data: dict, w0: float, win: float) -> dict:
    """What the window [w0, w0 + win) of a source's Timeline holds, from the data: its sessions, in the
    three groups they are drawn in (sweep attempts not answered, later sessions, sweep attempts
    answered), its bursts, and what is drawn for them: a bar per burst, a thin line across each pause
    that is in the band (the one running in from before the window too), and a lit stretch of track
    for each run of scoring windows in which the timing signal fired."""
    span = max(1000.0, t["seconds"] * 1000)
    at_end = w0 + win >= span - 1e-6
    lo, hi = -TL_LEN / 2, TL_LEN / 2

    def x(ms: float) -> float:
        return lo + TL_PAD + (ms - w0) / win * (TL_LEN - 2 * TL_PAD)

    def clip(v: float) -> float:
        return max(lo, min(hi, v))

    def pause_line(i: int) -> bool:
        b = t["bursts"][i]
        if b[4] < 1:
            return False
        x1, x2 = x(b[1]), x(b[1] + b[3] * 1000)
        return x2 >= lo and x1 <= hi and clip(x2) > clip(x1)

    kinds = [k & 7 for ms, _, k in t["sessions"] if ms >= w0 and (at_end or ms < w0 + win)]
    ids = [i for i, b in enumerate(t["bursts"]) if b[1] >= w0 and (at_end or b[0] < w0 + win)]
    before = (ids[0] if ids else sum(1 for b in t["bursts"] if b[0] < w0)) - 1
    scoring, runs = data.get("window_hours", 2) * 3_600_000, []
    for start, *_ in t["fired"]:
        if runs and start <= runs[-1][1]:
            runs[-1][1] = max(runs[-1][1], start + scoring)
        else:
            runs.append([start, start + scoring])
    return {"sessions": len(kinds), "bursts": len(ids), "paced": sum(1 for i in ids if t["bursts"][i][4] == 2),
            "bars": len(ids) + sum(1 for i in ids if pause_line(i)) + (1 if before >= 0 and pause_line(before) else 0),
            "groups": [sum(1 for k in kinds if k < 3 and k != 1), sum(1 for k in kinds if k >= 3),
                       sum(1 for k in kinds if k == 1)],
            "rails": sum(1 for a, b in runs if clip(x(min(b, span))) - clip(x(max(a, 0))) >= 0.5)}


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
    data = explore.read_data(page_path.read_text(encoding="utf-8"))
    want = expected(data)
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
        says = want["says"].get(ip)
        if says:                                   # a source: its tier or level, and why
            verdict, body = page.inner_text("#panel .verdict"), page.inner_text("#panel")
            for text in says["verdict"]:
                if text not in verdict:
                    problems.append(f"{name}: the panel of {ip} should say {text!r}, says {verdict!r}")
            for text in says["body"]:
                if text not in body:
                    problems.append(f"{name}: the panel of {ip} does not say {text!r}")
            offered = page.query_selector("#panel [data-timeline]") is not None
            if offered != (ip in want["timelines"] and page.evaluate("PWExplorer.can3d")):
                problems.append(f"{name}: the panel of {ip} {'offers' if offered else 'does not offer'} a Timeline")

    def tstep(name: str, wait: int = 700) -> dict:
        page.wait_for_timeout(wait)
        page.screenshot(path=str(shots / f"{label}__{name}.png"))
        while errors:
            problems.append(f"{name}: {errors.pop(0)}")
        return page.evaluate("window.PWTimeline ? PWTimeline.stats() : null") or {}

    def window_ok(name: str, s: dict, t: dict, w0: float, win: float) -> None:
        """The Timeline shows the window asked for, and draws what the data holds for it."""
        if not s.get("open"):
            problems.append(f"{name}: the Timeline is not open")
            return
        if abs(s["window"][0] - w0) > 1 or abs(s["window"][1] - win) > 1:
            problems.append(f"{name}: the window should start at {w0:.0f} ms and be {win:.0f} ms long, is {s['window']}")
            return
        held = tl_window(t, data, w0, win)
        got = {"sessions": s["inWindow"], "bursts": s["bursts"], "paced": s["paced"], "bars": s["bars"],
               "groups": s["groups"], "rails": s["rails"]}
        if got != held:
            problems.append(f"{name}: the window holds {held}, the page has {got}")
        if s["drawn"] != held["sessions"] or s["misplaced"]:
            problems.append(f"{name}: {held['sessions']} sessions to draw, {s['drawn']} drawn, {s['misplaced']} not at a place")
        if not s["playing"] and (s["shown"] != s["drawn"] or s["barsShown"] != s["bars"]):
            problems.append(f"{name}: not replaying, yet {s['shown']} of {s['drawn']} sessions and "
                            f"{s['barsShown']} of {s['bars']} bars are shown")

    def timeline(ip: str) -> None:
        """Open one source's Timeline from its panel and walk it: all of it, the shortest window, pointing
        at a burst and zooming to it, a replay, the other sources from its list, then back to the map."""
        t, name = data["timelines"][ip], "timeline"
        src = next(x for x in data["sources"] if x["ip"] == ip)
        span, wins = max(1000.0, t["seconds"] * 1000), tl_windows(t, data)
        page.evaluate("ip => PWExplorer.select(ip)", ip)
        page.wait_for_timeout(400)
        page.click("#panel [data-timeline]")
        s = tstep(name, 1500)
        if not s.get("open") or s.get("source") != ip:
            problems.append(f"{name}: the panel's button should open the Timeline of {ip}, got {s.get('source')}")
            return
        if [round(w) for w in s["windows"]] != [round(w) for w in wins]:
            problems.append(f"{name}: windows on offer should be {wins}, are {s['windows']}")
        if (s["lanes"], s["hosts"], s["sessions"]) != (len(t["lanes"]), len(t["hosts"]), len(t["sessions"])):
            problems.append(f"{name}: the data has {len(t['lanes'])} lanes, {len(t['hosts'])} hosts and "
                            f"{len(t['sessions'])} sessions; the page has {s['lanes']}, {s['hosts']}, {s['sessions']}")
        window_ok(name, s, t, 0, span)
        says(name, ip, src, t)
        if page.get_attribute("#tl-spin", "aria-pressed") == "true":      # hold the picture still to point at it
            page.click("#tl-spin")
        if len(wins) > 1 and t["bursts"]:
            i = next((k for k, b in enumerate(t["bursts"]) if b[4] == 2), 0)     # a burst of the signal's, if any
            burst, win = t["bursts"][i], wins[-1]
            start = max(0.0, min(span - win, burst[0] - win / 4))
            page.evaluate("([i, ms]) => { PWTimeline.length(i); PWTimeline.start(ms); }", [len(wins) - 1, burst[0] - win / 4])
            window_ok(name + "-short", tstep(name + "-short"), t, start, win)
            at = page.evaluate("i => PWTimeline.where(i)", i)
            if not at:
                problems.append(f"{name}-short: burst {i} is in the window and has no bar")
            else:
                page.mouse.move(at[0], at[1] + 3)                  # near the bar is enough: it is thin
                page.wait_for_timeout(200)
                tip = page.inner_text("#tl-tip") if page.is_visible("#tl-tip") else ""
                tstep(name + "-tip", 100)
                if f"Burst of {burst[2]:,} session" not in tip:
                    problems.append(f"{name}-tip: pointing at burst {i} should say 'Burst of {burst[2]:,} session', says {tip!r}")
                zoom = next((k for k, w in enumerate(wins) if w <= TL_ZOOM), 0)
                page.mouse.click(at[0], at[1] + 3)
                s = tstep(name + "-zoom")
                if zoom and (abs(s["window"][1] - wins[zoom]) > 1 or not s["window"][0] <= burst[0] <= sum(s["window"])):
                    problems.append(f"{name}-zoom: a click on burst {i} should show the {wins[zoom]:.0f} ms around it, "
                                    f"shows {s['window']}")
                elif zoom:
                    window_ok(name + "-zoom", s, t, s["window"][0], wins[zoom])
        page.evaluate("PWTimeline.length(0)")
        page.keyboard.press("Space")                               # replay: sessions appear in the order they started
        page.wait_for_timeout(1200)
        s = tstep(name + "-replay", 0)
        if not s.get("playing") or not 0 < s["shown"] < s["drawn"]:
            problems.append(f"{name}-replay: a second into a replay {s.get('shown')} of {s.get('drawn')} sessions are "
                            f"shown (replaying: {s.get('playing')})")
        page.keyboard.press("Space")
        window_ok(name + "-replay-stopped", tstep(name + "-replay-stopped", 300), t, 0, span)
        for n, other in enumerate([o for o in want["timelines"] if o != ip][:3]):      # the other sources, from the list
            page.select_option("#tl-pick", other)
            s, t2 = tstep(f"{name}-other-{n + 1}"), data["timelines"][other]
            if s.get("source") != other:
                problems.append(f"{name}-other-{n + 1}: {other} was picked from the list, {s.get('source')} is shown")
                continue
            window_ok(f"{name}-other-{n + 1}", s, t2, 0, max(1000.0, t2["seconds"] * 1000))
            says(f"{name}-other-{n + 1}", other, next(x for x in data["sources"] if x["ip"] == other), t2)
        frames = page.evaluate("PWExplorer.stats().frames")
        page.keyboard.press("Escape")
        page.wait_for_timeout(500)
        if page.evaluate("PWTimeline.isOpen()") or page.is_visible("#timeline-view"):
            problems.append(f"{name}: Esc did not go back to the map")
        elif page.evaluate("PWExplorer.stats().frames") <= frames:
            problems.append(f"{name}: back on the map, it is not drawing again")
        page.evaluate("PWExplorer.overview()")
        page.click("#btn-timeline")                                # the view switcher opens it too; 2 goes to Flat
        s = tstep(name + "-from-switcher")
        if not s.get("open"):
            problems.append(f"{name}-from-switcher: the Timeline button did not open the Timeline")
        page.keyboard.press("2")
        page.wait_for_timeout(300)
        if page.evaluate("PWTimeline.isOpen()") or page.evaluate("PWExplorer.stats().is3d"):
            problems.append(f"{name}-from-switcher: the 2 key should close the Timeline and show the Flat view")
        page.evaluate("PWExplorer.set3d(true)")

    def says(name: str, ip: str, src: dict, t: dict) -> None:
        """The Timeline's heading and side panel name the source, its verdict and its counts."""
        verdict = "Not flagged" if not src["flagged"] else f"Level {src['level']}" if src["level"] else "Tier 0"
        head, side = page.inner_text("#tl-sub"), page.inner_text("#tl-src .verdict")
        rows = dict(page.eval_on_selector_all("#tl-src .kv", "els => els.map(e => [e.children[0].textContent, e.children[1].textContent])"))
        for text, where in ((ip, head), (verdict, head), (verdict, side), (src["label"], side)):
            if text not in where:
                problems.append(f"{name}: the Timeline of {ip} should say {text!r}, says {where!r}")
        counts = {"Sessions": t["sessions_total"], "Bursts": t["bursts_total"],
                  "Scoring windows in which timing fired": len(t["fired"]),
                  next((k for k in rows if k.startswith("Short, then")), "Short, then"): sum(1 for b in t["bursts"] if b[4] == 2)}
        for key, value in counts.items():
            if rows.get(key) != f"{value:,}":
                problems.append(f"{name}: the Timeline of {ip} should give {key!r} as {value:,}, gives {rows.get(key)!r}")

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
    for i, ip in enumerate(want["beams"]):         # every source: flagged ones first, as in the report
        page.evaluate("ip => PWExplorer.select(ip)", ip)
        name = "3d-source" + (f"-{i + 1}" if i else "")
        selected(name, step(name, SETTLE_MS if i < 3 else 400), ip, want["beams"][ip])
    host = page.evaluate("window.VF_DATA.hosts[0].ip")
    page.evaluate("ip => PWExplorer.select(ip)", host)
    selected("3d-host", step("3d-host"), host)
    page.keyboard.press("Escape")
    s = step("3d-escape", 600)
    if s.get("selected") is not None:
        problems.append(f"3d-escape: Esc left {s.get('selected')} selected")

    if set(data.get("timelines", {})) != set(want["timelines"]):
        problems.append(f"timeline: the sources that narrowed are {want['timelines']}, the page has a Timeline for "
                        f"{list(data.get('timelines', {}))}")
    if page.evaluate("PWExplorer.can3d"):
        if page.is_visible("#btn-timeline") != bool(want["timelines"]):
            problems.append("timeline: the Timeline button should show only when a source has a Timeline")
        if want["timelines"] and want["timelines"][0] in data.get("timelines", {}):
            timeline(want["timelines"][0])

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
        # and its link to a flagged source's Timeline opens the Timeline on it
        flagged = {x["ip"] for x in data["sources"] if x["flagged"]} & set(want["timelines"])
        page.goto(report.resolve().as_uri())
        link = page.query_selector('a[href^="explorer.html#timeline="]')
        if link:
            ip = link.get_attribute("href").split("=", 1)[1]
            link.click()
            page.wait_for_function("!!window.PWTimeline", timeout=120_000)
            s = tstep("timeline-from-report", 2500)
            if not s.get("open") or s.get("source") != ip or ip not in flagged:
                problems.append(f"timeline-from-report: the report's Timeline link to {ip} opened {s.get('source')}")
        elif flagged:
            problems.append("timeline-from-report: the report has no link to a flagged source's Timeline")
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
