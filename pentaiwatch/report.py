"""The outputs of a run: results.json, and the report as Markdown and as a self-contained HTML page.

Both report files are built from the results alone, so a saved results.json can be turned back
into the same report.
"""
from __future__ import annotations

import html
import json
import os
import re

START_METHOD_TEXT = {
    "zeek_ts": "Zeek ts (always the session start)",
    "start_field": "firewall start-time field",
    "end_minus_elapsed": "firewall end time minus elapsed seconds",
    "none": "no start time available",
    "": "not stated by the log reader",
}
SOURCE_TEXT = {"zeek": "Zeek conn.log", "paloalto": "Palo Alto traffic log"}


def _when(iso: str) -> str:
    return iso.replace("T", " ").replace("Z", " UTC") if iso else "not seen"


def _span(hours: float) -> str:
    if hours >= 48:
        return f"{hours / 24:.1f} days"
    return f"{hours:.1f} hours" if hours >= 1 else f"{hours * 60:.0f} minutes"


def _n(count: int, word: str) -> str:
    return f"{count:,} {word}{'' if count == 1 else 's'}"


def _tier(f: dict) -> str:
    return "Tier 0" if f["level"] == 0 else f"Level {f['level']}"


def _service(s: dict) -> str:
    port = f"{s['port']}/{s['proto']}" if s["port"] is not None else s["proto"]
    return f"{s['host']} {port}"


def _finding_lines(f: dict) -> list[str]:
    methods = "; ".join(f"{START_METHOD_TEXT.get(k, k)} ({n:,} sessions)" for k, n in f["start_times"].items())
    lines = [f"### {f['source']}: {_tier(f)}. {f['label']}", "",
             "| | |", "|---|---|",
             f"| Tier or level | {_tier(f)}: {f['label']} |",
             f"| Built from | {', '.join(SOURCE_TEXT.get(s, s) for s in f['log_sources'])} |",
             f"| Start times resolved by | {methods} |",
             f"| Probe start | {_when(f['probe_start'])} |",
             f"| Sweep | {f['services_probed']:,} services tried on {f['hosts_probed']:,} hosts and "
             f"{f['ports_probed']:,} ports until {_when(f['probe_end'])}; {f['failed_share']:.0%} failed, "
             f"{f['services_answered']:,} answered |",
             f"| Narrowing start | {_when(f['narrowing_start'])} |",
             f"| After narrowing | {f['focus_share']:.0%} of its sessions went to services that answered |",
             f"| Hosts hit | {', '.join(f['hosts_hit'])} |",
             f"| Burst count | {f['timing']} |",
             f"| Typical pause length | {f['timing']} |",
             f"| Campaign span | {_span(f['campaign_hours'])}, {_when(f['first_seen'])} to "
             f"{_when(f['last_seen'])}, {f['sessions']:,} sessions |",
             f"| Probe start to first vulnerability hit | {f['threat_evidence']} |",
             f"| Threat hits | {f['threat_evidence']} |", "",
             "Services it narrowed to:", "",
             "| Service | Network | Completed sessions | First return |", "|---|---|---|---|"]
    for s in f["services"]:
        lines.append(f"| {_service(s)} | {s['network'] or 'unmapped'} | {s['sessions']:,} | {_when(s['first_return'])} |")
    if f["services_total"] > len(f["services"]):
        lines.append(f"| and {f['services_total'] - len(f['services']):,} more | | | |")
    return lines + [""]


def markdown(res: dict) -> str:
    det = res["detection"]
    found = det["findings"]
    lines = ["# PentAIWatch report", "",
             f"{res['sessions']:,} sessions were read from "
             f"{', '.join(SOURCE_TEXT.get(s, s) for s in res['log_sources']) or 'no usable log'}. "
             f"Scored: {det['inbound_sessions']:,} sessions from "
             f"{_n(det['outside_sources'], 'outside source')} to internal hosts, between {_when(det['lookback_start'] or '')} and "
             f"{_when(det['lookback_end'] or '')}. All times are UTC.", "",
             "## Agentic activity", ""]
    if found:
        lines += [f"{_n(len(found), 'outside source')} swept your hosts and then returned only to the "
                  "services that answered. That is how agentic, AI-driven pentest tools behave.", ""]
        for f in found:
            lines += _finding_lines(f)
    else:
        lines += ["No outside source showed a sweep followed by narrowing.", ""]
    swept_only = det["probing_sources"] - len(found)
    if swept_only > 0:
        lines += [f"{_n(swept_only, 'other source')} swept many hosts or ports and did not narrow. That "
                  "looks like plain scanning and is not flagged.", ""]
    lines += ["### What the tiers mean", "",
              "- **Tier 0. Sweep and narrow seen, timing unavailable.** Probing and narrowing fired. The "
              "timing signal (short bursts separated by 20 to 35 second pauses) could not be evaluated.",
              "- **Threat logs not provided** means no exploit evidence could be attached. It does not "
              "mean there were no exploit attempts.", "",
              "### Known limitations", ""]
    lines += [f"- {text}" for text in res["limitations"]] + [""]
    if res["warnings"]:
        lines += ["## Warnings", ""] + [f"- {w}" for w in res["warnings"]] + [""]
    lines += ["## Input files", "", "| File | Format | Records read | Kept | Notes |", "|---|---|---|---|---|"]
    for s in res["inputs"]:
        dropped = [f"{n:,} dropped: {why}" for why, n in s["dropped"].items()]
        lines.append(f"| {s['file']} | {s['format']} | {s['read']:,} | {s['kept']:,} | "
                     f"{'; '.join(s['notes'] + dropped)} |")
    dup = res["duplicates_removed"]
    lines += ["", f"Duplicates removed: {dup['exact']:,} exact, {dup['seen_by_two_sensors']:,} sessions seen "
              "by two sensors and counted once.", "", "## Settings used", ""]
    st = res["settings"]
    lines += [f"- Internal ranges: {', '.join(st['internal_nets'] + [n['cidr'] for n in res['networks']])}",
              f"- Lookback: {st['lookback_hours']:g} hours back from the last session. Scoring window: "
              f"{st['window_hours']:g} hours.",
              f"- Probing: {st['probing']['min_ports']}+ ports or {st['probing']['min_hosts']}+ hosts, "
              f"{st['probing']['min_failed_share']:.0%}+ failed "
              f"(Zeek states {', '.join(st['probing']['zeek_failed_states'])}).",
              f"- Narrowing: answered services at most {st['narrowing']['max_answered_share']:.0%} of those "
              f"probed, {st['narrowing']['min_sessions_per_service']}+ completed sessions per service "
              f"(Zeek states {', '.join(st['narrowing']['zeek_answered_states'])}), starting within "
              f"{st['narrowing']['max_start_delay_minutes']:g} minutes of the sweep, "
              f"{st['narrowing']['min_focus_share']:.0%}+ of later sessions to answered services.",
              f"- Never flagged: {', '.join(st['allowlist'] + [k['cidr'] for k in res['known_scanners']]) or 'nothing listed'}.",
              ""]
    return "\n".join(lines)


_CSS = """body{font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:#1c2330;background:#f6f7f9;margin:0}
main{max-width:980px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:26px;margin:0 0 12px}h2{font-size:20px;margin:32px 0 10px;border-bottom:1px solid #d5d9e0;padding-bottom:6px}
h3{font-size:16px;margin:24px 0 8px}table{border-collapse:collapse;width:100%;margin:8px 0 14px;background:#fff}
td,th{border:1px solid #d5d9e0;padding:6px 10px;text-align:left;vertical-align:top}th{background:#eceff3}
td:first-child{white-space:nowrap}code{background:#eceff3;padding:1px 4px;border-radius:3px}
@media (prefers-color-scheme:dark){body{color:#e4e7ec;background:#14181f}table{background:#1b212b}
td,th{border-color:#313948}th,code{background:#252d3a}h2{border-color:#313948}}"""


def _inline(text: str) -> str:
    text = html.escape(text, quote=False)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    return re.sub(r"`(.+?)`", r"<code>\1</code>", text)


def to_html(md: str, title: str = "PentAIWatch report") -> str:
    """The report's Markdown (headings, paragraphs, lists and tables only) as one HTML page."""
    out, mode = [], ""

    def close():
        nonlocal mode
        if mode:
            out.append({"ul": "</ul>", "table": "</tbody></table>"}[mode])
            mode = ""
    for line in md.split("\n"):
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if all(set(c) <= {"-"} and c for c in cells):
                continue
            if mode != "table":
                close()
                mode = "table"
                head = "".join(f"<th>{_inline(c)}</th>" for c in cells)
                out.append(f"<table>{'<thead><tr>' + head + '</tr></thead>' if any(cells) else ''}<tbody>")
                continue
            out.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells) + "</tr>")
        elif line.startswith("- "):
            if mode != "ul":
                close()
                mode = "ul"
                out.append("<ul>")
            out.append(f"<li>{_inline(line[2:])}</li>")
        else:
            close()
            m = re.match(r"(#{1,3}) (.*)", line)
            if m:
                out.append(f"<h{len(m[1])}>{_inline(m[2])}</h{len(m[1])}>")
            elif line.strip():
                out.append(f"<p>{_inline(line)}</p>")
    close()
    return (f"<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<title>{html.escape(title)}</title><style>{_CSS}</style></head>\n<body><main>\n"
            + "\n".join(out) + "\n</main></body></html>\n")


def write_all(res: dict, outdir: str) -> dict[str, str]:
    """Write results.json, report.md and report.html into ``outdir``; returns {name: path}."""
    os.makedirs(outdir, mode=0o700, exist_ok=True)
    md = markdown(res)
    paths = {}
    for name, text in (("results.json", json.dumps(res, indent=2) + "\n"), ("report.md", md),
                       ("report.html", to_html(md))):
        paths[name] = os.path.join(outdir, name)
        with open(paths[name], "w", encoding="utf-8") as fh:
            fh.write(text)
    return paths
