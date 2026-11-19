"""The outputs of a run: results.json, and the report as Markdown and as a self-contained HTML page.

Both report files are built from the results alone, so a saved results.json can be turned back
into the same report. When the results say an Explorer page was written next to the report
(``explorer``), the report links to it and to each flagged source on it.
"""
from __future__ import annotations

import html
import json
import os
import re

from . import csp

START_METHOD_TEXT = {
    "zeek_ts": "Zeek ts (always the session start)",
    "start_field": "firewall start-time field",
    "end_minus_elapsed": "firewall end time minus elapsed seconds",
    "none": "no start time available",
    "": "not stated by the log reader",
}
SOURCE_TEXT = {"zeek": "Zeek conn.log", "paloalto": "Palo Alto traffic log"}
# The Palo Alto fields a reader needs to check first: where times and outcomes come from.
PA_FIELD_TEXT = {"start": "start time", "end": "end time", "elapsed": "elapsed seconds",
                 "source": "source address", "bytes_received": "bytes received",
                 "packets_received": "packets received"}


def _when(iso: str) -> str:
    return iso.replace("T", " ").replace("Z", " UTC") if iso else "not seen"


def _span(hours: float) -> str:
    if hours >= 48:
        return f"{hours / 24:.1f} days"
    return f"{hours:.1f} hours" if hours >= 1 else f"{hours * 60:.0f} minutes"


def _n(count: int, word: str) -> str:
    return f"{count:,} {word}{'' if count == 1 else 's'}"


def _either(words: list[str], last: str = "or") -> str:
    return ", ".join(words[:-1]) + (f" {last} " if len(words) > 1 else "") + words[-1] if words else ""


def _all(words: list[str]) -> str:
    return _either(words, "and")


def _tier(f: dict) -> str:
    return "Tier 0" if f["level"] == 0 else f"Level {f['level']}"


def _service(s: dict) -> str:
    port = f"{s['port']}/{s['proto']}" if s["port"] is not None else s["proto"]
    return f"{s['host']} {port}"


FILE_KIND_TEXT = {"settings": "settings", "network_map": "network map", "known_scanners": "known scanners",
                  "known_bad": "known attacker addresses"}


def _cell(text: str) -> str:
    """Text from a list or a log, safe inside a table cell of this report."""
    return " ".join(str(text).replace("|", "/").split())


def _published(k: dict) -> str:
    """What a list of published attacker addresses says about a source."""
    conf = f", {k['confidence']} confidence" if k.get("confidence") else ""
    ref = f"; {_cell(k['reference'])}" if k.get("reference") else ""
    return f"{_cell(k['name']) or 'listed'} ({_cell(k['list_name'])}{conf}){ref}"


def _read_from(files: list[dict]) -> str:
    """The first line under "Settings used": which settings, network map and known-scanner files
    this run read, and which of them it found among the input files without being given them."""
    if not files:
        return "- Read from: no settings file, network map or known-scanner list. The defaults apply."
    named = [f"{FILE_KIND_TEXT[f['kind']]} {f['file']}"
             + (" (found among the input files)" if f["found_in_input"] else "") for f in files]
    return "- Read from: " + "; ".join(named) + "."


def _known_lines(known: list[dict]) -> list[str]:
    """The sources flagged only because a list of published attacker addresses names them."""
    if not known:
        return []
    lines = ["### Published attacker addresses", "",
             f"{_n(len(known), 'outside source')} reached your hosts from an address published for ARTEX or "
             "CyberStrikeAI activity (or listed in your known_bad.csv). Their traffic did not show the sweep, "
             "narrowing and pace above, so this rests on the list alone: check who published it and when.", "",
             "| Source | Published as | Sessions | Hosts | Services it reached | Seen |", "|---|---|---|---|---|---|"]
    for k in known:
        more = f" and {k['services_total'] - len(k['services']):,} more" if k["services_total"] > len(k["services"]) else ""
        lines.append(f"| {k['source']} | {_published(k)} | {k['sessions']:,} ({k['answered']:,} answered) | "
                     f"{k['hosts']:,} | {', '.join(k['services'])}{more}{_targets_note(k)} | {_when(k['first_seen'])} to "
                     f"{_when(k['last_seen'])} |")
    return lines + [""]


def _targets_note(item: dict) -> str:
    """'; named targets: ...' after a list of services, when any of them is a named target."""
    return f"; named targets: {', '.join(item['targets'])}" if item.get("targets") else ""


def _steady_run(r: dict) -> str:
    spread = ("times in whole seconds, so the gaps vary only by the rounding" if r.get("whole_seconds")
              and r["jitter"] > 0 else f"gaps vary by {r['jitter']:.0%}")
    kind = f" ({r['target']})" if r.get("target") else ""
    return (f"{r['service']}{kind}: {r['sessions']:,} sessions, one every {r['gap_seconds']:g} s "
            f"({spread}), {r['answered']:,} answered, {_when(r['first'])} to {_when(r['last'])}")


def _steady_lines(steady: list[dict], st: dict) -> list[str]:
    """The sources flagged for machine-steady repetition alone."""
    if not steady:
        return []
    s = st["steady"]
    lines = ["### Machine-steady repetition", "",
             f"{_n(len(steady), 'outside source')} hit one service over and over at an almost constant gap: "
             f"{s['min_sessions']}+ sessions in a row, each within {s['max_gap_seconds']:g} seconds of the last, with "
             f"gaps that vary by no more than {s['max_jitter']:.0%}. A scripted login brute force looks like this "
             "(CyberStrikeAI's FortiGate runs retried every 1.5 seconds); a person never keeps a gap that even. "
             "A health check or a monitoring probe can too, so list the ones you expect in known_scanners.csv.", "",
             "| Source | Built from | Runs |", "|---|---|---|"]
    for v in steady:
        more = f"; and {v['runs_total'] - len(v['runs']):,} more" if v["runs_total"] > len(v["runs"]) else ""
        lines.append(f"| {v['source']} | {_all([SOURCE_TEXT.get(x, x) for x in v['log_sources']])} | "
                     f"{'; '.join(_steady_run(r) for r in v['runs'])}{more} |")
    return lines + [""]


def _targets_line(st: dict) -> str:
    named = "; ".join(f"{name} (port{'s' if len(ports) > 1 else ''} {', '.join(str(p) for p in sorted(ports))})"
                      for name, ports in st.get("targets", {}).items())
    return f"- Named targets: {named or 'none'}."


def _known_bad_line(res: dict) -> str:
    lists = res.get("known_bad_lists") or {}
    parts = []
    if lists.get("bundled"):
        parts.append(f"the bundled list of published ARTEX and CyberStrikeAI addresses ({lists['bundled']:,} ranges)")
    if lists.get("yours"):
        parts.append(f"your known_bad.csv ({lists['yours']:,} ranges)")
    return "- Flagged on sight: " + (" and ".join(parts) if parts else "no list of attacker addresses") + "."


def _band(st: dict) -> str:
    """The pause band of the timing signal, as in "20 to 35 second"."""
    return f"{st['timing']['pause_min_seconds']:g} to {st['timing']['pause_max_seconds']:g} second"


def _timing_rows(f: dict, st: dict) -> list[str]:
    """The timing rows of a finding: what signal 3 measured, or why it could not."""
    t = f["timing"]
    if t["status"] != "agentic":
        why = f"not evaluated: {t['reason']}"
        return [f"| Burst count | {why} |", f"| Typical pause length | {why} |"]
    # sessions without a start time are never timed, so say when the count leaves some out
    part = ("" if t["sessions_timed"] >= f["sessions"] else
            f", counted over the {t['sessions_timed']:,} of its {f['sessions']:,} sessions that have a start time")
    return [f"| Burst count | {_n(t['bursts'], 'short burst')} ({st['timing']['max_burst_sessions']} sessions or "
            f"fewer), each followed by a {_band(st)} pause, of {_n(t['bursts_all'], 'burst')} in all{part} |",
            f"| Typical pause length | {t['typical_pause_seconds']:g} seconds (median of those pauses) |",
            f"| Timing fired in | the {st['window_hours']:g} hours from {_when(t['window_start'])}: "
            f"{_n(t['window_bursts'], 'such burst')}, and {t['window_pause_share']:.0%} of all the pauses in that "
            "window in the band |"]


def _finding_lines(f: dict, st: dict, map_file: str = "", timeline: bool = False) -> list[str]:
    """One finding. ``st``: the run's settings. ``map_file``: the Explorer page that draws this
    source, when there is one. ``timeline``: that page also has the source's Timeline."""
    methods = "; ".join(f"{START_METHOD_TEXT.get(k, k)} ({n:,} sessions)" for k, n in f["start_times"].items())
    lines = [f"### {f['source']}: {_tier(f)}. {f['label']}", "",
             "| | |", "|---|---|",
             f"| Tier or level | {_tier(f)}: {f['label']} |",
             f"| Built from | {_all([SOURCE_TEXT.get(s, s) for s in f['log_sources']])} |",
             f"| Start times resolved by | {methods} |",
             f"| Probe start | {_when(f['probe_start'])} |",
             f"| Sweep | {f['services_probed']:,} services tried on {f['hosts_probed']:,} hosts and "
             f"{f['ports_probed']:,} ports until {_when(f['probe_end'])}; {f['failed_share']:.0%} failed, "
             f"{f['services_answered']:,} answered |",
             f"| Narrowing start | {_when(f['narrowing_start'])} |",
             f"| After narrowing | {f['focus_share']:.0%} of its sessions went to services that answered |",
             f"| Hosts hit | {', '.join(f['hosts_hit'])} |",
             *([f"| Named targets | {', '.join(f['targets'])} |"] if f.get("targets") else []),
             *_timing_rows(f, st),
             f"| Campaign span | {_span(f['campaign_hours'])}, {_when(f['first_seen'])} to "
             f"{_when(f['last_seen'])}, {f['sessions']:,} sessions |",
             f"| Probe start to first vulnerability hit | {f['threat_evidence']} |",
             f"| Threat hits | {f['threat_evidence']} |"]
    if f.get("known"):
        lines.append(f"| Published attacker address | {_published(f['known'])} |")
    if f.get("steady"):
        lines.append(f"| Machine-steady repetition | {'; '.join(_steady_run(r) for r in f['steady'])} |")
    if f.get("notes"):
        lines.append(f"| Notes | {' '.join(f['notes'])} |")
    if map_file:
        lines.append(f"| Map | [Show this source on the map]({map_file}#source={f['source']}) |")
    if map_file and timeline:
        lines.append(f"| Timeline | [Replay its sessions in the order they started]({map_file}#timeline={f['source']}) |")
    lines += ["",
             "Services it narrowed to:", "",
             "| Service | Named target | Network | Completed sessions | First return |", "|---|---|---|---|---|"]
    for s in f["services"]:
        lines.append(f"| {_service(s)} | {s.get('target') or ''} | {s['network'] or 'unmapped'} | {s['sessions']:,} | "
                     f"{_when(s['first_return'])} |")
    if f["services_total"] > len(f["services"]):
        lines.append(f"| and {f['services_total'] - len(f['services']):,} more | | | | |")
    return lines + [""]


def _intro(res: dict) -> list[str]:
    """The analyst's report name and description, under the title (nothing when not given). Each
    line starts with text of ours, so none can become a heading, a list or a table; the HTML page
    escapes them like everything else."""
    r = res.get("report") or {}
    lines = [f"**Report:** {r['name']}", ""] if r.get("name") else []
    for para in (r.get("description") or "").split("\n\n"):
        if para.strip():
            lines += ["> " + ln for ln in para.splitlines() if ln.strip()] + [""]
    return lines


def markdown(res: dict) -> str:
    det = res["detection"]
    found = det["findings"]
    lines = ["# PentAIWatch report", "", *_intro(res),
             f"{res['sessions']:,} sessions were read from "
             f"{_all([SOURCE_TEXT.get(s, s) for s in res['log_sources']]) or 'no usable log'}. "
             f"Scored: {det['inbound_sessions']:,} sessions from "
             f"{_n(det['outside_sources'], 'outside source')} to internal hosts, between {_when(det['lookback_start'] or '')} and "
             f"{_when(det['lookback_end'] or '')}. All times are UTC.", ""]
    if det["never_flagged_sources"]:
        # what the allowlist and known_scanners.csv kept out, said up front: a list that hides a
        # source must not do it quietly
        lines += [f"Left out of the scoring: {_n(det['never_flagged_sessions'], 'session')} from "
                  f"{_n(det['never_flagged_sources'], 'outside source')} on the allowlist or in "
                  "known_scanners.csv. The ranges are listed under Settings used.", ""]
    lines += ["## Agentic activity", ""]
    # the Explorer page written next to the report, if any: {"file", "sources_drawn", "findings_drawn",
    # "timelines": the sources whose Timeline is in the page}
    ex = res.get("explorer") or {}
    map_file = ex.get("file", "") if ex.get("sources_drawn") else ""
    st = res["settings"]
    agentic = sum(1 for f in found if f["level"] >= 1)
    if agentic:
        lines += [f"{_n(agentic, 'outside source')} swept your hosts, returned only to the services that answered, "
                  f"and worked in short bursts separated by {_band(st)} pauses, the time a model takes to decide "
                  "its next step. That is how agentic, AI-driven pentest tools behave.", ""]
    if len(found) > agentic:
        lines += [f"{_n(len(found) - agentic, 'outside source')} swept your hosts and then returned only to the "
                  "services that answered, but the sessions have no start time, so the pace could not be "
                  "checked. That is reported as tier 0.", ""]
    if not found:
        lines += ["No outside source showed a sweep, then narrowing, at the pace of an agentic tool.", ""]
    for i, f in enumerate(found):
        lines += _finding_lines(f, st, map_file if i < ex.get("findings_drawn", 0) else "",
                                f["source"] in (ex.get("timelines") or []))
    other_pace = det["narrowing_sources"] - len(found)
    if other_pace > 0:
        lines += [f"{_n(other_pace, 'other source')} swept and then narrowed, but not in short bursts and "
                  f"{_band(st)} pauses. That looks like a scanner following up on what it found, or a person at "
                  "work, and is not flagged.", ""]
    swept_only = det["probing_sources"] - det["narrowing_sources"]
    if swept_only > 0:
        lines += [f"{_n(swept_only, 'other source')} swept many hosts or ports and did not narrow. That "
                  "looks like plain scanning and is not flagged.", ""]
    lines += _known_lines(det.get("known_sources") or [])
    lines += _steady_lines(det.get("steady_sources") or [], st)
    if map_file:
        replay = (" Its Timeline replays a source's sessions in the order they started, with its bursts and "
                  "pauses." if ex.get("timelines") else "")
        lines += [f"[Open the Explorer]({map_file}) to see every sweep on a map of your subnets, with the "
                  "services each flagged source came back to." + replay, ""]
    lines += ["### What the tiers and levels mean", "",
              "- **Level 1. Agentic behaviour.** Probing, narrowing and timing all fired: a sweep, a return to "
              f"what answered, and short bursts separated by {_band(st)} pauses.",
              "- **Tier 0. Sweep and narrow seen, timing unavailable.** Probing and narrowing fired. The "
              "timing could not be checked, because the sessions have no start time. A source whose timing "
              "was checked and did not fit is not flagged at all.",
              "- **Published attacker address.** A source on a list of addresses that vendors published for "
              "ARTEX or CyberStrikeAI activity, or on your own known_bad.csv, is flagged whatever its traffic "
              "looked like. The list says who published it and how sure they were.",
              "- **Machine-steady repetition.** A source that hit one service over and over at an almost "
              "constant gap, as a scripted login brute force does, is flagged on its own.",
              "- **Named targets** are the kinds of service the ARTEX and CyberStrikeAI reporting says the agents "
              "went for (edge-device consoles and VPNs, AI model gateways, databases, remote access), by port. "
              "They are named so you can check those services first; they do not change whether a source is "
              "flagged.",
              "- **Levels 2 and 3** add exploit evidence from Palo Alto threat logs, which are not scored yet.",
              "- **Threat logs not provided** means no exploit evidence could be attached. It does not "
              "mean there were no exploit attempts. Threat logs that were read are not scored yet either.", "",
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
    tm = st["timing"]
    ping = ("a ping with no reply counts as failed in either log" if st["probing"]["zeek_icmp_by_reply"]
            else "a ping in a Zeek log counts as neither failed nor answered")
    lines += [_read_from(res["settings_files"]),
              f"- Internal ranges: {', '.join(st['internal_nets'] + [n['cidr'] for n in res['networks']])}"
              + (" (internal_nets typed on the upload page, in place of any settings file's)"
                 if "internal_nets" in res.get("typed_settings", []) else ""),
              f"- Lookback: {st['lookback_hours']:g} hours back from the last session. Scoring window: "
              f"{st['window_hours']:g} hours.",
              f"- Probing: {st['probing']['min_ports']}+ ports or {st['probing']['min_hosts']}+ hosts, "
              f"{st['probing']['min_failed_share']:.0%}+ failed "
              f"(Zeek states {', '.join(st['probing']['zeek_failed_states'])}; {ping}).",
              f"- Narrowing: answered services at most {st['narrowing']['max_answered_share']:.0%} of those "
              f"probed, {st['narrowing']['min_sessions_per_service']}+ completed sessions per "
              f"{_either([p.upper() for p in st['narrowing']['protocols']])} service "
              f"(Zeek states {', '.join(st['narrowing']['zeek_answered_states'])}), starting within "
              f"{st['narrowing']['max_start_delay_minutes']:g} minutes of the sweep, "
              f"{st['narrowing']['min_focus_share']:.0%}+ of later sessions to answered services.",
              f"- Timing: a gap of more than {tm['burst_gap_seconds']:g} seconds between session starts ends a "
              f"burst. In one window, {tm['min_cycles']}+ bursts of {tm['max_burst_sessions']} sessions or fewer, "
              f"each followed by a {_band(st)} pause, and {tm['min_pause_share']:.0%}+ of all the window's pauses "
              f"in that band. A source's pace is only ruled out when {tm['min_timed_share']:.0%}+ of its sessions "
              "have a start time.",
              _known_bad_line(res),
              f"- Machine-steady repetition: {st['steady']['min_sessions']}+ sessions in a row to one service, each "
              f"within {st['steady']['max_gap_seconds']:g} seconds of the last, gaps varying by at most "
              f"{st['steady']['max_jitter']:.0%} of their mean.",
              _targets_line(st),
              f"- Never flagged: {', '.join(st['allowlist'] + [k['cidr'] for k in res['known_scanners']]) or 'nothing listed'}."
              + (f" That left out {_n(det['never_flagged_sources'], 'outside source')} with "
                 f"{_n(det['never_flagged_sessions'], 'inbound session')}." if det["never_flagged_sources"] else "")]
    if any(i["format"] == "paloalto" for i in res["inputs"]):
        pa = st["paloalto"]
        back = pa["failed_max_packets_received"]
        lines += [f"- Palo Alto: stopped when the action starts with {_either(pa['deny_actions'])}. An allowed "
                  f"session failed when {'no packets' if back == 0 else 'at most ' + _n(back, 'packet')} came "
                  "back (zero bytes received where the export has no packet count), and was answered when "
                  f"{pa['answered_min_bytes_received']:,} or more bytes came back.",
                  "- Palo Alto columns looked for: " + "; ".join(
                      f"{label} = {', '.join(pa['fields'][key]) or 'none'}" for key, label in PA_FIELD_TEXT.items())
                  + ". Syslog lines without a header are read by position. The full field map is in results.json."]
    lines.append("")
    return "\n".join(lines)


_CSS = """body{font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:#1c2330;background:#f6f7f9;margin:0}
main{max-width:980px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:26px;margin:0 0 12px}h2{font-size:20px;margin:32px 0 10px;border-bottom:1px solid #d5d9e0;padding-bottom:6px}
h3{font-size:16px;margin:24px 0 8px}table{border-collapse:collapse;width:100%;margin:8px 0 14px;background:#fff}
td,th{border:1px solid #d5d9e0;padding:6px 10px;text-align:left;vertical-align:top}th{background:#eceff3}
td:first-child{white-space:nowrap}code{background:#eceff3;padding:1px 4px;border-radius:3px}a{color:#1558b0}
blockquote{margin:0 0 14px;padding:2px 14px;border-left:3px solid #d5d9e0;color:#3a4352}blockquote p{margin:6px 0}
@media (prefers-color-scheme:dark){body{color:#e4e7ec;background:#14181f}table{background:#1b212b}
td,th{border-color:#313948}th,code{background:#252d3a}h2{border-color:#313948}a{color:#7db4f5}
blockquote{border-color:#313948;color:#c3c9d3}}"""


# The only links the report makes: to a page in its own folder, optionally at one source address
# (on the map, or on its Timeline). Text taken from the logs (file names, notes) can never turn into
# a link to anywhere else.
_LINK = re.compile(r"\[([^\[\]]+)\]\(([A-Za-z0-9_-]+\.html(?:#(?:source|timeline)=[0-9A-Fa-f:.]+)?)\)")


def _inline(text: str) -> str:
    text = html.escape(text, quote=False)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
    return _LINK.sub(r'<a href="\2">\1</a>', text)


def to_html(md: str, title: str = "PentAIWatch report") -> str:
    """The report's Markdown (headings, paragraphs, lists and tables only) as one HTML page."""
    out, mode = [], ""

    def close():
        nonlocal mode
        if mode:
            out.append({"ul": "</ul>", "table": "</tbody></table>", "quote": "</blockquote>"}[mode])
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
        elif line.startswith("> "):
            if mode != "quote":
                close()
                mode = "quote"
                out.append("<blockquote>")
            out.append(f"<p>{_inline(line[2:])}</p>")
        else:
            close()
            m = re.match(r"(#{1,3}) (.*)", line)
            if m:
                out.append(f"<h{len(m[1])}>{_inline(m[2])}</h{len(m[1])}>")
            elif line.strip():
                out.append(f"<p>{_inline(line)}</p>")
    close()
    # no script is named in the policy, so none can run in the report
    return (f"<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">{csp.meta()}"
            f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<title>{html.escape(title)}</title><style>{_CSS}</style></head>\n<body><main>\n"
            + "\n".join(out) + "\n</main></body></html>\n")


def title(res: dict, page: str = "PentAIWatch report") -> str:
    """A page's title, after the report name when there is one."""
    name = (res.get("report") or {}).get("name")
    return f"{name} · {page}" if name else page


def write_all(res: dict, outdir: str) -> dict[str, str]:
    """Write results.json, report.md and report.html into ``outdir``; returns {name: path}."""
    os.makedirs(outdir, mode=0o700, exist_ok=True)
    md = markdown(res)
    paths = {}
    for name, text in (("results.json", json.dumps(res, indent=2) + "\n"), ("report.md", md),
                       ("report.html", to_html(md, title(res)))):
        paths[name] = os.path.join(outdir, name)
        with open(paths[name], "w", encoding="utf-8") as fh:
            fh.write(text)
    return paths
