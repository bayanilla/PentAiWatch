# How PentAIWatch decides

PentAIWatch looks at one direction only: sessions from outside addresses to your internal hosts.
For each outside source it asks whether the source swept many targets, then went back only to
what answered. A plain scanner sweeps but rarely narrows. A person narrows but not at machine
pace. The combination is the signal.

All times are UTC. Every number below is a setting (see the README).

## What counts as internal

An address is internal when it is inside `internal_nets` (RFC 1918 by default) or inside a range
listed in `network_map.csv`. Everything else is outside. Sources in `known_scanners.csv` or in
the `allowlist` setting are never scored.

## One session shape for every log

Before any signal runs, sessions are put into one shape: start time, how that start time was
found, source, destination host, port and protocol, and an outcome.

| Outcome | Zeek `conn_state` |
|---|---|
| failed | `S0`, `REJ`, `RSTOS0`, `RSTR` |
| answered | `SF`, `S1`, `S2`, `S3`, `RSTO` |
| other | anything else (for example `OTH`, `SH`, `SHR`, `RSTRH`) |

Zeek's `ts` is always the session start, even though `conn.log` is written when the session
closes. Each finding records how its start times were found.

A *service* is a host, port and protocol.

## Lookback and windows

Scoring covers the last `lookback_hours` (72) before the last session in the run. Sessions are
scored in windows of `window_hours` (2). Windows start every half window, so a sweep that
crosses a window edge still falls whole inside one window.

A source gets one finding for the whole lookback. A campaign that pauses and resumes is not
split.

## Signal 1: probing

A sweep is made of first attempts: the first session from the source to each service. Counting
only first attempts keeps the many repeated sessions of the narrowing phase from hiding the
sweep.

Probing fires in a window when the source's first attempts in it reach

- `min_ports` (50) or more different ports, **or** `min_hosts` (20) or more different hosts, and
- `min_failed_share` (70%) or more of them failed.

## Signal 2: narrowing

For a window where probing fired, narrowing fires when all of these hold:

- Few services answered: the probed services with at least one answered session are at most
  `max_answered_share` (10%) of those probed.
- The source came back: at least one of them has `min_sessions_per_service` (5) or more answered
  sessions. Those are the services it *narrowed to*.
- It came back promptly: the first return (the first answered session after the first attempt)
  is no later than `max_start_delay_minutes` (15) after the sweep's last first attempt.
- It stayed on what answered: from that point, for one window, at least `min_focus_share` (60%)
  of the source's sessions went to services that had answered.

## Tiers and levels

| | Meaning |
|---|---|
| Tier 0. Sweep and narrow seen, timing unavailable | Probing and narrowing fired. Timing could not be evaluated. |

Levels 1 to 3 need the timing signal and Palo Alto threat logs, which are not built yet. Until
then every flagged source is tier 0 and every finding says "threat logs not provided", so a
low tier is never read as "no exploit attempts".

## Data-quality rules

- The DuckDB version is checked before any log is read. The detection is SQL, so a faulty
  engine does not crash, it quietly finds nothing. Versions older than 1.2 and version 1.3.0
  (which drops matching rows from joins on a time range) are refused with a message.
- A Zeek `conn.log` without `conn_state` stops the run with a message naming the file. Outcomes
  come from that field, and scoring nothing quietly would look like a clean result.
- Sessions with no readable time are left out and counted in a warning.
- Sessions older than the lookback are left out and counted in a warning, so a short lookback
  (or one wrong timestamp far in the future) cannot empty the report unnoticed.
- The source address is the one the sensor saw. A Zeek tap behind a NAT device or load balancer
  sees the translated address, not the outside one, so place the tap where the outside address
  is still visible.
- When no session goes from an outside address to an internal host, the report says so and
  points at the internal ranges.
- A session recorded twice (two Zeek taps, or Zeek and a firewall) is counted once. This is the
  de-duplication taken from VulnScope MAX: same source, destination, ports and protocol, start
  times within `dedup_skew_seconds` (2).

## Known limitation: proxy rotation

These tools rotate through residential, datacenter and free proxies or Tor when blocked. Scoring
is per source address, so one campaign can be split across several sources. Each finding carries
the services, hosts and times it involved, so a later step can group findings by targeted
service, time window and network owner without changing the signals.
