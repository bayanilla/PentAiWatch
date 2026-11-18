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

Before any signal runs, sessions are put into one shape, whichever log they came from: start
time, how that start time was found, source, destination host, port and protocol, and an outcome.
Every signal reads only that shape, so each works from Zeek alone, from Palo Alto alone, or from
both.

| Outcome | Zeek `conn_state` | Palo Alto traffic log |
|---|---|---|
| failed | `S0`, `REJ`, `RSTOS0`, `RSTR` | Stopped by the firewall (the action starts with `deny`, `drop`, `reset` or `block`), or allowed with no packets back |
| answered | `SF`, `S1`, `S2`, `S3`, `RSTO` | Allowed, with bytes back |
| other | anything else (for example `OTH`, `SH`, `SHR`, `RSTRH`) | anything else |

For Palo Alto, "no packets back" is the packets-received count when the export has one
(`failed_max_packets_received`, 0). When it has none, zero bytes received stands in, and the
finding says so. "Bytes back" is `answered_min_bytes_received` (1) or more bytes received.

**One difference between the two logs.** A closed port on a path the firewall permits answers
with a single reset. Zeek calls that `REJ`, which is failed. The firewall logs it as allowed with
one packet and about 60 bytes back, which is answered under the rule above. Most of a sweep
through a perimeter firewall is dropped by policy, so this rarely changes a result. Where it
matters, set `failed_max_packets_received` to 1 (needs the packet count) so a lone reset counts
as failed, or raise `answered_min_bytes_received` to 100 so it at least stops counting as
answered.

A *service* is a host, port and protocol.

## Start times

Timing is only ever worked out from session START times. Each session records how its start
time was found, and each finding reports the counts.

| Log | Start time | Recorded as |
|---|---|---|
| Zeek | `ts`, which is always the session start even though `conn.log` is written at close | `zeek_ts` |
| Palo Alto | the start-time field, when the row has one | `start_field` |
| Palo Alto | otherwise the end time minus the elapsed seconds | `end_minus_elapsed` |
| Palo Alto | otherwise none: the end time is kept so the session lands in the right scoring window, and it is never used for timing | `none` |

Rows resolve one by one, so an export where only some rows have a start time still gets the
best answer for each. Sessions recorded as `none` are counted in a warning, once.

## When both logs are present

A session recorded by Zeek and by the firewall is counted once. This is the de-duplication taken
from VulnScope MAX, unchanged: same source, destination, ports and protocol, start times within
`dedup_skew_seconds` (2). The firewall's record is the one kept, because it knows the policy
action, so the outcome of a shared session is judged the Palo Alto way. With one log alone the
matching has nothing to do.

The start time worked out from end minus elapsed feeds that matching, so an export without a
start field is still matched to Zeek. Rows with no start time cannot be matched (their time is an
end time), and the report warns that such sessions may be counted twice.

Each finding lists the logs that recorded its source, taken before the matching.

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

Levels 1 to 3 need the timing signal and the scoring of Palo Alto threat logs, which are not
built yet. Until then every flagged source is tier 0. A finding says "threat logs not provided"
when the run had none, and "threat logs were read but are not scored yet" when it had some, so a
low tier is never read as "no exploit attempts".

## Data-quality rules

- The DuckDB version is checked before any log is read. The detection is SQL, so a faulty
  engine does not crash, it quietly finds nothing. Versions older than 1.2 and version 1.3.0
  (which drops matching rows from joins on a time range) are refused with a message.
- A Zeek `conn.log` without `conn_state` stops the run with a message naming the file. Outcomes
  come from that field, and scoring nothing quietly would look like a clean result.
- A Palo Alto traffic export without a column for the source, destination, destination port,
  protocol, action, bytes received, or any time stops the run the same way. The message lists
  the columns the file has and where to name the right one. The one exception is the start
  time: a row with neither a start time nor an elapsed time is kept and marked, as described
  under Start times.
- An allowed firewall row with an empty bytes-received value is dropped and counted. Unknown is
  not zero, and reading it as zero would turn it into a failed attempt.
- Palo Alto session-start records are left out and counted. A session logged at its start has
  no reply yet, so it would read as "allowed with nothing back". If an export holds nothing but
  start records, the run stops and says so.
- Firewall times are read as UTC. When Zeek and Palo Alto logs are both present, sessions that
  both recorded but that did not match are compared: if the firewall's start times sit more than
  `dedup_skew_seconds` from Zeek's (median, 10 or more sessions), the report warns that the
  clocks disagree, by how much, and that those sessions are counted twice.
- The Palo Alto source is the address before NAT (`fields.source`, "Source address"), never the
  translated one.
- Sessions with no readable time are left out and counted in a warning.
- Sessions older than the lookback are left out and counted in a warning, so a short lookback
  (or one wrong timestamp far in the future) cannot empty the report unnoticed.
- For Zeek the source address is the one the sensor saw. A tap behind a NAT device or load
  balancer sees the translated address, not the outside one, so place the tap where the outside
  address is still visible.
- When no session goes from an outside address to an internal host, the report says so and
  points at the internal ranges.
- A session recorded twice (two Zeek taps, or Zeek and a firewall) is counted once. See "When
  both logs are present".
- A file that is neither a Zeek nor a Palo Alto log is left out, listed in the input table and
  named in a warning.

## Known limitation: proxy rotation

These tools rotate through residential, datacenter and free proxies or Tor when blocked. Scoring
is per source address, so one campaign can be split across several sources. Each finding carries
the services, hosts and times it involved, so a later step can group findings by targeted
service, time window and network owner without changing the signals.
