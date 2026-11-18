# How PentAIWatch decides

PentAIWatch looks at one direction only: sessions from outside addresses to your internal hosts.
For each outside source it asks whether the source swept many targets, then went back only to
what answered, in short bursts separated by pauses the length of a model's think time. A plain
scanner sweeps but rarely narrows. A person narrows but not at machine pace. The combination is
the signal.

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

**Pings are judged the same way in both logs.** Zeek gives every ICMP record the state `OTH`,
answered or not, so the lists of states cannot judge a ping. In a Zeek log a ping is therefore
judged by what came back, as the firewall rule already does: nothing back is failed, a reply is
answered (`probing.zeek_icmp_by_reply`, on). "Nothing back" is `resp_pkts` 0, or zero
`resp_bytes` when the log has no packet counts. Turn the setting off and ICMP in a Zeek log is
neither failed nor answered.

ICMP has no ports. Zeek writes the ICMP type and code where the ports go, so whatever a log
holds there, both readers store 0. A pinged host is then one service whichever log recorded it.

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
best answer for each. Sessions recorded as `none` are counted in a warning, once. They still count
in the sweep and the narrowing, and they are never timed.

## When both logs are present

A session recorded by Zeek and by the firewall is counted once. This is the de-duplication taken
from VulnScope MAX, unchanged: same source, destination, ports and protocol, start times within
`dedup_skew_seconds` (2). The firewall's record is the one kept, because it knows the policy
action, so the outcome of a shared session is judged the Palo Alto way. With one log alone the
matching has nothing to do.

A ping recorded by both logs is matched on source, destination and start time, since it has no
ports. Two pings from one source to one host inside the same `dedup_skew_seconds` can therefore
be counted as one; the sweep is not affected, because it counts each pinged host once anyway.

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
  sessions. Those are the services it *narrowed to*. Only TCP and UDP services can be narrowed
  to (`narrowing.protocols`): a host that keeps answering pings is not a service the source came
  back to. Pings still count in the sweep.
- It came back promptly: the first return (the first answered session after the first attempt)
  is no later than `max_start_delay_minutes` (15) after the sweep's last first attempt.
- It stayed on what answered: from that point, for one window, at least `min_focus_share` (60%)
  of the source's sessions went to services that had answered.

## Signal 3: timing

An agentic tool works in steps: a few connections, then a pause while the model decides what to
do next. Timing looks for that rhythm in the START times of a source's sessions (see "Start
times"), for every source where narrowing fired.

- **Bursts.** The source's sessions are put in order of start time. A gap of more than
  `burst_gap_seconds` (15) between two starts ends a burst. A burst is *short* when it has at most
  `max_burst_sessions` (15) sessions. Nothing is asked of the spacing inside a burst.
- **Pauses.** A pause runs from the last start of one burst to the first start of the next. It is
  *in the band* when it lasts `pause_min_seconds` (20) to `pause_max_seconds` (35).

Timing fires in a scoring window when both of these hold for the pauses that begin in it:

- at least `min_cycles` (5) short bursts are each followed by a pause in the band, and
- at least `min_pause_share` (60%) of all the pauses are in the band. This is the "mostly". A source
  whose pauses are of every length has some in the band by chance (the ordinary client in the
  tests has ten in one window), and this keeps it out.

The pauses need not be alike, and long breaks do no harm: a campaign that stops for an hour adds
one pause that is not in the band.

A source where probing and narrowing fired is then one of three things:

| Timing | Result |
|---|---|
| Fired in at least one window | Level 1 |
| Did not fire, and fewer than `min_timed_share` (90%) of the source's sessions have a start time. Usually none has: a Palo Alto export with neither a start nor an elapsed time | Tier 0. The pace could not be judged, and the finding says how many sessions could be timed |
| Did not fire, and the source was seen nearly whole | Not flagged. It swept and narrowed at some other pace: a scanner following up on what it found, or a person. The report counts these sources and the Explorer draws them |

A level 1 finding gives the number of short bursts followed by a pause in the band over the whole
lookback, the median of those pauses, and the window in which timing fired with the most of them.

**What timing cannot see.** Only the moment a connection starts is read. A tool that sends its
requests over one connection it keeps open shows one start, not a burst, and a tool that runs
several jobs at once from one address fills its own pauses. Either can leave an agentic tool
unflagged. Whole-second firewall times move a pause by up to a second either way, which matters
only for pauses at the very edge of the band.

## Tiers and levels

| | Meaning |
|---|---|
| Level 1. Agentic behaviour | Probing, narrowing and timing all fired. |
| Tier 0. Sweep and narrow seen, timing unavailable | Probing and narrowing fired. Timing could not be judged, because the sessions have no start time. |

Levels 2 and 3 need the scoring of Palo Alto threat logs, which is not built yet. A finding says
"threat logs not provided" when the run had none, and "threat logs were read but are not scored
yet" when it had some, so a low level is never read as "no exploit attempts".

## What the Explorer draws

`explorer.html` draws what the report says. It scores nothing of its own, and it reads the same
de-duplicated sessions as the detection, so a session both logs recorded counts once on the map too.

- **Sources.** A source is drawn when the probing signal fired for it. The flagged ones carry
  their finding. The others are marked *Swept, did not narrow* or, when they narrowed at another
  pace, *Swept and narrowed, not at an agent's pace*, with the bursts and pauses that say so.
- **One window per source.** Everything about a source's sweep (the services, hosts and ports it
  tried, the share that failed, what answered) is counted in one window: the one its finding was
  built from, or, for a source that is not flagged, the one after which it narrowed, else the one
  in which it tried the most services. A scanner that repeats its sweep every twelve hours is
  drawn with one sweep, not with their sum.
- **Hosts.** A dot is a host that a drawn source tried in that window. It shows the most telling
  thing that happened to it: a flagged source kept coming back to it, else it answered a sweep,
  else it was tried and nothing answered. Solid beams and pillars are kept for flagged sources: a
  host that only a source at another pace came back to is drawn as one that answered.
- **Subnets.** Hosts are grouped by /24 (IPv6: /64). A ring takes its name from the range in
  `network_map.csv` that holds its hosts, when there is one.
- **Cuts.** At most 48 sources (flagged ones first, in the report's order, then those that
  narrowed, then the largest sweeps), 120 subnets (those with a host a flagged source kept coming
  back to first, then by hosts that answered, then by hosts tried) and 2,000 hosts (every host a
  flagged source kept coming back to, then those that answered, then those only tried, each
  subnet taking its turn), and 200 services listed per source. Among equals the pick follows a hash of the address, so the same logs always
  give the same picture. Every count on the page is of the whole run; where less is drawn, the
  page says how much.

Those four limits are constants in `pentaiwatch/explore.py`, not settings: they say what a
browser draws comfortably, not what counts as agentic.

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
