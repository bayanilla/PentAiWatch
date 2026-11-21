# CyberStrikeAI sample (PentAIWatch copy)

Fabricated. This is `conn.log` from VulnScope MAX's `samples/cyberstrike_ai_fortigate_intrusion`
(fictional Tallmast Logistics), with one change: before its first session, each outside address with
30 or more sessions sweeps 172.16.10.1-30 on ports 22, 80, 443, 541, 3389, 4443, 8080, 8443, 9443 and
10443 (plus the services it later uses), about one probe a second, ending 90 seconds before that first
session. MAX's log has no sweep. The sweep is made up and is the only part that is not MAX's.

Rebuild it from MAX's log:

    python scripts/samples/build.py sweep MAX/samples/cyberstrike_ai_fortigate_intrusion/conn.log \
        172.16.10 22,80,443,541,3389,4443,8080,8443,9443,10443 samples/cyberstrike_ai_fortigate_intrusion/conn.log

Palo Alto versions (not committed): `python scripts/samples/build.py paloalto samples/cyberstrike_ai_fortigate_intrusion/conn.log OUT`.

## What PentAIWatch should find

| Input | Result |
| --- | --- |
| Zeek, Palo Alto with start time, or both | `212.11.64.250` Level 1, fixed-interval cadence (a login every 1.5 seconds) |
| Palo Alto, elapsed seconds only | no finding: a 1.5-second step cannot be read from whole-second end times minus elapsed, and the report says so; but the brute force still shows the repeated failed-login pattern on 172.16.10.1:10443, flagged because `212.11.64.250` swept first |
| Palo Alto, no start time | `212.11.64.250`, `146.190.195.154` and `64.176.48.93` Tier 0; timing not read |

`146.190.195.154` and `64.176.48.93` fingerprint the FortiGate's management ports after their sweep,
one request every 2 seconds, but only 24 in a row before a 4-second gap and 6 more. A fixed-interval
run needs 30 (`steady.min_sessions`), so they are not flagged. That is a deliberate near miss: the
threshold was not lowered to catch them. `tests/test_samples.py` checks all of this.
