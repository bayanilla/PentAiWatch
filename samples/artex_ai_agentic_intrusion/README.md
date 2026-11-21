# ARTEX sample (PentAIWatch copy)

Fabricated. This is `conn.log` from VulnScope MAX's `samples/artex_ai_agentic_intrusion` (fictional
Northfold Systems, `northfold.example`), with one change: before its first session, each outside
address with 30 or more sessions sweeps 10.50.1.1-30 on ports 22, 80, 443, 3389, 4443, 8080, 8443 and
9443 (plus the services it later uses), about one probe a second, ending 90 seconds before that first
session. MAX's log has no sweep. The sweep is made up and is the only part that is not MAX's.

Rebuild it from MAX's log:

    python scripts/samples/build.py sweep MAX/samples/artex_ai_agentic_intrusion/conn.log \
        10.50.1 22,80,443,3389,4443,8080,8443,9443 samples/artex_ai_agentic_intrusion/conn.log

Palo Alto versions (not committed): `python scripts/samples/build.py paloalto samples/artex_ai_agentic_intrusion/conn.log OUT`.

## What PentAIWatch should find

| Input | Result |
| --- | --- |
| Zeek, Palo Alto with start time, or both | `144.172.64.99` and `144.172.64.128` Level 1, burst and pause |
| Palo Alto, elapsed seconds only | the same (the pauses are 20 seconds and more, longer than the rounding) |
| Palo Alto, no start time | `144.172.64.60`, `.99`, `.128` and `104.194.150.21` Tier 0; timing not read |

`144.172.64.60` and `104.194.150.21` sweep and come back to what answered, but at an uneven pace, so
they are not findings: a person with a scanner does the same. `144.172.64.60`'s password spray on
the SSO page (10.50.1.11:443, about one attempt a second for 40 minutes, gaps of 0.8 to 1.4 seconds,
just under 60 a minute) is too uneven for a fixed interval and under the high-rate threshold, so it
is caught by the repeated failed-login pattern instead: 42 minutes of small, same-size replies,
flagged because the same address swept first. `144.172.64.99` shows the same pattern beside its
Level 1 finding. `tests/test_samples.py` checks all of this.
