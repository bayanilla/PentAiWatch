"""The synthetic three-source sample the detection tests run on.

* AGENT    sweeps 30 hosts x 10 ports, then returns only to three services that answered, in short
           bursts (1-14 sessions about a second apart) separated by 20-35 second pauses, for hours.
* SCANNER  sweeps 40 hosts x 25 ports at a steady rate, touches what answers once, and repeats
           the same sweep twelve hours later. It never narrows.
* CLIENT   an ordinary outside client of one public web service.

Everything is generated from a fixed seed, so every run gives the same sessions.
"""
from __future__ import annotations

import random

from tests import kit

T0 = 1_790_000_000.0                      # start of the sample (epoch seconds, UTC)
AGENT, SCANNER, CLIENT = "203.0.113.50", "198.51.100.77", "192.0.2.10"
HOSTS = [f"10.10.1.{i}" for i in range(10, 30)] + [f"10.10.2.{i}" for i in range(10, 30)]
AGENT_PORTS = [22, 80, 443, 3389, 4443, 8080, 8443, 9443, 10443, 11434]
# What is really listening: VPN portal, firewall admin, AI gateway, public web, and a mail relay.
OPEN = {("10.10.1.10", 443), ("10.10.1.10", 4443), ("10.10.1.11", 8443), ("10.10.1.12", 11434),
        ("10.10.1.20", 443), ("10.10.1.20", 80), ("10.10.2.15", 25)}
NARROWED = [("10.10.1.10", 443), ("10.10.1.11", 8443), ("10.10.1.12", 11434)]


def agent(rng: random.Random, hours: float = 4.0, pause_at: float | None = None,
          pause_hours: float = 1.0) -> list[dict]:
    """The agentic source. ``pause_at`` (hours into the narrowing) inserts a ``pause_hours`` gap."""
    out, t = [], T0 + 600
    targets = [(h, p) for h in HOSTS[:30] for p in AGENT_PORTS]
    rng.shuffle(targets)
    for host, port in targets:                                  # the sweep: about one a second
        state = "SF" if (host, port) in OPEN else rng.choice(["S0", "S0", "S0", "REJ"])
        out.append(kit.session(t, AGENT, host, port, state))
        t += rng.uniform(0.6, 1.4)
    t += 120                                                    # the model reads the results
    end, paused = t + hours * 3600, False
    while t < end:
        if pause_at is not None and not paused and t >= end - (hours - pause_at) * 3600:
            t += pause_hours * 3600
            end += pause_hours * 3600
            paused = True
        host, port = rng.choice(NARROWED)
        for _ in range(rng.randint(1, 14)):                     # a burst
            out.append(kit.session(t, AGENT, host, port, rng.choice(["SF", "SF", "SF", "RSTO"])))
            t += rng.uniform(0.7, 1.3)
        t += rng.uniform(20, 35)                                # think time
    return out


def scanner(rng: random.Random) -> list[dict]:
    """A plain scanner: steady sweep, one touch per service, repeated twelve hours later."""
    out = []
    for start in (T0 + 300, T0 + 300 + 12 * 3600):
        t = start
        for host in HOSTS:
            for port in range(1, 26):
                port = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1723,
                        3306, 3389, 5900, 8080, 8443, 4443, 11434, 8888][port - 1]
                state = "SF" if (host, port) in OPEN else rng.choice(["S0", "S0", "REJ", "RSTOS0"])
                out.append(kit.session(t, SCANNER, host, port, state))
                t += 2.0
    return out


def client(rng: random.Random, hours: float = 6.0) -> list[dict]:
    """An ordinary client of the public web service."""
    return [kit.session(T0 + rng.uniform(0, hours * 3600), CLIENT, "10.10.1.20", rng.choice([443, 443, 80]), "SF")
            for _ in range(200)]


def sessions(seed: int = 7, shift: float = 0.0, **agent_kw) -> list[dict]:
    """All three sources, in time order. ``shift`` moves every session by that many seconds."""
    rng = random.Random(seed)
    out = agent(rng, **agent_kw) + scanner(rng) + client(rng)
    for s in out:
        s["ts"] += shift
    return sorted(out, key=lambda s: s["ts"])
