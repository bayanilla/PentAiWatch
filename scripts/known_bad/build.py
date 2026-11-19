#!/usr/bin/env python3
"""Rebuild pentaiwatch/data/known_bad.csv, the bundled list of published attacker addresses.

Sources:
  * SecureDataSolutions/artex-hunting-pack, iocs.csv (MIT licence): every ipv4 and ipv4_range row.
    That pack collects the addresses CrowdStrike, Microsoft, Check Point, Censys and Team Cymru
    published for ARTEX and CyberStrikeAI activity, each with its source and confidence.
  * Unit 42 Timely Threat Intel, 2026-10-30 "activity using ARTEX agentic AI": four addresses
    (EXTRA below), copied by hand from the note.

Usage:
  curl -sSLO https://raw.githubusercontent.com/SecureDataSolutions/artex-hunting-pack/main/iocs.csv
  python scripts/known_bad/build.py iocs.csv > pentaiwatch/data/known_bad.csv

Nothing here downloads anything; PentAIWatch itself never goes online.
"""
from __future__ import annotations

import csv
import hashlib
import ipaddress
import sys

UNIT42 = ("https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/"
          "2026-10-30-activity-using-ARTEX-agentic-AI.txt")
EXTRA = [  # address, name, confidence, reference
    ("31.40.205.155", "ARTEX: primary origin of sign-up, API retrieval and IdP probing; Sub2API on 8080 (Unit 42)",
     "medium", UNIT42),
    ("173.254.220.78", "ARTEX: reconnaissance and account-recovery probing; Sub2API gateway (Unit 42)", "medium", UNIT42),
    ("103.100.158.103", "ARTEX: scanning and authorization-flow probing (Unit 42, monitor only)", "low", UNIT42),
    ("152.233.51.12", "ARTEX: probing and unauthenticated API writes (Unit 42, monitor only)", "low", UNIT42),
]


def cidrs(text: str) -> list[str]:
    if "-" in text:
        first, last = (ipaddress.ip_address(p.strip()) for p in text.split("-", 1))
        return [str(n) for n in ipaddress.summarize_address_range(first, last)]
    return [str(ipaddress.ip_network(text.strip(), strict=False))]


def main(path: str) -> None:
    with open(path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    out = csv.writer(sys.stdout, lineterminator="\n")
    print("# Published addresses of ARTEX and CyberStrikeAI activity, bundled with PentAIWatch.")
    print("# Built by scripts/known_bad/build.py from SecureDataSolutions/artex-hunting-pack iocs.csv")
    print(f"# (MIT licence, Copyright (c) 2026 Secure Data Solutions, Inc.; sha256 {digest})")
    print("# and the Unit 42 note of 2026-10-30. Each row names who published it and how sure they are.")
    out.writerow(["address", "name", "confidence", "reference"])
    seen = set()
    with open(path, encoding="utf-8", newline="") as fh:
        for r in csv.DictReader(fh):
            if r["type"] not in ("ipv4", "ipv4_range"):
                continue
            name = f"{r['campaign']}: {r['category'].replace('_', ' ')} ({r['source']})"
            for net in cidrs(r["indicator"]):
                if net not in seen:
                    seen.add(net)
                    out.writerow([net, name, r["confidence"], r["source_url"]])
    for addr, name, conf, ref in EXTRA:
        net = cidrs(addr)[0]
        if net not in seen:
            seen.add(net)
            out.writerow([net, name, conf, ref])


if __name__ == "__main__":
    main(sys.argv[1])
