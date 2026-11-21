"""Published attacker addresses: a source on this list is flagged and named whatever its traffic
looked like.

PentAIWatch carries a list of the addresses that vendors published for ARTEX, CyberStrikeAI and Cairn
activity (``data/known_bad.csv``, see scripts/known_bad/build.py for where each row comes from).
Your own list can be added in the same shape:

    address,name,confidence,reference
    203.0.113.0/28,Seen in our own incident 2026-11,high,ticket 4521
    198.51.100.7,ARTEX scanner from partner feed

Only the address is required; ``#`` starts a comment and the header row is optional. A file named
``known_bad.csv`` in an input folder is used automatically (it is not read as a log), or pass one
with ``--known-bad``. The bundled list can be turned off with the setting ``known_bad_bundled``.
The list is only ever read from disk: PentAIWatch never fetches a feed.
"""
from __future__ import annotations

import csv
import ipaddress
import os

from .errors import UserError

FILENAME = "known_bad.csv"
BUNDLED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", FILENAME)
CONFIDENCE = ("high", "medium", "low")
_HEAD = {"address", "ip", "cidr", "range", "indicator"}


def is_list_file(path: str) -> bool:
    return os.path.basename(path).lower() == FILENAME


def _networks(text: str, where: str) -> list[str]:
    """An address, a CIDR range, or a "first-last" range, as CIDR ranges."""
    try:
        if "-" in text:
            first, last = (ipaddress.ip_address(p.strip()) for p in text.split("-", 1))
            return [str(n) for n in ipaddress.summarize_address_range(first, last)]
        return [str(ipaddress.ip_network(text, strict=False))]
    except (ValueError, TypeError):
        raise UserError(f"{where}: '{text}' is not an address or address range") from None


def read(path: str, bundled: bool = False) -> list[dict]:
    """[{cidr, name, confidence, reference, list}] in file order. Raises UserError with the line."""
    out = []
    label = "bundled list" if bundled else os.path.basename(path)
    with open(path, encoding="utf-8-sig", newline="") as fh:
        for line, row in enumerate(csv.reader(fh), 1):
            cells = [c.strip() for c in row]
            if not any(cells) or cells[0].startswith("#"):
                continue
            if cells[0].lower() in _HEAD:
                continue
            cells += [""] * (4 - len(cells))
            conf = cells[2].lower()
            for net in _networks(cells[0], f"{os.path.basename(path)} line {line}"):
                out.append({"cidr": net, "name": cells[1][:160], "confidence": conf if conf in CONFIDENCE else "",
                            "reference": cells[3][:300], "list_name": label})
    return out


def bundled() -> list[dict]:
    return read(BUNDLED, bundled=True)


class KnownBad:
    """Look up an address in the lists; the most specific range wins, then the later list (yours)."""

    def __init__(self, entries: list[dict] | None = None):
        self.nets = [(ipaddress.ip_network(e["cidr"]), i, e) for i, e in enumerate(entries or ())]

    def match(self, ip: str) -> dict | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        hits = [(net.prefixlen, i, e) for net, i, e in self.nets if net.version == addr.version and addr in net]
        return max(hits, key=lambda h: (h[0], h[1]))[2] if hits else None
