"""The optional list of scanners you expect. Taken from VulnScope MAX (vulnflow/scanners.py).

Scanners you run yourself, or allow (vulnerability scanners, monitoring, attack-surface services),
can be listed in a small file so they are never flagged:

    address,name
    10.20.0.15,Nessus
    198.51.100.0/28,Attack-surface monitoring

The header row and the name are optional; ``#`` starts a comment. A file named
``known_scanners.csv`` in an input folder is used automatically (it is not read as telemetry), or
pass one with ``--known-scanners``.
"""
from __future__ import annotations

import csv
import ipaddress
import os

from .errors import UserError

FILENAME = "known_scanners.csv"
_HEAD = {"address", "ip", "cidr", "range", "scanner", "host"}


def is_list_file(path: str) -> bool:
    return os.path.basename(path).lower() == FILENAME


def read(path: str) -> list[dict]:
    """Return [{cidr, name}] in file order. Raises UserError with the line number."""
    out = []
    with open(path, encoding="utf-8-sig", newline="") as fh:
        for line, row in enumerate(csv.reader(fh), 1):
            cells = [c.strip() for c in row]
            if not any(cells) or cells[0].startswith("#"):
                continue
            if line == 1 and cells[0].lower() in _HEAD:
                continue
            try:
                net = ipaddress.ip_network(cells[0], strict=False)
            except ValueError:
                raise UserError(f"{os.path.basename(path)} line {line}: '{cells[0]}' is not an address "
                                "or address range") from None
            out.append({"cidr": str(net), "name": (cells[1] if len(cells) > 1 else "")[:60]})
    return out


class Known:
    def __init__(self, entries: list[dict] | None = None):
        self.nets = [(ipaddress.ip_network(e["cidr"]), e["name"]) for e in entries or ()]

    def label(self, ip: str) -> str | None:
        """The name of the expected scanner at this address, '' if listed without one, else None."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        hits = [(net.prefixlen, name) for net, name in self.nets if net.version == addr.version and addr in net]
        return max(hits)[1] if hits else None
