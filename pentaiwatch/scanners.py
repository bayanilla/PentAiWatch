"""The optional list of scanners you expect. Taken from VulnScope MAX (vulnflow/scanners.py).

Scanners you run yourself, or allow (vulnerability scanners, monitoring, attack-surface services),
can be listed in a small file:

    address,name,owner,expires,scope
    10.20.0.15,Nessus
    198.51.100.0/28,Attack-surface monitoring
    203.0.113.7,Q4 penetration test,Acme Security (J. Doe),2026-12-15,10.50.1.0/24 10.50.2.10

A row with only an address and a name is never flagged: its sessions are left out of the scoring, as
before. A row with an owner, an expiry date or a scope is an AUTHORIZATION instead: its sessions are
scored like any other's, and what it does is listed under "Authorized activity" with who owns it and
until when, not flagged. Whatever it does after the expiry date (the end of that day, UTC) or to a
host outside its scope (addresses or ranges, separated by spaces or ``;``) is flagged as usual, with
a note saying why the authorization did not cover it.

The header row and the name are optional; without a header the columns are in the order above. ``#``
starts a comment. A file named ``known_scanners.csv`` in an input folder is used automatically (it
is not read as telemetry), or pass one with ``--known-scanners``.
"""
from __future__ import annotations

import csv
import ipaddress
import os
import re
from datetime import datetime, time, timezone

from .errors import UserError

FILENAME = "known_scanners.csv"
_HEAD = {"address", "ip", "cidr", "range", "scanner", "host"}
COLUMNS = ("address", "name", "owner", "expires", "scope")


def is_list_file(path: str) -> bool:
    return os.path.basename(path).lower() == FILENAME


def is_authorization(entry: dict) -> bool:
    """True for an entry with an owner, an expiry or a scope: scored and annotated, not left out."""
    return bool(entry.get("owner") or entry.get("expires") or entry.get("scope"))


def _expires(text: str) -> str:
    """'' or the end of the given day (or the given time) as ISO text ending in Z, UTC."""
    if not text:
        return ""
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            when = datetime.combine(datetime.strptime(text, "%Y-%m-%d").date(), time(23, 59, 59))
        else:
            when = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if when.tzinfo is not None:
                when = when.astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        raise ValueError(f"'{text}' is not a date (YYYY-MM-DD) or a date and time") from None
    return when.isoformat(timespec="seconds") + "Z"


def read(path: str) -> list[dict]:
    """Return [{cidr, name, owner, expires, scope}] in file order (owner, expires and scope empty for
    a plain entry). Raises UserError with the line number."""
    out = []
    name = os.path.basename(path)
    columns: tuple[str, ...] = COLUMNS
    with open(path, encoding="utf-8-sig", newline="") as fh:
        for line, row in enumerate(csv.reader(fh), 1):
            cells = [c.strip() for c in row]
            if not any(cells) or cells[0].startswith("#"):
                continue
            if line == 1 and cells[0].lower() in _HEAD:
                heads = [c.lower() for c in cells]
                columns = tuple("address" if i == 0 else h for i, h in enumerate(heads))
                continue
            cell = {col: (cells[i] if i < len(cells) else "") for i, col in enumerate(columns)}
            try:
                net = ipaddress.ip_network(cell["address"], strict=False)
            except ValueError:
                raise UserError(f"{name} line {line}: '{cell['address']}' is not an address "
                                "or address range") from None
            scope = []
            for item in re.split(r"[\s;]+", cell.get("scope", "")):
                if not item:
                    continue
                try:
                    scope.append(str(ipaddress.ip_network(item, strict=False)))
                except ValueError:
                    raise UserError(f"{name} line {line}: scope: '{item}' is not an address or address range") from None
            try:
                expires = _expires(cell.get("expires", ""))
            except ValueError as exc:
                raise UserError(f"{name} line {line}: expires: {exc}") from None
            out.append({"cidr": str(net), "name": cell.get("name", "")[:60], "owner": cell.get("owner", "")[:80],
                        "expires": expires, "scope": scope})
    return out


class Known:
    def __init__(self, entries: list[dict] | None = None):
        self.entries = list(entries or ())
        self.nets = [(ipaddress.ip_network(e["cidr"]), e["name"]) for e in self.entries]

    def entry(self, ip: str) -> dict | None:
        """The most specific entry covering this address, or None."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        hits = [(net.prefixlen, i) for i, (net, _) in enumerate(self.nets) if net.version == addr.version and addr in net]
        return self.entries[max(hits)[1]] if hits else None

    def label(self, ip: str) -> str | None:
        """The name of the expected scanner at this address, '' if listed without one, else None."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        hits = [(net.prefixlen, name) for net, name in self.nets if net.version == addr.version and addr in net]
        return max(hits)[1] if hits else None
