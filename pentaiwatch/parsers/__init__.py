"""Format detection and dispatch. Taken from VulnScope MAX (vulnflow/parsers/__init__.py),
trimmed to the two sources PentAIWatch reads: Zeek logs and Palo Alto traffic/threat logs."""
from __future__ import annotations

import gzip

from . import paloalto, zeek

FORMATS = {
    "zeek": zeek.parse,
    "paloalto": paloalto.parse,
}


def detect(path: str) -> str | None:
    """Guess a file's format from its first few KB; None when it is neither Zeek nor Palo Alto."""
    opener = gzip.open if path.lower().endswith(".gz") else open
    try:
        with opener(path, "rt", encoding="utf-8-sig", errors="replace") as fh:
            head = fh.read(16384)
    except OSError:
        return None
    first = next((l for l in head.splitlines() if l.strip()), "")
    low = first.lower()
    if head.startswith("#separator") or "\n#fields" in head or first.startswith("#fields"):
        return "zeek"
    if first.lstrip().startswith("[") and '"_path"' in head[:4096]:
        return "zeek"                 # Zui/Brim JSON export: one array of records tagged by _path
    if first.lstrip().startswith("{") and ('"id.orig_h"' in first or '"_path"' in first
                                           or ('"ts"' in first and '"uid"' in first)):
        return "zeek"
    if ",TRAFFIC," in head or ",THREAT," in head or ("source address" in low and "destination address" in low):
        return "paloalto"
    return None
