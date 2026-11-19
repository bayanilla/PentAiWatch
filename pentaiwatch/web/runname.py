"""The timestamped folder each run of the upload page is saved in (from VulnScope MAX 6a7ac93,
vulnflow/runname.py)."""
from __future__ import annotations

import os
import re
import secrets
import unicodedata
from datetime import datetime

SLUG_MAX = 60           # characters of the name used in the folder name
# A run's folder name, as it appears in /runs/<id>/ addresses: "<name or 16 hex>_YYYY-MM-DD_HH-MM-SS"
# (plus "-2", "-3"... on a clash). No dots or slashes, so it can never leave the runs folder.
RUN_ID = r"[A-Za-z0-9][A-Za-z0-9_-]{0,120}"


def slug(name: str) -> str:
    """Folder-safe form of a name: ASCII letters, digits, '-' and '_' only."""
    ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    s = re.sub(r"[^A-Za-z0-9_-]+", "-", ascii_name).strip("-_")
    return re.sub(r"-{2,}", "-", s)[:SLUG_MAX].strip("-_")


def stamp(now: datetime | None = None) -> str:
    return (now or datetime.now()).strftime("%Y-%m-%d_%H-%M-%S")


def new_run(data_dir: str, name: str = "", now: datetime | None = None) -> str:
    """Create and return a new run folder under ``data_dir``: "<name>_<timestamp>", or a random
    id and the timestamp when there is no name."""
    base = f"{slug(name) or secrets.token_hex(8)}_{stamp(now)}"
    for n in range(1, 1000):
        run_id = base if n == 1 else f"{base}-{n}"
        try:
            os.makedirs(os.path.join(data_dir, run_id), mode=0o700)
            return run_id
        except FileExistsError:
            continue
    raise RuntimeError("Could not create a run folder")
