"""Refuse DuckDB versions that are known to give wrong answers or cannot run the queries.

The whole detection is SQL run by DuckDB, so a faulty engine does not crash: it quietly finds
nothing. That is the one failure this tool must never have, so the version is checked before any
log is read and again when the detection starts.
"""
from __future__ import annotations

import re

import duckdb

from .errors import UserError

MINIMUM = (1, 2, 0)        # 1.1 lacks a read_csv option the session store uses
# Versions that return wrong results. 1.3.0: a join on equal addresses plus a time range drops
# matching rows (tests/test_detect.py finds no agentic source at all on it); fixed in 1.3.1.
BROKEN = {(1, 3, 0): "it drops matching rows from joins on a time range, so sources are missed"}


def version(text: str | None = None) -> tuple[int, ...]:
    """The leading numbers of a DuckDB version: '1.3.0' and '1.3.0.dev12' both give (1, 3, 0)."""
    parts = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", text if text is not None else duckdb.__version__)
    return tuple(int(p or 0) for p in parts.groups()) if parts else (0, 0, 0)


def check(text: str | None = None) -> None:
    """Raise UserError when the installed DuckDB cannot be trusted with the detection."""
    found = version(text)
    shown = text if text is not None else duckdb.__version__
    fix = "Upgrade it with:  pip install --upgrade duckdb"
    if found < MINIMUM:
        raise UserError(f"DuckDB {shown} is too old for PentAIWatch, which needs "
                        f"{'.'.join(map(str, MINIMUM))} or newer. {fix}")
    if found in BROKEN:
        raise UserError(f"DuckDB {shown} cannot be used: {BROKEN[found]}. {fix}")
