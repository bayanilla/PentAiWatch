"""MITRE ATT&CK and MITRE ATLAS labels for the detectors (``data/frameworks.csv``).

Labels only: they say which published technique a detector's behaviour corresponds to, so a finding
can be filed under the framework a team already reports in. They change nothing about what is
detected or flagged. ATT&CK describes the network behaviour; ATLAS (Adversarial Threat Landscape for
AI Systems) describes what is specific to an AI agent doing it. A label's ``fit`` is "direct" when
the detector sees the technique itself and "possible" when the behaviour is consistent with it and
connection logs cannot confirm it: whether an agent or a person chose the next step is never in a log.
"""
from __future__ import annotations

import csv
import os
import re
from functools import lru_cache

BUNDLED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "frameworks.csv")
FRAMEWORKS = {"attack": "ATT&CK", "atlas": "ATLAS"}
FITS = ("direct", "possible")
_ID = {"attack": re.compile(r"T\d{4}(\.\d{3})?"), "atlas": re.compile(r"AML\.T\d{4}(\.\d{3})?")}

# Detector key -> the names its row can have in the report's "What could be checked" table. Every
# coverage row must be here (tests/test_frameworks.py); a row that is not a detector maps to no key.
DETECTORS: dict[str, tuple[str, ...]] = {
    "sweep": ("Sweep and narrowing (signals 1 and 2)",),
    "burst_pause": ("Timing pattern a: burst and pause",),
    "steady": ("Timing pattern b and fixed-interval repetition",),
    "spray": ("High-rate repeated connections",),
    "login_spray": ("Repeated failed-login pattern",),
    "rotation": ("Rotating sources",),
    "shared_sweep": ("Shared sweeps",),
    "known_bad": ("Published attacker addresses (context, not behaviour)",),
    "nonstop": ("No overnight break",),
    "tool_user_agent": ("Agentic tools' user agents (Zeek http.log)", "Agentic tools' user agents, and watched names"),
    "watched_names": ("Watched names such as AI model APIs (Zeek dns, http and ssl logs)",
                      "Agentic tools' user agents, and watched names"),
    "beacon": ("Fixed-interval calls out",),
    "outbound": ("Outbound to attacker infrastructure",),
}
# Rows of that table that are not detectors: a baseline, and levels that are not built.
NOT_DETECTORS = ("Regular clients", "Levels 2 and 3 (threat logs)")
# What a finding (sweep, narrowing and a timing pattern together) is labelled with.
FINDING = ("sweep", "burst_pause")


def url(framework: str, technique: str) -> str:
    if framework == "attack":
        return "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"
    return "https://atlas.mitre.org/techniques/" + technique


@lru_cache(maxsize=1)
def labels() -> dict[str, list[dict]]:
    """Per detector key, its labels in file order: framework, id, name, tactic, fit, why, url. A
    detector whose only row is ``none`` has an empty list; its reason is in ``reasons()``."""
    return _read()[0]


@lru_cache(maxsize=1)
def reasons() -> dict[str, str]:
    """Per detector key with no technique, why not."""
    return _read()[1]


@lru_cache(maxsize=1)
def _read() -> tuple[dict[str, list[dict]], dict[str, str]]:
    out: dict[str, list[dict]] = {key: [] for key in DETECTORS}
    none: dict[str, str] = {}
    with open(BUNDLED, encoding="utf-8", newline="") as fh:
        for n, row in enumerate(csv.DictReader(line for line in fh if not line.startswith("#")), start=2):
            row = {k: (v or "").strip() for k, v in row.items()}
            key, framework = row["detector"], row["framework"]
            where = f"frameworks.csv row {n}"
            if key not in DETECTORS:
                raise ValueError(f"{where}: '{key}' is not a detector")
            if framework == "none":
                none[key] = row["why"]
                continue
            if framework not in FRAMEWORKS or not _ID[framework].fullmatch(row["id"]):
                raise ValueError(f"{where}: '{row['id']}' is not an {FRAMEWORKS.get(framework, 'ATT&CK or ATLAS')} "
                                 "technique id")
            if row["fit"] not in FITS or not row["name"] or not row["tactic"] or not row["why"]:
                raise ValueError(f"{where}: name, tactic and why are needed, and fit is direct or possible")
            out[key].append({**{k: row[k] for k in ("framework", "id", "name", "tactic", "fit", "why")},
                             "url": url(framework, row["id"])})
    missing = [key for key in DETECTORS if not out[key] and key not in none]
    if missing:
        raise ValueError("frameworks.csv has no row for: " + ", ".join(missing))
    return out, none


def keys_for(detector: str) -> list[str]:
    """The detector keys a coverage row's name stands for."""
    return [key for key, names in DETECTORS.items() if detector in names]


def ids_for(detector: str) -> list[str]:
    """Technique ids for a coverage row, ATT&CK first, without repeats."""
    found = [lab for key in keys_for(detector) for lab in labels()[key]]
    found.sort(key=lambda lab: lab["framework"] != "attack")
    return list(dict.fromkeys(lab["id"] for lab in found))


def finding_labels() -> list[dict]:
    return [lab for key in FINDING for lab in labels()[key]]


def text(lab: dict) -> str:
    """"T1595.001 Scanning IP Blocks (ATT&CK)", with "possible" said when it is."""
    return (f"{lab['id']} {lab['name']} ({FRAMEWORKS[lab['framework']]}"
            + (", possible)" if lab["fit"] == "possible" else ")"))
