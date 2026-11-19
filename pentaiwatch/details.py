"""The report details an analyst can give a run (after VulnScope MAX 6a7ac93, vulnflow/runname.py):
a one-line name and a description, shown at the top of the report and in the Explorer, and kept in
results.json as ``report``. MAX's third field, the network a report came from, is for its Compare
page, which PentAIWatch does not have."""
from __future__ import annotations

import re

NAME_MAX = 100          # characters kept from the report name
DESCRIPTION_MAX = 2000  # characters kept from the description


def clean(name: str | None, description: str | None) -> dict:
    """{"name", "description"}: the name on one line, the description with its paragraphs kept and
    each line's spacing tidied, both cut to their maximum length."""
    name = " ".join((name or "").split())[:NAME_MAX]
    lines = [" ".join(ln.split()) for ln in (description or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(lines).strip())[:DESCRIPTION_MAX].strip()
    return {"name": name, "description": text}
