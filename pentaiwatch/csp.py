"""The Content-Security-Policy that the report and the Explorer page carry.

Both pages are opened straight from disk, and both are built from logs that an outsider's traffic
helped to write. Everything they show is escaped; this is the second line behind that. A page may
run only the scripts PentAIWatch wrote into it, each named by its SHA-256 (the report has none, so
nothing runs in it), and it may load nothing and contact nothing: no script, image, font, frame or
request to anywhere else. Text that reached a page some other way can then neither run nor send
anything out."""
from __future__ import annotations

import base64
import hashlib
from collections.abc import Iterable


def policy(scripts: Iterable[str] = ()) -> str:
    """The policy for a page whose inline scripts are ``scripts`` (the exact text between the tags)."""
    hashes = " ".join("'sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii") + "'"
                      for text in scripts)
    return ("default-src 'none'; " + (f"script-src {hashes}; " if hashes else "")
            # the pages style themselves inline; the only image is the empty data: icon
            + "style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'")


def meta(scripts: Iterable[str] = ()) -> str:
    """The policy as the <meta> tag that must come before anything else in the page's <head>."""
    return f'<meta http-equiv="Content-Security-Policy" content="{policy(scripts)}">'
