"""Which view answers which path. Patterns match the whole path (without the query); a view is
called as ``view(req, *groups)``."""
from __future__ import annotations

import re

from . import folders, runs, upload
from .runname import RUN_ID

GET = [
    (re.compile(r"/(?:index\.html)?"), upload.page_view),
    (re.compile(rf"/runs/({RUN_ID})/status"), runs.status_view),
    (re.compile(rf"/runs/({RUN_ID})"), runs.slash),
    (re.compile(rf"/runs/({RUN_ID})/(.*)"), runs.get),
]
POST = [
    (re.compile(r"/analyze"), upload.analyze_upload),
    (re.compile(r"/analyze-folder"), upload.analyze_folder),
    (re.compile(r"/browse"), folders.browse),
    (re.compile(r"/pick-folder"), folders.pick),
]
