"""What one upload-page server remembers between requests: where its runs go, the largest upload
it takes, the access token and host names for remote use, its CSRF token, the runs it is running,
and what was typed on the upload page (kept after an error)."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field

from .jobs import Jobs


@dataclass
class App:
    data_dir: str                           # one folder per run: <data_dir>/<run id>/{in,out}
    max_upload: int                         # bytes
    access_token: str | None = None         # remote access: every request must carry it (cookie)
    allowed_hosts: frozenset[str] = frozenset()   # Host headers accepted besides loopback
    csrf: str = field(default_factory=lambda: secrets.token_urlsafe(24))   # guards posts from other sites
    jobs: Jobs = field(default_factory=Jobs)
    last_path: str = ""                     # kept on the upload page after an error
    last_nets: str = ""

    def csrf_ok(self, token) -> bool:
        return isinstance(token, str) and secrets.compare_digest(token.encode(), self.csrf.encode())

    def run_root(self, run_id: str) -> str:
        """<data_dir>/<run id>: the run's uploaded files (in/), working files and results (out/)."""
        return os.path.join(self.data_dir, run_id)

    def run_out(self, run_id: str) -> str:
        return os.path.realpath(os.path.join(self.data_dir, run_id, "out"))
