"""Start the upload page (after VulnScope MAX 6a7ac93, vulnflow/web/server.py): on this computer's
loopback address only, unless --allow-remote, which then requires an access token on every request.
"""
from __future__ import annotations

import errno
import ipaddress
import os
import secrets
import threading
import webbrowser
from http.server import ThreadingHTTPServer

from .. import resources
from .app import App
from .handler import Handler

DEFAULT_PORT = 8770
MAX_UPLOAD = 20 * 1024 ** 3        # uploads stream to disk; the free-disk check also applies
PORT_TRIES = 20                    # when the default port is taken, try the next ones


def make_handler(data_dir: str, max_upload: int = MAX_UPLOAD, access_token: str | None = None,
                 allowed_hosts: tuple[str, ...] = ()):
    """The request handler class for one server. Without ``access_token`` it answers only requests
    whose Host header names this computer's loopback address (or one of ``allowed_hosts``)."""
    app = App(data_dir=data_dir, max_upload=max_upload, access_token=access_token,
              allowed_hosts=frozenset(h.lower() for h in allowed_hosts))
    return type("PentAIWatchHandler", (Handler,), {"app": app})


def is_loopback_host(host: str) -> bool:
    """True for a bind address that only this computer can reach."""
    host = host.strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _bind(host: str, port: int, handler, try_next: bool) -> ThreadingHTTPServer:
    for p in range(port, port + (PORT_TRIES if try_next else 1)):
        try:
            return ThreadingHTTPServer((host, p), handler)
        except OSError as exc:
            if exc.errno != errno.EADDRINUSE or not try_next:
                raise SystemExit(f"Cannot listen on {host}:{p}: {exc.strerror or exc}.") from None
    raise SystemExit(f"Ports {port} to {port + PORT_TRIES - 1} are all in use; choose one with --port.")


def serve(host: str = "127.0.0.1", port: int | None = None, data_dir: str = "pentaiwatch_runs",
          max_upload: int = MAX_UPLOAD, allow_remote: bool = False, open_browser: bool = False) -> None:
    """Serve the upload page until Ctrl+C. ``port`` None means DEFAULT_PORT, or the next free one."""
    remote = not is_loopback_host(host)
    if remote and not allow_remote:
        raise SystemExit(f"Refusing to listen on {host}: the upload page can read any folder this account can. "
                         "Use the default 127.0.0.1, or pass --allow-remote to require an access token.")
    os.umask(0o077)                                     # runs hold raw logs and results
    data_dir = os.path.abspath(data_dir)
    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    os.chmod(data_dir, 0o700)
    token = secrets.token_urlsafe(24) if remote else None
    handler = make_handler(data_dir, max_upload, access_token=token)
    srv = _bind(host, port or DEFAULT_PORT, handler, try_next=port is None)
    bound = srv.server_address[1]
    shown = f"[{host}]" if ":" in host else host
    if token:
        url = f"http://{shown}:{bound}/?token={token}"
        print(f"Upload page (remote access; keep this link private): {url}")
        print("Traffic is plain HTTP; use it only on a trusted network or through an SSH tunnel.")
    else:
        url = f"http://{shown}:{bound}/"
        print(f"Upload page: {url}")
    print(f"Runs are kept in {data_dir}")
    print(f"Analyses: {resources.max_jobs()} at a time; " + resources.plan(workdir=data_dir).describe())
    print("Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.5, webbrowser.open, (url,)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
