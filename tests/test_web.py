"""The upload page (python -m pentaiwatch serve): its safety checks, both ways of starting an
analysis, runs in the background, and serving a run's files. A real server on a free loopback port
answers real HTTP requests."""
import base64
import hashlib
import http.client
import io
import json
import os
import re
import tempfile
import threading
import time
import unittest
import uuid
from collections import namedtuple
from http.server import ThreadingHTTPServer
from unittest import mock

from pentaiwatch.web import jobs, multipart, runs, upload
from pentaiwatch.web.server import is_loopback_host, make_handler
from tests import kit, sample

Reply = namedtuple("Reply", "status headers body")


class Server(unittest.TestCase):
    token = None

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data = os.path.join(self.tmp.name, "runs")
        os.makedirs(self.data)
        handler = make_handler(self.data, max_upload=10 * 1024 * 1024, access_token=self.token)
        handler.log_message = lambda *a: None          # keep the test output readable
        self.app = handler.app
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.srv.daemon_threads = True
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def ask(self, method, path, body=None, headers=None, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        h = {"Host": host or f"127.0.0.1:{self.port}", **(headers or {})}
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        reply = Reply(r.status, {k.lower(): v for k, v in r.getheaders()}, r.read().decode("utf-8", "replace"))
        conn.close()
        return reply

    def form(self, path, fields):
        from urllib.parse import urlencode
        return self.ask("POST", path, urlencode(fields), {"Content-Type": "application/x-www-form-urlencoded"})

    def upload(self, files, fields=None):
        """POST /analyze with ``files`` as [(field, filename, bytes)]."""
        b = uuid.uuid4().hex
        out = io.BytesIO()
        for name, value in {"csrf": self.app.csrf, **(fields or {})}.items():
            out.write(f'--{b}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
        for field, filename, data in files:
            out.write(f'--{b}\r\nContent-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
                      "Content-Type: application/octet-stream\r\n\r\n".encode() + data + b"\r\n")
        out.write(f"--{b}--\r\n".encode())
        return self.ask("POST", "/analyze", out.getvalue(), {"Content-Type": f"multipart/form-data; boundary={b}"})

    def logs(self):
        d = os.path.join(self.tmp.name, "logs")
        os.makedirs(d, exist_ok=True)
        kit.write_zeek_conn(os.path.join(d, "conn.log"), sample.sessions())
        return d

    def wait(self, location, seconds=60):
        """Wait until the run behind ``location`` stops running; its status."""
        run_id = location.strip("/").split("/")[1]
        end = time.time() + seconds
        while time.time() < end:
            status = json.loads(self.ask("GET", f"/runs/{run_id}/status").body)
            if status["state"] != "running":
                return run_id, status
            time.sleep(0.1)
        self.fail("the run did not finish")


class Gate(Server):
    def test_other_host_names_are_refused(self):
        self.assertEqual(self.ask("GET", "/", host="attacker.example:%d" % self.port).status, 421)
        self.assertEqual(self.ask("GET", "/", host=f"localhost:{self.port}").status, 200)

    def test_posts_from_other_sites_are_refused(self):
        r = self.ask("POST", "/browse", json.dumps({"csrf": self.app.csrf}),
                     {"Content-Type": "application/json", "Origin": "http://attacker.example"})
        self.assertEqual(r.status, 403)
        r = self.ask("POST", "/browse", json.dumps({"csrf": self.app.csrf}), {"Origin": "null"})
        self.assertEqual(r.status, 403)          # a sandboxed run file posts with Origin: null

    def test_csrf_token_is_required(self):
        self.assertEqual(self.form("/analyze-folder", {"path": self.logs()}).status, 403)
        self.assertEqual(self.form("/analyze-folder", {"path": self.logs(), "csrf": "wrong"}).status, 403)
        self.assertEqual(self.ask("POST", "/browse", json.dumps({"path": "/"})).status, 403)
        self.assertEqual(self.upload([], {"csrf": "wrong"}).status, 403)
        self.assertEqual(os.listdir(self.data), [])          # the refused upload left nothing behind

    def test_page_policy_names_its_scripts(self):
        r = self.ask("GET", "/")
        policy = r.headers["content-security-policy"]
        scripts = re.findall(r"<script>(.*?)</script>", r.body, re.S)
        self.assertEqual(len(scripts), 3)
        for s in scripts:
            digest = base64.b64encode(hashlib.sha256(s.encode()).digest()).decode()
            self.assertIn(f"'sha256-{digest}'", policy)
        self.assertNotIn("unsafe-inline' ;", policy)
        self.assertNotRegex(policy, r"script-src[^;]*unsafe")
        self.assertEqual(r.headers["x-frame-options"], "DENY")
        self.assertEqual(r.headers["cache-control"], "no-store")

    def test_json_answers_run_nothing(self):
        r = self.ask("POST", "/browse", json.dumps({"csrf": self.app.csrf, "path": self.tmp.name}))
        self.assertEqual(r.status, 200)
        self.assertTrue(r.headers["content-security-policy"].startswith("default-src 'none'"))
        self.assertIn("runs", json.loads(r.body)["dirs"])

    def test_loopback_names(self):
        for host in ("127.0.0.1", "localhost", "::1", "[::1]", "127.0.0.2"):
            self.assertTrue(is_loopback_host(host), host)
        for host in ("0.0.0.0", "192.168.1.10", "example.com"):
            self.assertFalse(is_loopback_host(host), host)


class RemoteGate(Server):
    token = "s3cret-token"

    def test_every_request_needs_the_token(self):
        self.assertEqual(self.ask("GET", "/").status, 401)
        r = self.ask("GET", "/?token=wrong")
        self.assertEqual(r.status, 401)
        r = self.ask("GET", "/?token=s3cret-token")
        self.assertEqual(r.status, 303)
        cookie = r.headers["set-cookie"].split(";")[0]
        self.assertIn("HttpOnly", r.headers["set-cookie"])
        self.assertEqual(self.ask("GET", "/", headers={"Cookie": cookie}).status, 200)
        # remote access: any host name, but still the token
        self.assertEqual(self.ask("GET", "/", headers={"Cookie": cookie}, host="box.lan:8770").status, 200)
        self.assertEqual(self.ask("GET", "/", host="box.lan:8770").status, 401)


class Analyze(Server):
    def test_folder_runs_in_the_background_and_flags_the_agent(self):
        r = self.form("/analyze-folder", {"path": self.logs(), "csrf": self.app.csrf})
        self.assertEqual(r.status, 303)
        run_id, status = self.wait(r.headers["location"])
        self.assertEqual(status["state"], "done")
        page = self.ask("GET", f"/runs/{run_id}/")
        self.assertIn("1 source flagged", page.body)
        self.assertIn(sample.AGENT, page.body)
        self.assertIn(f"explorer.html#timeline={sample.AGENT}", page.body)
        root = os.path.join(self.data, run_id)
        with open(os.path.join(root, "in", "SOURCE.txt"), encoding="utf-8") as fh:
            self.assertIn("conn.log", fh.read())
        self.assertEqual(os.listdir(os.path.join(root, "in")), ["SOURCE.txt"])    # read in place, not copied
        explorer = self.ask("GET", f"/runs/{run_id}/explorer.html")
        self.assertEqual(explorer.status, 200)
        self.assertTrue(explorer.headers["content-security-policy"].startswith("sandbox allow-scripts "))
        self.assertNotIn("allow-same-origin", explorer.headers["content-security-policy"])
        report = self.ask("GET", f"/runs/{run_id}/report.md").body
        self.assertNotIn("typed on the upload page", report)
        listed = self.ask("GET", "/").body
        self.assertIn("Recent reports", listed)
        self.assertIn(f'/runs/{run_id}/', listed)

    def test_typed_internal_networks_reach_the_report(self):
        r = self.form("/analyze-folder", {"path": self.logs(), "csrf": self.app.csrf,
                                          "internal_nets": "10.0.0.0/8, 192.168.0.0/16"})
        run_id, status = self.wait(r.headers["location"])
        self.assertEqual(status["state"], "done")
        report = self.ask("GET", f"/runs/{run_id}/report.md").body
        self.assertIn("Internal ranges: 10.0.0.0/8, 192.168.0.0/16 (internal_nets typed on the upload page", report)

    def test_bad_internal_networks_are_refused_before_a_run(self):
        r = self.form("/analyze-folder", {"path": self.logs(), "csrf": self.app.csrf, "internal_nets": "10.0.0.0/8 lan"})
        self.assertEqual(r.status, 200)
        self.assertIn("&#x27;lan&#x27; is not an address", r.body)
        self.assertIn('value="10.0.0.0/8 lan"', r.body)          # what was typed is kept
        self.assertEqual(os.listdir(self.data), [])

    def test_missing_folder(self):
        r = self.form("/analyze-folder", {"path": os.path.join(self.tmp.name, "nope"), "csrf": self.app.csrf})
        self.assertIn("Folder not found", r.body)
        r = self.form("/analyze-folder", {"path": "", "csrf": self.app.csrf})
        self.assertIn("Choose a folder first", r.body)

    def test_the_runs_folder_itself_is_skipped(self):
        r = self.form("/analyze-folder", {"path": self.data, "csrf": self.app.csrf})
        self.assertIn("No files found", r.body)

    def test_upload_keeps_names_so_a_settings_file_is_found(self):
        logs = self.logs()
        with open(os.path.join(logs, "conn.log"), "rb") as fh:
            conn = fh.read()
        settings = json.dumps({"internal_nets": ["10.0.0.0/8"]}).encode()
        r = self.upload([("folder", "case/zeek/conn.log", conn), ("folder", "case/pentaiwatch.json", settings),
                         ("files", "../../escape.log", b"")])
        self.assertEqual(r.status, 303)
        run_id, status = self.wait(r.headers["location"])
        self.assertEqual(status["state"], "done", status)
        self.assertEqual(jobs.read_status(os.path.join(self.data, run_id))["source"], "Upload of 2 files")
        root = os.path.join(self.data, run_id, "in")
        self.assertTrue(os.path.isfile(os.path.join(root, "case", "zeek", "conn.log")))
        report = self.ask("GET", f"/runs/{run_id}/report.md").body
        self.assertIn(os.path.join("in", "case", "pentaiwatch.json") + " (found among the input files)", report)
        self.assertIn("1 source flagged", self.ask("GET", f"/runs/{run_id}/").body)

    def test_upload_over_the_cap_is_not_read(self):
        self.app.max_upload = 1000
        r = self.upload([("files", "conn.log", b"x" * 2000)])
        self.assertEqual(r.status, 200)
        self.assertIn("An upload can be up to", r.body)
        self.assertEqual(os.listdir(self.data), [])

    def test_upload_needs_free_disk(self):
        usage = namedtuple("usage", "total used free")(10 ** 12, 10 ** 12, 1024)
        with mock.patch("pentaiwatch.web.upload.shutil.disk_usage", return_value=usage):
            r = self.upload([("files", "conn.log", b"x" * 100)])
        self.assertIn("not enough free disk space", r.body)
        self.assertEqual(os.listdir(self.data), [])

    def test_empty_upload(self):
        r = self.upload([("files", "", b"")])
        self.assertIn("Choose a folder of logs or at least one log file", r.body)
        self.assertEqual(os.listdir(self.data), [])

    def test_a_failed_run_says_why(self):
        bad = os.path.join(self.tmp.name, "bad")
        os.makedirs(bad)
        with open(os.path.join(bad, "notes.txt"), "w") as fh:
            fh.write("hello\n")
        r = self.form("/analyze-folder", {"path": bad, "csrf": self.app.csrf})
        run_id, status = self.wait(r.headers["location"])
        self.assertEqual(status["state"], "failed")
        page = self.ask("GET", f"/runs/{run_id}/").body
        self.assertIn("The analysis did not finish", page)
        self.assertIn("Failed", self.ask("GET", "/").body)


class Background(Server):
    def slow_run(self):
        """A stand-in for pipeline.run that waits until released."""
        release = threading.Event()
        self.addCleanup(release.set)

        def run(files, out, workdir=None, internal_nets=None, report=None):
            release.wait(30)
            os.makedirs(out)
            return {"sessions": 3, "warnings": [], "detection": {"findings": []}, "explorer": {}}, {}
        return release, run

    def start(self, run):
        real = self.app.jobs.start
        with mock.patch.object(self.app.jobs, "start", lambda *a, **k: real(*a, run=run)):
            return self.form("/analyze-folder", {"path": self.logs(), "csrf": self.app.csrf})

    def test_progress_page_then_results_and_one_run_at_a_time(self):
        release, run = self.slow_run()
        r = self.start(run)
        self.assertEqual(r.status, 303)
        run_id = r.headers["location"].split("/")[2]
        page = self.ask("GET", f"/runs/{run_id}/")
        self.assertIn('id="busy" role="alertdialog"', page.body)
        self.assertNotIn('id="busy" role="alertdialog" aria-modal="true" aria-labelledby="busy-title" '
                         'aria-describedby="busy-hint" hidden', page.body)
        self.assertIn(f'"status": "/runs/{run_id}/status"', page.body)
        status = json.loads(self.ask("GET", f"/runs/{run_id}/status").body)
        self.assertEqual(status["state"], "running")
        # a second analysis is refused while one runs, and leaves no run folder behind
        again = self.form("/analyze-folder", {"path": self.logs(), "csrf": self.app.csrf})
        self.assertIn("Another analysis is already running", again.body)
        self.assertEqual(os.listdir(self.data), [run_id])
        self.assertIn("Another analysis is already running", self.upload([("files", "conn.log", b"x")]).body)
        self.assertEqual(os.listdir(self.data), [run_id])
        self.assertIn("Running", self.ask("GET", "/").body)
        release.set()
        _, status = self.wait(f"/runs/{run_id}/")
        self.assertEqual(status["state"], "done")
        self.assertIn("3 sessions read; 0 sources flagged", self.ask("GET", f"/runs/{run_id}/").body)

    def test_a_run_cut_short_by_a_restart_says_so(self):
        root = os.path.join(self.data, "abc_2026-01-01_00-00-00")
        os.makedirs(root)
        jobs.write_status(root, {"state": "running", "started": "2026-01-01T00:00:00Z", "source": "Folder x"})
        self.assertEqual(json.loads(self.ask("GET", "/runs/abc_2026-01-01_00-00-00/status").body)["state"], "stopped")
        self.assertIn("The analysis stopped", self.ask("GET", "/runs/abc_2026-01-01_00-00-00/").body)
        self.assertIn("Stopped", self.ask("GET", "/").body)


class RunFiles(Server):
    def setUp(self):
        super().setUp()
        self.root = os.path.join(self.data, "r1_2026-01-01_00-00-00")
        os.makedirs(os.path.join(self.root, "out"))
        os.makedirs(os.path.join(self.root, "in"))
        with open(os.path.join(self.root, "in", "conn.log"), "w") as fh:
            fh.write("secret\n")
        with open(os.path.join(self.root, "out", "report.html"), "w") as fh:
            fh.write("<p>report</p>")
        jobs.write_status(self.root, {"state": "done", "started": "2026-01-01T00:00:00Z", "summary": {}})

    def test_only_out_is_served(self):
        base = "/runs/r1_2026-01-01_00-00-00/"
        self.assertEqual(self.ask("GET", base + "report.html").status, 200)
        for path in ("../in/conn.log", "..%2Fin%2Fconn.log", "../STATUS.json", "%2e%2e/in/conn.log",
                     "../../../etc/passwd", "", "missing.html"):
            r = self.ask("GET", base + path)
            if path == "":
                self.assertEqual(r.status, 200)          # the run's own page
                continue
            self.assertEqual(r.status, 404, path)
            self.assertNotIn("secret", r.body)
        self.assertEqual(self.ask("GET", "/runs/r1_2026-01-01_00-00-00").status, 303)
        self.assertEqual(self.ask("GET", "/runs/no-such-run/").status, 404)
        self.assertEqual(self.ask("GET", "/runs/no-such-run/status").status, 404)
        self.assertEqual(self.ask("GET", "/runs/..%2F/").status, 404)

    def test_recent_ignores_other_folders(self):
        os.makedirs(os.path.join(self.data, ".hidden"))
        os.makedirs(os.path.join(self.data, "no-status"))
        self.assertEqual([r for r, *_ in runs.recent(self.app)], ["r1_2026-01-01_00-00-00"])


class RunState(unittest.TestCase):
    """A run that finishes while its state is being read is read as finished, never as stopped."""

    def test_finishing_between_the_two_looks(self):
        with tempfile.TemporaryDirectory() as root:
            jobs.write_status(root, {"state": "running"})

            def finish(run_id):                      # the job ends at the worst moment: final status, then off the list
                jobs.write_status(root, {"state": "done"})
                return False

            app = mock.Mock(run_root=lambda run_id: root)
            app.jobs.is_live.side_effect = finish
            status, live = runs.read_run(app, "r1")
            self.assertEqual(runs.state(status, live), "done")

    def test_running_and_stopped(self):
        self.assertEqual(runs.state({"state": "running"}, True), "running")
        self.assertEqual(runs.state({"state": "running"}, False), "stopped")
        self.assertEqual(runs.state({"state": "odd"}, True), "failed")


class Details(Server):
    NAME = 'DMZ <sweep> & "review"'

    def test_named_folder_run(self):
        r = self.form("/analyze-folder", {"path": self.logs(), "csrf": self.app.csrf, "report_name": self.NAME,
                                          "report_description": "Case 42.\r\n  Asked by the SOC.\r\n\r\n\r\nSecond  part."})
        run_id, status = self.wait(r.headers["location"])
        self.assertEqual(status["state"], "done")
        self.assertRegex(run_id, r"^DMZ-sweep-review_\d{4}-\d\d-\d\d_\d\d-\d\d-\d\d$")
        md = self.ask("GET", f"/runs/{run_id}/report.md").body
        self.assertIn(f"# PentAIWatch report\n\n**Report:** {self.NAME}\n\n> Case 42.\n> Asked by the SOC.\n\n> Second part.\n", md)
        page = self.ask("GET", f"/runs/{run_id}/report.html").body
        self.assertIn("<title>DMZ &lt;sweep&gt; &amp; &quot;review&quot; · PentAIWatch report</title>", page)
        self.assertIn("<blockquote>\n<p>Case 42.</p>\n<p>Asked by the SOC.</p>\n</blockquote>", page)
        self.assertNotIn("<sweep>", page)
        explorer = self.ask("GET", f"/runs/{run_id}/explorer.html").body
        self.assertIn("<title>DMZ &lt;sweep&gt; &amp; &quot;review&quot; · Explorer · PentAIWatch</title>", explorer)
        res = json.loads(self.ask("GET", f"/runs/{run_id}/results.json").body)
        self.assertEqual(res["report"], {"name": self.NAME, "description": "Case 42.\nAsked by the SOC.\n\nSecond part."})
        run_page = self.ask("GET", f"/runs/{run_id}/").body
        self.assertIn("Results: DMZ &lt;sweep&gt; &amp; &quot;review&quot;</h1>", run_page)
        self.assertIn("Case 42.<br>Asked by the SOC.", run_page)
        self.assertIn("<strong>DMZ &lt;sweep&gt; &amp; &quot;review&quot;</strong>", self.ask("GET", "/").body)

    def test_named_upload_is_moved_to_its_named_folder(self):
        with open(os.path.join(self.logs(), "conn.log"), "rb") as fh:
            conn = fh.read()
        r = self.upload([("files", "conn.log", conn)], {"report_name": "Upload one"})
        run_id, status = self.wait(r.headers["location"])
        self.assertEqual(status["state"], "done")
        self.assertTrue(run_id.startswith("Upload-one_"))
        self.assertEqual(os.listdir(self.data), [run_id])
        self.assertTrue(os.path.isfile(os.path.join(self.data, run_id, "in", "conn.log")))
        self.assertIn("**Report:** Upload one", self.ask("GET", f"/runs/{run_id}/report.md").body)

    def test_details_are_kept_after_an_error(self):
        r = self.form("/analyze-folder", {"path": "/no/such/folder", "csrf": self.app.csrf,
                                          "report_name": "Keep me", "report_description": "and me"})
        self.assertIn('value="Keep me"', r.body)
        self.assertIn(">and me</textarea>", r.body)

    def test_unnamed_runs_say_nothing(self):
        r = self.form("/analyze-folder", {"path": self.logs(), "csrf": self.app.csrf})
        run_id, _ = self.wait(r.headers["location"])
        self.assertRegex(run_id, r"^[0-9a-f]{16}_")
        md = self.ask("GET", f"/runs/{run_id}/report.md").body
        self.assertNotIn("**Report:**", md)
        self.assertIn("<title>PentAIWatch report</title>", self.ask("GET", f"/runs/{run_id}/report.html").body)


class Clean(unittest.TestCase):
    def test_clean(self):
        from pentaiwatch import details
        self.assertEqual(details.clean(None, None), {"name": "", "description": ""})
        self.assertEqual(details.clean("  a \n b\t", "x\r\ny\r\rz"), {"name": "a b", "description": "x\ny\n\nz"})
        self.assertEqual(len(details.clean("n" * 500, "d" * 5000)["name"]), details.NAME_MAX)
        self.assertEqual(len(details.clean("n", "d" * 5000)["description"]), details.DESCRIPTION_MAX)


class Placer(unittest.TestCase):
    def test_names_are_kept_safe_and_inside(self):
        with tempfile.TemporaryDirectory() as d:
            place = upload._placer(d)
            real = os.path.realpath(d)
            self.assertEqual(place(0, "case/zeek/conn.log"), os.path.join(real, "case", "zeek", "conn.log"))
            self.assertEqual(place(1, "../../etc/passwd"), os.path.join(real, "etc", "passwd"))
            self.assertEqual(place(2, "C:\\logs\\a b.log"), os.path.join(real, "C_", "logs", "a_b.log"))
            self.assertEqual(place(3, ".."), os.path.join(real, "upload-4"))
            open(os.path.join(real, "x.log"), "w").close()
            self.assertEqual(place(4, "x.log"), os.path.join(real, "x-2.log"))
            deep = "/".join("abcdefghijk") + "/f.log"
            self.assertEqual(len(os.path.relpath(place(5, deep), real).split(os.sep)), 8)

    def test_a_link_out_of_the_folder_is_refused(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as other:
            os.symlink(other, os.path.join(d, "link"))
            with self.assertRaises(multipart.MultipartError):
                upload._placer(d)(0, "link/conn.log")


class Nets(unittest.TestCase):
    def test_parse(self):
        self.assertIsNone(upload._nets("  "))
        self.assertEqual(upload._nets("10.0.0.0/8,192.168.1.0/24  2001:db8::/32"),
                         ["10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32"])
        with self.assertRaises(upload.UserError):
            upload._nets("10.0.0.0/33")


if __name__ == "__main__":
    unittest.main()
