import http.client
import json
import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from tester.demo import start_demo
from tester.network import Client, NetworkError, Response, ScanCancelled, address_allowed, normalize_url, origin
from tester.reports import export_report
from tester.rules import inspect
from tester.scanner import DEFAULTS, run_scan, validate_options
from tester.server import Application, make_server
from tester.storage import Store


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.demo = start_demo()
        cls.url = f"http://127.0.0.1:{cls.demo.server_port}/"
        cls.options = {**DEFAULTS, "allow_private": True, "exposure_checks": True, "rate": 5}
        cls.result = run_scan(cls.url, cls.options)

    @classmethod
    def tearDownClass(cls):
        cls.demo.shutdown()
        cls.demo.server_close()

    def test_real_crawl_and_exposure(self):
        r = self.result
        self.assertEqual(r["status"], "completed")
        self.assertEqual(len(r["pages"]), 4)
        self.assertEqual(r["requests"], 21)
        rules = {f["rule"] for f in r["findings"]}
        self.assertTrue({"exposure.env", "exposure.git", "exposure.openapi", "cors.reflected", "forms.password_get", "forms.password_http", "http.error", "cookies.secure", "content.directory"} <= rules)
        self.assertFalse(any("logout" in p["url"] for p in r["pages"]))
        self.assertFalse(any("?" in p["url"] for p in r["pages"]))

    def test_secrets_not_persisted_in_result(self):
        serialized = json.dumps(self.result)
        for value in ("SYNTHETIC-DEMO-NOT-A-REAL-SECRET", "SYNTHETIC-COOKIE-VALUE", "private-example"):
            self.assertNotIn(value, serialized)

    def test_default_private_block(self):
        with self.assertRaises(NetworkError):
            Client(delay=0).get(self.url)

    def test_destination_guards(self):
        for address in ("169.254.169.254", "100.100.100.200", "fd00:ec2::254", "fd20:ce::254", "::ffff:169.254.169.254", "0.0.0.0", "224.0.0.1", "fe80::1"):
            self.assertFalse(address_allowed(address, True), address)
        self.assertFalse(address_allowed("127.0.0.1", False))
        self.assertTrue(address_allowed("127.0.0.1", True))
        self.assertTrue(address_allowed("::1", True))
        self.assertFalse(address_allowed("::1", False))
        self.assertTrue(address_allowed("192.168.1.10", True))
        self.assertFalse(address_allowed("192.168.1.10", False))
        self.assertTrue(address_allowed("8.8.8.8", False))

    def test_url_validation(self):
        for value in ("file:///tmp/a", "https://user:pass@example.com/", "http://example.com\\evil", "http://example.com/\n", "https://example.com:99999/"):
            with self.assertRaises(ValueError, msg=value):
                normalize_url(value)
        self.assertEqual(normalize_url("https://EXAMPLE.com:443/a#fragment"), "https://example.com/a")

    def test_cancellation(self):
        event = threading.Event()
        event.set()
        result = run_scan(self.url, self.options, event)
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(result["requests"], 0)

    def test_page_limits_and_baseline_only(self):
        r = run_scan(self.url, {**self.options, "max_pages": 1, "exposure_checks": False})
        self.assertEqual(len(r["pages"]), 1)
        self.assertEqual(r["requests"], 1)
        self.assertNotIn("exposure.env", r["checked_rules"])
        self.assertTrue(any("unvisited" in x for x in r["limitations"]))

    def test_headers_and_html_checks(self):
        headers = [("Content-Type", "text/html"), ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"), ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"), ("Strict-Transport-Security", "max-age=31536000"), ("Set-Cookie", "session=secret; Secure; HttpOnly; SameSite=Lax")]
        findings, _, checks = inspect(Response("https://example.test/", 200, headers, '<title>Good</title><form method="post"><input name="csrf_token"></form>', 10))
        self.assertFalse(findings)
        self.assertIn("headers.frame", checks)
        findings, _, _ = inspect(Response("https://example.test/", 200, headers, '<img src="http://example.test/pic.png"><script src="https://external.test/script.js"></script>', 10))
        self.assertEqual({f["rule"] for f in findings}, {"content.mixed", "content.sri"})

    def test_cross_origin_redirect_does_not_send_auth(self):
        calls = []
        def fake_get(client, url, headers=None):
            calls.append(url)
            return Response(url, 302, [("Location", "https://another.test/")], "", 1)
        with patch.object(Client, "get", fake_get):
            result = run_scan("https://original.test/", DEFAULTS, auth={"Authorization": "Bearer unique-private-auth-987"})
        self.assertEqual(calls, ["https://original.test/"])
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("unique-private-auth-987", json.dumps(result))

    def test_redirect_loop_and_tls_failure_reported(self):
        with patch.object(Client, "get", return_value=Response("https://test.invalid/", 302, [("Location", "/")], "", 0)):
            result = run_scan("https://test.invalid/", DEFAULTS)
        self.assertEqual(result["status"], "failed")
        self.assertIn("loop", result["errors"][0]["message"])
        with patch.object(Client, "get", side_effect=NetworkError("TLS certificate verification failed (untrusted, expired, or hostname mismatch).")):
            result = run_scan("https://test.invalid/", DEFAULTS)
        self.assertEqual(result["findings"][0]["rule"], "tls.invalid")

    def test_scope_validation(self):
        for opts in ({"max_pages": 201}, {"max_pages": True}, {"rate": 0}, {"allow_private": "true"}, {"path_scope": "admin"}):
            with self.assertRaises(ValueError):
                validate_options(opts)
        r = run_scan(self.url, {**self.options, "path_scope": "/login"})
        self.assertEqual(r["requests"], 0)

    def test_encoded_traversal_does_not_escape_scope(self):
        with patch.object(Client, "get") as get:
            r = run_scan("https://test.invalid/app/%2e%2e/private", {**DEFAULTS, "path_scope": "/app"})
        get.assert_not_called()
        self.assertEqual(r["requests"], 0)

    def test_auth_reflection_is_scrubbed_from_title(self):
        secret = "unique-token-for-reflection-test"
        response = Response("https://test.invalid/", 200, [("Content-Type", "text/html")], f"<title>{secret}</title>", 1)
        saved = []
        with patch.object(Client, "get", return_value=response):
            r = run_scan("https://test.invalid/", DEFAULTS, auth={"Authorization": f"Bearer {secret}"}, update=lambda result: saved.append(json.dumps(result)))
        self.assertNotIn(secret, json.dumps(r))
        self.assertFalse(any(secret in result for result in saved))

    def test_cookie_values_cannot_rewrite_scan_state_or_ids(self):
        response = Response("https://test.invalid/", 200, [("Content-Type", "text/html"), ("Set-Cookie", "scan_status=completed; Path=/"), ("Set-Cookie", "rule=headers.csp; Path=/")], "<title>completed</title>", 1)
        with patch.object(Client, "get", return_value=response):
            r = run_scan("https://test.invalid/", DEFAULTS)
        self.assertEqual(r["status"], "completed")
        self.assertEqual(r["pages"][0]["title"], "[redacted]")
        self.assertIn("headers.csp", r["checked_rules"])
        self.assertTrue(any(f["rule"] == "headers.csp" for f in r["findings"]))

    def test_cors_error_redacts_redirect_query(self):
        secret_url = "https://test.invalid/?token=private-query-value"
        def fake_get(client, url, headers=None):
            if headers:
                raise NetworkError("Connection failed.")
            if url == "https://test.invalid/":
                return Response(url, 302, [("Location", secret_url)], "", 1)
            if url == secret_url:
                return Response(url, 200, [("Content-Type", "text/html")], "<title>Home</title>", 1)
            return Response(url, 404, [], "", 1)
        saved = []
        with patch.object(Client, "get", fake_get):
            r = run_scan("https://test.invalid/", {**DEFAULTS, "include_queries": True, "exposure_checks": True}, update=lambda r: saved.append(json.dumps(r)))
        self.assertEqual(r["status"], "partial")
        self.assertNotIn("private-query-value", json.dumps(r))
        self.assertFalse(any("private-query-value" in s for s in saved))
        self.assertIn("[redacted]", r["errors"][-1]["url"])

    def test_localhost_dual_stack_resolves_and_connects(self):
        client = Client(allow_private=True, delay=0)
        r = client.get(self.url.replace("127.0.0.1", "localhost"))
        self.assertEqual(r.status, 200)

    def test_path_scope_is_case_sensitive(self):
        with patch.object(Client, "get") as get:
            r = run_scan("https://test.invalid/APP", {**DEFAULTS, "path_scope": "/app"})
        get.assert_not_called()
        self.assertEqual(r["requests"], 0)

    def test_slow_headers_respect_deadline_and_cancellation(self):
        class SlowHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                try:
                    for byte in b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nHello":
                        self.connection.sendall(bytes([byte]))
                        time.sleep(0.04)
                except OSError:
                    pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/"
            started = time.monotonic()
            with self.assertRaises(NetworkError):
                Client(allow_private=True, timeout=0.15, delay=0).get(url)
            self.assertLess(time.monotonic() - started, 0.6)
            cancel = threading.Event()
            timer = threading.Timer(0.12, cancel.set)
            timer.start()
            started = time.monotonic()
            with self.assertRaises(ScanCancelled):
                Client(allow_private=True, timeout=3, delay=0, cancel=cancel).get(url)
            self.assertLess(time.monotonic() - started, 0.6)
            timer.join()
        finally:
            server.shutdown()
            server.server_close()

    def test_report_escaping_and_formats(self):
        scan = {"id": "test", "created_at": "2026-11-23", "result": json.loads(json.dumps(self.result))}
        scan["result"]["findings"][0]["note"] = '<script>alert("bad")</script>'
        project = {"name": "<img onerror=alert(1)>", "url": self.url}
        body, _ = export_report(scan, project, "html")
        self.assertNotIn(b"<script>", body)
        self.assertIn(b"&lt;script&gt;", body)
        self.assertIn(b"Scope and limitations", body)
        self.assertIn(b"Pages observed", body)
        data, _ = export_report(scan, project, "json")
        self.assertEqual(json.loads(data)["scan"]["id"], "test")
        scan["result"]["findings"][0]["note"] = "=cmd()"
        csv, _ = export_report(scan, project, "csv")
        self.assertIn(b"'=cmd()", csv)


class PersistenceTests(unittest.TestCase):
    def test_second_instance_preserves_running_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Application(directory)
            p = app.store.save_project({"name": "Site", "url": "https://test.invalid/"})
            ident = app.store.create_scan(p["id"], DEFAULTS, False)
            try:
                with self.assertRaises(RuntimeError):
                    Application(directory)
                self.assertEqual(app.store.scan(ident)["status"], "queued")
            finally:
                app.shutdown()

    def test_demo_restarts_with_saved_target(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Application(directory)
            first = app.start_demo_scan()
            app.shutdown()
            second_app = Application(directory)
            try:
                second = second_app.start_demo_scan()
                self.assertEqual(first["project_id"], second["project_id"])
            finally:
                second_app.shutdown()

    def test_history_triage_comparison_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            p = store.save_project({"name": "Site", "url": "https://example.test/"})
            result = {"status": "completed", "phase": "Finished", "findings": [{"id": "a", "status": "open"}], "pages": [], "errors": [], "requests": 0, "options": DEFAULTS, "auth_used": False}
            first = store.create_scan(p["id"], DEFAULTS, False)
            store.update_scan(first, result)
            store.set_triage(p["id"], "a", "accepted", "Known")
            second = store.create_scan(p["id"], DEFAULTS, False)
            store.update_scan(second, result)
            current = store.scan(second)["result"]
            self.assertEqual(current["comparison"]["new"], 0)
            self.assertEqual(current["findings"][0]["status"], "accepted")
            queued = store.create_scan(p["id"], DEFAULTS, False)
            restored = Store(directory)
            self.assertEqual(restored.scan(queued)["status"], "interrupted")
            self.assertEqual(restored.scan(second)["result"]["findings"][0]["note"], "Known")


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.app = Application(cls.temp.name)
        cls.server = make_server(cls.app, 0)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        _, _, headers = cls.request("GET", "/")
        cls.cookie = dict(headers)["Set-Cookie"].split(";")[0]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.app.shutdown()
        cls.temp.cleanup()

    @classmethod
    def request(cls, method, path, data=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", cls.server.server_port, timeout=10)
        h = headers or {}
        if data is not None:
            h = {"Content-Type": "application/json", **h}
        conn.request(method, path, json.dumps(data) if data is not None else None, h)
        response = conn.getresponse()
        status, result, response_headers = response.status, response.read(), response.getheaders()
        conn.close()
        return status, result, response_headers

    def test_control_api_security(self):
        self.assertEqual(self.request("GET", "/api/state")[0], 401)
        headers = {"Cookie": self.cookie}
        self.assertEqual(self.request("GET", "/api/state", headers=headers)[0], 200)
        self.assertEqual(self.request("POST", "/api/projects", {}, {**headers, "Origin": "https://untrusted.test"})[0], 403)
        self.assertEqual(self.request("GET", "/", headers={"Host": "attacker.test"})[0], 403)
        self.assertEqual(self.request("GET", "/api/state", headers={**headers, "Sec-Fetch-Site": "cross-site"})[0], 403)

    def test_authenticated_transport_restrictions(self):
        project = self.app.store.save_project({"name": "No TLS", "url": "http://localhost:1234/", "options": {"allow_private": True}})
        with self.assertRaises(ValueError):
            self.app.start_scan(project["id"], {"Authorization": "Bearer secret"})

    def test_detection_options_roundtrip(self):
        headers = {"Cookie": self.cookie}
        options = {"discovery_checks": True, "network_checks": True, "tls_checks": True, "network_ports": "443,80", "max_pages": 200}
        status, body, _ = self.request("POST", "/api/projects", {"name": "Options fixture", "url": "https://example.invalid/", "options": options}, headers)
        self.assertEqual(status, 201, body)
        _, body, _ = self.request("GET", "/api/state", headers=headers)
        project = next(p for p in json.loads(body)["projects"] if p["name"] == "Options fixture")
        self.assertEqual(project["options"]["network_ports"], "80,443")
        self.assertTrue(project["options"]["discovery_checks"])
        self.assertTrue(project["options"]["network_checks"])
        self.assertTrue(project["options"]["tls_checks"])
        self.assertEqual(project["scans"], [])

    def test_demo_api_end_to_end(self):
        headers = {"Cookie": self.cookie}
        status, body, _ = self.request("POST", "/api/demo", {}, headers)
        self.assertEqual(status, 201, body)
        ident = json.loads(body)["scan_id"]
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            status, body, _ = self.request("GET", f"/api/scans/{ident}", headers=headers)
            result = json.loads(body)
            if result["status"] not in ("queued", "running"):
                break
            time.sleep(0.1)
        self.assertEqual(result["status"], "completed", result)
        for kind in ("html", "json", "csv"):
            status, body, _ = self.request("GET", f"/api/scans/{ident}/{kind}", headers=headers)
            self.assertEqual(status, 200, body)
            self.assertGreater(len(body), 100)
        f = result["result"]["findings"][0]
        status, _, _ = self.request("POST", f'/api/scans/{ident}/findings/{f["id"]}', {"status": "reviewing", "note": "Investigating"}, headers)
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
