"""Explicitly synthetic, loopback-only website used for demonstrations and tests."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "SyntheticDemo/1.0"

    def log_message(self, *args):
        pass

    def do_GET(self):
        routes = {
            "/": (200, "text/html", '<!doctype html><title>Synthetic demo website</title><h1>Local test fixture</h1><p>This website is intentionally misconfigured for testing.</p><a href="/login">Login form</a><a href="/docs">Documents</a><a href="/missing">Broken link</a><a href="/logout">Excluded route</a><a href="/search?q=private-example">Query link</a><script src="https://cdn.example.invalid/demo.js"></script>'),
            "/login": (200, "text/html", '<title>Example login</title><form method="get"><input type="password" name="password"></form><form method="post"><input name="comment"></form>'),
            "/docs": (200, "text/html", '<title>Index of /docs</title><h1>Index of /docs</h1>'),
            "/.env": (200, "text/plain", "APP_KEY=SYNTHETIC-DEMO-NOT-A-REAL-SECRET\n"),
            "/.git/HEAD": (200, "text/plain", "ref: refs/heads/demo\n"),
            "/openapi.json": (200, "application/json", '{"openapi":"3.0.0","info":{"title":"Synthetic demo","version":"1"},"paths":{}}'),
        }
        status, mime, body = routes.get(self.path, (404, "text/html", "<title>Not found</title>"))
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        if self.path == "/":
            self.send_header("Set-Cookie", "demo_session=SYNTHETIC-COOKIE-VALUE; Path=/")
            if self.headers.get("Origin"):
                self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
                self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(data)


def start_demo(port=0):
    server = ThreadingHTTPServer(("127.0.0.1", port), DemoHandler)
    Thread(target=server.serve_forever, daemon=True, name="synthetic-demo").start()
    return server
