from __future__ import annotations

import hmac
import json
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from . import VERSION
from .demo import start_demo
from .instance import InstanceLock
from .network import origin
from .reports import export_report
from .rules import RULES
from .scanner import DEFAULTS, LIMITATIONS, run_scan
from .storage import Store

ROOT = Path(__file__).resolve().parent.parent


class Application:
    def __init__(self, data_dir):
        self.instance_lock = InstanceLock(data_dir)
        try:
            self.store = Store(data_dir)
        except Exception:
            self.instance_lock.close()
            raise
        self.token = secrets.token_urlsafe(32)
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="website-scan")
        self.jobs = {}
        self.lock = threading.RLock()
        self.port = None
        self.stopping = False
        self.demo = None
        self.demo_record = Path(data_dir) / "demo.json"
        self.demo_project_id = None
        if self.demo_record.exists():
            try:
                self.demo_project_id = json.loads(self.demo_record.read_text())["project_id"]
            except (ValueError, KeyError, OSError):
                pass

    def start_demo_scan(self):
        with self.lock:
            if self.demo is None:
                previous = self.store.project(self.demo_project_id)
                try:
                    self.demo = start_demo(urlsplit(previous["url"]).port if previous else 0)
                except OSError:
                    raise ValueError("The saved demo port is busy. Stop the conflicting process and try again.") from None
            url = f"http://127.0.0.1:{self.demo.server_port}/"
            project = next((p for p in self.store.projects() if p["url"] == url), None)
            if project is None:
                project = self.store.save_project({"name": "Local demonstration", "url": url, "options": {"allow_private": True, "exposure_checks": True, "rate": 5}})
            self.demo_project_id = project["id"]
            self.demo_record.write_text(json.dumps({"project_id": project["id"]}), encoding="utf-8")
            return {"project_id": project["id"], "scan_id": self.start_scan(project["id"], {})}

    def start_scan(self, project_id, auth):
        with self.lock:
            project = self.store.project(project_id)
            if not project:
                raise ValueError("Website not found.")
            if project_id == self.demo_project_id and self.demo is None:
                try:
                    self.demo = start_demo(urlsplit(project["url"]).port)
                except OSError:
                    raise ValueError("The saved demo port is busy. Stop the conflicting process and try again.") from None
            if self.stopping or len(self.jobs) >= 5:
                raise ValueError("The scanner is stopping or its five-scan queue is full.")
            if any(p == project_id for p, _ in self.jobs.values()):
                raise ValueError("This website already has an active or queued scan.")
            auth_headers = {}
            if not isinstance(auth, dict):
                raise ValueError("Authentication must be an object.")
            for key in ("Authorization", "Cookie"):
                value = auth.get(key, "")
                if not isinstance(value, str) or len(value) > 8192 or any(ord(c) < 32 or ord(c) > 126 for c in value):
                    raise ValueError("Authentication header must be single-line ASCII, up to 8,192 characters.")
                if value:
                    auth_headers[key] = value
            if auth_headers and urlsplit(project["url"]).scheme != "https":
                raise ValueError("Authenticated scans require an HTTPS target.")
            if auth_headers and not project["options"]["verify_tls"]:
                raise ValueError("Authenticated scans require certificate verification.")
            ident = self.store.create_scan(project_id, project["options"], bool(auth_headers))
            cancel = threading.Event()
            self.jobs[ident] = (project_id, cancel)
            self.executor.submit(self._scan, ident, project, cancel, auth_headers)
            return ident

    def _scan(self, ident, project, cancel, auth):
        try:
            run_scan(project["url"], project["options"], cancel, lambda r: self.store.update_scan(ident, r), auth, blocked_origins={("http", h, self.port) for h in ("localhost", "127.0.0.1", "::1")})
        finally:
            auth.clear()
            with self.lock:
                self.jobs.pop(ident, None)

    def shutdown(self):
        with self.lock:
            self.stopping = True
            for _, cancel in self.jobs.values():
                cancel.set()
        self.executor.shutdown(wait=True)
        if self.demo:
            self.demo.shutdown()
            self.demo.server_close()
        self.instance_lock.close()


def make_server(app, port=8765):
    class Handler(BaseHTTPRequestHandler):
        server_version = "WebsiteTester"

        def log_message(self, *args):
            # Request paths may contain sensitive information; no access log.
            pass

        def send_data(self, status, body, content_type="application/json; charset=utf-8", extra=None):
            if isinstance(body, (dict, list)):
                body = json.dumps(body).encode()
            elif isinstance(body, str):
                body = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def trusted_request(self):
            host = self.headers.get("Host", "")
            if host not in (f"127.0.0.1:{app.port}", f"localhost:{app.port}"):
                self.send_data(403, {"error": "Unrecognized local Host."})
                return False
            site = self.headers.get("Sec-Fetch-Site")
            if site == "cross-site":
                self.send_data(403, {"error": "Cross-site requests are blocked."})
                return False
            request_origin = self.headers.get("Origin")
            if request_origin and request_origin != f"http://{host}":
                self.send_data(403, {"error": "Origin does not match the local application."})
                return False
            return True

        def authorized(self):
            cookies = SimpleCookie()
            try:
                cookies.load(self.headers.get("Cookie", ""))
            except Exception:
                pass
            token = cookies.get("xa_session")
            if not token or not hmac.compare_digest(token.value, app.token):
                self.send_data(401, {"error": "Open or refresh the local dashboard to establish a session."})
                return False
            return True

        def do_GET(self):
            if not self.trusted_request():
                return
            path = urlsplit(self.path).path
            assets = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8"), "/style.css": ("style.css", "text/css; charset=utf-8"), "/favicon.svg": ("favicon.svg", "image/svg+xml")}
            if path in assets:
                name, mime = assets[path]
                extra = {"Set-Cookie": f"xa_session={app.token}; HttpOnly; SameSite=Strict; Path=/"} if path == "/" else None
                self.send_data(200, (ROOT / "web" / name).read_bytes(), mime, extra)
                return
            if not self.authorized():
                return
            try:
                parts = path.strip("/").split("/")
                if path == "/api/state":
                    projects = app.store.projects()
                    for p in projects:
                        p["scans"] = app.store.scans(p["id"])
                    self.send_data(200, {"version": VERSION, "projects": projects, "defaults": DEFAULTS, "limitations": LIMITATIONS, "rules": [{"id": k, "severity": v[0], "title": v[1], "category": v[2]} for k, v in RULES.items()]})
                elif len(parts) >= 3 and parts[:2] == ["api", "scans"]:
                    scan = app.store.scan(parts[2])
                    if not scan:
                        self.send_data(404, {"error": "Scan not found."})
                    elif len(parts) == 3:
                        self.send_data(200, scan)
                    elif len(parts) == 4 and parts[3] in ("json", "csv", "html"):
                        kind = parts[3]
                        data, mime = export_report(scan, app.store.project(scan["project_id"]), kind)
                        self.send_data(200, data, mime, {"Content-Disposition": f'attachment; filename="website-report-{scan["id"][:8]}.{kind}"'})
                    else:
                        self.send_data(404, {"error": "Route not found."})
                else:
                    self.send_data(404, {"error": "Route not found."})
            except ValueError as exc:
                self.send_data(400, {"error": str(exc)})
            except Exception:
                self.send_data(500, {"error": "Unable to read local data."})

        def do_POST(self):
            if not self.trusted_request() or not self.authorized():
                return
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                self.send_data(415, {"error": "Use application/json."})
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 32768:
                    raise ValueError("Request body must be 1–32,768 bytes.")
                self.connection.settimeout(5)
                body = json.loads(self.rfile.read(size))
                if not isinstance(body, dict):
                    raise ValueError("Expected a JSON object.")
                parts = urlsplit(self.path).path.strip("/").split("/")
                if parts == ["api", "demo"]:
                    self.send_data(201, app.start_demo_scan())
                elif parts == ["api", "projects"]:
                    self.send_data(201, app.store.save_project(body))
                elif len(parts) == 3 and parts[:2] == ["api", "projects"]:
                    self.send_data(200, app.store.save_project(body, parts[2]))
                elif len(parts) == 4 and parts[:2] == ["api", "projects"] and parts[3] == "scan":
                    self.send_data(201, {"id": app.start_scan(parts[2], body.get("auth", {}))})
                elif len(parts) == 4 and parts[:2] == ["api", "scans"] and parts[3] == "cancel":
                    with app.lock:
                        job = app.jobs.get(parts[2])
                        if job:
                            job[1].set()
                    self.send_data(200, {"requested": bool(job)})
                elif len(parts) == 5 and parts[:2] == ["api", "scans"] and parts[3] == "findings":
                    scan = app.store.scan(parts[2])
                    if not scan or not any(f["id"] == parts[4] for f in scan["result"]["findings"]):
                        raise ValueError("Finding not found.")
                    app.store.set_triage(scan["project_id"], parts[4], body.get("status"), body.get("note", ""))
                    self.send_data(200, {"saved": True})
                else:
                    self.send_data(404, {"error": "Route not found."})
            except (ValueError, TypeError) as exc:
                self.send_data(400, {"error": str(exc)})
            except Exception:
                self.send_data(500, {"error": "Unable to complete this local operation."})

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    app.port = server.server_port
    return server
