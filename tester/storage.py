from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .network import normalize_url
from .scanner import validate_options
from . import DETECTOR_REVISION
from .rules import summarize_findings


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, directory):
        Path(directory).mkdir(parents=True, exist_ok=True)
        self.path = Path(directory) / "website-tester.sqlite3"
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, options TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, project_id TEXT NOT NULL, created_at TEXT NOT NULL, status TEXT NOT NULL, result TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS triage(project_id TEXT NOT NULL, finding_id TEXT NOT NULL, status TEXT NOT NULL, note TEXT NOT NULL, PRIMARY KEY(project_id,finding_id));
            """)
            for row in db.execute("SELECT id,result FROM scans WHERE status IN ('running','queued')").fetchall():
                result = json.loads(row["result"])
                result.update(status="interrupted", phase="Application stopped before completion")
                db.execute("UPDATE scans SET status=?,result=? WHERE id=?", ("interrupted", json.dumps(result), row["id"]))

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def projects(self):
        with self.connect() as db:
            rows = db.execute("SELECT * FROM projects ORDER BY created_at DESC").fetchall()
        return [{**dict(r), "options": validate_options(json.loads(r["options"]))} for r in rows]

    def project(self, ident):
        return next((p for p in self.projects() if p["id"] == ident), None)

    def save_project(self, values, ident=None):
        name = str(values.get("name", "")).strip()
        if not 1 <= len(name) <= 100:
            raise ValueError("Website name must be 1–100 characters.")
        url = normalize_url(str(values.get("url", "")))
        if "?" in url:
            raise ValueError("Save a URL without a query string. Enable query crawling separately if needed.")
        options = validate_options(values.get("options", {}))
        with self.connect() as db:
            if ident:
                old = db.execute("SELECT url FROM projects WHERE id=?", (ident,)).fetchone()
                if not old:
                    raise ValueError("Website not found.")
                if old["url"] != url:
                    raise ValueError("Add a new website to change the target URL; this preserves history and triage boundaries.")
                db.execute("UPDATE projects SET name=?,options=? WHERE id=?", (name, json.dumps(options), ident))
            else:
                ident = uuid.uuid4().hex
                db.execute("INSERT INTO projects VALUES(?,?,?,?,?)", (ident, name, url, json.dumps(options), now()))
        return self.project(ident)

    def create_scan(self, project_id, options, auth_used):
        ident = uuid.uuid4().hex
        result = {"status": "queued", "phase": "Waiting for scanner", "findings": [], "pages": [], "errors": [], "skipped": [], "checked_rules": [], "limitations": [], "requests": 0, "duration_seconds": 0, "options": options, "auth_used": auth_used}
        result["detector_revision"] = DETECTOR_REVISION
        with self.connect() as db:
            db.execute("INSERT INTO scans VALUES(?,?,?,?,?)", (ident, project_id, now(), "queued", json.dumps(result)))
        return ident

    def update_scan(self, ident, result):
        with self.connect() as db:
            db.execute("UPDATE scans SET status=?,result=? WHERE id=?", (result["status"], json.dumps(result), ident))

    def scans(self, project_id):
        with self.connect() as db:
            rows = db.execute("SELECT * FROM scans WHERE project_id=? ORDER BY created_at DESC,rowid DESC", (project_id,)).fetchall()
        answer = []
        for r in rows:
            data = json.loads(r["result"])
            answer.append({"id": r["id"], "created_at": r["created_at"], "status": r["status"], "findings": len(data["findings"]), "pages": len(data["pages"]), "requests": data["requests"], "duration_seconds": data.get("duration_seconds", 0)})
        return answer

    def scan(self, ident):
        with self.connect() as db:
            row = db.execute("SELECT * FROM scans WHERE id=?", (ident,)).fetchone()
            if not row:
                return None
            result = {**dict(row), "result": json.loads(row["result"])}
            states = {r["finding_id"]: dict(r) for r in db.execute("SELECT * FROM triage WHERE project_id=?", (row["project_id"],))}
            old_rows = db.execute("SELECT id,result FROM scans WHERE project_id=? AND rowid<(SELECT rowid FROM scans WHERE id=?) AND status='completed' ORDER BY rowid DESC", (row["project_id"], ident)).fetchall()
        data = result["result"]
        baseline = next((r for r in old_rows if json.loads(r["result"])["options"] == data["options"] and json.loads(r["result"]).get("auth_used") == data.get("auth_used") and json.loads(r["result"]).get("detector_revision", 1) == data.get("detector_revision", 1)), None)
        old = {f["id"] for f in json.loads(baseline["result"])["findings"]} if baseline else None
        for f in data["findings"]:
            state = states.get(f["id"], {})
            f.update(status=state.get("status", "open"), note=state.get("note", ""), change=("new" if f["id"] not in old else "recurring") if old is not None else "first scan")
        current = {f["id"] for f in data["findings"]}
        data["finding_groups"] = summarize_findings(data["findings"])
        data["comparison"] = {"baseline_id": baseline["id"] if baseline else None, "new": len(current - old) if old is not None else None, "not_seen": len(old - current) if old is not None and data["status"] == "completed" else None, "note": "Compared with the previous completed scan using matching detector revision, options and authentication presence. Accounts and crawl coverage can differ; not seen does not mean fixed."}
        def open_ports(result):
            return {(r["address"], r["port"]) for r in (result.get("network") or {}).get("observations", []) if r["state"] == "open"}
        if baseline and data.get("network"):
            previous = json.loads(baseline["result"])
            data["comparison"]["new_open_ports"] = [f"{a}:{p}" for a, p in sorted(open_ports(data) - open_ports(previous))]
        return result

    def set_triage(self, project_id, finding_id, status, note):
        if status not in ("open", "reviewing", "accepted") or not isinstance(note, str) or len(note) > 2000:
            raise ValueError("Invalid finding status or note (maximum 2,000 characters).")
        with self.connect() as db:
            db.execute("INSERT INTO triage VALUES(?,?,?,?) ON CONFLICT(project_id,finding_id) DO UPDATE SET status=excluded.status,note=excluded.note", (project_id, finding_id, status, note))
