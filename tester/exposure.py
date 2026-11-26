############################################################################################################################
# Website Tester exposure checks
# Content-confirmed public endpoint checks with a soft-404 control response.
# Candidate paths never establish exposure without the expected response structure.
# Core features: bounded probes; structured matchers; secret-free evidence; soft-404 suppression.
# Important note: findings are observations, not proof of exploitation.
# Last Updated: 2026-11-26 12:30:00
# Release Notes: Expanded detector set for the local scanner.
############################################################################################################################
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Probe:
    path: str
    rule: str
    kind: str


PROBES = (
    Probe(".env", "exposure.env", "env"),
    Probe(".env.local", "exposure.env", "env"),
    Probe(".env.production", "exposure.env", "env"),
    Probe(".git/HEAD", "exposure.git", "git-head"),
    Probe(".git/config", "exposure.git", "git-config"),
    Probe("openapi.json", "exposure.openapi", "openapi"),
    Probe("swagger.json", "exposure.openapi", "openapi"),
    Probe("phpinfo.php", "exposure.phpinfo", "phpinfo"),
    Probe("server-status", "exposure.server_status", "server-status"),
    Probe("actuator/env", "exposure.actuator", "actuator"),
    Probe(".DS_Store", "exposure.ds_store", "ds-store"),
    Probe("package.json", "exposure.package", "package"),
    Probe("composer.json", "exposure.package", "composer"),
    Probe("wp-config.php.bak", "exposure.source", "php-config"),
    Probe("config.php.bak", "exposure.source", "php-config"),
)


def soft404(response, control):
    if control is None or response.status != control.status or response.status != 200:
        return False
    if response.body == control.body:
        return True
    if "html" not in response.header("content-type").lower() or "html" not in control.header("content-type").lower():
        return False
    def normalized(r):
        value = r.body[:32768].replace(urlsplit(r.url).path, "[path]")
        return re.sub(r"\s+", " ", value).strip()
    a, b = normalized(response), normalized(control)
    if min(len(a), len(b)) < 100:
        return False
    return SequenceMatcher(None, a, b, autojunk=True).ratio() > 0.95


def matches(probe, response):
    if response.status != 200:
        return False
    text = response.body
    lower = text[:65536].lower()
    html = "<html" in lower or "<!doctype html" in lower
    kind = probe.kind
    if kind == "env":
        return not html and bool(re.search(r"(?m)^\s*(?:DB_PASSWORD|DATABASE_URL|APP_KEY|SECRET_KEY|AWS_SECRET_ACCESS_KEY)\s*=\s*\S+", text))
    if kind == "git-head":
        return bool(re.fullmatch(r"\s*ref:\s+refs/heads/[\w./-]+\s*", text)) or bool(re.fullmatch(r"[0-9a-f]{40}\s*", text))
    if kind == "git-config":
        return not html and "[core]" in text and bool(re.search(r"(?m)^\s*(?:repositoryformatversion|bare)\s*=", text))
    if kind == "phpinfo":
        return "php version" in lower and ("phpinfo()" in lower or "php variables" in lower) and "configuration" in lower
    if kind == "server-status":
        return ("apache server status for" in lower and "server version:" in lower) or ("total accesses:" in lower and "scoreboard:" in lower)
    if kind == "ds-store":
        return text.startswith("\x00\x00\x00\x01Bud1")
    if kind == "php-config":
        return not html and "<?php" in text and bool(re.search(r"DB_PASSWORD|DB_HOST|database_password|\$password\s*=", text, re.I))
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return False
    if not isinstance(data, dict):
        return False
    if kind == "openapi":
        return isinstance(data.get("info"), dict) and isinstance(data.get("paths"), dict) and bool(re.match(r"^[23]\.", str(data.get("openapi", data.get("swagger", "")))))
    if kind == "actuator":
        return isinstance(data.get("propertySources"), list) and any(isinstance(x, dict) and "properties" in x and "name" in x for x in data["propertySources"])
    if kind == "package":
        return isinstance(data.get("name"), str) and any(isinstance(data.get(k), dict) for k in ("scripts", "dependencies", "devDependencies"))
    if kind == "composer":
        return isinstance(data.get("require"), dict) and any(k in data for k in ("name", "autoload", "repositories", "require-dev"))
    return False
