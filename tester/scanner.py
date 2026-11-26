from __future__ import annotations

import re
import threading
import time
import posixpath
import uuid
from http.cookies import SimpleCookie
from collections import deque
from urllib.parse import unquote, urljoin, urlsplit

from .network import Client, NetworkError, ScanCancelled, display_url, normalize_url, origin, upgrade_allowed
from .rules import RULES, finding, inspect, summarize_findings
from . import DETECTOR_REVISION
from .exposure import PROBES, matches, soft404
from .surface import DEFAULT_PORTS, SENSITIVE_PORTS, parse_ports, sitemap_entries, tcp_inventory, tls_inventory

DEFAULTS = {"max_pages": 30, "max_depth": 3, "rate": 2, "allow_private": False, "verify_tls": True, "exposure_checks": False, "include_queries": False, "path_scope": "/", "exclude_paths": "/logout\n/signout\n/delete\n/remove\n/unsubscribe\n/checkout\n/purchase\n/revoke\n/reset"}
DEFAULTS.update(discovery_checks=False, network_checks=False, tls_checks=False, network_ports=DEFAULT_PORTS)
LIMITATIONS = ["HTTP responses, HTML links and optional sitemaps only: JavaScript-rendered routes and browser interactions are not executed.", "GET requests only; forms are inspected but never submitted. Application-specific GET routes can still have side effects; exclude them before scanning.", "No exploit validation, SQL injection/XSS payloads, dependency/CVE audit, cloud audit, source-code review or automatic fixes.", "A missing finding does not prove security. Authentication success and application-specific authorization are not verified.", "Response bodies are limited to 1 MiB; scans stop after 10 minutes or 450 requests. DNS resolution uses the operating system resolver.", "Finding evidence omits cookie values and query values. URL paths, page titles and cookie names remain in local reports."]


def validate_options(values):
    if not isinstance(values, dict):
        raise ValueError("Options must be an object.")
    result = {**DEFAULTS, **{k: v for k, v in values.items() if k in DEFAULTS}}
    for field, low, high in (("max_pages", 1, 200), ("max_depth", 0, 8), ("rate", 1, 5)):
        if type(result[field]) is not int or not low <= result[field] <= high:
            raise ValueError(f"{field} must be an integer from {low} to {high}.")
    for field in ("allow_private", "verify_tls", "exposure_checks", "include_queries", "discovery_checks", "network_checks", "tls_checks"):
        if type(result[field]) is not bool:
            raise ValueError(f"{field} must be true or false.")
    if not isinstance(result["path_scope"], str) or not result["path_scope"].startswith("/") or len(result["path_scope"]) > 500:
        raise ValueError("Path scope must start with / and be at most 500 characters.")
    if not isinstance(result["exclude_paths"], str) or len(result["exclude_paths"]) > 4000:
        raise ValueError("Excluded paths must be text up to 4000 characters.")
    result["network_ports"] = ",".join(map(str, parse_ports(result["network_ports"])))
    return result


def run_scan(url, options, cancel=None, update=None, auth=None, blocked_origins=()):
    options = validate_options(options)
    cancel = cancel or threading.Event()
    update = update or (lambda r: None)
    started = time.monotonic()
    client = Client(allow_private=options["allow_private"], verify_tls=options["verify_tls"], delay=1 / options["rate"], cancel=cancel, auth=auth, blocked_origins=blocked_origins)
    client.auth_origin = origin(url)
    result = {"status": "running", "phase": "Crawling pages", "pages": [], "findings": [], "errors": [], "skipped": [], "checked_rules": [], "requests": 0, "limitations": list(LIMITATIONS), "options": options, "auth_used": bool(auth), "duration_seconds": 0}
    result.update(detector_revision=DETECTOR_REVISION, assets=[], probes=[], discovery=[], network=None, tls_checks=None)
    result["limitations"].extend(["Observed hostnames are inventory leads only; they are not automatically scanned. TCP inventory is opt-in and tests only the selected hostname's resolved IPs; no exploit or authentication attempts.", "TLS protocol probes send no application credentials and assess capability separately from certificate trust. Handshake failures are inconclusive."])
    if not options["verify_tls"]:
        result["limitations"].append("TLS verification was disabled for this scan; certificate trust and expiry were not assessed.")
    result["limitations"].append("Optional exposure and CORS checks were " + ("enabled." if options["exposure_checks"] else "disabled."))
    findings, checked, seen = {}, set(), set()
    first_url = None
    assets_seen = set()
    secrets = set()
    for key, value in (auth or {}).items():
        if value:
            secrets.add(value)
        if key == "Authorization" and " " in value:
            secrets.add(value.split(" ", 1)[1])
        if key == "Cookie":
            for chunk in value.split(";"):
                if "=" in chunk:
                    secrets.add(chunk.split("=", 1)[1].strip())

    def scrub(value, field=None):
        if isinstance(value, str) and field in {"title", "url", "evidence", "detail", "note", "content_type"}:
            for secret in sorted(secrets, key=len, reverse=True):
                if secret and (len(secret) >= 8 or value == secret):
                    value = value.replace(secret, "[redacted]")
            value = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255}|xox[baprs]-[A-Za-z0-9-]{20,})\b", "[redacted-token]", value)
            value = re.sub(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)", "[redacted-private-key]", value)
            return value
        if isinstance(value, list):
            return [scrub(v, field) for v in value]
        if isinstance(value, dict):
            return {k: scrub(v, k) for k, v in value.items()}
        return value
    root_origin = origin(url)
    queue = deque([(url, 0)])
    exclusions = [x.strip().lower() for x in options["exclude_paths"].splitlines() if x.strip()]
    scope = options["path_scope"].rstrip("/") or "/"

    def path_allowed(target):
        path = unquote(urlsplit(target).path)
        # Ambiguous encoded separators/traversal should not expand a declared path scope.
        if "\\" in path or "%" in path or any(part in (".", "..") for part in path.split("/")):
            return False
        path = posixpath.normpath(path)
        scoped = scope == "/" or path == scope or path.startswith(scope + "/")
        return scoped and not any(x in path.lower() for x in exclusions)

    def add_skip(target, reason):
        if len(result["skipped"]) < 100:
            result["skipped"].append({"url": display_url(target), "reason": reason})

    def publish():
        result["findings"] = sorted(findings.values(), key=lambda f: (['critical', 'high', 'medium', 'low', 'info'].index(f['severity']), f['title'], f['url']))
        result["checked_rules"] = sorted(checked)
        result["finding_groups"] = summarize_findings(result["findings"])
        result["requests"] = client.requests
        result["duration_seconds"] = round(time.monotonic() - started, 1)
        update(scrub(result))

    def asset(target, source):
        try:
            host = urlsplit(normalize_url(target)).hostname
        except ValueError:
            return
        key = (host, source)
        if key not in assets_seen and len(result["assets"]) < 200:
            assets_seen.add(key)
            result["assets"].append({"host": host, "source": source, "scope": "selected host" if host == root_origin[1] else "unverified external host; not scanned"})

    def discover(base_url):
        base = urlsplit(base_url)
        prefix = f"{base.scheme}://{base.netloc}" + (scope.rstrip("/") + "/" if scope != "/" else "/")
        maps = deque([urljoin(prefix, "sitemap.xml")])
        robots_url = urljoin(prefix, "robots.txt")
        if path_allowed(robots_url):
            try:
                robots = fetch(robots_url)
                result["discovery"].append({"url": display_url(robots_url), "type": "robots", "status": robots.status})
                if robots.status == 200:
                    # Disallow entries may be stateful; never turn them into crawl targets.
                    for line in robots.body.splitlines()[:2000]:
                        if line.lower().startswith("sitemap:"):
                            try:
                                maps.append(urljoin(prefix, line.split(":", 1)[1].strip()))
                            except ValueError:
                                result["errors"].append({"url": display_url(robots_url), "message": "Malformed Sitemap directive skipped."})
            except NetworkError as exc:
                result["errors"].append({"url": display_url(robots_url), "message": str(exc)})
        visited_maps = set()
        discovered = 0
        while maps and len(visited_maps) < 5:
            raw = maps.popleft()
            try:
                target = normalize_url(raw)
            except ValueError:
                continue
            if target in visited_maps:
                continue
            if origin(target) != root_origin or not path_allowed(target) or (urlsplit(target).query and not options["include_queries"]):
                add_skip(target, "Sitemap is outside the allowed origin/path/query scope.")
                continue
            visited_maps.add(target)
            try:
                response = fetch(target)
                row = {"url": display_url(target), "type": "sitemap", "status": response.status, "discovered": 0}
                result["discovery"].append(row)
                if response.status != 200:
                    continue
                if response.truncated:
                    row["note"] = "Truncated sitemap was not parsed."
                    continue
                kind, links, capped = sitemap_entries(response.body)
                row.update(type=kind, discovered=len(links), limited=capped)
                for link in links:
                    try:
                        link = normalize_url(urljoin(target, link))
                    except ValueError:
                        continue
                    asset(link, "sitemap")
                    if origin(link) != root_origin or not path_allowed(link) or (urlsplit(link).query and not options["include_queries"]):
                        add_skip(link, "Sitemap entry is outside origin/path/query scope.")
                        continue
                    if kind == "sitemapindex":
                        if len(maps) < 10:
                            maps.append(link)
                    elif options["max_depth"] >= 1 and discovered < 2000 and len(queue) < 2000:
                        queue.append((link, 1))
                        discovered += 1
            except (NetworkError, ValueError) as exc:
                result["errors"].append({"url": display_url(target), "message": str(exc)})
        if maps:
            result["limitations"].append("Sitemap discovery stopped after five documents; additional map entries were not fetched.")

    def fetch(target, initial=False, headers=None):
        nonlocal root_origin
        chain = set()
        for _ in range(6):
            if time.monotonic() - started > 600:
                raise NetworkError("Ten-minute scan budget reached.")
            if target in chain:
                raise NetworkError("Redirect loop detected.")
            chain.add(target)
            response = client.get(target, headers=headers)
            if response.status in (301, 302, 303, 307, 308) and response.header("location"):
                try:
                    next_url = normalize_url(urljoin(target, response.header("location")))
                except ValueError:
                    raise NetworkError("Malformed redirect URL; request skipped.") from None
                if not ((initial and upgrade_allowed(target, next_url)) or origin(next_url) == root_origin):
                    add_skip(next_url, "Redirect leaves the selected origin; add the final website URL as a separate target.")
                    raise NetworkError("Redirect left the selected origin.")
                if not path_allowed(next_url):
                    raise NetworkError("Redirect leaves path scope or matches an excluded path.")
                if urlsplit(next_url).query and not options["include_queries"]:
                    raise NetworkError("Redirect has a query string; query crawling is disabled.")
                if initial:
                    root_origin = origin(next_url)
                target = next_url
                continue
            return response
        raise NetworkError("Redirect limit reached.")

    try:
        while queue and len(result["pages"]) < options["max_pages"]:
            client.check_cancel()
            target, depth = queue.popleft()
            if target in seen:
                continue
            seen.add(target)
            if not path_allowed(target):
                add_skip(target, "Outside path scope or matches an excluded path.")
                continue
            if time.monotonic() - started > 600 or client.requests >= client.max_requests:
                result["errors"].append({"url": display_url(target), "message": "Scan time/request budget reached."})
                break
            try:
                response = fetch(target, initial=not result["pages"] and len(seen) == 1)
                is_first = first_url is None
                if is_first:
                    first_url = response.url
                asset(response.url, "HTTP response")
                for san in response.tls.get("sans", []):
                    if "*" not in san:
                        asset("https://" + san, "certificate SAN; ownership unverified")
                for key, value in response.headers:
                    if key.lower() == "set-cookie":
                        jar = SimpleCookie()
                        try:
                            jar.load(value)
                            secrets.update(cookie.value for cookie in jar.values() if cookie.value)
                        except Exception:
                            pass
                seen.add(response.url)
                observed, doc, tested = inspect(response)
                for f in observed:
                    findings[f["id"]] = f
                checked.update(tested)
                page = {"url": display_url(response.url), "status": response.status, "title": doc.title[:200] if doc else "", "elapsed_ms": response.elapsed_ms, "depth": depth, "content_type": response.header("content-type")[:120], "truncated": response.truncated, "tls": response.tls, "address": response.address, "checked_rules": sorted(tested)}
                result["pages"].append(page)
                if response.truncated:
                    result["errors"].append({"url": page["url"], "message": "Body truncated at 1 MiB; analysis is partial."})
                if doc:
                    if doc.invalid_urls:
                        result["errors"].append({"url": page["url"], "message": f"Skipped {doc.invalid_urls} malformed resource/form/base URL references; content coverage is partial."})
                    for _, resource, _ in doc.resources:
                        try:
                            asset(urljoin(urljoin(response.url, doc.base) if doc.base else response.url, resource), "HTML resource")
                        except (ValueError, UnicodeError):
                            pass
                    for link in doc.links:
                        if len(queue) >= 2000:
                            add_skip(response.url, "Discovery queue limit reached (2,000 URLs).")
                            break
                        try:
                            next_url = normalize_url(urljoin(urljoin(response.url, doc.base) if doc.base else response.url, link))
                        except ValueError:
                            continue
                        asset(next_url, "HTML link")
                        if origin(next_url) != root_origin or next_url in seen:
                            continue
                        if not path_allowed(next_url):
                            add_skip(next_url, "Excluded path or outside path scope.")
                        elif urlsplit(next_url).query and not options["include_queries"]:
                            add_skip(next_url, "Query crawling disabled.")
                        elif re.search(r"\.(?:zip|exe|dll|pdf|png|jpg|jpeg|gif|woff2?|mp4|mp3|svg|ico|css|js)$", urlsplit(next_url).path, re.I):
                            add_skip(next_url, "Binary/static asset link omitted from page crawl.")
                        elif depth >= options["max_depth"]:
                            add_skip(next_url, "Depth limit reached.")
                        else:
                            queue.append((next_url, depth + 1))
                if is_first and options["discovery_checks"]:
                    result["phase"] = "Discovering sitemap pages"
                    publish()
                    discover(response.url)
                    result["phase"] = "Crawling pages"
            except NetworkError as exc:
                message = str(exc)
                result["errors"].append({"url": display_url(target), "message": message})
                if message.startswith("TLS certificate verification"):
                    f = finding("tls.invalid", target, message)
                    findings[f["id"]] = f
                    checked.add("tls.invalid")
            publish()
        if queue:
            result["limitations"].append(f"Page/time/request limit left {len(queue)} queued URL entries unvisited (entries may contain duplicates).")
        if options["exposure_checks"] and result["pages"] and not cancel.is_set():
            result["phase"] = "Checking exposure and CORS"
            publish()
            first = first_url
            base = urlsplit(first)
            base_url = f"{base.scheme}://{base.netloc}" + (scope.rstrip("/") + "/" if scope != "/" else "/")
            control = None
            control_url = urljoin(base_url, "xa-nonexistent-" + uuid.uuid4().hex)
            if path_allowed(control_url):
                try:
                    control = fetch(control_url)
                except NetworkError as exc:
                    result["errors"].append({"url": display_url(control_url), "message": "Soft-404 control failed: " + str(exc)})
            for probe in PROBES:
                target = urljoin(base_url, probe.path)
                if not path_allowed(target):
                    add_skip(target, "Probe matches an excluded path.")
                    continue
                try:
                    r = fetch(target)
                    checked.add(probe.rule)
                    suppressed = soft404(r, control)
                    observed = not suppressed and matches(probe, r)
                    result["probes"].append({"url": display_url(target), "rule": probe.rule, "http_status": r.status, "outcome": "soft-404 suppressed" if suppressed else "observed" if observed else "incomplete" if r.truncated else "not observed" if r.status in (200, 404, 410) else "access denied" if r.status in (401, 403) else "inconclusive"})
                    if r.truncated:
                        result["errors"].append({"url": display_url(target), "message": "Exposure response truncated at 1 MiB; review is partial."})
                    if observed:
                        control_note = "Nonexistent-page control did not match." if control is not None else "Nonexistent-page control was unavailable; review manually."
                        f = finding(probe.rule, target, f"GET returned HTTP 200 and matched the {probe.kind} content structure. {control_note} Body and potential secret values are omitted.", confidence="high" if control is not None else "medium")
                        findings[f["id"]] = f
                except NetworkError as exc:
                    result["probes"].append({"url": display_url(target), "rule": probe.rule, "outcome": "error"})
                    result["errors"].append({"url": display_url(target), "message": str(exc)})
                publish()
            try:
                # Header only; the scanner never contacts this external origin.
                r = fetch(first, headers={"Origin": "https://xa-origin-check.invalid"})
                checked.add("cors.reflected")
                if r.header("access-control-allow-origin").strip() == "https://xa-origin-check.invalid" and r.header("access-control-allow-credentials").strip().lower() == "true":
                    f = finding("cors.reflected", first, "Response reflected https://xa-origin-check.invalid and Access-Control-Allow-Credentials: true. Browser readability and sensitivity are not proven.", confidence="medium")
                    findings[f["id"]] = f
            except NetworkError as exc:
                result["errors"].append({"url": display_url(first), "message": str(exc)})
        if options["network_checks"] and time.monotonic()-started < 600:
            result["phase"] = "Checking selected-host TCP services"
            publish()
            try:
                result["network"] = tcp_inventory(url, parse_ports(options["network_ports"]), options["allow_private"], cancel, options["rate"], min(60, 600-(time.monotonic()-started)), blocked_ports={x[2] for x in blocked_origins})
                checked.add("network.sensitive_port")
                for row in result["network"]["observations"]:
                    if row["state"] == "open" and row["port"] in SENSITIVE_PORTS:
                        f = finding("network.sensitive_port", url, f"TCP connection succeeded to {row['address']}:{row['port']}. Port convention: {row['service_hint']}; actual service, ownership, authentication and exploitability were not verified.", detail=f"{row['address']}:{row['port']}", confidence="medium")
                        findings[f["id"]] = f
            except NetworkError as exc:
                result["errors"].append({"url": display_url(url), "message": str(exc)})
        if options["tls_checks"] and time.monotonic()-started < 600:
            result["phase"] = "Checking TLS protocol capabilities"
            publish()
            try:
                result["tls_checks"] = tls_inventory(first_url or url, options["allow_private"], cancel, min(25, 600-(time.monotonic()-started)), blocked_ports={x[2] for x in blocked_origins})
                checked.add("tls.legacy")
                for row in result["tls_checks"]["observations"]:
                    if row["state"] == "supported" and row["protocol"] in ("TLSv1", "TLSv1_1"):
                        f = finding("tls.legacy", first_url or url, f"A handshake succeeded using {row['negotiated']} and cipher {row['cipher']}. No application data or credentials were sent.", detail=row["protocol"])
                        findings[f["id"]] = f
            except NetworkError as exc:
                result["errors"].append({"url": display_url(url), "message": str(exc)})
        observed_any = result["pages"] or (result["network"] or {}).get("observations") or (result["tls_checks"] or {}).get("observations")
        result["status"] = "completed" if result["pages"] and not result["errors"] else ("partial" if observed_any else "failed")
        if result["status"] == "completed" and any(r is not None and not r.get("complete", True) for r in (result["network"], result["tls_checks"])):
            result["status"] = "partial"
        if result["status"] == "completed" and (queue or result["skipped"]):
            result["limitations"].append("Completed means the configured scan finished, not that the whole website was covered; review skipped URLs.")
        result["phase"] = "Finished"
    except ScanCancelled:
        result["status"], result["phase"] = "cancelled", "Cancelled"
    except Exception as exc:
        result["status"], result["phase"] = "failed", "Scan failed"
        result["errors"].append({"url": display_url(url), "message": f"Unexpected scanner error ({type(exc).__name__})."})
    finally:
        client.auth.clear()
        publish()
    return scrub(result)
