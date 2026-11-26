"""Response evidence checks. Findings describe observations, not proven exploits."""
from __future__ import annotations

import hashlib
import re
import ssl
import time
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from urllib.parse import urljoin, urlsplit

from .network import display_url

RULES = {
    "tls.legacy": ("high", "Legacy TLS protocol accepted", "Transport", "Disable TLS 1.0 and TLS 1.1 at the TLS termination point. Retain TLS 1.2/1.3 and retest client compatibility.", "CWE-327"),
    "network.sensitive_port": ("medium", "Management or database port is reachable", "Network", "Confirm the service and ownership of this IP. Restrict management/database access with a firewall or VPN if public access is unnecessary. The port number alone does not verify the product or a vulnerability.", "CWE-200"),
    "headers.csp_script": ("medium", "CSP leaves script sources unrestricted", "Headers", "Add a restrictive script-src or default-src directive. A policy containing only unrelated directives does not restrict script execution.", "CWE-693"),
    "headers.csp_frame_wildcard": ("medium", "Framing policy permits arbitrary origins", "Headers", "Restrict frame-ancestors to 'none', 'self' or the specific sites that must embed this page.", "CWE-1021"),
    "headers.csp_report_only": ("info", "CSP is report-only", "Headers", "Use reports to tune a policy, then deploy an enforced Content-Security-Policy. Report-only policies do not block execution.", "CWE-693"),
    "headers.hsts_short": ("low", "HSTS lifetime is short", "Headers", "Once HTTPS is stable, increase max-age to at least 15552000 seconds. Short lifetimes may be deliberate during rollout.", "CWE-319"),
    "cookies.prefix": ("medium", "Security-prefixed cookie violates prefix requirements", "Cookies", "__Secure- requires Secure; __Host- requires Secure, Path=/ and no Domain attribute. Browsers may reject cookies that violate these rules.", "CWE-614"),
    "content.private_key": ("high", "Private-key block is present in a public response", "Exposure", "Remove private keys from public responses and rotate/revoke the affected key. Confirm exposure in a protected environment; this report deliberately omits the key material.", "CWE-200"),
    "content.token": ("high", "Credential-shaped token is present in a response", "Exposure", "Review the matched credential format, revoke confirmed exposed credentials, and remove them from frontend content. Pattern matching does not establish token validity.", "CWE-200"),
    "content.source_map": ("info", "Source map reference is advertised", "Exposure", "Confirm source maps are intentionally public and contain no private source or embedded credentials. This check does not download the map.", "CWE-200"),
    "forms.password_external": ("medium", "Password form posts to another origin", "Forms", "Verify this is the intended authentication provider and that the destination is trusted. External form actions can be legitimate.", "CWE-200"),
    "forms.cache": ("low", "Password page lacks a no-store cache policy", "Forms", "Review caching of authentication pages and sensitive responses; set Cache-Control: no-store where appropriate.", "CWE-525"),
    "cors.wildcard": ("info", "CORS allows any origin", "Headers", "Confirm the resource is intended to be readable by any website. Wildcard CORS is normal for public resources and does not permit credentialed browser reads.", "CWE-942"),
    "exposure.phpinfo": ("medium", "PHP diagnostic page is exposed", "Exposure", "Remove phpinfo pages from production or restrict them to administrators.", "CWE-200"),
    "exposure.server_status": ("medium", "Server status details are exposed", "Exposure", "Restrict the status endpoint to trusted administrators and monitoring systems.", "CWE-200"),
    "exposure.actuator": ("high", "Application environment endpoint is exposed", "Exposure", "Restrict environment/management endpoints and review whether configuration or secrets were disclosed. Masked values still disclose configuration structure.", "CWE-200"),
    "exposure.ds_store": ("low", "Directory metadata file is exposed", "Exposure", "Exclude .DS_Store files from deployment and deny public access to them.", "CWE-200"),
    "exposure.package": ("info", "Package manifest is publicly readable", "Exposure", "Confirm this manifest is intentionally public. Review scripts and dependency details for unnecessary disclosure; this is not a dependency vulnerability assessment.", "CWE-200"),
    "exposure.source": ("high", "Backup file exposes server-side configuration source", "Exposure", "Remove backup/source files from the web root, block backup extensions and rotate any exposed secrets.", "CWE-552"),
    "transport.http": ("medium", "Page served over HTTP", "Transport", "Serve the site over HTTPS and redirect HTTP requests to HTTPS.", "CWE-319"),
    "tls.invalid": ("high", "TLS certificate could not be verified", "Transport", "Install a valid certificate with the correct hostname and complete trust chain.", "CWE-295"),
    "tls.expiring": ("medium", "TLS certificate expires soon", "Transport", "Renew the certificate and automate renewal before its expiry date.", "CWE-298"),
    "headers.hsts": ("low", "HSTS missing or disabled", "Headers", "After confirming HTTPS works throughout the site, set Strict-Transport-Security: max-age=31536000. Add includeSubDomains only when every subdomain supports HTTPS.", "CWE-319"),
    "headers.csp": ("medium", "Content Security Policy is missing", "Headers", "Deploy a tested Content-Security-Policy using nonces or hashes and narrowly scoped sources. Start in report-only mode if needed.", "CWE-693"),
    "headers.csp_unsafe": ("low", "CSP contains a permissive script directive", "Headers", "Review unsafe-inline, unsafe-eval and wildcard script sources; replace them with nonces, hashes and explicit origins where possible.", "CWE-693"),
    "headers.frame": ("medium", "Framing protection is missing", "Headers", "Set CSP frame-ancestors 'none' or a trusted allowlist, or X-Frame-Options: DENY/SAMEORIGIN.", "CWE-1021"),
    "headers.nosniff": ("low", "MIME sniffing protection is missing", "Headers", "Return X-Content-Type-Options: nosniff with accurate Content-Type values.", "CWE-693"),
    "headers.referrer": ("low", "Referrer policy is missing or permissive", "Headers", "Set Referrer-Policy: strict-origin-when-cross-origin or a stricter policy.", "CWE-200"),
    "headers.version": ("info", "Server version is advertised", "Headers", "Remove unnecessary version details from Server and X-Powered-By headers. Keep the underlying software patched.", "CWE-200"),
    "cookies.secure": ("low", "Cookie lacks the Secure attribute", "Cookies", "Use Secure for cookies that must only travel over HTTPS; review session and authentication cookies first.", "CWE-614"),
    "cookies.httponly": ("low", "Cookie is accessible to JavaScript", "Cookies", "Use HttpOnly on session and authentication cookies. Some client-side preference or CSRF cookies intentionally need JavaScript access.", "CWE-1004"),
    "cookies.samesite": ("low", "Cookie SameSite policy needs review", "Cookies", "Set SameSite=Lax or Strict where compatible; SameSite=None requires Secure. Missing attributes may use browser defaults.", "CWE-1275"),
    "content.mixed": ("medium", "HTTPS page references an HTTP resource", "Content", "Serve the referenced resource over HTTPS. Browsers may block or upgrade mixed content.", "CWE-319"),
    "content.sri": ("low", "External script lacks integrity metadata", "Content", "Pin third-party scripts and use Subresource Integrity when the provider supports stable assets, or self-host audited copies.", "CWE-353"),
    "content.directory": ("medium", "Directory listing pattern detected", "Exposure", "Disable automatic directory indexes and restrict access to files that are not intended to be public.", "CWE-548"),
    "content.debug": ("medium", "Debug error pattern detected", "Exposure", "Disable production debug pages and return generic errors while retaining details in private server logs.", "CWE-209"),
    "forms.password_http": ("high", "Password form uses unencrypted transport", "Forms", "Serve the form and submit its action over HTTPS.", "CWE-319"),
    "forms.password_get": ("high", "Password form submits with GET", "Forms", "Use POST over HTTPS so credentials do not appear in URL history and access logs.", "CWE-598"),
    "forms.csrf": ("low", "POST form has no recognizable CSRF token", "Forms", "Review server-side CSRF protections. Origin checks, framework tokens and SameSite cookies may protect this form; this heuristic cannot verify them.", "CWE-352"),
    "cors.reflected": ("medium", "CORS accepts an untrusted origin with credentials", "Headers", "Validate Origin against an explicit trusted allowlist and enable credentials only where required. Confirm that sensitive responses are actually readable.", "CWE-942"),
    "exposure.env": ("high", "Environment configuration pattern exposed", "Exposure", "Block public access to environment files, remove them from the web root and rotate any exposed credentials.", "CWE-552"),
    "exposure.git": ("high", "Git metadata is publicly readable", "Exposure", "Deny access to .git and deploy only application artifacts. Assess whether repository history or secrets were exposed.", "CWE-552"),
    "exposure.openapi": ("info", "API specification is publicly readable", "Exposure", "Confirm this API documentation is intentionally public and excludes private endpoints and sensitive examples.", "CWE-200"),
    "http.error": ("low", "Internal page returned an error", "Reliability", "Review this route, its referring links and server logs; authentication-required routes may intentionally deny access.", ""),
}


class Document(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.links, self.resources, self.forms = [], [], []
        self.current_form = None
        self.title = ""
        self.in_title = False
        self.meta_policies = []
        self.meta_referrer = ""
        self.base = ""
        self.invalid_urls = 0
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        a = {key: value or "" for key, value in attrs}
        if tag == "meta":
            if a.get("http-equiv", "").lower() == "content-security-policy":
                self.meta_policies.append(a.get("content", ""))
            if a.get("name", "").lower() == "referrer":
                self.meta_referrer = a.get("content", "")
        if tag == "base" and not self.base:
            self.base = a.get("href", "")
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        if tag in ("script", "img", "iframe", "source", "video", "audio", "link", "embed", "object"):
            src = a.get("src") or (a.get("href") if tag == "link" and a.get("rel", "").lower() in ("stylesheet", "preload") else None)
            if src:
                self.resources.append((tag, src, a))
            if tag == "object" and a.get("data"):
                self.resources.append((tag, a["data"], a))
            if tag in ("source", "img") and a.get("srcset"):
                for srcset in a["srcset"].split(","):
                    if srcset.strip():
                        self.resources.append((tag, srcset.strip().split()[0], a))
        if tag == "form":
            method = a.get("method", "get").lower()
            self.current_form = {"action": a.get("action", ""), "method": method if method in ("post", "dialog") else "get", "inputs": []}
            self.forms.append(self.current_form)
        if tag == "input" and self.current_form is not None:
            self.current_form["inputs"].append(a)
        if tag == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag == "form":
            self.current_form = None
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data


def finding(rule, url, evidence, detail="", confidence="high"):
    severity, title, category, fix, cwe = RULES[rule]
    location = display_url(url)
    key = hashlib.sha256(f"{rule}|{location}|{detail}".encode()).hexdigest()[:20]
    return {"id": key, "rule": rule, "title": title, "severity": severity, "category": category, "url": location, "evidence": evidence[:1600], "remediation": fix, "cwe": cwe, "confidence": confidence, "detail": detail, "status": "open"}


def summarize_findings(findings):
    groups = {}
    for item in findings:
        key = item.get("rule", item["id"])
        group = groups.setdefault(key, {"rule": key, "title": item.get("title", key), "severity": item.get("severity", "info"), "occurrences": 0, "open_occurrences": 0, "urls": [], "finding_ids": []})
        group["occurrences"] += 1
        group["open_occurrences"] += item.get("status", "open") != "accepted"
        group["finding_ids"].append(item["id"])
        if item.get("url") and item["url"] not in group["urls"]:
            group["urls"].append(item["url"])
    return list(groups.values())


def csp_directives(value):
    directives = {}
    for chunk in value.split(";"):
        parts = chunk.strip().split()
        if parts:
            # Browsers use the first occurrence of each directive within a policy.
            directives.setdefault(parts[0].lower(), parts[1:])
    return directives


def permissive_scripts(policy):
    # Compare matching contexts across policies; different permissive contexts do
    # not survive an otherwise restrictive intersection of multiple policies.
    capabilities = set()
    fallback = policy.get("script-src", policy.get("default-src"))
    for directive, context in (("script-src-elem", "element-inline"), ("script-src-attr", "attribute-inline")):
        tokens = policy.get(directive, fallback)
        if tokens is None:
            capabilities.add(context)
            if directive == "script-src-elem":
                capabilities.add("external")
            continue
        nonce_or_hash = any(re.fullmatch(r"'(?:nonce-[A-Za-z0-9+/_=-]+|sha(?:256|384|512)-[A-Za-z0-9+/_=-]+)'", t) for t in tokens)
        if "'unsafe-inline'" in tokens and not nonce_or_hash:
            capabilities.add(context)
        if directive == "script-src-elem" and not (nonce_or_hash and "'strict-dynamic'" in tokens) and any(t in tokens for t in ("*", "http:", "https:", "data:")):
            capabilities.add("external")
    if fallback is None or "'unsafe-eval'" in fallback:
        capabilities.add("eval")
    return capabilities


def inspect(response):
    r = response
    findings = []
    checked = set()
    def check(rule, condition, evidence, detail="", confidence="high"):
        checked.add(rule)
        if condition:
            findings.append(finding(rule, r.url, evidence, detail, confidence))
    https = urlsplit(r.url).scheme == "https"
    check("transport.http", not https, "The observed response was served over HTTP.")
    if r.tls.get("expires"):
        days = int((ssl.cert_time_to_seconds(r.tls["expires"]) - time.time()) / 86400)
        check("tls.expiring", days < 30, f"Certificate expires in {days} days ({r.tls['expires']}).")
    if https:
        hsts = r.header("strict-transport-security")
        age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", hsts, re.I)
        check("headers.hsts", not age or int(age.group(1)) == 0, "Strict-Transport-Security is absent or does not contain a positive max-age.")
        if age and int(age.group(1)) > 0:
            check("headers.hsts_short", int(age.group(1)) < 15552000, f"HSTS max-age={int(age.group(1))} seconds.")
    check("cors.wildcard", r.header("access-control-allow-origin").strip() == "*", "Access-Control-Allow-Origin: *. This does not establish sensitive data access or credentialed browser access.", confidence="medium")
    # Never persist matched secret material or nearby response text.
    check("content.private_key", bool(re.search(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]{20,}?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", r.body)), "A complete PEM/private-key block marker was observed. Key material omitted; validity was not tested.", confidence="medium")
    check("content.token", bool(re.search(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255}|xox[baprs]-[A-Za-z0-9-]{20,})\b", r.body)), "A GitHub/Slack credential-shaped token pattern was observed. Value omitted; validity was not tested.", confidence="medium")
    check("content.source_map", bool(re.search(r"[#@]\s*sourceMappingURL\s*=", r.body)), "A sourceMappingURL marker is present; the referenced map was not fetched.", confidence="medium")
    check("headers.version", bool(re.search(r"\d+\.\d+", r.header("server") + r.header("x-powered-by"))), "Server/X-Powered-By advertises a numeric software version.")
    check("http.error", r.status >= 400, f"GET returned HTTP {r.status}.")
    for key, value in r.headers:
        if key.lower() != "set-cookie":
            continue
        cookies = SimpleCookie()
        try:
            cookies.load(value)
        except Exception:
            continue
        for name, cookie in cookies.items():
            check("cookies.secure", not cookie["secure"], f"Cookie {name!r}: Secure is absent. Cookie value omitted.", name)
            check("cookies.httponly", not cookie["httponly"], f"Cookie {name!r}: HttpOnly is absent. Cookie value omitted.", name, "medium")
            same = cookie["samesite"].lower()
            check("cookies.samesite", same not in ("lax", "strict", "none") or (same == "none" and not cookie["secure"]), f"Cookie {name!r}: SameSite={same or '(absent)'}, Secure={bool(cookie['secure'])}. Value omitted.", name, "medium")
            if name.startswith(("__Host-", "__Secure-")):
                invalid_prefix = not cookie["secure"] or (name.startswith("__Host-") and (cookie["path"] != "/" or bool(cookie["domain"])))
                check("cookies.prefix", invalid_prefix, f"Cookie {name!r} violates prefix attribute requirements; value omitted.", name)
    if "text/html" not in r.header("content-type").lower() or not 200 <= r.status < 300:
        return findings, None, checked
    doc = Document(r.body)
    def resolve_reference(raw, base):
        try:
            target = urljoin(base, raw)
            parts = urlsplit(target)
            parts.port  # Validate malformed port literals as well as IPv6 syntax.
            return target, parts
        except (ValueError, UnicodeError):
            doc.invalid_urls += 1
            return None
    resolved_base = resolve_reference(doc.base, r.url) if doc.base else None
    if doc.base and resolved_base is None:
        doc.base = ""
    document_base = resolved_base[0] if resolved_base else r.url
    csp = r.header("content-security-policy")
    header_policies = [csp_directives(v) for k, v in r.headers if k.lower() == "content-security-policy" for v in v.split(",") if v.strip()]
    policies = header_policies + [csp_directives(v) for v in doc.meta_policies if v.strip()]
    check("headers.csp", not policies, "No enforced CSP header or HTML meta policy was observed.")
    check("headers.csp_report_only", not policies and bool(r.header("content-security-policy-report-only")), "Only Content-Security-Policy-Report-Only was observed.")
    if policies:
        check("headers.csp_script", all(not any(k in p for k in ("script-src", "script-src-elem", "default-src")) for p in policies), "No enforced policy restricts script sources.")
        check("headers.csp_unsafe", bool(set.intersection(*(permissive_scripts(p) for p in policies))), "At least one script context remains permissive across all observed policies. Nonce/hash suppression and strict-dynamic were considered; browser behavior and script contexts still need manual review.", confidence="medium")
    frame = r.header("x-frame-options").strip().lower()
    frame_policies = [p["frame-ancestors"] for p in header_policies if "frame-ancestors" in p]
    # frame-ancestors in HTML meta is ignored by browsers.
    check("headers.frame", not frame_policies and frame not in ("deny", "sameorigin"), "No enforced header frame-ancestors or recognized X-Frame-Options policy was observed.")
    check("headers.csp_frame_wildcard", bool(frame_policies) and all(any(t in p for t in ("*", "http:", "https:")) for p in frame_policies), "Every header frame-ancestors policy permits a wildcard/scheme-wide source.")
    check("headers.nosniff", r.header("x-content-type-options").strip().lower() != "nosniff", "X-Content-Type-Options: nosniff was not observed.")
    referrer = (doc.meta_referrer or r.header("referrer-policy")).lower().split(",")[-1].strip()
    check("headers.referrer", referrer not in ("no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"), "No explicit restrictive Referrer-Policy header/meta was observed. Modern browsers generally default to strict-origin-when-cross-origin; absence alone is not a demonstrated leak.", confidence="medium")
    check("content.directory", bool(re.search(r"<title>\s*Index of\s+/", r.body, re.I)), "HTML title matches the common 'Index of /' directory listing pattern.", confidence="medium")
    check("content.debug", any(s in r.body for s in ("Traceback (most recent call last)", "Fatal error:", "Whoops, looks like something went wrong.", "Microsoft.AspNetCore.Diagnostics.DeveloperExceptionPageMiddleware")), "Response contains a known debug/stack-trace marker; content omitted.", confidence="medium")
    for tag, src, attrs in doc.resources:
        reference = resolve_reference(src, document_base)
        if reference is None:
            continue
        target, p = reference
        check("content.mixed", https and p.scheme == "http", f"{tag} references {display_url(target)}", display_url(target))
        integrity = bool(re.search(r"(?:^|\s)sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}(?:\s|$)", attrs.get("integrity", "")))
        check("content.sri", tag == "script" and p.scheme in ("http", "https") and p.netloc != urlsplit(r.url).netloc and not integrity, f"External script {display_url(target)} has no recognizable integrity hash.", display_url(target), "medium")
    for i, form in enumerate(doc.forms):
        reference = resolve_reference(form["action"], document_base) if form["action"] else (r.url, urlsplit(r.url))
        if reference is None:
            continue
        action, action_parts = reference
        password = any(a.get("type", "").lower() == "password" for a in form["inputs"])
        detail = f"form-{i + 1}"
        check("forms.password_http", password and (not https or urlsplit(action).scheme != "https"), f"Password form {i + 1}; action {display_url(action)}.", detail)
        check("forms.password_get", password and form["method"] == "get", f"Password form {i + 1} uses GET.", detail)
        check("forms.password_external", password and urlsplit(action).netloc != urlsplit(r.url).netloc, f"Password form {i + 1} targets another origin: {display_url(action)}. Provider trust was not verified.", detail, "medium")
        check("forms.cache", password and "no-store" not in r.header("cache-control").lower(), "Password form page has no Cache-Control: no-store response directive.", detail, "medium")
        token = any(re.search(r"csrf|xsrf|authenticity|requestverification", a.get("name", ""), re.I) for a in form["inputs"])
        check("forms.csrf", form["method"] == "post" and not token, f"POST form {i + 1} has no recognizable CSRF token input. Server-side protection was not tested.", detail, "low")
    return findings, doc, checked
