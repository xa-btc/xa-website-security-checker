"""Small HTTP transport with explicit destination, redirect and resource limits."""
from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import time
import posixpath
import threading
import zlib
from dataclasses import dataclass, field
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

MAX_BODY = 1_048_576
METADATA = {"169.254.169.254", "100.100.100.200", "fd00:ec2::254", "fd20:ce::254"}


def normalize_url(value: str) -> str:
    if any(ord(c) < 32 or c == "\\" for c in value) or len(value) > 4096:
        raise ValueError("Invalid URL characters or length.")
    value = value.strip()
    p = urlsplit(value)
    if p.scheme not in ("http", "https") or not p.hostname or p.username is not None or p.password is not None:
        raise ValueError("Enter an http:// or https:// URL without embedded credentials.")
    host = p.hostname.encode("idna").decode("ascii").lower()
    port = p.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid port.")
    host = f"[{host}]" if ":" in host else host
    authority = host + (f":{port}" if port and port != (443 if p.scheme == "https" else 80) else "")
    path = p.path or "/"
    # Normalize literal dot segments before applying crawl scope.
    trailing = path.endswith("/")
    path = posixpath.normpath(path)
    if trailing and path != "/":
        path += "/"
    return urlunsplit((p.scheme, authority, quote(path, safe="/%:@!$&'()*+,;=-._~"), p.query, ""))


def origin(url: str) -> tuple:
    p = urlsplit(url)
    return p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)


def upgrade_allowed(source: str, target: str) -> bool:
    a, b = origin(source), origin(target)
    return a == b or (a[0] == "http" and b[0] == "https" and a[1] == b[1] and a[2] == 80 and b[2] == 443)


def address_allowed(address: str, allow_private: bool) -> bool:
    ip = ipaddress.ip_address(address.split("%")[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if str(ip) in METADATA or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return False
    if ip.is_loopback:
        return allow_private
    if ip.is_reserved:
        return False
    return ip.is_global or (allow_private and (ip.is_private or ip.is_loopback))


def display_url(url: str) -> str:
    try:
        p = urlsplit(url)
    except ValueError:
        return "[invalid URL]"
    # Query values may contain sessions or personal data. Never store them.
    query = "&".join(part.split("=", 1)[0] + "=[redacted]" for part in p.query.split("&") if part)
    # Discovered HTML URLs can contain userinfo even though target URLs reject it.
    return urlunsplit((p.scheme, p.netloc.rsplit("@", 1)[-1], p.path, query, ""))


def resolve_checked(host, port, allow_private=False):
    try:
        addresses = list(dict.fromkeys(row[4][0] for row in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
    except OSError:
        raise NetworkError("DNS resolution failed.") from None
    if not addresses or any(not address_allowed(a, allow_private) for a in addresses):
        raise NetworkError("Destination is blocked. Enable local/private targets for your LAN or localhost; known metadata and link-local addresses remain blocked.")
    return addresses


class NetworkError(Exception):
    pass


class ScanCancelled(Exception):
    pass


@dataclass
class Response:
    url: str
    status: int
    headers: list[tuple[str, str]]
    body: str
    elapsed_ms: int
    truncated: bool = False
    tls: dict = field(default_factory=dict)
    address: str = ""

    def header(self, name: str) -> str:
        return ", ".join(v for k, v in self.headers if k.lower() == name.lower())


class Client:
    def __init__(self, allow_private=False, verify_tls=True, delay=0.5, timeout=8, cancel=None, auth=None, max_requests=450, blocked_origins=()):
        self.allow_private = allow_private
        self.verify_tls = verify_tls
        self.delay = delay
        self.timeout = timeout
        self.cancel = cancel
        self.auth = auth or {}
        self.auth_origin = None
        self.last_request = 0.0
        self.requests = 0
        self.max_requests = max_requests
        self.blocked_origins = set(blocked_origins)

    def check_cancel(self):
        if self.cancel and self.cancel.is_set():
            raise ScanCancelled()

    def get(self, url: str, headers=None) -> Response:
        self.check_cancel()
        url = normalize_url(url)
        if origin(url) in self.blocked_origins:
            raise NetworkError("The scanner's own control server cannot be scanned.")
        if self.requests >= self.max_requests:
            raise NetworkError("Request budget reached.")
        wait = max(0, self.delay - (time.monotonic() - self.last_request))
        if self.cancel:
            if self.cancel.wait(wait):
                raise ScanCancelled()
        else:
            time.sleep(wait)
        self.check_cancel()
        p = urlsplit(url)
        port = p.port or (443 if p.scheme == "https" else 80)
        addresses = resolve_checked(p.hostname, port, self.allow_private)
        self.requests += 1
        self.last_request = time.monotonic()
        start = time.monotonic()
        conn = http.client.HTTPConnection(p.hostname, port, timeout=self.timeout)
        response = None
        active_socket = [None]
        finished = threading.Event()
        interrupted = threading.Event()

        def watchdog():
            # Socket timeouts alone can be defeated by slowly dripped header bytes.
            while not finished.wait(0.025):
                if (self.cancel and self.cancel.is_set()) or time.monotonic() - start >= self.timeout:
                    interrupted.set()
                    channel = active_socket[0]
                    if channel:
                        try:
                            channel.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                    return

        watcher = threading.Thread(target=watchdog, daemon=True, name="request-deadline")
        watcher.start()
        try:
            # Connect to a checked numeric address, preventing a second DNS lookup/rebinding.
            last_error = None
            for address in addresses:
                remaining = self.timeout - (time.monotonic() - start)
                if remaining <= 0:
                    break
                try:
                    conn.sock = socket.create_connection((address, port), min(remaining, 3))
                    active_socket[0] = conn.sock
                    conn.sock.settimeout(max(0.1, self.timeout - (time.monotonic() - start)))
                    break
                except OSError as exc:
                    last_error = exc
            if conn.sock is None:
                raise last_error or TimeoutError("Connection deadline exceeded")
            self.check_cancel()
            if interrupted.is_set():
                raise NetworkError("Request deadline exceeded.")
            tls = {}
            if p.scheme == "https":
                context = ssl.create_default_context() if self.verify_tls else ssl._create_unverified_context()
                conn.sock = context.wrap_socket(conn.sock, server_hostname=p.hostname)
                active_socket[0] = conn.sock
                cert = conn.sock.getpeercert()
                tls = {"protocol": conn.sock.version(), "cipher": conn.sock.cipher()[0], "verified": self.verify_tls, "expires": cert.get("notAfter"), "issuer": ", ".join(f"{k}={v}" for group in cert.get("issuer", ()) for k, v in group), "sans": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:100]}
            request_headers = {"User-Agent": "XA-Website-Tester/1.1 (owner-authorized assessment)", "Accept": "text/html,application/json,text/plain,*/*;q=0.5", "Accept-Encoding": "identity", "Connection": "close"}
            if self.auth and self.auth_origin == origin(url):
                request_headers.update(self.auth)
            request_headers.update(headers or {})
            path = p.path or "/"
            if p.query:
                path += "?" + quote(p.query, safe="%=&;:+,/?@!$'()*-._~")
            conn.request("GET", path, headers=request_headers)
            response = conn.getresponse()
            response_headers = response.getheaders()
            chunks = []
            size = 0
            deadline = start + self.timeout
            while size <= MAX_BODY:
                self.check_cancel()
                if time.monotonic() > deadline:
                    raise NetworkError("Response read deadline exceeded.")
                chunk = response.read1(min(65536, MAX_BODY + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            raw = b"".join(chunks)
            # read1 can end early without raising IncompleteRead.
            declared_length = response.getheader("Content-Length", "")
            if declared_length.isascii() and declared_length.isdigit() and not response.chunked and size <= MAX_BODY and size < int(declared_length):
                raise NetworkError("Response ended before the declared Content-Length was received.")
            self.check_cancel()
            if interrupted.is_set() or time.monotonic() - start >= self.timeout:
                raise NetworkError("Request deadline exceeded.")
            content_type = response.getheader("Content-Type", "")
            encoding = response.getheader("Content-Encoding", "identity").lower()
            truncated = len(raw) > MAX_BODY
            if encoding in ("gzip", "deflate"):
                try:
                    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS)
                    raw = decoder.decompress(raw, MAX_BODY + 1)
                    truncated = truncated or len(raw) > MAX_BODY or bool(decoder.unconsumed_tail)
                    if not decoder.eof and not truncated:
                        raise NetworkError("Compressed response ended before the complete stream was received.")
                    if decoder.unused_data:
                        raise NetworkError("Additional compressed streams or trailing data were not analyzed.")
                except zlib.error:
                    raise NetworkError("Invalid compressed response.") from None
            elif encoding not in ("", "identity"):
                raise NetworkError("Unsupported content encoding; response body was not analyzed.")
            charset = re.search(r"charset=([\w-]+)", content_type, re.I)
            try:
                body = raw[:MAX_BODY].decode(charset.group(1) if charset else "utf-8", errors="replace")
            except LookupError:
                body = raw[:MAX_BODY].decode("utf-8", errors="replace")
            return Response(url, response.status, response_headers, body, int((time.monotonic() - start) * 1000), truncated, tls, address)
        except ssl.SSLCertVerificationError:
            raise NetworkError("TLS certificate verification failed (untrusted, expired, or hostname mismatch).") from None
        except (OSError, http.client.HTTPException, UnicodeError) as exc:
            self.check_cancel()
            if interrupted.is_set():
                raise NetworkError("Request deadline exceeded.") from None
            raise NetworkError(f"Connection failed ({type(exc).__name__}).") from None
        finally:
            finished.set()
            if response:
                response.close()
            conn.close()
            watcher.join(timeout=0.1)
