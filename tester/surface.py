############################################################################################################################
# Website Tester surface inventory
# Bounded selected-host TCP and TLS observations, plus XML discovery parsing.
# TCP connections never authenticate or send exploit commands. TLS capabilities are positive observations only.
# Core features: checked IP addresses; cancellation; per-probe deadlines; explicit unassessed states.
# Important note: an open port or failed handshake does not establish a vulnerability or absence of support.
# Last Updated: 2026-11-26 12:30:00
# Release Notes: Added opt-in service and TLS capability inventory.
############################################################################################################################
from __future__ import annotations

import errno
import select
import socket
import ssl
import time
import warnings
from urllib.parse import urlsplit
from xml.etree import ElementTree

from .network import NetworkError, ScanCancelled, resolve_checked

PORT_HINTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 1433: "SQL Server", 2375: "Docker API", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP alternate", 8443: "HTTPS alternate", 9200: "Elasticsearch", 27017: "MongoDB"}
SENSITIVE_PORTS = {23, 445, 1433, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 27017}
DEFAULT_PORTS = "21,22,25,80,110,143,443,445,3306,3389,5432,6379,8080,8443,9200,27017"


def parse_ports(value):
    if not isinstance(value, str) or len(value) > 250:
        raise ValueError("Network ports must be a comma-separated list of at most 32 port numbers.")
    try:
        chunks = value.split(",")
        if any(not x.strip().isascii() or not x.strip().isdigit() for x in chunks):
            raise ValueError()
        ports = sorted(set(int(x.strip()) for x in chunks))
    except ValueError:
        raise ValueError("Use individual comma-separated TCP port numbers, without ranges.") from None
    if not 1 <= len(ports) <= 32 or any(not 1 <= p <= 65535 for p in ports):
        raise ValueError("Select 1–32 TCP ports between 1 and 65535.")
    return ports


def sitemap_entries(text):
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("Sitemap declarations/entities are not supported.")
    try:
        root = ElementTree.fromstring(text)
    except (ElementTree.ParseError, RecursionError):
        raise ValueError("Invalid sitemap XML.") from None
    kind = root.tag.rsplit("}", 1)[-1]
    if kind not in ("urlset", "sitemapindex"):
        raise ValueError("Response is not a sitemap urlset or index.")
    links = [e.text.strip() for e in root.iter() if e.tag.rsplit("}", 1)[-1] == "loc" and e.text and e.text.strip()]
    return kind, links[:2000], len(links) > 2000


def check_stop(cancel, deadline):
    if cancel and cancel.is_set():
        raise ScanCancelled()
    if time.monotonic() >= deadline:
        raise TimeoutError("Probe deadline reached")


def connect(address, port, cancel, deadline):
    check_stop(cancel, deadline)
    channel = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM)
    channel.setblocking(False)
    try:
        result = channel.connect_ex((address, port))
        pending = {0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, 10035, 10036, 10037}
        if result not in pending:
            raise OSError(result, "TCP connect rejected")
        while result != 0:
            check_stop(cancel, deadline)
            _, writable, exceptional = select.select([], [channel], [channel], min(0.1, max(0, deadline-time.monotonic())))
            if writable or exceptional:
                result = channel.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if result:
                    raise OSError(result, "TCP connect rejected")
                break
        return channel
    except BaseException:
        channel.close()
        raise


def tcp_inventory(url, ports, allow_private, cancel, rate=2, budget=60, blocked_ports=()):
    host = urlsplit(url).hostname
    deadline = time.monotonic() + budget
    if cancel.is_set():
        raise ScanCancelled()
    addresses = resolve_checked(host, ports[0], allow_private)
    result = {"host": host, "addresses": addresses[:4], "ports": ports, "observations": [], "complete": True, "note": "Up to four resolved IPs, 32 selected TCP ports and 60 seconds. Port-based service names are hints, not verified products. Shared/CDN addresses may belong to a provider. No credentials or service commands are sent."}
    if len(addresses) > 4:
        result["complete"] = False
        result["note"] += f" {len(addresses)-4} additional addresses were not tested."
    previous = 0.0
    try:
        for address in addresses[:4]:
            for port in ports:
                check_stop(cancel, deadline)
                if port in blocked_ports:
                    result["observations"].append({"address": address, "port": port, "state": "skipped", "service_hint": PORT_HINTS.get(port, "unknown"), "reason": "Local control port is excluded."})
                    result["complete"] = False
                    continue
                delay = max(0, 1/rate - (time.monotonic()-previous))
                if cancel.wait(min(delay, max(0, deadline-time.monotonic()))):
                    raise ScanCancelled()
                check_stop(cancel, deadline)
                previous = time.monotonic()
                row = {"address": address, "port": port, "state": "unknown", "service_hint": PORT_HINTS.get(port, "unknown")}
                try:
                    channel = connect(address, port, cancel, min(deadline, time.monotonic()+2))
                    channel.close()
                    row["state"] = "open"
                except TimeoutError:
                    row["state"] = "timeout"
                except OSError as exc:
                    row["state"] = "closed" if exc.errno in (errno.ECONNREFUSED, 10061) else "unreachable"
                result["observations"].append(row)
    except TimeoutError:
        result["complete"] = False
        result["note"] += " Network time budget reached; remaining combinations were not assessed."
    return result


def tls_inventory(url, allow_private, cancel, budget=25, blocked_ports=()):
    p = urlsplit(url)
    if p.scheme != "https":
        return {"host": p.hostname, "observations": [], "complete": False, "note": "TLS protocol checks require an HTTPS target."}
    deadline = time.monotonic() + budget
    check_stop(cancel, deadline)
    if (p.port or 443) in blocked_ports:
        raise NetworkError("The scanner's control port is excluded from TLS probes.")
    addresses = resolve_checked(p.hostname, p.port or 443, allow_private)
    result = {"host": p.hostname, "address": addresses[0], "port": p.port or 443, "observations": [], "complete": True, "note": "Capability probes use SNI and no application data or authentication. Certificate trust is checked separately by the website crawl. A failed handshake is inconclusive, not proof that a version is disabled. First resolved address only."}
    for name in ("TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"):
        try:
            check_stop(cancel, deadline)
        except TimeoutError:
            result["complete"] = False
            break
        version = getattr(ssl.TLSVersion, name, None)
        row = {"protocol": name, "state": "unassessed"}
        channel = None
        try:
            if version is None:
                raise ValueError("Runtime does not offer this protocol")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                context.minimum_version = version
                context.maximum_version = version
            if name in ("TLSv1", "TLSv1_1"):
                context.set_ciphers("DEFAULT:@SECLEVEL=0")
            probe_deadline = min(deadline, time.monotonic()+5)
            channel = connect(addresses[0], p.port or 443, cancel, probe_deadline)
            channel = context.wrap_socket(channel, server_hostname=p.hostname, do_handshake_on_connect=False)
            while True:
                check_stop(cancel, probe_deadline)
                try:
                    channel.do_handshake()
                    row.update(state="supported", negotiated=channel.version(), cipher=channel.cipher()[0])
                    break
                except ssl.SSLWantReadError:
                    select.select([channel], [], [], 0.1)
                except ssl.SSLWantWriteError:
                    select.select([], [channel], [], 0.1)
        except (ValueError, ssl.SSLError, OSError, TimeoutError) as exc:
            row.update(state="inconclusive", reason=type(exc).__name__)
        finally:
            if channel:
                channel.close()
        result["observations"].append(row)
    return result
