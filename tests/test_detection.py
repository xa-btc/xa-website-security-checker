"""Synthetic local fixtures; never contacts public targets or uses real credentials."""
import copy
import errno
import gzip
import json
import socket
import ssl
import tempfile
import threading
import time
import unittest
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from tester import DETECTOR_REVISION
from tester.exposure import PROBES, matches, soft404
from tester.network import Client, MAX_BODY, NetworkError, Response, ScanCancelled
from tester.reports import export_report
from tester.rules import inspect, summarize_findings
from tester.scanner import DEFAULTS, run_scan
from tester.storage import Store
from tester.surface import parse_ports, sitemap_entries, tcp_inventory, tls_inventory


def response(body, headers=(), url="https://example.test/", status=200):
    return Response(url, status, [("Content-Type", "text/html"), *headers], body, 1)


def rules(body, headers=()):
    return {f["rule"] for f in inspect(response(body, headers))[0]}


class RuleTests(unittest.TestCase):
    def test_meta_and_nonce_csp(self):
        body = '<meta http-equiv="Content-Security-Policy" content="script-src \'nonce-YWJjZGVm\' \'unsafe-inline\'; frame-ancestors \'none\'"><meta name="referrer" content="no-referrer">'
        found = rules(body)
        self.assertNotIn("headers.csp", found)
        self.assertNotIn("headers.csp_unsafe", found)
        self.assertNotIn("headers.referrer", found)
        self.assertIn("headers.frame", found)  # Meta frame-ancestors has no effect.

    def test_multiple_and_duplicate_csp(self):
        found = rules("<title>Test</title>", [("Content-Security-Policy", "script-src 'self'; script-src *"), ("Content-Security-Policy", "script-src *")])
        self.assertNotIn("headers.csp_unsafe", found)
        found = rules("<title>Test</title>", [("Content-Security-Policy", "frame-ancestors *")])
        self.assertTrue({"headers.csp_script", "headers.csp_frame_wildcard"} <= found)

    def test_report_only_and_short_hsts(self):
        found = rules("<title>Test</title>", [("Content-Security-Policy-Report-Only", "default-src 'none'"), ("Strict-Transport-Security", "max-age=120")])
        self.assertTrue({"headers.csp", "headers.csp_report_only", "headers.hsts_short"} <= found)

    def test_csp_intersection_compares_same_context(self):
        headers = [('Content-Security-Policy', "script-src 'self' 'unsafe-inline'"), ('Content-Security-Policy', "script-src 'self' 'unsafe-eval'")]
        self.assertNotIn('headers.csp_unsafe', rules('<title>Test</title>', headers))
        headers[1] = ('Content-Security-Policy', "script-src 'self' 'unsafe-inline'")
        self.assertIn('headers.csp_unsafe', rules('<title>Test</title>', headers))

    def test_csp_strict_dynamic_suppresses_scheme_allowlist(self):
        headers = [('Content-Security-Policy', "script-src 'nonce-YWJjZGVm' 'strict-dynamic' https:")]
        self.assertNotIn('headers.csp_unsafe', rules('<title>Test</title>', headers))
        headers[0] = ('Content-Security-Policy', "script-src 'nonce-YWJjZGVm' 'strict-dynamic' https: 'unsafe-eval'")
        self.assertIn('headers.csp_unsafe', rules('<title>Test</title>', headers))

    def test_cookie_prefix(self):
        bad = [("Set-Cookie", "__Host-session=test-only; Secure; Path=/app; Domain=example.test")]
        self.assertIn("cookies.prefix", rules("", bad))
        good = [("Set-Cookie", "__Host-session=test-only; Secure; Path=/; HttpOnly; SameSite=Lax")]
        self.assertNotIn("cookies.prefix", rules("", good))

    def test_html_base_forms_and_malformed_attributes(self):
        body = '<meta http-equiv><base href="https://provider.test/"><form action="/login" method="invalid"><input type="password"></form><script integrity src="https://cdn.test/a.js"></script>'
        found = rules(body)
        self.assertTrue({"forms.password_external", "forms.password_get", "forms.cache", "content.sri"} <= found)

    def test_secret_detection_and_metadata_redaction(self):
        token = "ghp_" + "T" * 36
        key = "-----BEGIN PRIVATE KEY-----\n" + "QUJD" * 40 + "\n-----END PRIVATE KEY-----"
        body = f'<title>{token} {key}</title><script>//# sourceMappingURL=app.js.map</script>'
        with patch.object(Client, "get", return_value=response(body)):
            result = run_scan("https://example.test/", DEFAULTS)
        found = {f['rule'] for f in result['findings']}
        self.assertTrue({"content.token", "content.private_key", "content.source_map"} <= found)
        serialized = json.dumps(result)
        self.assertNotIn(token, serialized)
        self.assertNotIn("QUJD" * 10, serialized)

    def test_malformed_urls_do_not_abort_scan(self):
        body = '<base href="https://[bad"><img src="http://[bad"><form action="https://bad:port/login"><input type="password"></form><title>Still checked</title>'
        with patch.object(Client, 'get', return_value=response(body)):
            result = run_scan('https://example.test/', DEFAULTS)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(len(result['pages']), 1)
        self.assertTrue(any('malformed resource/form/base' in e['message'] for e in result['errors']))
        self.assertTrue(any(f['rule'] == 'headers.csp' for f in result['findings']))

    def test_html_url_userinfo_is_removed_from_results(self):
        body = '<script src="http://demo-user:synthetic-password@example.test/a.js"></script><form action="https://demo-user:synthetic-password@external.test/login"><input type="password"></form>'
        with patch.object(Client, 'get', return_value=response(body)):
            result = run_scan('https://example.test/', DEFAULTS)
        saved = json.dumps(result)
        self.assertNotIn('synthetic-password', saved)
        self.assertNotIn('demo-user', saved)
        self.assertIn('http://example.test/a.js', saved)

    def test_structured_exposure_and_soft404(self):
        env = PROBES[0]
        self.assertTrue(matches(env, Response("https://example.test/.env", 200, [], "DB_PASSWORD=synthetic-test\n", 1)))
        self.assertFalse(matches(env, response("<html><pre>DB_PASSWORD=example</pre></html>")))
        api = next(p for p in PROBES if p.path == "openapi.json")
        self.assertFalse(matches(api, response('{"openapi":"hello"}')))
        self.assertTrue(matches(api, response('{"openapi":"3.1.0","info":{},"paths":{}}')))
        a = response("<html>" + "Application shell " * 30 + " /candidate</html>", url="https://example.test/candidate")
        b = response("<html>" + "Application shell " * 30 + " /random</html>", url="https://example.test/random")
        self.assertTrue(soft404(a, b))
        self.assertFalse(soft404(a, None))

    def test_app_shell_does_not_become_exposure(self):
        def get(client, url, headers=None):
            return response('<html><title>Application</title><p>PHP Version phpinfo() Configuration</p></html>', url=url)
        with patch.object(Client, "get", get):
            result = run_scan("https://example.test/", {**DEFAULTS, "exposure_checks": True})
        self.assertEqual(len(result["probes"]), 15)
        self.assertTrue(all(p["outcome"] == "soft-404 suppressed" for p in result["probes"]))
        self.assertFalse(any(f['rule'].startswith('exposure.') for f in result['findings']))


class DiscoveryTests(unittest.TestCase):
    def test_malformed_robots_directive_preserves_valid_discovery(self):
        def get(client, url, headers=None):
            if url.endswith('robots.txt'):
                return response('Sitemap: http://[bad\n', url=url)
            if url.endswith('sitemap.xml'):
                return response('<urlset><url><loc>https://example.test/good</loc></url></urlset>', url=url)
            return response('<title>Page</title>', url=url)
        with patch.object(Client, 'get', get):
            result = run_scan('https://example.test/', {**DEFAULTS, 'discovery_checks': True})
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(len(result['pages']), 2)
        self.assertTrue(any('Malformed Sitemap' in e['message'] for e in result['errors']))

    def test_malformed_redirect_preserves_other_pages_and_probes(self):
        def get(client, url, headers=None):
            if url.endswith('/bad') or url.endswith('/.env'):
                return response('', [('Location', 'http://[bad')], url, 302)
            if url.endswith('/'):
                return response('<a href="/bad">Bad</a><a href="/good">Good</a>', url=url)
            return response('<title>Page</title>', url=url, status=200 if url.endswith('/good') else 404)
        with patch.object(Client, 'get', get):
            result = run_scan('https://example.test/', {**DEFAULTS, 'exposure_checks': True})
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(len(result['pages']), 2)
        self.assertEqual(len(result['probes']), 15)
        self.assertEqual(sum('Malformed redirect' in e['message'] for e in result['errors']), 2)

    def test_xml_entities_and_entry_limit(self):
        for xml in ('<!DOCTYPE x [<!ENTITY a "x">]><urlset/>', '<html/>', '<urlset>'):
            with self.assertRaises(ValueError):
                sitemap_entries(xml)
        kind, links, capped = sitemap_entries('<urlset>' + '<url><loc>https://example.test/</loc></url>' * 2001 + '</urlset>')
        self.assertEqual((kind, len(links), capped), ('urlset', 2000, True))

    def test_scoped_discovery_and_hostname_inventory(self):
        called = []
        def get(client, url, headers=None):
            called.append(url)
            path = url.removeprefix('https://example.test')
            if path == '/app/robots.txt':
                return response('Disallow: /app/delete-me\nSitemap: https://foreign.test/map.xml', url=url)
            if path == '/app/sitemap.xml':
                return response('<urlset>' + ''.join(f'<url><loc>{p}</loc></url>' for p in ('https://example.test/app/found', 'https://foreign.test/private', 'https://example.test/elsewhere', 'https://example.test/app/%2e%2e/private', 'https://example.test/app/?token=secret')) + '</urlset>', url=url)
            return response('<title>Page</title>', url=url)
        with patch.object(Client, 'get', get):
            result = run_scan('https://example.test/app/', {**DEFAULTS, 'path_scope': '/app', 'discovery_checks': True})
        self.assertEqual(set(called), {'https://example.test/app/', 'https://example.test/app/robots.txt', 'https://example.test/app/sitemap.xml', 'https://example.test/app/found'})
        self.assertTrue(any(a['host'] == 'foreign.test' for a in result['assets']))
        self.assertNotIn('token=secret', json.dumps(result))

    def test_sitemap_document_budget(self):
        called = []
        def get(client, url, headers=None):
            called.append(url)
            if url.endswith('.xml'):
                return response('<sitemapindex>' + ''.join(f'<sitemap><loc>https://example.test/map{i}.xml</loc></sitemap>' for i in range(20)) + '</sitemapindex>', url=url)
            return response('<title>Page</title>', url=url)
        with patch.object(Client, 'get', get):
            result = run_scan('https://example.test/', {**DEFAULTS, 'discovery_checks': True})
        self.assertEqual(sum(u.endswith('.xml') for u in called), 5)
        self.assertTrue(any('five documents' in s for s in result['limitations']))


class SurfaceTests(unittest.TestCase):
    def test_port_validation(self):
        self.assertEqual(parse_ports('443,80,443'), [80, 443])
        for value in ('', '1-100', '0', '65536', '80,', ','.join(map(str, range(1, 34))), None):
            with self.assertRaises(ValueError):
                parse_ports(value)

    def test_real_open_closed_and_blocked_tcp(self):
        with socket.socket() as opened, socket.socket() as closed:
            opened.bind(('127.0.0.1', 0))
            opened.listen()
            closed.bind(('127.0.0.1', 0))
            # A bound but non-listening socket refuses TCP connections.
            ports = [opened.getsockname()[1], closed.getsockname()[1]]
            result = tcp_inventory('http://127.0.0.1/', ports, True, threading.Event(), rate=5)
            self.assertEqual(result['observations'][0]['state'], 'open')
            self.assertIn(result['observations'][1]['state'], ('closed', 'timeout'))
            # Windows firewall can silently drop SYNs to a non-listening port.
            with patch('tester.surface.connect', side_effect=ConnectionRefusedError(errno.ECONNREFUSED, 'synthetic refusal')):
                refused = tcp_inventory('http://127.0.0.1/', [ports[1]], True, threading.Event())
            self.assertEqual(refused['observations'][0]['state'], 'closed')
            blocked = tcp_inventory('http://127.0.0.1/', [ports[0]], True, threading.Event(), blocked_ports=ports)
            self.assertEqual(blocked['observations'][0]['state'], 'skipped')
            with self.assertRaises(NetworkError):
                tcp_inventory('http://127.0.0.1/', ports, False, threading.Event())

    def test_tcp_cancellation_and_budget(self):
        event = threading.Event()
        event.set()
        with self.assertRaises(ScanCancelled):
            tcp_inventory('http://127.0.0.1/', [80], True, event)
        result = tcp_inventory('http://127.0.0.1/', [80], True, threading.Event(), budget=0)
        self.assertFalse(result['complete'])
        self.assertEqual(result['observations'], [])

    def test_network_only_failure_is_partial(self):
        inventory = {'observations': [{'address': '127.0.0.1', 'port': 50000, 'state': 'open', 'service_hint': 'unknown'}], 'complete': True}
        with patch.object(Client, 'get', side_effect=NetworkError('HTTP failed')), patch('tester.scanner.tcp_inventory', return_value=inventory):
            result = run_scan('http://127.0.0.1/', {**DEFAULTS, 'allow_private': True, 'network_checks': True})
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['findings'], [])


class WireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                raw = b'<title>Compressed page</title>'
                encoding = 'gzip'
                if self.path == '/large':
                    raw = b'A' * (MAX_BODY + 10000)
                if self.path == '/deflate':
                    raw, encoding = zlib.compress(raw), 'deflate'
                else:
                    raw = gzip.compress(raw)
                if self.path == '/broken':
                    raw = raw[:-5]
                if self.path == '/short':
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(raw) + 10))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Encoding', encoding)
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        cls.http = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.https = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        fixtures = Path(__file__).parent / 'fixtures'
        cls.cert = fixtures / 'localhost-test-cert.pem'
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cls.cert, fixtures / 'localhost-test-key.pem')
        cls.https.socket = context.wrap_socket(cls.https.socket, server_side=True)
        for server in (cls.http, cls.https):
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        for server in (cls.http, cls.https):
            server.shutdown()
            server.server_close()

    def test_bounded_decompression_and_incomplete_stream(self):
        client = Client(allow_private=True, delay=0)
        url = f'http://127.0.0.1:{self.http.server_port}'
        for path in ('/', '/deflate'):
            r = client.get(url + path)
            self.assertEqual(r.body, '<title>Compressed page</title>')
            self.assertFalse(r.truncated)
        r = client.get(url + '/large')
        self.assertEqual(len(r.body), MAX_BODY)
        self.assertTrue(r.truncated)
        with self.assertRaises(NetworkError):
            client.get(url + '/broken')
        with self.assertRaises(NetworkError):
            client.get(url + '/short')

    def test_actual_tls_trust_and_protocol_capabilities(self):
        url = f'https://127.0.0.1:{self.https.server_port}/'
        with self.assertRaises(NetworkError):
            Client(allow_private=True, delay=0).get(url)
        trusted = ssl.create_default_context(cafile=str(self.cert))
        with patch('tester.network.ssl.create_default_context', return_value=trusted):
            r = Client(allow_private=True, delay=0).get(url)
        self.assertTrue(r.tls['verified'])
        self.assertIn('localhost', r.tls['sans'])
        self.assertEqual(r.address, '127.0.0.1')
        capabilities = tls_inventory(url, True, threading.Event())
        states = {r['protocol']: r['state'] for r in capabilities['observations']}
        self.assertEqual(states['TLSv1_2'], 'supported')
        self.assertNotEqual(states['TLSv1'], 'supported')
        self.assertEqual(states['TLSv1'], 'inconclusive')
        self.assertEqual(len(capabilities['observations']), 4)

    def test_tls_requires_https_and_cancels(self):
        self.assertFalse(tls_inventory('http://127.0.0.1/', True, threading.Event())['complete'])
        event = threading.Event()
        event.set()
        with self.assertRaises(ScanCancelled):
            tls_inventory(f'https://127.0.0.1:{self.https.server_port}/', True, event)


class CompatibilityTests(unittest.TestCase):
    def test_old_options_and_revision_comparison(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(folder)
            project = store.save_project({'name': 'Test', 'url': 'https://example.test/'})
            with store.connect() as db:
                db.execute('UPDATE projects SET options=? WHERE id=?', (json.dumps({'max_pages': 12}), project['id']))
            self.assertFalse(store.project(project['id'])['options']['network_checks'])
            self.assertEqual(store.project(project['id'])['options']['max_pages'], 12)
            with patch.object(Client, 'get', return_value=response('<title>Test</title>')):
                result = run_scan(project['url'], DEFAULTS)
            legacy = copy.deepcopy(result)
            legacy.pop('detector_revision')
            ids = []
            for data in (legacy, result, result):
                ident = store.create_scan(project['id'], DEFAULTS, False)
                store.update_scan(ident, data)
                ids.append(ident)
            self.assertIsNone(store.scan(ids[1])['result']['comparison']['baseline_id'])
            self.assertEqual(store.scan(ids[2])['result']['comparison']['baseline_id'], ids[1])

    def test_grouping_exports_and_old_results(self):
        with patch.object(Client, 'get', return_value=response('<title>Test</title>')):
            result = run_scan('https://example.test/', DEFAULTS)
        extra = copy.deepcopy(result['findings'][0])
        extra.update(id='different-id', url='https://example.test/second', status='accepted')
        result['findings'].append(extra)
        groups = summarize_findings(result['findings'])
        group = next(g for g in groups if g['rule'] == extra['rule'])
        self.assertEqual((group['occurrences'], group['open_occurrences']), (2, 1))
        result['network'] = {'note': '<script>bad</script>', 'observations': [{'address': '127.0.0.1', 'port': 50000, 'state': 'open', 'service_hint': 'unknown'}]}
        scan = {'created_at': 'test', 'result': result}
        project = {'name': 'test', 'url': 'https://example.test/'}
        body, _ = export_report(scan, project, 'html')
        self.assertIn(b'Selected-host TCP observations', body)
        self.assertIn(b'50000', body)
        self.assertNotIn(b'<script>', body)
        for key in ('network', 'tls_checks', 'assets', 'probes', 'discovery', 'detector_revision', 'finding_groups'):
            result.pop(key, None)
        body, _ = export_report(scan, project, 'html')
        self.assertIn(b'Not evaluated for this scan.', body)


if __name__ == '__main__':
    unittest.main(verbosity=2)
