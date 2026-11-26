"""Run the local dashboard or a single command-line scan. Python 3.10+."""
import argparse
import json
import threading
import webbrowser
from pathlib import Path

from tester.scanner import DEFAULTS, run_scan
from tester.network import normalize_url
from tester.server import Application, make_server


def main():
    parser = argparse.ArgumentParser(description="XA Website Tester — local website security assessments")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--data-dir", type=Path, default=Path(__file__).resolve().parent / "data")
    parser.add_argument("--scan", metavar="URL", help="Run one scan and print a JSON report")
    parser.add_argument("--allow-private", action="store_true", help="Permit localhost/LAN targets")
    parser.add_argument("--exposure-checks", action="store_true", help="Run 15 content-confirmed exposure probes, a nonexistent-page control and CORS")
    parser.add_argument("--max-pages", type=int, help="Page budget; default 30, or 200 with --enhanced")
    parser.add_argument("--discover", action="store_true", help="Discover same-origin pages from robots.txt and up to five sitemaps")
    parser.add_argument("--network-checks", action="store_true", help="Check selected TCP ports on the selected hostname; only use on infrastructure you may test")
    parser.add_argument("--ports", default=DEFAULTS["network_ports"], help="Comma-separated TCP ports (at most 32)")
    parser.add_argument("--tls-checks", action="store_true", help="Probe TLS protocol capabilities without application credentials")
    parser.add_argument("--enhanced", action="store_true", help="Enable discovery and exposure checks with a 200-page budget; network checks remain separate")
    args = parser.parse_args()
    if args.scan:
        result = run_scan(normalize_url(args.scan), {**DEFAULTS, "allow_private": args.allow_private, "exposure_checks": args.exposure_checks or args.enhanced, "max_pages": args.max_pages if args.max_pages is not None else 200 if args.enhanced else 30, "max_depth": 5 if args.enhanced else DEFAULTS["max_depth"], "discovery_checks": args.discover or args.enhanced, "network_checks": args.network_checks, "network_ports": args.ports, "tls_checks": args.tls_checks})
        print(json.dumps(result, indent=2))
        return 0 if result["status"] == "completed" else 2
    try:
        app = Application(args.data_dir)
    except RuntimeError as exc:
        print(str(exc))
        print(f"Open the existing dashboard at http://127.0.0.1:{args.port}/ or use a separate --data-dir.")
        return 1
    try:
        server = make_server(app, args.port)
    except OSError:
        app.shutdown()
        print(f"Cannot start on port {args.port}. If Website Tester is already running, open http://127.0.0.1:{args.port}/. Otherwise choose --port 8766.")
        return 1
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"XA Website Tester: {url}\nData: {app.store.path}\nPress Ctrl+C to stop.", flush=True)
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping scans...", flush=True)
    finally:
        server.server_close()
        app.shutdown()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        import sys
        import traceback
        from datetime import datetime
        detail = traceback.format_exc()
        print(detail, file=sys.stderr)
        crash_path = Path(__file__).parent / ("crash_log_" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".log")
        try:
            crash_path.write_text(detail, encoding="utf-8")
            print(f"Crash details saved to {crash_path}", file=sys.stderr)
        except OSError:
            print("Could not save crash details.", file=sys.stderr)
        raise SystemExit(1)
