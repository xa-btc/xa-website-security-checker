import csv
import html
import io
import json

from .rules import summarize_findings


def export_report(scan, project, kind):
    r = scan["result"]
    if kind == "json":
        return json.dumps({"website": project["name"], "target": project["url"], "scan": scan}, indent=2).encode(), "application/json"
    if kind == "csv":
        out = io.StringIO(newline="")
        writer = csv.writer(out)
        columns = ["severity", "title", "url", "confidence", "status", "evidence", "remediation", "note"]
        writer.writerow(columns)
        for f in r["findings"]:
            # Prevent spreadsheet formula execution when an untrusted string is opened.
            values = [str(f.get(c, "")) for c in columns]
            writer.writerow(["'" + v if v.lstrip().startswith(("=", "+", "-", "@", "\t", "\r", "\n")) else v for v in values])
        return out.getvalue().encode("utf-8-sig"), "text/csv; charset=utf-8"
    if kind != "html":
        raise ValueError("Report format must be json, html or csv.")
    e = lambda v: html.escape(str(v))
    items = "".join(f'<article><span class="badge">{e(f["severity"].upper())} · {e(f["confidence"])} confidence · {e(f["status"])}</span><h2>{e(f["title"])}</h2><p>{e(f["url"])}</p><h3>Evidence</h3><pre>{e(f["evidence"])}</pre><h3>Recommended fix</h3><p>{e(f["remediation"])}</p><p>Note: {e(f.get("note", ""))}</p></article>' for f in r["findings"])
    limits = "".join(f"<li>{e(x)}</li>" for x in r["limitations"])
    errors = "".join(f'<li>{e(x["url"])}: {e(x["message"])}</li>' for x in r["errors"])
    skipped = "".join(f'<li>{e(x["url"])}: {e(x["reason"])}</li>' for x in r["skipped"])
    pages = "".join(f'<tr><td>{e(p["status"])}</td><td>{e(p["url"])}</td><td>{e(p["elapsed_ms"])} ms</td><td>{e(p["truncated"])}</td></tr>' for p in r["pages"])
    groups = summarize_findings(r["findings"])
    def table(headers, rows):
        return '<table><thead><tr>' + ''.join(f'<th>{e(h)}</th>' for h in headers) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join(f'<td>{e(v)}</td>' for v in row) + '</tr>' for row in rows) + '</tbody></table>'
    coverage = '<h2>Issue types</h2>' + table(['Issue', 'Severity', 'Occurrences', 'Locations', 'Open / reviewing'], [(g['title'], g['severity'], g['occurrences'], len(g['urls']), g['open_occurrences']) for g in groups])
    coverage += '<h2>Observed hostnames</h2><p>Inventory leads only; other hosts are not automatically scanned.</p>' + table(['Host', 'Source', 'Scope'], [(a['host'], a['source'], a['scope']) for a in r.get('assets', [])])
    network = r.get('network')
    tls = r.get('tls_checks')
    coverage += '<h2>Selected-host TCP observations</h2><p>' + e(network['note'] if network else 'Not evaluated for this scan.') + '</p>'
    if network:
        coverage += table(['Address', 'Port', 'State', 'Service hint', 'Reason'], [(x['address'], x['port'], x['state'], x['service_hint'], x.get('reason', '')) for x in network['observations']])
    if r.get('comparison', {}).get('new_open_ports'):
        coverage += '<p>Newly observed open ports: ' + e(', '.join(r['comparison']['new_open_ports'])) + '</p>'
    coverage += '<h2>TLS protocol capabilities</h2><p>' + e(tls['note'] if tls else 'Not evaluated for this scan.') + '</p>'
    if tls:
        coverage += table(['Protocol', 'State', 'Negotiated', 'Cipher', 'Reason'], [(x['protocol'], x['state'], x.get('negotiated', ''), x.get('cipher', ''), x.get('reason', '')) for x in tls['observations']])
    coverage += '<h2>Exposure probe outcomes</h2>' + table(['URL', 'HTTP', 'Outcome'], [(x['url'], x.get('http_status', ''), x['outcome']) for x in r.get('probes', [])])
    coverage += '<h2>Discovery documents</h2>' + table(['URL', 'Type', 'HTTP', 'Entries', 'Note'], [(x['url'], x['type'], x['status'], x.get('discovered', 0), x.get('note', '') + (' Entry limit reached.' if x.get('limited') else '')) for x in r.get('discovery', [])])
    document = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>Website Tester report</title><style>body{{font:16px/1.6 system-ui;color:#172524;max-width:1000px;margin:50px auto;padding:0 24px}}h1{{font-size:36px}}h2{{font-size:21px}}h3{{font-size:16px}}article{{border:1px solid #d4dfda;border-radius:12px;padding:24px;margin:20px 0;break-inside:avoid}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f0f5f3;padding:16px}}p,td,li{{overflow-wrap:anywhere}}.badge{{font-size:14px;color:#425c52}}table{{border-collapse:collapse;width:100%}}td,th{{text-align:left;border-bottom:1px solid #ddd;padding:10px}}@media print{{body{{margin:0}}}}</style><header><p>XA / WEBSITE TESTER · LOCAL ASSESSMENT</p><h1>{e(project["name"])}</h1><p>{e(project["url"])}</p><p>{e(scan["created_at"])} · {e(r["status"])} · {len(r["pages"])} pages · {r["requests"]} requests · {len(r["findings"])} findings</p></header><h2>Scope and limitations</h2><ul>{limits}</ul><p>{e(r.get("comparison", {}).get("note", ""))}</p><p>Enabled options: {e(json.dumps(r["options"]))}</p><p>Checks evaluated: {e(", ".join(r["checked_rules"]))}</p>{items or '<p>No findings recorded. Review coverage and errors before drawing conclusions.</p>'}<h2>Pages observed</h2><table><tr><th>Status</th><th>URL</th><th>Time</th><th>Truncated</th></tr>{pages}</table><h2>Errors and incomplete checks</h2><ul>{errors or '<li>None recorded.</li>'}</ul><h2>Skipped URLs (up to 100 examples)</h2><ul>{skipped or '<li>None recorded.</li>'}</ul></html>'''
    document = document.replace('<h2>Pages observed</h2>', coverage + '<h2>Pages observed</h2>')
    return document.encode(), "text/html; charset=utf-8"
