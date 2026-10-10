"""Safe JSON and HTML report serialization."""
from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any, Iterable

from .scanner import redact_sensitive
from .security import safe_report_url


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def build_report(scan: Any, findings: Iterable[Any]) -> dict[str, Any]:
    normalized = []
    for finding in findings:
        normalized.append({
            "id": finding.id,
            "title": redact_sensitive(str(finding.title), 240),
            "category": str(finding.category),
            "severity": str(finding.severity),
            "status": str(finding.finding_status),
            "confidence": int(finding.confidence),
            "affected_url": safe_report_url(str(finding.affected_url)),
            "evidence": redact_sensitive(str(finding.evidence)),
            "impact": redact_sensitive(str(finding.impact)),
            "remediation": redact_sensitive(str(finding.remediation)),
            "observed_at": _iso(finding.observed_at),
        })
    counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    for item in normalized:
        if item["severity"] in counts:
            counts[item["severity"]] += 1
    return {
        "report_version": "1.0",
        "scan": {
            "id": str(scan.id),
            "target": safe_report_url(str(scan.target_url)),
            "hostname": str(scan.hostname),
            "path_scope": str(scan.path_scope),
            "mode": str(scan.mode),
            "status": str(scan.status),
            "created_at": _iso(scan.created_at),
            "started_at": _iso(scan.started_at),
            "completed_at": _iso(scan.completed_at),
            "pages_scanned": int((scan.summary or {}).get("pages_scanned", 0)),
        },
        "summary": {
            "finding_count": len(normalized),
            "by_severity": counts,
            "result_note": "No findings does not mean the website is vulnerability-free. Automated checks cover only the listed, unauthenticated observations.",
        },
        "findings": normalized,
        "tested_areas": list(scan.tested_areas or []),
        "warnings": [redact_sensitive(str(item), 300) for item in (scan.warnings or [])],
        "limitations": [
            "Only explicitly authorized, unauthenticated HTTP(S) content was examined using bounded safe requests.",
            "Scripts and downloads were never executed; backup/configuration-like links were not requested.",
            "The scan does not attempt authentication, exploitation, password guessing, uploads or data changes.",
            "Potential findings and component version matches require manual verification; no scan can prove that a site is free of weaknesses.",
            "Only the configured host and path scope were eligible for crawling; redirects outside scope were blocked.",
        ],
    }


def render_html_report(report: dict[str, Any]) -> str:
    scan = report["scan"]
    summary = report["summary"]
    severity = summary["by_severity"]
    findings_html = []
    for finding in report["findings"]:
        esc = lambda value: html.escape(str(value), quote=True)
        findings_html.append(
            "<article class='finding'>"
            f"<div class='finding-top'><span class='severity severity-{esc(finding['severity'])}'>{esc(finding['severity'])}</span>"
            f"<span class='finding-state'>{esc(finding['status'])} · {esc(finding['confidence'])}% confidence</span></div>"
            f"<h3>{esc(finding['title'])}</h3>"
            f"<p class='url'>{esc(finding['affected_url'])}</p>"
            f"<p><strong>Evidence</strong><br>{esc(finding['evidence'])}</p>"
            f"<p><strong>Possible impact</strong><br>{esc(finding['impact'])}</p>"
            f"<p><strong>Remediation</strong><br>{esc(finding['remediation'])}</p>"
            f"<p class='observed'>Observed: {esc(finding['observed_at'] or '—')}</p>"
            "</article>"
        )
    if not findings_html:
        findings_html.append("<p class='empty'>No reportable findings were observed in the checks that completed. This does not mean the website is vulnerability-free.</p>")
    tested = "".join(f"<li>{html.escape(str(item))}</li>" for item in report["tested_areas"])
    warnings = "".join(f"<li>{html.escape(str(item))}</li>" for item in report["warnings"])
    limitations = "".join(f"<li>{html.escape(str(item))}</li>" for item in report["limitations"])
    target = html.escape(scan["target"], quote=True)
    scan_id = html.escape(scan["id"], quote=True)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Website security scan report · {target}</title>
<style>
:root{{color-scheme:light;--ink:#182331;--muted:#647184;--line:#e5eaf0;--blue:#3559d5;--bg:#f5f7fb}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:980px;margin:38px auto;padding:0 22px}}header,.panel,.finding{{background:#fff;border:1px solid var(--line);border-radius:16px;padding:24px;margin-bottom:18px;box-shadow:0 8px 24px #24324808}}
.kicker{{color:var(--blue);font-size:12px;letter-spacing:.12em;text-transform:uppercase;font-weight:700}}h1{{font-size:30px;margin:8px 0}}h2{{font-size:19px;margin:0 0 14px}}h3{{font-size:18px;margin:12px 0 4px}}p{{margin:8px 0}}.muted,.url,.observed{{color:var(--muted);font-size:13px;overflow-wrap:anywhere}}.summary{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:20px}}.count{{border:1px solid var(--line);border-radius:12px;padding:12px}}.count b{{display:block;font-size:21px;text-transform:capitalize}}.count span{{color:var(--muted);font-size:12px}}.finding-top{{display:flex;align-items:center;gap:10px}}.severity{{border-radius:999px;padding:4px 9px;background:#edf0f6;font-size:11px;text-transform:uppercase;font-weight:700}}.severity-critical,.severity-high{{background:#ffe4e6;color:#ae2638}}.severity-medium{{background:#fff0d7;color:#9a5c00}}.severity-low{{background:#e7f3ff;color:#22589b}}.severity-info{{background:#eef1f5;color:#566173}}.finding-state{{color:var(--muted);font-size:12px}}.empty{{padding:22px;background:#f5f7fb;border-radius:12px}}li{{margin:7px 0}}.disclaimer{{border-left:4px solid #d99a24;background:#fff8e8;padding:14px 16px;border-radius:8px}}@media(max-width:600px){{main{{margin:18px auto}}header,.panel,.finding{{padding:17px}}.summary{{grid-template-columns:repeat(2,1fr)}}}}
</style></head><body><main>
<header><div class="kicker">Safe Website Scanner · Report</div><h1>Security observations</h1>
<p class="muted">Target: <strong>{target}</strong><br>Scope: {html.escape(scan['path_scope'])} · Mode: {html.escape(scan['mode'])} · Status: {html.escape(scan['status'])}<br>Scan ID: {scan_id}<br>Completed: {html.escape(scan['completed_at'] or 'Not completed')}</p>
<div class="summary">{''.join(f'<div class="count"><b>{severity[key]}</b><span>{key}</span></div>' for key in ('critical','high','medium','low','info'))}</div>
<p class="disclaimer"><strong>Interpretation:</strong> {html.escape(summary['result_note'])}</p></header>
<section class="panel"><h2>Findings ({summary['finding_count']})</h2>{''.join(findings_html)}</section>
<section class="panel"><h2>Checks performed</h2><ul>{tested or '<li>No checks were completed.</li>'}</ul></section>
<section class="panel"><h2>Warnings and inconclusive checks</h2><ul>{warnings or '<li>No additional warnings were recorded.</li>'}</ul></section>
<section class="panel"><h2>Limitations</h2><ul>{limitations}</ul></section>
<p class="muted">Generated by Safe Website Scanner. This report is private to the scan owner.</p></main></body></html>"""
