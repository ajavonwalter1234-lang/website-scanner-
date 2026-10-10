from __future__ import annotations

import json
from datetime import datetime, timezone
from types import SimpleNamespace

from app.reports import build_report, render_html_report


def test_json_and_html_reports_redact_sensitive_values_and_state_limitations():
    now = datetime.now(timezone.utc)
    scan = SimpleNamespace(
        id="scan-123",
        target_url="https://example.com/account?token=do-not-show",
        hostname="example.com",
        path_scope="/account",
        mode="basic",
        status="completed",
        created_at=now,
        started_at=now,
        completed_at=now,
        summary={"pages_scanned": 2},
        tested_areas=["Headers"],
        warnings=["A check was inconclusive"],
    )
    finding = SimpleNamespace(
        id="finding-1",
        title="Header signal <script>alert(1)</script>",
        category="information-disclosure-banner",
        severity="low",
        finding_status="potential",
        confidence=70,
        affected_url="https://example.com/account?secret=value",
        evidence="api_key=super-secret-value; evidence is redacted",
        impact="Possible exposure",
        remediation="Update configuration",
        observed_at=now,
    )
    report = build_report(scan, [finding])
    serialized = json.dumps(report)
    html = render_html_report(report)

    assert report["scan"]["target"] == "https://example.com/account"
    assert "do-not-show" not in serialized
    assert "super-secret-value" not in serialized
    assert "secret=value" not in serialized
    assert "No findings does not mean the website is vulnerability-free" in serialized
    assert "&lt;script&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert "do-not-show" not in html
    assert "super-secret-value" not in html
    assert "Potential findings and component version matches require manual verification" in html


def test_empty_report_does_not_claim_target_is_safe():
    now = datetime.now(timezone.utc)
    scan = SimpleNamespace(
        id="scan-empty", target_url="https://example.com/", hostname="example.com", path_scope="/",
        mode="basic", status="completed", created_at=now, started_at=now, completed_at=now,
        summary={"pages_scanned": 1}, tested_areas=["Headers"], warnings=[],
    )
    report = build_report(scan, [])
    html = render_html_report(report)
    assert report["summary"]["finding_count"] == 0
    assert "vulnerability-free" in html
    assert "No reportable findings" in html
