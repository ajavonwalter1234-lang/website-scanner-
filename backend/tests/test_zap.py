from __future__ import annotations

from app.zap import normalize_zap_report


def test_zap_alerts_are_scoped_and_raw_attack_evidence_is_discarded():
    report = {
        "site": [{
            "alerts": [{
                "pluginid": "10020",
                "alert": "Example passive header observation",
                "riskcode": "2",
                "confidence": "3",
                "desc": "Sensitive response text must not be retained",
                "solution": "Safe configuration guidance",
                "instances": [
                    {
                        "uri": "https://example.com/app/page?token=private",
                        "attack": "do-not-display-payload",
                        "evidence": "do-not-display-secret",
                    },
                    {"uri": "https://other.example.net/app/page"},
                ],
            }]
        }]
    }
    findings = normalize_zap_report(report, hostname="example.com", path_scope="/app")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "medium"
    assert finding.finding_status == "potential"
    assert finding.affected_url == "https://example.com/app/page"
    assert "do-not-display-payload" not in finding.evidence
    assert "do-not-display-secret" not in finding.evidence
    assert "Sensitive response text" not in finding.evidence
    assert "token=private" not in finding.affected_url
