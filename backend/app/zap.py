"""Optional OWASP ZAP Baseline CLI adapter.

The adapter is passive-only, time-bounded, and refuses to run without the
allowlisting egress proxy. It discards ZAP's raw evidence/attack fields so a
report cannot accidentally include payloads, cookies, or response secrets.
"""
from __future__ import annotations

import html
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .config import settings
from .scanner import FindingDraft, classify_severity, redact_sensitive
from .security import TargetValidationError, safe_report_url, validate_target_url


def _clean_label(value: object) -> str:
    text = html.unescape(str(value or ""))
    text = re.sub(r"<[^>]*>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return redact_sensitive(text, 180) or "Passive rule signal"


def normalize_zap_report(document: dict, *, hostname: str, path_scope: str) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    sites = document.get("site", []) if isinstance(document, dict) else []
    if not isinstance(sites, list):
        return findings
    seen: set[tuple[str, str]] = set()
    for site in sites:
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts", [])
        if not isinstance(alerts, list):
            continue
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            name = _clean_label(alert.get("alert"))
            plugin_id = str(alert.get("pluginid", "unknown"))[:32]
            instances = alert.get("instances", [])
            if not isinstance(instances, list):
                continue
            try:
                riskcode = int(alert.get("riskcode", 0))
            except (TypeError, ValueError):
                riskcode = 0
            try:
                zap_confidence = int(alert.get("confidence", 1))
            except (TypeError, ValueError):
                zap_confidence = 1
            for instance in instances[:50]:
                if not isinstance(instance, dict):
                    continue
                raw_url = str(instance.get("uri", ""))
                try:
                    parsed = urlsplit(raw_url)
                    # Keep only the public origin/path in the report. Query strings
                    # are deliberately discarded and are not retained as evidence.
                    clean_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
                    target = validate_target_url(clean_url, path_scope, resolve_dns=False)
                except (ValueError, TargetValidationError):
                    continue
                if target.hostname != hostname:
                    continue
                key = (plugin_id, safe_report_url(target.url))
                if key in seen:
                    continue
                seen.add(key)
                confidence = max(20, min(95, 35 + zap_confidence * 15))
                status = "confirmed" if zap_confidence >= 4 else "potential"
                risk_label = {0: "informational", 1: "low", 2: "medium", 3: "high", 4: "critical"}.get(riskcode, "unrated")
                findings.append(FindingDraft(
                    title=f"OWASP ZAP: {name}",
                    category=f"zap-{plugin_id}",
                    severity=classify_severity(f"zap-{plugin_id}", riskcode),
                    finding_status=status,
                    confidence=confidence,
                    affected_url=safe_report_url(target.url),
                    evidence=f"OWASP ZAP Baseline reported a {risk_label} passive signal (confidence {zap_confidence}/4). Raw response evidence and scanner payload fields were not retained.",
                    impact="The passive signal may indicate a security weakness; manual verification may be required to determine applicability.",
                    remediation="Review the control identified by the alert and apply the framework or vendor's current secure configuration guidance.",
                ))
    return findings


def run_zap_baseline(scan_id: str, target_url: str, hostname: str, path_scope: str, proxy_url: str | None, proxy_key: str | None) -> tuple[list[FindingDraft], list[str]]:
    if not proxy_url or not proxy_key:
        return [], ["OWASP ZAP Baseline was not run because the allowlisting egress proxy is required."]
    command = shutil.which(settings.zap_command)
    if command is None:
        return [], ["OWASP ZAP Baseline is enabled but its CLI is not installed in the isolated worker image."]
    try:
        proxy = urlsplit(proxy_url)
        proxy_host = proxy.hostname or ""
        proxy_port = proxy.port or 3128
        with tempfile.TemporaryDirectory(prefix="safe-zap-") as temporary:
            output_path = Path(temporary) / "baseline.json"
            env = os.environ.copy()
            # Java's HTTP client sends Proxy-Authorization after a 407 challenge;
            # the egress proxy binds those credentials to the active scan policy.
            java_options = (
                f"-Dhttp.proxyHost={proxy_host} -Dhttp.proxyPort={proxy_port} "
                f"-Dhttps.proxyHost={proxy_host} -Dhttps.proxyPort={proxy_port} "
                f"-Dhttp.proxyUser={scan_id} -Dhttp.proxyPassword={proxy_key} "
                f"-Dhttps.proxyUser={scan_id} -Dhttps.proxyPassword={proxy_key}"
            )
            old_options = env.get("JAVA_TOOL_OPTIONS", "").strip()
            env["JAVA_TOOL_OPTIONS"] = f"{old_options} {java_options}".strip()
            completed = subprocess.run(
                [command, "-t", target_url, "-m", "1", "-I", "-J", str(output_path)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=settings.zap_timeout_seconds,
                check=False,
                env=env,
                close_fds=True,
            )
            if not output_path.is_file():
                return [], ["OWASP ZAP Baseline did not produce a report; its checks are inconclusive."]
            try:
                document = json.loads(output_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                return [], ["OWASP ZAP Baseline returned an unreadable report; its checks are inconclusive."]
            findings = normalize_zap_report(document, hostname=hostname, path_scope=path_scope)
            warnings = []
            if completed.returncode not in (0, 1, 2):
                warnings.append("OWASP ZAP Baseline exited unexpectedly; review the custom passive results as partial coverage.")
            if completed.returncode == 2:
                warnings.append("OWASP ZAP Baseline could not access the target; its results are incomplete.")
            return findings, warnings
    except subprocess.TimeoutExpired:
        return [], ["OWASP ZAP Baseline exceeded its configured time limit; its checks are inconclusive."]
    except Exception:
        return [], ["OWASP ZAP Baseline could not run safely; its checks are inconclusive."]
