"""Single-job-at-a-time isolated scan worker process."""
from __future__ import annotations

import logging
import signal
import sys
import time
from datetime import datetime, timezone

from sqlalchemy import select

from .config import settings
from .db import SessionLocal, init_db
from .models import Finding, Scan, utcnow
from .proxy_client import ProxyControlError, check_dns_records, register_scan_policy, revoke_scan_policy
from .scanner import PassiveScanner, SafeScanError, ScanCancelled
from .security import TargetValidationError, validate_target_url
from .zap import run_zap_baseline


class WorkerFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        import json
        payload = {
            "time": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "event": getattr(record, "event", record.getMessage()),
        }
        for key in ("scan_id", "hostname", "status"):
            if getattr(record, key, None) is not None:
                payload[key] = getattr(record, key)
        return json.dumps(payload, separators=(",", ":"))


handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(WorkerFormatter())
logger = logging.getLogger("safe_scanner.worker")
logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = False

_stop = False


def _request_stop(_signum, _frame):
    global _stop
    _stop = True


def claim_next_scan() -> str | None:
    with SessionLocal() as db:
        scan = db.scalar(
            select(Scan)
            .where(Scan.status == "queued")
            .order_by(Scan.created_at.asc())
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if scan is None:
            return None
        scan.status = "running"
        scan.progress = 1
        scan.progress_message = "Validating target and preparing isolated checks"
        scan.started_at = utcnow()
        scan.error_message = None
        db.commit()
        return scan.id


def _snapshot(scan_id: str) -> dict | None:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return None
        return {
            "id": scan.id,
            "target_url": scan.target_url,
            "hostname": scan.hostname,
            "path_scope": scan.path_scope,
            "mode": scan.mode,
            "max_pages": scan.max_pages,
            "status": scan.status,
        }


def _scan_exists(scan_id: str) -> bool:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        return scan is not None and scan.status == "running"


def _update_progress(scan_id: str, percent: int, message: str) -> bool:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.status != "running":
            return False
        scan.progress = max(scan.progress, min(98, percent))
        scan.progress_message = message[:240]
        db.commit()
        return True


def _fail(scan_id: str, message: str) -> None:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = "failed"
        scan.progress = 100
        scan.progress_message = "Scan could not be completed safely"
        scan.error_message = message[:300]
        scan.completed_at = utcnow()
        scan.warnings = list(dict.fromkeys((scan.warnings or []) + [message]))[:30]
        db.commit()


def process_scan(scan_id: str) -> None:
    snapshot = _snapshot(scan_id)
    if snapshot is None or snapshot["status"] != "running":
        return
    policy_registered = False
    start = time.monotonic()
    try:
        target = validate_target_url(
            snapshot["target_url"],
            snapshot["path_scope"],
            resolve_dns=not bool(settings.proxy_url),
        )
        if target.hostname != snapshot["hostname"]:
            raise TargetValidationError("The target host changed after validation")
        if settings.proxy_url:
            register_scan_policy(scan_id, target.hostname, target.path_scope)
            policy_registered = True

        def update(percent: int, message: str) -> None:
            if not _update_progress(scan_id, percent, message):
                raise ScanCancelled("Scan cancelled because its stored record was deleted")

        scanner = PassiveScanner(
            scan_id=scan_id,
            target=target,
            max_pages=snapshot["max_pages"],
            progress=update,
            cancelled=lambda: not _scan_exists(scan_id),
            dns_checker=check_dns_records if settings.proxy_url else None,
            zap_runner=run_zap_baseline if settings.zap_enabled and settings.proxy_url else None,
        )
        result = scanner.run()
        if not _scan_exists(scan_id):
            return
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            if scan is None or scan.status != "running":
                return
            for item in result.findings:
                db.add(Finding(
                    scan_id=scan_id,
                    fingerprint=item.fingerprint,
                    title=item.title,
                    category=item.category,
                    severity=item.severity,
                    finding_status=item.finding_status,
                    confidence=item.confidence,
                    affected_url=item.affected_url,
                    evidence=item.evidence,
                    impact=item.impact,
                    remediation=item.remediation,
                    observed_at=utcnow(),
                ))
            scan.status = "completed"
            scan.progress = 100
            scan.progress_message = "Scan complete · review findings and warnings"
            scan.tested_areas = result.tested_areas
            scan.warnings = list(dict.fromkeys((scan.warnings or []) + result.warnings))[:30]
            scan.summary = {
                "pages_scanned": result.pages_scanned,
                "finding_count": len(result.findings),
                "tls": result.tls,
                "duration_seconds": round(time.monotonic() - start, 2),
            }
            scan.completed_at = utcnow()
            db.commit()
        logger.info("scan_completed", extra={"event": "scan_completed", "scan_id": scan_id, "hostname": snapshot["hostname"], "status": "completed"})
    except ScanCancelled:
        logger.info("scan_cancelled", extra={"event": "scan_cancelled", "scan_id": scan_id, "hostname": snapshot["hostname"], "status": "cancelled"})
        return
    except SafeScanError:
        message = "The target could not be reached or validated within the safe scan policy."
        _fail(scan_id, message)
        logger.warning("scan_failed", extra={"event": "scan_failed", "scan_id": scan_id, "hostname": snapshot["hostname"], "status": "failed"})
    except (TargetValidationError, ProxyControlError):
        message = "The target could not be resolved safely or the isolated egress policy was unavailable."
        _fail(scan_id, message)
        logger.warning("scan_failed", extra={"event": "scan_failed", "scan_id": scan_id, "hostname": snapshot["hostname"], "status": "failed"})
    except Exception:
        message = "An internal scan error occurred; no raw request or response data was retained."
        _fail(scan_id, message)
        logger.error("scan_failed", extra={"event": "scan_failed", "scan_id": scan_id, "hostname": snapshot["hostname"], "status": "failed"})
    finally:
        if policy_registered:
            revoke_scan_policy(scan_id)


def run_forever() -> None:
    init_db()
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    logger.info("worker_started", extra={"event": "worker_started"})
    while not _stop:
        try:
            scan_id = claim_next_scan()
            if scan_id is None:
                time.sleep(settings.worker_poll_seconds)
            else:
                process_scan(scan_id)
        except Exception:
            logger.error("worker_loop_error", extra={"event": "worker_loop_error"})
            time.sleep(settings.worker_poll_seconds)
    logger.info("worker_stopped", extra={"event": "worker_stopped"})


if __name__ == "__main__":
    run_forever()
