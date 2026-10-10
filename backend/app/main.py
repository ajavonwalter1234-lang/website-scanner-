"""FastAPI application for the authorized safe website scanner."""
from __future__ import annotations

import hashlib
import ipaddress
from contextlib import asynccontextmanager
import json
import logging
import secrets
import sys
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import AuthenticatedUser, CurrentUser
from .config import settings
from .db import get_db, init_db
from .models import DomainVerification, Finding, Scan, utcnow
from .proxy_client import ProxyControlError, ProxyTargetRejected, check_dns_txt, validate_public_host
from .rate_limit import limiter
from .reports import build_report, render_html_report
from .schemas import (
    FindingOut,
    OwnershipChallengeCreate,
    OwnershipChallengeOut,
    OwnershipStatusOut,
    OwnershipVerify,
    ScanCreate,
    ScanOut,
)
from .security import TargetValidationError, normalize_hostname, resolve_public_addresses, validate_target_url


class StructuredFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "time": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": getattr(record, "event", record.getMessage()),
        }
        for name in ("scan_id", "owner_id", "hostname", "status", "duration_ms"):
            value = getattr(record, name, None)
            if value is not None:
                payload[name] = value
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=True)


_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(StructuredFormatter())
_root = logging.getLogger()
if not _root.handlers:
    _root.addHandler(_handler)
_root.setLevel(logging.INFO)
logger = logging.getLogger("safe_scanner.api")
logger.handlers.clear()
logger.addHandler(_handler)
logger.setLevel(logging.INFO)
logger.propagate = False

@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Safe Website Scanner API",
    description="Authorized, bounded, passive website security observations. No exploit testing is performed.",
    version="1.0.0",
    docs_url=None if settings.app_env == "production" else "/docs",
    redoc_url=None if settings.app_env == "production" else "/redoc",
    lifespan=lifespan,
)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _scan_out(scan: Scan) -> ScanOut:
    return ScanOut(
        id=scan.id,
        target_url=scan.target_url,
        hostname=scan.hostname,
        path_scope=scan.path_scope,
        mode=scan.mode,
        max_pages=scan.max_pages,
        status=scan.status,
        progress=scan.progress,
        progress_message=scan.progress_message,
        created_at=_aware(scan.created_at),
        started_at=_aware(scan.started_at),
        completed_at=_aware(scan.completed_at),
        warnings=list(scan.warnings or []),
        tested_areas=list(scan.tested_areas or []),
        summary=dict(scan.summary or {}),
    )


def _owned_scan(db: Session, scan_id: str, user: CurrentUser) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.owner_id != user.user_id:
        # Do not disclose whether another owner's ID exists.
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def _verification(db: Session, owner_id: str, hostname: str) -> DomainVerification | None:
    records = db.scalars(
        select(DomainVerification).where(
            DomainVerification.owner_id == owner_id,
            DomainVerification.hostname == hostname,
            DomainVerification.verified_at.is_not(None),
        )
    ).all()
    now = datetime.now(timezone.utc)
    return next((item for item in records if (_aware(item.expires_at) or now) > now), None)


def _normalize_domain(value: str) -> str:
    hostname = normalize_hostname(value)
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return hostname
    raise TargetValidationError("Domain verification requires a DNS hostname, not an IP address")


def _verify_txt_locally(hostname: str, txt_name: str, expected_hash: str) -> bool:
    try:
        import dns.resolver
    except ImportError:
        return False
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 2
    resolver.lifetime = 4
    try:
        records = resolver.resolve(txt_name, "TXT", lifetime=4)
    except Exception:
        return False
    for record in records:
        chunks = getattr(record, "strings", ())
        value = b"".join(chunks) if chunks else str(record).strip('"').encode("utf-8")
        if secrets.compare_digest(hashlib.sha256(value).hexdigest(), expected_hash):
            return True
    return False


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/scans", response_model=list[ScanOut])
def list_scans(
    user: AuthenticatedUser,
    db: Annotated[Session, Depends(get_db)],
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10000),
) -> list[ScanOut]:
    limiter.check(user.user_id, "read")
    scans = db.scalars(
        select(Scan).where(Scan.owner_id == user.user_id).order_by(Scan.created_at.desc()).offset(offset).limit(limit)
    ).all()
    return [_scan_out(scan) for scan in scans]


@app.post("/api/scans", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    request: ScanCreate,
    user: AuthenticatedUser,
    db: Annotated[Session, Depends(get_db)],
) -> ScanOut:
    limiter.check(user.user_id, "create_scan")
    if request.authorized is not True:
        raise HTTPException(status_code=400, detail="Confirm that you are authorized to scan this website")
    page_limit = 10 if request.mode == "basic" else 30
    if request.max_pages > page_limit:
        raise HTTPException(status_code=422, detail=f"{request.mode.title()} scans are limited to {page_limit} pages")
    try:
        target = validate_target_url(request.url, request.path_scope, resolve_dns=False)
    except TargetValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    try:
        if settings.proxy_url:
            validate_public_host(target.hostname, target.port)
        else:
            resolve_public_addresses(target.hostname, target.port)
    except (TargetValidationError, ProxyTargetRejected):
        raise HTTPException(status_code=422, detail="The hostname must resolve exclusively to public, routable addresses") from None
    except ProxyControlError:
        raise HTTPException(status_code=503, detail="Public DNS safety validation is temporarily unavailable") from None

    if request.mode == "deep" or settings.require_domain_verification:
        try:
            ipaddress.ip_address(target.hostname)
        except ValueError:
            pass
        else:
            raise HTTPException(status_code=403, detail="DNS hostname ownership must be verified; IP-address scans are not available in this mode")
        verification = _verification(db, user.user_id, target.hostname)
        if verification is None:
            raise HTTPException(
                status_code=403,
                detail="Verify ownership of this exact hostname before starting this scan",
            )

    scan = Scan(
        owner_id=user.user_id,
        target_url=target.url,
        hostname=target.hostname,
        path_scope=target.path_scope,
        mode=request.mode,
        max_pages=request.max_pages,
        authorization_confirmed=True,
        status="queued",
        progress=0,
        progress_message="Waiting for an isolated worker",
        tested_areas=[],
        warnings=["Automated results are limited to the configured host and path scope; absence of findings is not proof of security."],
        summary={},
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    logger.info("scan_queued", extra={"event": "scan_queued", "scan_id": scan.id, "owner_id": user.user_id, "hostname": scan.hostname})
    return _scan_out(scan)


@app.get("/api/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: str,
    user: AuthenticatedUser,
    db: Annotated[Session, Depends(get_db)],
) -> ScanOut:
    limiter.check(user.user_id, "read")
    return _scan_out(_owned_scan(db, scan_id, user))


@app.get("/api/scans/{scan_id}/findings", response_model=list[FindingOut])
def get_findings(
    scan_id: str,
    user: AuthenticatedUser,
    db: Annotated[Session, Depends(get_db)],
) -> list[FindingOut]:
    limiter.check(user.user_id, "read")
    scan = _owned_scan(db, scan_id, user)
    findings = db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda item: (order.get(item.severity, 5), item.title.lower(), item.affected_url))
    return [FindingOut(
        id=item.id,
        title=item.title,
        category=item.category,
        severity=item.severity,
        status=item.finding_status,
        confidence=item.confidence,
        affected_url=item.affected_url,
        evidence=item.evidence,
        impact=item.impact,
        remediation=item.remediation,
        observed_at=_aware(item.observed_at),
    ) for item in findings]


@app.get("/api/scans/{scan_id}/report")
def get_report(
    scan_id: str,
    user: AuthenticatedUser,
    db: Annotated[Session, Depends(get_db)],
    report_format: Literal["json", "html"] = Query(default="json", alias="format"),
) -> Response:
    limiter.check(user.user_id, "read")
    scan = _owned_scan(db, scan_id, user)
    if scan.status != "completed":
        raise HTTPException(status_code=409, detail="A report is available after the scan completes")
    findings = db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
    report = build_report(scan, findings)
    filename = f"safe-scan-{scan.id}-report.{report_format}"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"', "X-Content-Type-Options": "nosniff"}
    if report_format == "html":
        return Response(render_html_report(report), media_type="text/html; charset=utf-8", headers=headers)
    return JSONResponse(report, headers=headers)


@app.delete("/api/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: str,
    user: AuthenticatedUser,
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    limiter.check(user.user_id, "delete")
    scan = _owned_scan(db, scan_id, user)
    db.delete(scan)
    db.commit()
    logger.info("scan_deleted", extra={"event": "scan_deleted", "scan_id": scan_id, "owner_id": user.user_id})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.post("/api/ownership/challenges", response_model=OwnershipChallengeOut, status_code=status.HTTP_201_CREATED)
def create_ownership_challenge(
    request: OwnershipChallengeCreate,
    user: AuthenticatedUser,
    db: Annotated[Session, Depends(get_db)],
) -> OwnershipChallengeOut:
    limiter.check(user.user_id, "ownership")
    try:
        hostname = _normalize_domain(request.hostname)
        if settings.proxy_url:
            validate_public_host(hostname, 443)
        else:
            resolve_public_addresses(hostname, 443)
    except (TargetValidationError, ProxyTargetRejected) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except ProxyControlError:
        raise HTTPException(status_code=503, detail="Public DNS safety validation is temporarily unavailable") from None
    if len(hostname) > 220:
        raise HTTPException(status_code=422, detail="The hostname is too long for a DNS verification record")

    token_value = f"safe-website-scanner-verification={secrets.token_urlsafe(32)}"
    token_hash = hashlib.sha256(token_value.encode("utf-8")).hexdigest()
    txt_name = f"_safe-website-scanner-challenge.{hostname}"
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=30)
    existing = db.scalar(select(DomainVerification).where(
        DomainVerification.owner_id == user.user_id,
        DomainVerification.hostname == hostname,
    ))
    if existing is None:
        existing = DomainVerification(
            owner_id=user.user_id,
            hostname=hostname,
            txt_name=txt_name,
            token_hash=token_hash,
            expires_at=expires_at,
            verified_at=None,
        )
        db.add(existing)
    else:
        existing.txt_name = txt_name
        existing.token_hash = token_hash
        existing.expires_at = expires_at
        existing.verified_at = None
    db.commit()
    logger.info("ownership_challenge_created", extra={"event": "ownership_challenge_created", "owner_id": user.user_id, "hostname": hostname})
    return OwnershipChallengeOut(
        hostname=hostname,
        txt_name=txt_name,
        txt_value=token_value,
        expires_at=expires_at,
        instructions="Add this TXT record at your DNS provider, wait for it to propagate, then select Verify ownership. The value is shown only once.",
    )


@app.get("/api/ownership", response_model=OwnershipStatusOut)
def ownership_status(
    hostname: str,
    user: AuthenticatedUser,
    db: Annotated[Session, Depends(get_db)],
) -> OwnershipStatusOut:
    limiter.check(user.user_id, "read")
    try:
        normalized = _normalize_domain(hostname)
    except TargetValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    record = _verification(db, user.user_id, normalized)
    return OwnershipStatusOut(
        hostname=normalized,
        verified=record is not None,
        valid_until=_aware(record.expires_at) if record else None,
    )


@app.post("/api/ownership/verify", response_model=OwnershipStatusOut)
def verify_ownership(
    request: OwnershipVerify,
    user: AuthenticatedUser,
    db: Annotated[Session, Depends(get_db)],
) -> OwnershipStatusOut:
    limiter.check(user.user_id, "ownership")
    try:
        hostname = _normalize_domain(request.hostname)
    except TargetValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    record = db.scalar(select(DomainVerification).where(
        DomainVerification.owner_id == user.user_id,
        DomainVerification.hostname == hostname,
    ))
    now = datetime.now(timezone.utc)
    if record is None or (_aware(record.expires_at) or now) < now:
        raise HTTPException(status_code=404, detail="No active ownership challenge exists for this hostname")
    try:
        if settings.proxy_url:
            verified = check_dns_txt(hostname, record.txt_name, record.token_hash)
        else:
            verified = _verify_txt_locally(hostname, record.txt_name, record.token_hash)
    except ProxyControlError:
        raise HTTPException(status_code=503, detail="DNS verification is temporarily unavailable") from None
    if not verified:
        raise HTTPException(status_code=409, detail="The DNS TXT record was not observed yet; verify the record name and value and try again")
    record.verified_at = now
    record.expires_at = now + timedelta(days=180)
    db.commit()
    logger.info("ownership_verified", extra={"event": "ownership_verified", "owner_id": user.user_id, "hostname": hostname})
    return OwnershipStatusOut(hostname=hostname, verified=True, valid_until=record.expires_at)
