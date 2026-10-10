"""Environment-backed configuration with safe defaults."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class Settings:
    app_env: str
    database_url: str
    api_tokens: Mapping[str, str]
    require_domain_verification: bool
    proxy_url: str | None
    proxy_key: str | None
    zap_enabled: bool
    zap_command: str
    zap_timeout_seconds: int
    scan_timeout_seconds: int
    max_response_bytes: int
    worker_poll_seconds: float


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _load_tokens(app_env: str) -> dict[str, str]:
    raw = os.getenv("SCANNER_API_TOKENS", "").strip()
    if not raw:
        if app_env == "production":
            raise RuntimeError("SCANNER_API_TOKENS must be configured in production")
        # A conspicuously development-only identity. Replace this before exposing
        # the service beyond a local machine.
        return {"dev-local-token": "local-user"}
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("SCANNER_API_TOKENS must be a JSON object of token:user-id pairs") from exc
    if not isinstance(decoded, dict) or not decoded:
        raise RuntimeError("SCANNER_API_TOKENS must be a non-empty JSON object")
    tokens: dict[str, str] = {}
    for token, user_id in decoded.items():
        if not isinstance(token, str) or len(token) < 16 or not isinstance(user_id, str) or not user_id.strip():
            raise RuntimeError("API tokens must be at least 16 characters and map to non-empty user IDs")
        tokens[token] = user_id.strip()[:128]
    return tokens


def load_settings() -> Settings:
    app_env = os.getenv("APP_ENV", "development").strip().lower()
    database_url = os.getenv("DATABASE_URL", "sqlite:///./scanner.db")
    if database_url.startswith("postgres://"):
        database_url = "postgresql+psycopg://" + database_url[len("postgres://"):]
    if app_env == "production" and database_url.startswith("sqlite:"):
        raise RuntimeError("Production deployments must use PostgreSQL (set DATABASE_URL)")

    require_domain_verification = _bool(
        "REQUIRE_DOMAIN_VERIFICATION", app_env == "production"
    )
    proxy_url = os.getenv("SCANNER_PROXY_URL") or None
    proxy_key = os.getenv("SCANNER_PROXY_KEY") or None
    if proxy_url and not proxy_key:
        raise RuntimeError("SCANNER_PROXY_KEY is required when SCANNER_PROXY_URL is configured")
    if proxy_key and len(proxy_key) < 24:
        raise RuntimeError("SCANNER_PROXY_KEY must contain at least 24 characters")
    zap_timeout = int(os.getenv("ZAP_BASELINE_TIMEOUT_SECONDS", "75"))
    scan_timeout = int(os.getenv("SCAN_TIMEOUT_SECONDS", "180"))
    max_response_bytes = int(os.getenv("MAX_RESPONSE_BYTES", str(512 * 1024)))
    if not 15 <= zap_timeout <= 180:
        raise RuntimeError("ZAP_BASELINE_TIMEOUT_SECONDS must be between 15 and 180")
    if not 30 <= scan_timeout <= 600:
        raise RuntimeError("SCAN_TIMEOUT_SECONDS must be between 30 and 600")
    if not 16 * 1024 <= max_response_bytes <= 2 * 1024 * 1024:
        raise RuntimeError("MAX_RESPONSE_BYTES must be between 16 KiB and 2 MiB")

    return Settings(
        app_env=app_env,
        database_url=database_url,
        api_tokens=_load_tokens(app_env),
        require_domain_verification=require_domain_verification,
        proxy_url=proxy_url,
        proxy_key=proxy_key,
        zap_enabled=_bool("ZAP_BASELINE_ENABLED", False),
        zap_command=os.getenv("ZAP_BASELINE_COMMAND", "zap-baseline.py"),
        zap_timeout_seconds=zap_timeout,
        scan_timeout_seconds=scan_timeout,
        max_response_bytes=max_response_bytes,
        worker_poll_seconds=max(0.25, float(os.getenv("WORKER_POLL_SECONDS", "2"))),
    )


settings = load_settings()
