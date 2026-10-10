from __future__ import annotations

import anyio
import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main
from app.db import Base, get_db


class SyncASGIClient:
    """Small synchronous adapter over HTTPX's ASGI transport (no network socket)."""

    def request(self, method: str, path: str, **kwargs):
        async def run_request():
            transport = httpx.ASGITransport(app=main.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                return await client.request(method, path, **kwargs)
        return anyio.run(run_request)

    def get(self, path: str, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs):
        return self.request("POST", path, **kwargs)

    def delete(self, path: str, **kwargs):
        return self.request("DELETE", path, **kwargs)


@pytest.fixture
def client(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db():
        session = TestingSession()
        try:
            yield session
        finally:
            session.close()

    monkeypatch.setattr(main, "init_db", lambda: None)
    monkeypatch.setattr(main, "resolve_public_addresses", lambda _host, _port: ["8.8.8.8"])
    main.app.dependency_overrides[get_db] = override_db
    original = dict(main.settings.api_tokens)
    main.settings.api_tokens["other-user-token-long-enough"] = "other-user"
    yield SyncASGIClient()
    main.settings.api_tokens.clear()
    main.settings.api_tokens.update(original)
    main.app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()


def headers(token="dev-local-token"):
    return {"Authorization": f"Bearer {token}"}


def scan_payload(**updates):
    value = {
        "url": "https://example.com/app",
        "path_scope": "/app",
        "mode": "basic",
        "max_pages": 8,
        "authorized": True,
    }
    value.update(updates)
    return value


def test_scan_endpoints_require_authentication(client):
    response = client.get("/api/scans")
    assert response.status_code == 401
    response = client.post("/api/scans", json=scan_payload())
    assert response.status_code == 401


def test_create_scan_requires_explicit_authorization_and_safe_url(client):
    response = client.post("/api/scans", headers=headers(), json=scan_payload(authorized=False))
    assert response.status_code == 400
    assert client.post("/api/scans", headers=headers(), json=scan_payload(authorized=1)).status_code == 422
    assert client.post("/api/scans", headers=headers(), json=scan_payload(max_pages=True)).status_code == 422

    response = client.post("/api/scans", headers=headers(), json=scan_payload(url="http://127.0.0.1/"))
    assert response.status_code == 422

    created = client.post("/api/scans", headers=headers(), json=scan_payload())
    assert created.status_code == 202
    assert created.json()["status"] == "queued"
    assert created.json()["target_url"] == "https://example.com/app"


def test_deep_scan_requires_domain_ownership(client):
    response = client.post("/api/scans", headers=headers(), json=scan_payload(mode="deep", max_pages=20))
    assert response.status_code == 403
    assert "Verify ownership" in response.json()["detail"]


def test_scan_and_findings_are_owner_scoped_and_deletable(client):
    created = client.post("/api/scans", headers=headers(), json=scan_payload())
    scan_id = created.json()["id"]

    assert client.get(f"/api/scans/{scan_id}", headers=headers()).status_code == 200
    assert client.get(f"/api/scans/{scan_id}/findings", headers=headers()).status_code == 200
    assert client.get(f"/api/scans/{scan_id}", headers=headers("other-user-token-long-enough")).status_code == 404
    assert client.delete(f"/api/scans/{scan_id}", headers=headers("other-user-token-long-enough")).status_code == 404
    assert client.delete(f"/api/scans/{scan_id}", headers=headers()).status_code == 204
    assert client.get(f"/api/scans/{scan_id}", headers=headers()).status_code == 404
