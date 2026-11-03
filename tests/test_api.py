from __future__ import annotations

import re

import pytest
from conftest import AppFactory
from fastapi import FastAPI
from fastapi.testclient import TestClient
from web_helpers import post, register, run_worker

from kalkan.web import services
from kalkan.web.verification import VerificationResult

TOKEN_RE = re.compile(r"(klk_[A-Za-z0-9_-]{20,})")


def create_token(client: TestClient, name: str = "CI hattı") -> str:
    response = post(client, "/account/tokens", {"name": name})
    assert response.status_code == 201, response.text
    assert response.headers["cache-control"] == "no-store"
    match = TOKEN_RE.search(response.text)
    assert match, "token not shown"
    return match.group(1)


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def token(client: TestClient) -> str:
    register(client)
    return create_token(client)


@pytest.fixture
def verified(monkeypatch: pytest.MonkeyPatch) -> None:
    async def ok(hostname: str, token: str, **kwargs: object) -> VerificationResult:
        return VerificationResult("http", "Doğrulama dosyası bulundu.")

    monkeypatch.setattr(services, "verify_ownership", ok)


def test_requires_a_valid_token(client: TestClient) -> None:
    for headers in ({}, auth("klk_yanlis"), auth("baska-bir-sey"), {"Authorization": "Basic eA=="}):
        response = client.get("/api/v1/me", headers=headers)
        assert response.status_code == 401, headers
        assert response.headers["www-authenticate"] == "Bearer"
        assert response.json() == {"detail": "Geçerli bir API tokeni gerekiyor."}


def test_session_cookie_is_not_accepted(client: TestClient) -> None:
    """The API ignores the browser session, so it cannot be driven by CSRF."""
    register(client)
    assert client.get("/api/v1/me").status_code == 401


def test_me_and_token_bookkeeping(client: TestClient, token: str) -> None:
    me = client.get("/api/v1/me", headers=auth(token)).json()
    assert me["email"] == "sahip@example.com"
    assert me["email_verified"] is False
    page = client.get("/account").text
    assert "CI hattı" in page
    assert token[:12] in page
    assert token not in page  # shown once, never again
    assert "Son kullanım" in page


def test_domain_lifecycle(app: FastAPI, client: TestClient, token: str, verified: None) -> None:
    created = client.post(
        "/api/v1/domains", json={"hostname": "https://Örnek.com.tr/"}, headers=auth(token)
    )
    assert created.status_code == 201
    domain = created.json()
    assert created.headers["location"] == f"/api/v1/domains/{domain['id']}"
    assert domain["hostname"] == "xn--rnek-4qa.com.tr"
    assert domain["display_name"] == "örnek.com.tr"
    assert domain["verified"] is False
    assert domain["verification"]["txt_record_value"].startswith("kalkan-site-verification=")
    assert domain["verification"]["file_url"].endswith("/.well-known/kalkan-verification.txt")

    duplicate = client.post(
        "/api/v1/domains", json={"hostname": "örnek.com.tr"}, headers=auth(token)
    )
    assert duplicate.status_code == 409
    invalid = client.post("/api/v1/domains", json={"hostname": "10.0.0.1"}, headers=auth(token))
    assert invalid.status_code == 422

    base = f"/api/v1/domains/{domain['id']}"
    early = client.post(f"{base}/scans", headers=auth(token))
    assert early.status_code == 403
    assert "doğrulamanız gerekiyor" in early.json()["detail"]

    verification = client.post(f"{base}/verify", headers=auth(token)).json()
    assert verification == {
        "verified": True,
        "method": "http",
        "message": "Doğrulama dosyası bulundu.",
    }
    detail = client.get(base, headers=auth(token)).json()
    assert detail["verified"] is True and detail["verification"] is None

    started = client.post(f"{base}/scans", headers=auth(token))
    assert started.status_code == 202
    scan = started.json()
    assert scan["status"] == "queued" and scan["trigger"] == "api"
    scan_url = started.headers["location"]
    assert client.post(f"{base}/scans", headers=auth(token)).status_code == 409
    assert client.get(f"{scan_url}/report", headers=auth(token)).status_code == 409

    run_worker(app)
    finished = client.get(scan_url, headers=auth(token)).json()
    assert finished["status"] == "done" and finished["grade"] == "C"
    report = client.get(f"{scan_url}/report", headers=auth(token)).json()
    assert report["findings"][0]["id"] == "software.eol.php"
    history = client.get(f"{base}/scans?limit=5", headers=auth(token)).json()
    assert [s["id"] for s in history] == [scan["id"]]
    assert client.get(f"{base}/scans?limit=500", headers=auth(token)).status_code == 422

    listed = client.get("/api/v1/domains", headers=auth(token)).json()
    assert [d["id"] for d in listed] == [domain["id"]]

    assert client.delete(base, headers=auth(token)).status_code == 204
    assert client.get(base, headers=auth(token)).status_code == 404
    assert client.get(scan_url, headers=auth(token)).status_code == 404


def test_schedule_settings(client: TestClient, token: str) -> None:
    domain_id = client.post(
        "/api/v1/domains", json={"hostname": "example.com"}, headers=auth(token)
    ).json()["id"]
    url = f"/api/v1/domains/{domain_id}"
    updated = client.patch(url, json={"scan_interval_days": 7}, headers=auth(token)).json()
    assert updated["scan_interval_days"] == 7
    assert updated["next_scan_at"] is not None
    assert updated["notify_email"] is True
    muted = client.patch(url, json={"notify_email": False}, headers=auth(token)).json()
    assert muted["scan_interval_days"] == 7 and muted["notify_email"] is False
    off = client.patch(url, json={"scan_interval_days": 0}, headers=auth(token)).json()
    assert off["next_scan_at"] is None
    bad = client.patch(url, json={"scan_interval_days": 3}, headers=auth(token))
    assert bad.status_code == 422
    assert bad.json() == {"detail": "Geçersiz tarama sıklığı."}


def test_daily_limit_is_429(app: FastAPI, client: TestClient, token: str, verified: None) -> None:
    domain_id = client.post(
        "/api/v1/domains", json={"hostname": "example.com"}, headers=auth(token)
    ).json()["id"]
    client.post(f"/api/v1/domains/{domain_id}/verify", headers=auth(token))
    for _ in range(5):  # the Pro plan
        assert (
            client.post(f"/api/v1/domains/{domain_id}/scans", headers=auth(token)).status_code
            == 202
        )
        run_worker(app)
    assert client.post(f"/api/v1/domains/{domain_id}/scans", headers=auth(token)).status_code == 429


def test_tokens_only_see_their_owners_data(client: TestClient, token: str) -> None:
    domain_id = client.post(
        "/api/v1/domains", json={"hostname": "example.com"}, headers=auth(token)
    ).json()["id"]
    post(client, "/logout")
    register(client, "ikinci@example.com")
    other = create_token(client)
    assert client.get("/api/v1/domains", headers=auth(other)).json() == []
    for method, path in (
        ("GET", f"/api/v1/domains/{domain_id}"),
        ("PATCH", f"/api/v1/domains/{domain_id}"),
        ("DELETE", f"/api/v1/domains/{domain_id}"),
        ("POST", f"/api/v1/domains/{domain_id}/verify"),
        ("POST", f"/api/v1/domains/{domain_id}/scans"),
        ("GET", f"/api/v1/domains/{domain_id}/scans"),
    ):
        response = client.request(method, path, headers=auth(other), json={})
        assert response.status_code == 404, (method, path)


def test_rate_limit(make_app: AppFactory) -> None:
    with TestClient(make_app(api_requests_per_minute=3)) as client:
        register(client)
        token = create_token(client)
        statuses = [client.get("/api/v1/me", headers=auth(token)).status_code for _ in range(4)]
        assert statuses == [200, 200, 200, 429]
        limited = client.get("/api/v1/me", headers=auth(token))
        assert limited.headers["retry-after"] == "60"


def test_deleted_token_stops_working(client: TestClient, token: str) -> None:
    assert client.get("/api/v1/me", headers=auth(token)).status_code == 200
    token_id = re.search(r"/account/tokens/(\d+)/delete", client.get("/account").text)
    assert token_id
    post(client, f"/account/tokens/{token_id.group(1)}/delete")
    assert "API tokeni silindi" in client.get("/account").text
    assert client.get("/api/v1/me", headers=auth(token)).status_code == 401
    post(client, "/account/tokens/999/delete")
    assert "Token bulunamadı" in client.get("/account").text


def test_token_limits_and_names(make_app: AppFactory) -> None:
    with TestClient(make_app(max_api_tokens_per_user=1)) as client:
        register(client)
        post(client, "/account/tokens", {"name": "   "})
        assert "Token için bir ad girin" in client.get("/account").text
        create_token(client)
        post(client, "/account/tokens", {"name": "ikinci"})
        assert "En fazla 1 API tokeni" in client.get("/account").text


def test_openapi_documents_only_the_public_api(client: TestClient) -> None:
    schema = client.get("/api/openapi.json").json()
    assert schema["info"]["title"] == "Kalkan API"
    paths = set(schema["paths"])
    assert paths and all(p.startswith("/api/v1/") for p in paths)
    assert "/api/v1/domains/{domain_id}/scans" in paths
    assert "API token" in schema["components"]["securitySchemes"]

    docs = client.get("/api/docs")
    assert docs.status_code == 200
    assert "swagger-ui" in docs.text
    csp = docs.headers["content-security-policy"]
    assert "https://cdn.jsdelivr.net" in csp and "frame-ancestors 'none'" in csp
    # the relaxed policy is limited to the docs page
    assert "cdn.jsdelivr.net" not in client.get("/").headers["content-security-policy"]
