from __future__ import annotations

import time

import pytest
from conftest import AppFactory
from fastapi import FastAPI
from fastapi.testclient import TestClient
from web_helpers import PASSWORD, add_domain, csrf, post, register, run_worker

from kalkan.web import services
from kalkan.web.verification import VerificationResult


@pytest.fixture
def verified(monkeypatch: pytest.MonkeyPatch) -> None:
    async def ok(hostname: str, token: str, **kwargs: object) -> VerificationResult:
        return VerificationResult("dns", "DNS kaydı bulundu.")

    monkeypatch.setattr(services, "verify_ownership", ok)


# --- public pages -------------------------------------------------------------


def test_public_pages(client: TestClient) -> None:
    landing = client.get("/")
    assert landing.status_code == 200
    assert "Web sitenizin güvenlik karnesi</span></span></h1>" in landing.text
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/report.css").headers["content-type"].startswith("text/css")
    for asset in ("app.js", "app.css", "landing.js", "landing.css"):
        assert client.get(f"/static/{asset}").status_code == 200, asset


def test_security_headers_on_our_own_pages(client: TestClient) -> None:
    headers = client.get("/").headers
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert "script-src 'self'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "server" not in headers or "uvicorn" not in headers["server"]


def test_hsts_and_secure_cookie_when_https_only(make_app: AppFactory) -> None:
    app = make_app(https_only=True)
    with TestClient(app, base_url="https://testserver") as client:
        response = client.get("/register")
        assert response.headers["strict-transport-security"] == "max-age=31536000"
        assert "secure" in response.headers["set-cookie"].lower()


def test_pages_require_login(client: TestClient) -> None:
    for path in ("/dashboard", "/domains/1", "/scans/1"):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == f"/login?next={path}"
    api = client.get("/api/scans/1")
    assert api.status_code == 401
    assert api.json() == {"detail": "Oturum açmanız gerekiyor."}


def test_not_found_pages(client: TestClient) -> None:
    page = client.get("/yok-boyle-bir-sayfa")
    assert page.status_code == 404
    assert "Aradığınız sayfa bulunamadı" in page.text


# --- accounts -----------------------------------------------------------------


def test_register_logout_login(client: TestClient) -> None:
    response = register(client)
    assert response.status_code == 303 and response.headers["location"] == "/dashboard"
    dashboard = client.get("/dashboard")
    assert "Hesabınız oluşturuldu" in dashboard.text
    assert "sahip@example.com" in dashboard.text
    assert "Hesabınız oluşturuldu" not in client.get("/dashboard").text  # flash shown once

    assert post(client, "/logout").headers["location"] == "/"
    assert client.get("/dashboard", follow_redirects=False).status_code == 303

    token = csrf(client, "/login")
    login = client.post(
        "/login",
        data={
            "email": " SAHIP@example.com ",
            "password": PASSWORD,
            "csrf_token": token,
            "next": "/domains/1",
        },
        follow_redirects=False,
    )
    assert login.status_code == 303 and login.headers["location"] == "/domains/1"
    assert client.get("/", follow_redirects=False).headers["location"] == "/dashboard"
    assert client.get("/login", follow_redirects=False).status_code == 303
    assert client.get("/register", follow_redirects=False).status_code == 303


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"password_confirm": "baska-bir-sifre"}, "Şifreler birbiriyle aynı değil."),
        ({"consent": ""}, "taramak için izniniz olan"),
        ({"password": "kisa", "password_confirm": "kisa"}, "en az 10 karakter"),
        ({"email": "e-posta-degil"}, "Geçerli bir e-posta adresi girin."),
    ],
)
def test_register_validation(client: TestClient, overrides: dict[str, str], message: str) -> None:
    response = register(client, **overrides)
    assert response.status_code == 400
    assert message in response.text


def test_register_duplicate_email(client: TestClient) -> None:
    register(client)
    post(client, "/logout")
    response = register(client, email="Sahip@Example.com")
    assert response.status_code == 400
    assert "zaten bir hesap var" in response.text


def test_login_failures_are_throttled(client: TestClient) -> None:
    register(client)
    post(client, "/logout")
    statuses = []
    for _ in range(4):
        token = csrf(client, "/login")
        response = client.post(
            "/login",
            data={"email": "sahip@example.com", "password": "yanlis-sifre", "csrf_token": token},
        )
        statuses.append(response.status_code)
    assert statuses == [400, 400, 400, 429]
    assert "Çok fazla hatalı deneme" in response.text


def test_login_rejects_open_redirect(client: TestClient) -> None:
    register(client)
    post(client, "/logout")
    token = csrf(client, "/login")
    response = client.post(
        "/login",
        data={
            "email": "sahip@example.com",
            "password": PASSWORD,
            "csrf_token": token,
            "next": "//evil.example",
        },
        follow_redirects=False,
    )
    assert response.headers["location"] == "/dashboard"


def test_unknown_email_login(client: TestClient) -> None:
    token = csrf(client, "/login")
    response = client.post(
        "/login", data={"email": "kimse@example.com", "password": "x" * 12, "csrf_token": token}
    )
    assert response.status_code == 400
    assert "E-posta adresi veya şifre hatalı." in response.text


def test_post_without_csrf_token_is_rejected(client: TestClient) -> None:
    register(client)
    response = client.post("/domains", data={"hostname": "example.com"}, follow_redirects=False)
    assert response.status_code == 403
    forged = client.post(
        "/domains", data={"hostname": "example.com", "csrf_token": "sahte"}, follow_redirects=False
    )
    assert forged.status_code == 403


# --- domains and scans ------------------------------------------------------------


def test_full_scan_flow(app: FastAPI, client: TestClient, verified: None) -> None:
    register(client)
    domain_id = add_domain(client, "https://Example.com/iletisim")
    page = client.get(f"/domains/{domain_id}")
    assert "example.com eklendi" in page.text
    assert "kalkan-site-verification=" in page.text
    assert "/.well-known/kalkan-verification.txt" in page.text
    assert "Taramayı başlat" not in page.text

    refused = post(client, f"/domains/{domain_id}/scans")
    assert refused.headers["location"] == f"/domains/{domain_id}"
    assert "doğrulamanız gerekiyor" in client.get(f"/domains/{domain_id}").text

    post(client, f"/domains/{domain_id}/verify")
    page = client.get(f"/domains/{domain_id}")
    assert "example.com doğrulandı" in page.text
    assert "DNS kaydıyla" in page.text
    assert "Taramayı başlat" in page.text

    started = post(client, f"/domains/{domain_id}/scans")
    scan_url = started.headers["location"]
    scan_id = int(scan_url.rsplit("/", 1)[1])
    pending = client.get(scan_url)
    assert "taranıyor" in pending.text
    assert f'data-scan-poll="/api/scans/{scan_id}"' in pending.text
    assert client.get(f"/api/scans/{scan_id}").json()["status"] == "queued"

    busy = post(client, f"/domains/{domain_id}/scans")
    assert busy.headers["location"] == f"/domains/{domain_id}"
    assert "devam eden bir tarama var" in client.get(f"/domains/{domain_id}").text

    assert run_worker(app) is True
    assert run_worker(app) is False  # queue is empty now

    status = client.get(f"/api/scans/{scan_id}").json()
    assert status == {"id": scan_id, "status": "done", "grade": "C", "score": 79, "error": None}
    report = client.get(scan_url)
    assert "PHP 7.4 artık güvenlik güncellemesi almıyor" in report.text
    assert "PDF olarak indir" in report.text

    download = client.get(f"{scan_url}/report.html")
    assert download.headers["content-disposition"].startswith("attachment;")
    assert "style-src 'unsafe-inline'" in download.headers["content-security-policy"]
    assert "<style>" in download.text
    assert client.get(f"{scan_url}/report.json").json()["grade"] == "C"

    dashboard = client.get("/dashboard")
    assert "Doğrulandı" in dashboard.text and "79/100" in dashboard.text


def test_daily_scan_limit(app: FastAPI, client: TestClient, verified: None) -> None:
    register(client)
    domain_id = add_domain(client)
    post(client, f"/domains/{domain_id}/verify")
    for _ in range(5):  # the Pro plan
        assert post(client, f"/domains/{domain_id}/scans").headers["location"].startswith("/scans/")
        run_worker(app)
    assert (
        post(client, f"/domains/{domain_id}/scans").headers["location"] == f"/domains/{domain_id}"
    )
    assert "günde en fazla 5 kez" in client.get(f"/domains/{domain_id}").text


def test_failed_scan_is_shown(app: FastAPI, client: TestClient, verified: None) -> None:
    register(client)
    domain_id = add_domain(client, "broken.example.com")
    post(client, f"/domains/{domain_id}/verify")
    scan_url = post(client, f"/domains/{domain_id}/scans").headers["location"]
    run_worker(app)
    page = client.get(scan_url)
    assert "Tarama tamamlanamadı" in page.text
    assert "çözümlenemedi" in page.text
    assert client.get(f"{scan_url}/report.html").status_code == 404
    assert client.get(f"{scan_url}/report.json").status_code == 404


def test_failed_verification_message(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    async def nope(hostname: str, token: str, **kwargs: object) -> VerificationResult:
        return VerificationResult(None, "Doğrulama kaydı veya dosyası bulunamadı.")

    monkeypatch.setattr(services, "verify_ownership", nope)
    register(client)
    domain_id = add_domain(client)
    post(client, f"/domains/{domain_id}/verify")
    assert "Doğrulama kaydı veya dosyası bulunamadı." in client.get(f"/domains/{domain_id}").text


@pytest.mark.parametrize(
    ("hostname", "message"),
    [
        ("93.184.216.34", "IP adresi değil, alan adı girin"),
        ("localhost", "IP adresi değil, alan adı girin"),
        ("bozuk alan", "geçerli bir alan adı değil"),
    ],
)
def test_invalid_domains(client: TestClient, hostname: str, message: str) -> None:
    register(client)
    response = post(client, "/domains", {"hostname": hostname})
    assert response.headers["location"] == "/dashboard"
    assert message in client.get("/dashboard").text


def test_domain_limits(client: TestClient) -> None:
    register(client)
    add_domain(client, "example.com")
    post(client, "/domains", {"hostname": "EXAMPLE.com"})
    assert "zaten çalışma alanınızda ekli" in client.get("/dashboard").text
    for tld in ("org", "net", "info", "dev"):
        add_domain(client, f"example.{tld}")
    post(client, "/domains", {"hostname": "example.app"})
    page = client.get("/dashboard").text
    assert "Planınız en fazla 5 alan adına izin veriyor" in page
    assert "5/5 alan adı kullanılıyor" in page


def test_delete_domain(app: FastAPI, client: TestClient, verified: None) -> None:
    register(client)
    domain_id = add_domain(client)
    post(client, f"/domains/{domain_id}/verify")
    scan_url = post(client, f"/domains/{domain_id}/scans").headers["location"]
    run_worker(app)
    assert post(client, f"/domains/{domain_id}/delete").headers["location"] == "/dashboard"
    assert "tüm tarama geçmişi silindi" in client.get("/dashboard").text
    assert client.get(f"/domains/{domain_id}").status_code == 404
    assert client.get(scan_url).status_code == 404


def test_users_cannot_reach_each_others_data(
    app: FastAPI, client: TestClient, verified: None
) -> None:
    register(client, "birinci@example.com")
    domain_id = add_domain(client)
    post(client, f"/domains/{domain_id}/verify")
    scan_url = post(client, f"/domains/{domain_id}/scans").headers["location"]
    scan_id = scan_url.rsplit("/", 1)[1]
    run_worker(app)
    post(client, "/logout")

    register(client, "ikinci@example.com")
    for path in (
        f"/domains/{domain_id}",
        scan_url,
        f"{scan_url}/report.html",
        f"{scan_url}/report.json",
    ):
        assert client.get(path).status_code == 404, path
    assert client.get(f"/api/scans/{scan_id}").status_code == 404
    for action in ("verify", "scans", "delete"):
        assert post(client, f"/domains/{domain_id}/{action}").status_code == 404, action
    # The same domain can be added by another account, but must be verified again.
    other_id = add_domain(client)
    assert other_id != domain_id
    assert "1. Adım" in client.get(f"/domains/{other_id}").text


def test_skip_verification_for_local_development(make_app: AppFactory) -> None:
    app = make_app(skip_verification=True)
    with TestClient(app) as client:
        register(client)
        domain_id = add_domain(client)
        assert "Taramayı başlat" in client.get(f"/domains/{domain_id}").text
        assert post(client, f"/domains/{domain_id}/scans").headers["location"].startswith("/scans/")


def test_embedded_worker_processes_scans(make_app: AppFactory, verified: None) -> None:
    app = make_app(embedded_worker=True, worker_poll_interval=0.05)
    with TestClient(app) as client:
        register(client)
        domain_id = add_domain(client)
        post(client, f"/domains/{domain_id}/verify")
        scan_id = post(client, f"/domains/{domain_id}/scans").headers["location"].rsplit("/", 1)[1]
        for _ in range(100):
            if client.get(f"/api/scans/{scan_id}").json()["status"] == "done":
                break
            time.sleep(0.05)
        assert client.get(f"/api/scans/{scan_id}").json()["status"] == "done"
