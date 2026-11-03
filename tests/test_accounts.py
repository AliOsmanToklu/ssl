from __future__ import annotations

import json
from collections.abc import Iterator

import pytest
from conftest import AppFactory
from fastapi.testclient import TestClient
from web_helpers import (
    PASSWORD,
    add_domain,
    csrf,
    last_email,
    link_path,
    login,
    post,
    register,
)

from kalkan.web.mail import MemoryMailer
from kalkan.web.tokens import Signer

NEW_PASSWORD = "yepyeni-sifre-2026"


@pytest.fixture
def strict_client(make_app: AppFactory) -> Iterator[TestClient]:
    """An app that requires a verified e-mail address before scanning (the default)."""
    with TestClient(make_app(require_email_verification=True, skip_verification=True)) as client:
        yield client


# --- e-mail verification ---------------------------------------------------------


def test_registration_sends_a_verification_link(
    strict_client: TestClient, mailer: MemoryMailer
) -> None:
    register(strict_client)
    email = last_email(mailer, "verify")
    assert email.to == "sahip@example.com"
    assert "https://kalkan.test/verify-email/" in email.body

    dashboard = strict_client.get("/dashboard").text
    assert "E-posta adresinizi doğrulayın" in dashboard  # banner

    domain_id = add_domain(strict_client)
    refused = post(strict_client, f"/domains/{domain_id}/scans")
    assert refused.headers["location"] == f"/domains/{domain_id}"
    assert "e-posta adresinizi doğrulayın" in strict_client.get(f"/domains/{domain_id}").text

    confirmed = strict_client.get(link_path(email), follow_redirects=False)
    assert confirmed.headers["location"] == "/dashboard"
    page = strict_client.get("/dashboard").text
    assert "E-posta adresiniz doğrulandı" in page
    assert "E-posta adresinizi doğrulayın" not in page
    assert (
        post(strict_client, f"/domains/{domain_id}/scans").headers["location"].startswith("/scans/")
    )


def test_verification_link_works_when_signed_out(
    strict_client: TestClient, mailer: MemoryMailer
) -> None:
    register(strict_client)
    post(strict_client, "/logout")
    response = strict_client.get(link_path(last_email(mailer, "verify")), follow_redirects=False)
    assert response.headers["location"] == "/login"


@pytest.mark.parametrize("token", ["bozuk-token", "eyJ1IjoxfQ.aaaa.bbbb"])
def test_invalid_verification_link(strict_client: TestClient, token: str) -> None:
    response = strict_client.get(f"/verify-email/{token}", follow_redirects=False)
    assert response.headers["location"] == "/login"
    assert "geçersiz veya süresi dolmuş" in strict_client.get("/login").text


def test_expired_verification_token_is_rejected() -> None:
    from kalkan.web.models import User

    signer = Signer("secret")
    user = User(id=1, email="a@example.com", password_hash="x")
    token = signer.email_token(user)
    assert signer.read_email_token(token) is not None
    assert signer.read_email_token(token, max_age=-1) is None
    assert Signer("baska-secret").read_email_token(token) is None


def test_resend_verification(strict_client: TestClient, mailer: MemoryMailer) -> None:
    register(strict_client)
    for _ in range(3):
        post(strict_client, "/verify-email/resend")
    assert len([e for e in mailer.outbox if e.kind == "verify"]) == 4  # signup + 3 resends
    post(strict_client, "/verify-email/resend")
    assert "Çok sık istek" in strict_client.get("/account").text
    assert len([e for e in mailer.outbox if e.kind == "verify"]) == 4

    strict_client.get(link_path(last_email(mailer, "verify")))
    post(strict_client, "/verify-email/resend")
    assert "zaten doğrulanmış" in strict_client.get("/account").text


# --- password reset ---------------------------------------------------------------


def test_password_reset_flow(client: TestClient, mailer: MemoryMailer) -> None:
    register(client)
    post(client, "/logout")

    page = client.post(
        "/forgot-password",
        data={"email": "SAHIP@example.com", "csrf_token": csrf(client, "/forgot-password")},
    )
    assert "Bu adresle kayıtlı bir hesap varsa" in page.text
    reset_path = link_path(last_email(mailer, "reset"))

    form = client.get(reset_path)
    assert form.headers["referrer-policy"] == "no-referrer"
    assert "Yeni şifre belirleyin" in form.text
    mismatch = client.post(
        reset_path,
        data={
            "password": NEW_PASSWORD,
            "password_confirm": "farkli",
            "csrf_token": csrf(client, reset_path),
        },
    )
    assert mismatch.status_code == 400
    done = client.post(
        reset_path,
        data={
            "password": NEW_PASSWORD,
            "password_confirm": NEW_PASSWORD,
            "csrf_token": csrf(client, reset_path),
        },
        follow_redirects=False,
    )
    assert done.headers["location"] == "/dashboard"
    assert "Şifreniz değiştirildi" in client.get("/dashboard").text
    assert last_email(mailer, "password-changed").to == "sahip@example.com"

    # The link is single-use: the password fingerprint inside it no longer matches.
    reused = client.get(reset_path)
    assert reused.status_code == 400
    assert "kullanılmış" in reused.text

    post(client, "/logout")
    assert login(client, password=PASSWORD).status_code == 400
    assert login(client, password=NEW_PASSWORD).status_code == 303


def test_forgot_password_does_not_reveal_accounts(client: TestClient, mailer: MemoryMailer) -> None:
    response = client.post(
        "/forgot-password",
        data={"email": "kimse@example.com", "csrf_token": csrf(client, "/forgot-password")},
    )
    assert response.status_code == 200
    assert "Bu adresle kayıtlı bir hesap varsa" in response.text
    assert mailer.outbox == []


def test_forgot_password_is_rate_limited(client: TestClient) -> None:
    statuses = []
    for _ in range(6):
        response = client.post(
            "/forgot-password",
            data={"email": "a@example.com", "csrf_token": csrf(client, "/forgot-password")},
        )
        statuses.append(response.status_code)
    assert statuses == [200] * 5 + [429]


def test_reset_with_bad_token_or_short_password(client: TestClient, mailer: MemoryMailer) -> None:
    assert client.get("/reset-password/bozuk").status_code == 400
    register(client)
    client.post(
        "/forgot-password",
        data={"email": "sahip@example.com", "csrf_token": csrf(client, "/forgot-password")},
    )
    reset_path = link_path(last_email(mailer, "reset"))
    short = client.post(
        reset_path,
        data={
            "password": "kisa",
            "password_confirm": "kisa",
            "csrf_token": csrf(client, reset_path),
        },
    )
    assert short.status_code == 400
    assert "en az 10 karakter" in short.text


def test_password_reset_signs_out_other_sessions(
    make_app: AppFactory, mailer: MemoryMailer
) -> None:
    app = make_app()
    with TestClient(app) as laptop, TestClient(app) as phone:
        register(laptop)
        login(phone)
        assert phone.get("/dashboard", follow_redirects=False).status_code == 200

        laptop.post(
            "/forgot-password",
            data={"email": "sahip@example.com", "csrf_token": csrf(laptop, "/forgot-password")},
        )
        reset_path = link_path(last_email(mailer, "reset"))
        laptop.post(
            reset_path,
            data={
                "password": NEW_PASSWORD,
                "password_confirm": NEW_PASSWORD,
                "csrf_token": csrf(laptop, reset_path),
            },
        )
        assert laptop.get("/dashboard", follow_redirects=False).status_code == 200
        assert phone.get("/dashboard", follow_redirects=False).status_code == 303


# --- account settings -------------------------------------------------------------


def test_change_password(make_app: AppFactory, mailer: MemoryMailer) -> None:
    app = make_app()
    with TestClient(app) as client, TestClient(app) as other:
        register(client)
        login(other)
        wrong = post(
            client,
            "/account/password",
            {
                "current_password": "yanlis",
                "password": NEW_PASSWORD,
                "password_confirm": NEW_PASSWORD,
            },
        )
        assert wrong.headers["location"] == "/account"
        assert "Mevcut şifreniz hatalı" in client.get("/account").text
        post(
            client,
            "/account/password",
            {"current_password": PASSWORD, "password": NEW_PASSWORD, "password_confirm": "x"},
        )
        assert "aynı değil" in client.get("/account").text

        post(
            client,
            "/account/password",
            {
                "current_password": PASSWORD,
                "password": NEW_PASSWORD,
                "password_confirm": NEW_PASSWORD,
            },
        )
        assert "Şifreniz değiştirildi" in client.get("/account").text
        assert client.get("/account", follow_redirects=False).status_code == 200  # still in
        assert other.get("/account", follow_redirects=False).status_code == 303  # signed out
        assert last_email(mailer, "password-changed")


def test_export_my_data(client: TestClient) -> None:
    register(client)
    add_domain(client, "örnek.com.tr")
    response = client.get("/account/export.json")
    assert response.headers["content-disposition"].startswith(
        'attachment; filename="kalkan-verilerim-'
    )
    assert response.headers["cache-control"] == "no-store"
    data = json.loads(response.text)
    assert data["account"]["email"] == "sahip@example.com"
    [organization] = data["organizations"]
    assert (organization["name"], organization["role"]) == ("sahip@example.com", "owner")
    assert organization["domains"][0]["hostname"] == "xn--rnek-4qa.com.tr"
    assert organization["domains"][0]["scans"] == []
    assert "password_hash" not in response.text


def test_delete_account(client: TestClient) -> None:
    register(client)
    add_domain(client)
    post(client, "/account/delete", {"password": "yanlis"})
    assert "hesap silinmedi" in client.get("/account").text

    response = post(client, "/account/delete", {"password": PASSWORD})
    assert response.headers["location"] == "/"
    assert "kalıcı olarak silindi" in client.get("/").text
    assert client.get("/dashboard", follow_redirects=False).status_code == 303
    assert login(client).status_code == 400
    assert register(client).status_code == 303  # the address is free again


def test_account_page(client: TestClient) -> None:
    register(client)
    page = client.get("/account").text
    assert "Hesabım" in page and "sahip@example.com" in page
    assert "Doğrulanmadı" in page
    assert "Verilerimi indir" in page
    assert "Hesabı sil" in page
