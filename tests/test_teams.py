"""Organizations: members, roles, invitations, plans and switching between workspaces."""

from __future__ import annotations

import re
from collections.abc import Iterator

import pytest
from conftest import AppFactory
from fastapi import FastAPI
from fastapi.testclient import TestClient
from web_helpers import PASSWORD, add_domain, last_email, link_path, login, post, register

from kalkan import cli
from kalkan.web import services
from kalkan.web.db import utcnow
from kalkan.web.mail import MemoryMailer
from kalkan.web.models import Domain, Invitation, Organization, Plan, User
from kalkan.web.verification import VerificationResult

OWNER = "sahip@example.com"


@pytest.fixture(autouse=True)
def verified(monkeypatch: pytest.MonkeyPatch) -> None:
    async def ok(hostname: str, token: str, **kwargs: object) -> VerificationResult:
        return VerificationResult("dns", "DNS kaydı bulundu.")

    monkeypatch.setattr(services, "verify_ownership", ok)


@pytest.fixture
def second(app: FastAPI) -> Iterator[TestClient]:
    """Another browser."""
    with TestClient(app) as other:
        yield other


def invite(client: TestClient, mailer: MemoryMailer, email: str, role: str = "member") -> str:
    response = post(client, "/team/invitations", {"email": email, "role": role})
    assert response.headers["location"] == "/team"
    invitation = last_email(mailer, "invitation")
    assert invitation.to == email
    return link_path(invitation)


def join(client: TestClient, path: str, email: str) -> None:
    """Sign up from an invitation link and accept it."""
    page = client.get(path)
    assert page.status_code == 200
    assert page.headers["referrer-policy"] == "no-referrer"  # the token is in the URL
    response = register(client, email, next=path)
    assert response.headers["location"] == path
    accepted = post(client, f"{path}/accept")
    assert accepted.headers["location"] == "/dashboard"


def org_id(client: TestClient) -> int:
    match = re.search(r'action="/orgs/(\d+)/switch"', client.get("/team").text)
    assert match
    return int(match.group(1))


def test_team_page(client: TestClient) -> None:
    register(client)
    page = client.get("/team").text
    assert OWNER in page and "(siz)" in page
    assert "rolünüz: Sahip" in page
    assert "Şu anki planınız: <strong>Pro</strong>" in page
    assert "0/5 alan adı" in page and "1/3 kişi" in page
    assert 'action="/team/name"' in page  # owners may rename
    assert "Çalışma alanından ayrıl" not in page  # alone: delete the account instead


def test_invitation_flow(client: TestClient, second: TestClient, mailer: MemoryMailer) -> None:
    register(client)
    domain_id = add_domain(client)
    post(client, f"/domains/{domain_id}/verify")
    post(client, "/team/name", {"name": "  Örnek   Ticaret A.Ş. "})
    path = invite(client, mailer, "uye@example.com")
    email = last_email(mailer, "invitation")
    assert email.subject == "Kalkan: Örnek Ticaret A.Ş. çalışma alanına davet edildiniz"
    assert OWNER in email.body
    assert "Bekleyen davetler</h3>" in client.get("/team").text

    landing = second.get(path).text
    assert "Örnek Ticaret A.Ş. çalışma alanına katılın" in landing
    assert "/register?email=uye%40example.com" in landing
    join(second, path, "uye@example.com")
    dashboard = second.get("/dashboard").text
    assert "Örnek Ticaret A.Ş. çalışma alanına katıldınız" in dashboard
    assert "example.com" in dashboard
    assert "E-posta adresinizi doğrulayın" not in dashboard  # the invitation proved it
    assert 'action="/domains"' not in dashboard  # members do not add domains

    # members read reports and start scans, but do not manage domains
    assert second.get(f"/domains/{domain_id}").status_code == 200
    assert post(second, f"/domains/{domain_id}/scans").headers["location"].startswith("/scans/")
    post(second, "/domains", {"hostname": "example.org"})
    assert "Bu işlem için yetkiniz yok" in second.get("/dashboard").text
    post(second, f"/domains/{domain_id}/delete")
    assert second.get(f"/domains/{domain_id}").status_code == 200

    # used up
    assert "Davet geçersiz" in second.get(path).text
    assert second.get(path).status_code == 404
    team = client.get("/team").text
    assert "uye@example.com" in team and "Bekleyen davetler</h3>" not in team


def test_invitation_belongs_to_one_address(
    client: TestClient, second: TestClient, mailer: MemoryMailer
) -> None:
    register(client)
    path = invite(client, mailer, "uye@example.com")
    register(second, "baskasi@example.com")
    page = second.get(path).text
    assert "Bu davet uye@example.com adresine gönderildi" in page
    post(second, f"{path}/accept")
    assert "Bu davet uye@example.com adresine gönderildi" in second.get("/dashboard").text
    assert "baskasi@example.com" not in client.get("/team").text


def test_expired_and_revoked_invitations(
    app: FastAPI, client: TestClient, second: TestClient, mailer: MemoryMailer
) -> None:
    register(client)
    path = invite(client, mailer, "uye@example.com")
    with app.state.session_factory() as db:
        invitation = db.query(Invitation).one()
        invitation.expires_at = utcnow()
        db.commit()
    assert second.get(path).status_code == 404

    path = invite(client, mailer, "uye@example.com")  # a new invitation replaces the old one
    with app.state.session_factory() as db:
        [invitation] = db.query(Invitation).all()
        invitation_id = invitation.id
    post(client, f"/team/invitations/{invitation_id}/revoke")
    assert "Davet iptal edildi" in client.get("/team").text
    assert second.get(path).status_code == 404
    post(client, f"/team/invitations/{invitation_id}/revoke")
    assert "Davet bulunamadı" in client.get("/team").text


def test_invitation_rules(client: TestClient, mailer: MemoryMailer) -> None:
    register(client)
    cases = [
        ({"email": OWNER}, "Bu kişi zaten çalışma alanında"),
        ({"email": "x@example.com", "role": "owner"}, "yalnızca üye veya yönetici"),
        ({"email": "x@example.com", "role": "kral"}, "Geçersiz rol"),
        ({"email": "gecersiz"}, "Geçerli bir e-posta adresi girin"),
    ]
    for data, message in cases:
        post(client, "/team/invitations", data)
        assert message in client.get("/team").text, message
    invite(client, mailer, "bir@example.com")
    invite(client, mailer, "iki@example.com")  # owner + 2 pending = Pro's 3 seats
    post(client, "/team/invitations", {"email": "uc@example.com"})
    assert "en fazla 3 kişilik ekibe" in client.get("/team").text


def test_roles(app: FastAPI, client: TestClient, second: TestClient, mailer: MemoryMailer) -> None:
    register(client)
    join(second, invite(client, mailer, "yonetici@example.com", "admin"), "yonetici@example.com")
    with app.state.session_factory() as db:
        owner = db.query(User).filter_by(email=OWNER).one()
        admin = db.query(User).filter_by(email="yonetici@example.com").one()
        owner_ms, admin_ms = owner.memberships[0].id, admin.memberships[-1].id

    # admins manage domains and people, but not roles or owners
    domain_id = add_domain(second, "example.org")
    post(second, f"/team/members/{owner_ms}/role", {"role": "member"})
    assert "Bu işlem için yetkiniz yok" in second.get("/team").text
    post(second, f"/team/members/{owner_ms}/remove")
    assert "Bu işlem için yetkiniz yok" in second.get("/team").text
    post(second, "/team/name", {"name": "Yeni ad"})
    assert "Bu işlem için yetkiniz yok" in second.get("/team").text

    # owners do; the last owner stays
    post(client, f"/team/members/{owner_ms}/role", {"role": "admin"})
    assert "en az bir sahip kalmalı" in client.get("/team").text
    post(client, f"/team/members/{owner_ms}/remove")
    assert "Çalışma alanından ayrıl" in client.get("/team").text
    post(client, f"/team/members/{admin_ms}/role", {"role": "member"})
    assert "Rol güncellendi" in client.get("/team").text
    post(second, f"/domains/{domain_id}/delete")
    assert "Bu işlem için yetkiniz yok" in second.get(f"/domains/{domain_id}").text

    post(client, f"/team/members/{admin_ms}/remove")
    assert "Üye çalışma alanından çıkarıldı" in client.get("/team").text
    assert second.get(f"/domains/{domain_id}").status_code == 404
    # with no workspace left, a personal one is created on the spot
    assert "yonetici@example.com" in second.get("/team").text
    post(client, "/team/members/9999/remove")
    assert "Üye bulunamadı" in client.get("/team").text


def test_switch_and_leave(client: TestClient, second: TestClient, mailer: MemoryMailer) -> None:
    register(client)
    add_domain(client, "sahibin-sitesi.com")
    register(second, "uye@example.com")
    add_domain(second, "uyenin-sitesi.com")
    path = invite(client, mailer, "uye@example.com")
    post(second, f"{path}/accept")
    assert "sahibin-sitesi.com" in second.get("/dashboard").text

    personal = org_id(second)
    post(second, f"/orgs/{personal}/switch")
    dashboard = second.get("/dashboard").text
    assert "uyenin-sitesi.com" in dashboard and "sahibin-sitesi.com" not in dashboard
    assert post(second, "/orgs/9999/switch").status_code == 404

    # following a link into another workspace switches to it
    with client.app.state.session_factory() as db:  # type: ignore[attr-defined]
        shared = db.query(Domain).filter_by(hostname="sahibin-sitesi.com").one().id
    second.get(f"/domains/{shared}")
    assert "sahibin-sitesi.com" in second.get("/dashboard").text

    post(second, "/team/leave")
    dashboard = second.get("/dashboard").text
    assert "çalışma alanından ayrıldınız" in dashboard and "uyenin-sitesi.com" in dashboard
    post(second, "/team/leave")
    assert "tek üyesisiniz" in second.get("/team").text


def test_free_plan(make_app: AppFactory, mailer: MemoryMailer) -> None:
    with TestClient(make_app(default_plan="free")) as client:
        register(client)
        domain_id = add_domain(client)
        post(client, "/domains", {"hostname": "example.org"})
        assert "en fazla 1 alan adına izin veriyor" in client.get("/dashboard").text
        post(client, f"/domains/{domain_id}/verify")
        page = client.get(f"/domains/{domain_id}").text
        assert '<option value="7" disabled>Haftalık (üst planlarda)</option>' in page
        post(client, f"/domains/{domain_id}/settings", {"interval_days": "7"})
        assert "Bu tarama sıklığı planınızda yok" in client.get(f"/domains/{domain_id}").text
        post(client, f"/domains/{domain_id}/settings", {"interval_days": "30"})
        assert "Aylık" in client.get(f"/domains/{domain_id}").text

        account = client.get("/account").text
        assert "API erişimi Pro ve Ajans planlarında" in account
        post(client, "/account/tokens", {"name": "CI"})
        assert "API erişimi Pro ve Ajans planlarında" in client.get("/account").text
        post(client, "/team/invitations", {"email": "uye@example.com"})
        assert "en fazla 1 kişilik ekibe" in client.get("/team").text
        assert mailer.outbox and all(e.kind != "invitation" for e in mailer.outbox)


def test_downgrade_pauses_schedules_and_api(app: FastAPI, client: TestClient) -> None:
    register(client)
    domain_id = add_domain(client)
    post(client, f"/domains/{domain_id}/verify")
    post(client, f"/domains/{domain_id}/settings", {"interval_days": "7", "notify_email": "yes"})
    response = post(client, "/account/tokens", {"name": "CI"})
    token = re.search(r"(klk_[A-Za-z0-9_-]{20,})", response.text)
    assert token
    headers = {"Authorization": f"Bearer {token.group(1)}"}
    assert client.get("/api/v1/me", headers=headers).json()["organization"]["plan"]["name"] == "pro"

    with app.state.session_factory() as db:
        organization = db.query(Organization).one()
        services.set_plan(db, organization, Plan.FREE)
        domain = db.get(Domain, domain_id)
        assert domain is not None and domain.scan_interval_days == 0 and domain.next_scan_at is None
    denied = client.get("/api/v1/me", headers=headers)
    assert denied.status_code == 403
    assert denied.json() == {"detail": "API erişimi Pro ve Ajans planlarında kullanılabilir."}


def test_api_tokens_act_in_their_workspace(
    client: TestClient, second: TestClient, mailer: MemoryMailer
) -> None:
    register(client)
    add_domain(client, "sahibin-sitesi.com")
    register(second, "uye@example.com")
    add_domain(second, "uyenin-sitesi.com")
    post(second, f"{invite(client, mailer, 'uye@example.com')}/accept")  # now in the shared one
    response = post(second, "/account/tokens", {"name": "ortak"})
    assert "Örnek" not in response.text and "sahip@example.com için token oluştur" in response.text
    token = re.search(r"(klk_[A-Za-z0-9_-]{20,})", response.text)
    assert token
    headers = {"Authorization": f"Bearer {token.group(1)}"}
    me = second.get("/api/v1/me", headers=headers).json()
    assert me["organization"]["name"] == OWNER and me["organization"]["role"] == "member"
    hostnames = [d["hostname"] for d in second.get("/api/v1/domains", headers=headers).json()]
    assert hostnames == ["sahibin-sitesi.com"]
    created = second.post("/api/v1/domains", json={"hostname": "x.com"}, headers=headers)
    assert created.status_code == 403

    post(second, "/team/leave")  # leaving the workspace revokes its tokens
    assert second.get("/api/v1/me", headers=headers).status_code == 401


def test_deleting_an_account_keeps_shared_workspaces(
    client: TestClient, second: TestClient, mailer: MemoryMailer
) -> None:
    register(client)
    domain_id = add_domain(client)
    join(second, invite(client, mailer, "uye@example.com"), "uye@example.com")
    post(client, "/account/delete", {"password": PASSWORD})
    assert login(client).status_code == 400
    # the remaining member inherits the workspace and its domains
    assert "rolünüz: Sahip" in second.get("/team").text
    assert second.get(f"/domains/{domain_id}").status_code == 200


def test_admin_cli(
    app: FastAPI,
    client: TestClient,
    database_url: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    register(client)
    add_domain(client)
    monkeypatch.setenv("KALKAN_DATABASE_URL", database_url)
    assert cli.main(["admin", "orgs"]) == 0
    out = capsys.readouterr().out
    assert "pro" in out and "1/5" in out and f"({OWNER})" in out

    assert cli.main(["admin", "set-plan", OWNER, "agency"]) == 0
    assert "pro → agency" in capsys.readouterr().out
    assert "Ajans" in client.get("/team").text
    with app.state.session_factory() as db:
        organization_id = db.query(Organization).one().id
    assert cli.main(["admin", "set-plan", str(organization_id), "free"]) == 0
    assert cli.main(["admin", "set-plan", "yok@example.com", "pro"]) == 2
    assert "çalışma alanı bulunamadı" in capsys.readouterr().err
