"""Translations: catalog completeness, language choice, English pages, e-mails and reports."""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from types import ModuleType

import pytest
from conftest import ContextFactory, FakeWeb, Page, make_report
from fastapi.testclient import TestClient
from web_helpers import PASSWORD, add_domain, last_email, login, post, register

from kalkan import cli
from kalkan.i18n import DEFAULT_LANGUAGE, LANGUAGES, T, best_language, localize, translate
from kalkan.report import render_html, render_pdf, render_text
from kalkan.scanner import ScanOptions, ScanReport
from kalkan.scanner.checks import http
from kalkan.scanner.scoring import compute_score
from kalkan.web import sample
from kalkan.web.mail import MemoryMailer

ROOT = Path(__file__).resolve().parents[1]
# Letters only Turkish uses. English pages may still show user data and the name "Türkçe".
TURKISH = re.compile(r"[ğĞşŞıİçÇöÖüÜ]")


def checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location("i18n_check", ROOT / "scripts" / "i18n_check.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def turkish_left(html: str) -> list[str]:
    text = re.sub(r"<[^>]+>", " ", html.replace("Türkçe", ""))
    return sorted({word for word in text.split() if TURKISH.search(word)})


# --- the catalog -----------------------------------------------------------------


@pytest.mark.parametrize("lang", [code for code in LANGUAGES if code != DEFAULT_LANGUAGE])
def test_catalog_is_complete(lang: str) -> None:
    assert checker().problems(lang) == []


def test_extraction_covers_code_and_templates() -> None:
    messages = checker().all_messages()
    assert "Riskli bir port internete açık değil" in messages  # T() in a check
    assert "Acil" in messages  # N_() label
    assert "{used}/{limit} alan adı kullanılıyor" in messages  # template, with parameters
    assert "Kalkan: {domain} için {n} yeni önemli sorun" in messages  # e-mail subject


def test_translate() -> None:
    assert translate("Sahip", "en") == "Owner"
    assert translate("Sahip", "tr") == "Sahip"
    assert translate("Sahip", "de") == "Sahip"  # unknown language: the source text
    assert translate("Henüz çevrilmemiş bir metin", "en") == "Henüz çevrilmemiş bir metin"
    assert translate("{n} tarayıcı güvenlik başlığı eksik", "en", n=1) == (
        "1 browser security header is missing"
    )
    assert translate("{n} tarayıcı güvenlik başlığı eksik", "en", n=3) == (
        "3 browser security headers are missing"
    )
    joined = T("{name} çalışma alanına katıldınız.", name=T("Ekip"))
    assert joined.get("en") == "You joined the Team workspace."  # nested Text, per language
    assert localize("Acil", "en") == "Critical"  # plain stored strings use the catalog
    assert localize({"tr": "x", "en": "y"}, "en") == "y"


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("en-GB,en;q=0.9,tr;q=0.8", "en"),
        ("de-DE,tr;q=0.5,en;q=0.4", "tr"),
        ("de", "tr"),
        (None, "tr"),
        ("en;q=0, tr", "tr"),
        ("en;q=abc, tr", "tr"),
    ],
)
def test_best_language(header: str | None, expected: str) -> None:
    assert best_language(header) == expected


# --- pages ---------------------------------------------------------------------------


def test_browser_language_and_explicit_choice(client: TestClient) -> None:
    english = {"Accept-Language": "en-US,en;q=0.9"}
    page = client.get("/register", headers=english).text
    assert '<html lang="en">' in page and "Create a free account" in page
    response = client.get("/lang/tr?next=/register", follow_redirects=False)
    assert response.headers["location"] == "/register"
    page = client.get("/register", headers=english).text  # the choice beats the browser
    assert '<html lang="tr">' in page and "Ücretsiz hesap oluşturun" in page
    client.get("/lang/xx")  # unknown codes are ignored
    assert '<html lang="tr">' in client.get("/register").text
    assert (
        client.get("/lang/en?next=//evil.example", follow_redirects=False).headers["location"]
        == "/dashboard"
    )


def test_the_users_language_is_remembered(app: object, mailer: MemoryMailer) -> None:
    with TestClient(app) as first:  # type: ignore[arg-type]
        first.get("/lang/en")
        register(first)
        assert last_email(mailer, "verify").subject == "Kalkan: verify your e-mail address"
    with TestClient(app) as second:  # type: ignore[arg-type]
        login(second)  # a new browser, no language in the session
        assert "My domains" in second.get("/dashboard").text
        second.get("/lang/tr")
    with TestClient(app) as third:  # type: ignore[arg-type]
        login(third)
        assert "Alan adlarım" in third.get("/dashboard").text


def test_english_pages_have_no_turkish_left(client: TestClient) -> None:
    for path in ("/", "/register", "/login", "/forgot-password", "/sayfa-yok"):
        response = client.get(path, headers={"Accept-Language": "en"})
        assert turkish_left(response.text) == [], path
    client.get("/lang/en")
    register(client)
    domain_id = add_domain(client)
    for path in ("/dashboard", "/team", "/account", f"/domains/{domain_id}"):
        assert turkish_left(client.get(path).text) == [], path


def test_api_errors_follow_the_language(client: TestClient) -> None:
    response = client.get(
        "/api/v1/me", headers={"Authorization": "Bearer klk_x", "Accept-Language": "en"}
    )
    assert response.json() == {"detail": "A valid API token is required."}
    client.get("/lang/en")
    register(client)
    created = post(client, "/account/tokens", {"name": "CI"})
    token = re.search(r"(klk_[A-Za-z0-9_-]{20,})", created.text)
    assert token
    missing = client.get("/api/v1/domains/999", headers={"Authorization": f"Bearer {token[1]}"})
    assert missing.json() == {"detail": "Domain not found."}


# --- the landing page's sample site ---------------------------------------------------------


def test_sample_site_regrades_from_f_to_a() -> None:
    grades = []
    open_findings = list(sample.SAMPLE_FINDINGS)
    while open_findings:
        grades.append(compute_score(open_findings)[1])
        open_findings = open_findings[1:]  # fix from the top
    assert grades == ["F", "D", "C", "B", "A", "A"]
    assert [f.severity for f in sample.SAMPLE_FINDINGS] == sorted(
        (f.severity for f in sample.SAMPLE_FINDINGS), key=lambda s: s.rank
    )


def test_landing_page_carries_the_real_scoring_rules(client: TestClient) -> None:
    page = client.get("/").text
    match = re.search(r'data-rules="([^"]+)"', page)
    assert match
    rules = json.loads(match.group(1).replace("&#34;", '"'))
    assert rules == sample.scoring_rules()
    assert 'data-fix="5" data-severity="low"' in page
    assert '<span class="k-grade-letter" data-grade>F</span>' in page
    # the self check prints what this response really carries
    assert "nosniff" in page and "strict-origin-when-cross-origin" in page


def test_landing_page_keeps_flashes(client: TestClient) -> None:
    register(client)
    post(client, "/account/delete", {"password": PASSWORD})
    assert "kalıcı olarak silindi" in client.get("/").text


# --- reports and the CLI in English ------------------------------------------------------


async def test_reports_in_english(web: FakeWeb, make_context: ContextFactory) -> None:
    web.add("https://example.com/", Page(body="<html><form action='http://x/'></form></html>"))
    web.add("http://example.com/", Page(body="<html></html>"))
    findings = await http.run(make_context())
    score, grade = compute_score(findings)
    report = make_report(findings=findings, software=[], score=score, grade=grade)
    text = render_text(report, lang="en")
    assert "Kalkan security report: example.com" in text
    assert "Your site does not redirect visitors to an encrypted connection" in text
    assert turkish_left(text) == []
    html = render_html(report, "en")
    assert '<html lang="en">' in html and turkish_left(html) == []
    pdf = render_pdf(report, "en")
    assert pdf.startswith(b"%PDF")


@pytest.fixture
def english_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scan(target: str, options: ScanOptions) -> ScanReport:
        return make_report(findings=[sample.REMOTE_DESKTOP], software=[])

    monkeypatch.setattr(cli, "scan", scan)


def test_cli_language(
    english_scan: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["scan", "example.com", "--no-color", "--lang", "en"]) == 0
    out = capsys.readouterr().out
    assert "Kalkan security report: example.com" in out
    assert "Remote Desktop (RDP) is open to the internet (port 3389)" in out
    monkeypatch.setenv("KALKAN_LANG", "en_US.UTF-8")
    assert cli.main(["scan", "example.com", "--no-color"]) == 0
    assert "Kalkan security report" in capsys.readouterr().out
