from __future__ import annotations

import re

import pytest
from conftest import make_report
from fastapi import FastAPI
from fastapi.testclient import TestClient
from web_helpers import add_domain, post, register, run_worker

from kalkan.scanner import ScanOptions, ScanReport
from kalkan.scanner.models import Category, Finding, Severity
from kalkan.web import services
from kalkan.web.verification import VerificationResult

FIRST = make_report(
    findings=[
        Finding("ports.open_3389", Category.PORTS, Severity.HIGH, "Uzak Masaüstü (RDP) açık"),
        Finding("http.hsts_missing", Category.HTTP, Severity.LOW, "HSTS yok"),
    ],
    score=70,
    grade="C",
)
SECOND = make_report(
    findings=[
        Finding("http.hsts_missing", Category.HTTP, Severity.LOW, "HSTS yok"),
        Finding("email.spf_missing", Category.EMAIL, Severity.MEDIUM, "SPF kaydı yok"),
    ],
    score=91,
    grade="A",
)


@pytest.fixture
def scanning_app(app: FastAPI, monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    async def ok(hostname: str, token: str, **kwargs: object) -> VerificationResult:
        return VerificationResult("dns", "ok")

    reports = [FIRST, SECOND]

    async def scanner(hostname: str, options: ScanOptions) -> ScanReport:
        return reports.pop(0)

    monkeypatch.setattr(services, "verify_ownership", ok)
    app.state.worker.scanner = scanner
    return app


def scan_once(app: FastAPI, client: TestClient, domain_id: int) -> str:
    location = post(client, f"/domains/{domain_id}/scans").headers["location"]
    assert run_worker(app)
    return str(location)


def test_history_chart_and_comparison(scanning_app: FastAPI, client: TestClient) -> None:
    register(client)
    domain_id = add_domain(client)
    post(client, f"/domains/{domain_id}/verify")

    first_url = scan_once(scanning_app, client, domain_id)
    domain_page = client.get(f"/domains/{domain_id}").text
    assert "Puan geçmişi" not in domain_page  # one point is not a trend
    assert "Önceki taramaya göre" not in client.get(first_url).text

    second_url = scan_once(scanning_app, client, domain_id)
    domain_page = client.get(f"/domains/{domain_id}").text
    assert "Puan geçmişi" in domain_page
    assert domain_page.count('class="sc-point"') == 2
    assert f'href="{first_url}"' in domain_page and f'href="{second_url}"' in domain_page
    assert "style=" not in domain_page.split("Puan geçmişi")[1].split("</section>")[0]  # CSP

    report_page = client.get(second_url).text
    comparison = report_page.split("Önceki taramaya göre")[1].split("</section>")[0]
    assert "(+21 puan)" in comparison
    assert "Çözülen sorunlar (1)" in comparison and "Uzak Masaüstü (RDP) açık" in comparison
    assert "Yeni veya kötüleşen sorunlar (1)" in comparison and "SPF kaydı yok" in comparison
    assert f'href="{first_url}"' in comparison


def test_pdf_downloads(scanning_app: FastAPI, client: TestClient) -> None:
    register(client)
    domain_id = add_domain(client)
    post(client, f"/domains/{domain_id}/verify")
    pending_url = post(client, f"/domains/{domain_id}/scans").headers["location"]
    assert client.get(f"{pending_url}/report.pdf").status_code == 404
    run_worker(scanning_app)

    response = client.get(f"{pending_url}/report.pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert re.fullmatch(
        r'attachment; filename="kalkan-rapor-example\.com-\d{8}\.pdf"',
        response.headers["content-disposition"],
    )
    assert response.content.startswith(b"%PDF-")

    token_page = post(client, "/account/tokens", {"name": "pdf"})
    token = re.search(r"(klk_[A-Za-z0-9_-]{20,})", token_page.text)
    assert token
    scan_id = pending_url.rsplit("/", 1)[1]
    api = client.get(
        f"/api/v1/scans/{scan_id}/report.pdf", headers={"Authorization": f"Bearer {token.group(1)}"}
    )
    assert api.status_code == 200 and api.content.startswith(b"%PDF-")
    assert "/api/v1/scans/{scan_id}/report.pdf" in client.get("/api/openapi.json").json()["paths"]


def test_api_pdf_for_unfinished_scan(scanning_app: FastAPI, client: TestClient) -> None:
    register(client)
    domain_id = add_domain(client)
    post(client, f"/domains/{domain_id}/verify")
    scan_id = post(client, f"/domains/{domain_id}/scans").headers["location"].rsplit("/", 1)[1]
    token = re.search(
        r"(klk_[A-Za-z0-9_-]{20,})", post(client, "/account/tokens", {"name": "t"}).text
    )
    assert token
    response = client.get(
        f"/api/v1/scans/{scan_id}/report.pdf", headers={"Authorization": f"Bearer {token.group(1)}"}
    )
    assert response.status_code == 409
