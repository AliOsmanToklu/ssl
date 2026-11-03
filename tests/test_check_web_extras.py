from __future__ import annotations

import pytest
from conftest import ContextFactory, FakeWeb, Page, by_id, finding_ids

from kalkan.scanner import fingerprint
from kalkan.scanner.checks import http, software
from kalkan.scanner.http_client import FetchResult
from kalkan.scanner.models import DetectedSoftware, Severity

HTML = {"Content-Type": "text/html; charset=utf-8"}


def page(body: str) -> FetchResult:
    import httpx

    return FetchResult("https://example.com/", 200, httpx.Headers(HTML), body)


# --- mixed content ----------------------------------------------------------------


def test_active_mixed_content_is_medium() -> None:
    findings = http.mixed_content_findings(
        page(
            '<script src="http://cdn.example.net/app.js"></script>'
            '<link rel="stylesheet" href="HTTP://cdn.example.net/site.css">'
            '<img src="http://example.com/logo.png">'
            '<img src="https://example.com/ok.png"><img src="/relative.png">'
        )
    )
    finding = by_id(findings, "http.mixed_content")
    assert finding.severity is Severity.MEDIUM
    assert finding.details["Engellenen (betik/stil)"] == "2"
    assert finding.details["Uyarı veren (resim/medya)"] == "1"
    assert finding.details["URL 1"] == "http://cdn.example.net/app.js"


def test_passive_mixed_content_is_low() -> None:
    findings = http.mixed_content_findings(
        page(
            '<video><source src="http://example.com/v.mp4"></video><link rel="icon" href="http://x/f.ico">'
        )
    )
    assert by_id(findings, "http.mixed_content").severity is Severity.LOW


def test_form_posting_over_http() -> None:
    findings = http.mixed_content_findings(
        page('<form action="http://example.com/giris" method="post"><input name="sifre"></form>')
    )
    assert finding_ids(findings) == {"http.insecure_form"}
    assert by_id(findings, "http.insecure_form").details == {"Form 1": "http://example.com/giris"}


def test_clean_page_and_non_html() -> None:
    assert http.mixed_content_findings(page('<script src="https://x/app.js"></script>')) == []
    import httpx

    json_page = FetchResult(
        "https://example.com/", 200, httpx.Headers({"Content-Type": "application/json"}), "{}"
    )
    assert http.mixed_content_findings(json_page) == []


async def test_mixed_content_only_reported_over_https(
    web: FakeWeb, make_context: ContextFactory
) -> None:
    body = '<script src="http://cdn.example.net/app.js"></script>'
    web.add("http://example.com/", Page(body=body, headers=HTML))
    findings = await http.run(make_context())
    assert "http.mixed_content" not in finding_ids(findings)


# --- security.txt ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "status", "expected"),
    [
        ("Contact: mailto:security@example.com\n", 200, "http.security_txt_ok"),
        ("# comment\n  contact: https://example.com/report\n", 200, "http.security_txt_ok"),
        ("<html><body>Contact: us</body></html>", 200, "http.security_txt_missing"),
        ("Contact: mailto:x@example.com", 404, "http.security_txt_missing"),
        ("Expires: 2030-01-01", 200, "http.security_txt_missing"),
    ],
)
async def test_security_txt(
    web: FakeWeb, make_context: ContextFactory, body: str, status: int, expected: str
) -> None:
    web.add("https://example.com/", Page(body="<html></html>", headers=HTML))
    web.add("https://example.com/.well-known/security.txt", Page(status=status, body=body))
    findings = await http.run(make_context())
    assert expected in finding_ids(findings)


# --- JavaScript libraries ---------------------------------------------------------


def test_libraries_in_page() -> None:
    found = fingerprint.from_html(
        '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>'
        '<script src="/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1"></script>'
        '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">'
        '<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js"></script>'
        '<script src="https://unpkg.com/vue@2.6.14/dist/vue.js"></script>'
    )
    assert {(s.product, s.version) for s in found} == {
        ("wordpress", "3.7.1"),  # wp-includes asset version, judged elsewhere
        ("jquery", "3.7.1"),
        ("bootstrap", "4.6.2"),
        ("angularjs", "1.8.2"),
        ("vue", "2.6.14"),
    }


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://code.jquery.com/jquery-1.12.4.min.js", ("jquery", "1.12.4")),
        (
            "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.slim.min.js",
            ("jquery", "3.4.1"),
        ),
        ("https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js", ("jquery", "3.6.0")),
        ("/static/bootstrap-3.3.7.min.js", ("bootstrap", "3.3.7")),
        ("https://cdnjs.cloudflare.com/ajax/libs/vue/2.7.16/vue.min.js", ("vue", "2.7.16")),
        ("/js/jquery-ui-1.12.1.min.js", None),
        ("/theme/bootstrap.min.js?ver=2.1.0", None),  # a theme version, not Bootstrap's
    ],
)
def test_library_url_patterns(url: str, expected: tuple[str, str] | None) -> None:
    found = [(s.product, s.version) for s in fingerprint.libraries_from_assets([url])]
    assert found == ([expected] if expected else [])


async def test_client_side_libraries_are_one_level_milder(make_context: ContextFactory) -> None:
    ctx = make_context()
    ctx.software.extend(
        [
            DetectedSoftware("jquery", "jQuery", "3.4.1", "test"),  # below minimum safe 3.5.0
            DetectedSoftware("angularjs", "AngularJS", "1.8.2", "test"),  # EOL
            DetectedSoftware("bootstrap", "Bootstrap", "5.3.0", "test"),  # outdated
        ]
    )
    findings = await software.run(ctx)
    jquery = by_id(findings, "software.vulnerable.jquery")
    assert jquery.severity is Severity.MEDIUM
    assert "CVE-2020-11022" in jquery.description
    assert "tarayıcısında çalışır" in jquery.description
    assert by_id(findings, "software.eol.angularjs").severity is Severity.MEDIUM
    assert by_id(findings, "software.outdated.bootstrap").severity is Severity.LOW
