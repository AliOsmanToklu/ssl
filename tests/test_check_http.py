from __future__ import annotations

import httpx
from conftest import ContextFactory, FakeWeb, Page, by_id, finding_ids

from kalkan.scanner.checks import http
from kalkan.scanner.models import Severity

GOOD_HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Server": "nginx",
}


async def test_well_configured_site(web: FakeWeb, make_context: ContextFactory) -> None:
    web.redirect("http://example.com/", "https://example.com/")
    web.add("https://example.com/", Page(body="<html></html>", headers=GOOD_HEADERS))
    web.add(
        "https://example.com/.well-known/security.txt",
        body="Contact: mailto:guvenlik@example.com\nExpires: 2027-01-01T00:00:00Z\n",
    )
    ctx = make_context()
    findings = await http.run(ctx)
    assert finding_ids(findings) == {
        "http.redirect_ok",
        "http.hsts_ok",
        "http.security_headers_ok",
        "http.security_txt_ok",
    }
    assert all(f.severity is Severity.PASS for f in findings)
    assert ctx.facts.homepage is not None
    assert ctx.facts.base_url == "https://example.com"
    assert ctx.facts.http_ok is True
    assert [(s.product, s.version) for s in ctx.software] == [("nginx", None)]


async def test_typical_small_business_site(web: FakeWeb, make_context: ContextFactory) -> None:
    web.add("http://example.com/", body="<html>http</html>", headers={"Content-Type": "text/html"})
    web.add(
        "https://example.com/",
        Page(
            body='<html><meta name="generator" content="WordPress 6.4.2"></html>',
            headers=[
                ("Content-Type", "text/html; charset=UTF-8"),
                ("Server", "Apache/2.4.41 (Ubuntu)"),
                ("X-Powered-By", "PHP/7.4.3"),
                ("Set-Cookie", "PHPSESSID=abc; path=/"),
                ("Set-Cookie", "pref=1; Secure; HttpOnly; SameSite=Lax"),
            ],
        ),
    )
    ctx = make_context()
    findings = await http.run(ctx)
    assert finding_ids(findings) == {
        "http.no_https_redirect",
        "http.hsts_missing",
        "http.security_headers_missing",
        "http.version_disclosure",
        "http.cookie_flags",
        "http.security_txt_missing",
    }
    assert by_id(findings, "http.no_https_redirect").severity is Severity.MEDIUM
    headers = by_id(findings, "http.security_headers_missing")
    assert headers.title == "4 tarayıcı güvenlik başlığı eksik"
    assert set(headers.details) == {
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    }
    assert by_id(findings, "http.version_disclosure").details == {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
    }
    assert by_id(findings, "http.cookie_flags").details == {
        "PHPSESSID": "Eksik: Secure, HttpOnly, SameSite"
    }
    detected = {(s.product, s.version) for s in ctx.software}
    assert detected == {("apache", "2.4.41"), ("php", "7.4.3"), ("wordpress", "6.4.2")}


async def test_short_hsts_and_wrong_nosniff(web: FakeWeb, make_context: ContextFactory) -> None:
    headers = dict(GOOD_HEADERS)
    headers["Strict-Transport-Security"] = "max-age=300"
    headers["X-Content-Type-Options"] = "sniff-please"
    web.add("https://example.com/", Page(headers=headers))
    findings = await http.run(make_context())
    assert by_id(findings, "http.hsts_short").severity is Severity.LOW
    assert set(by_id(findings, "http.security_headers_missing").details) == {
        "X-Content-Type-Options"
    }


async def test_http_only_site(web: FakeWeb, make_context: ContextFactory) -> None:
    web.add(
        "http://example.com/",
        Page(headers={"Content-Type": "text/html", "X-AspNet-Version": "4.0.30319"}),
    )
    ctx = make_context()
    findings = await http.run(ctx)
    ids = finding_ids(findings)
    assert "http.hsts_missing" not in ids  # HSTS only means something over HTTPS
    assert "http.no_https_redirect" not in ids  # the TLS check reports "no HTTPS"
    assert "http.version_disclosure" in ids
    assert ctx.facts.base_url == "http://example.com"
    assert ("aspnet", "4.0.30319") in {(s.product, s.version) for s in ctx.software}


async def test_non_html_homepage_skips_header_advice(
    web: FakeWeb, make_context: ContextFactory
) -> None:
    web.add("https://example.com/", Page(body="{}", headers={"Content-Type": "application/json"}))
    findings = await http.run(make_context())
    assert "http.security_headers_missing" not in finding_ids(findings)


async def test_unreachable_site(make_context: ContextFactory) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    ctx = make_context(http_transport=httpx.MockTransport(refuse))
    findings = await http.run(ctx)
    assert finding_ids(findings) == {"http.unreachable"}
    assert ctx.facts.homepage is None
    assert ctx.notes


def test_detect_cdn() -> None:
    assert http.detect_cdn(httpx.Headers({"server": "cloudflare", "cf-ray": "x"})) == "Cloudflare"
    assert http.detect_cdn(httpx.Headers({"x-amz-cf-id": "x"})) == "Amazon CloudFront"
    assert http.detect_cdn(httpx.Headers({"server": "AkamaiGHost"})) == "Akamai"
    assert (
        http.detect_cdn(httpx.Headers({"x-served-by": "cache-fra1", "via": "1.1 varnish"}))
        == "Fastly"
    )
    assert http.detect_cdn(httpx.Headers({"x-sucuri-id": "1"})) == "Sucuri"
    assert http.detect_cdn(httpx.Headers({"server": "nginx"})) is None
