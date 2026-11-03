from __future__ import annotations

from datetime import date
from typing import Any

import httpx
import pytest
from conftest import TODAY, ContextFactory, FakeWeb, Page, by_id, fake_wordpress

from kalkan.scanner.checks import http, wordpress
from kalkan.scanner.models import Severity
from kalkan.scanner.wporg import WordPressOrg, WpInfo, parse_info

HOMEPAGE = """
<html><head>
<meta name="generator" content="WordPress 6.8.1">
<link rel="stylesheet" href="/wp-content/themes/astra/style.min.css?ver=4.1.0">
<link rel="stylesheet" href="/wp-content/plugins/elementor/assets/css/frontend.min.css?ver=3.10.0">
<script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=6.8.1"></script>
<script src="/wp-content/plugins/wp-gdpr-compliance/assets/js/front.js?ver=2.0.1"></script>
<script src="/wp-content/plugins/old-slider/js/slider.js?ver=1.0"></script>
<script src="/wp-content/plugins/premium-thing/app.js?ver=9.9.9"></script>
<script src="/wp-content/plugins/elementor/assets/js/frontend.min.js"></script>
</head></html>
"""

CATALOGUE = {
    ("plugin", "elementor"): WpInfo("elementor", "Elementor", "4.3.6", date(2026, 10, 30)),
    ("plugin", "contact-form-7"): WpInfo(
        "contact-form-7", "Contact Form 7", "6.2.4", date(2026, 10, 29)
    ),
    ("plugin", "wp-gdpr-compliance"): WpInfo(
        "wp-gdpr-compliance", "WP GDPR Compliance", None, date(2024, 2, 23), True, "security-issue"
    ),
    ("plugin", "old-slider"): WpInfo("old-slider", "Old Slider", "1.0", date(2019, 5, 1)),
    ("theme", "astra"): WpInfo("astra", "Astra", "4.14.2", date(2026, 10, 29)),
}


async def scan(web: FakeWeb, make_context: ContextFactory, catalogue: dict[Any, WpInfo]) -> Any:
    web.add("https://example.com/", Page(body=HOMEPAGE, headers={"Content-Type": "text/html"}))
    web.add(
        "https://example.com/wp-content/plugins/contact-form-7/readme.txt",
        body="=== Contact Form 7 ===\nStable tag: 6.2.4\n",
    )
    web.add(
        "https://example.com/wp-content/themes/astra/style.css",
        body="/*\nTheme Name: Astra\nVersion: 4.14.2\n*/",
    )
    ctx = make_context(wordpress=fake_wordpress(catalogue))
    await http.run(ctx)
    return ctx, await wordpress.run(ctx)


async def test_wordpress_components(web: FakeWeb, make_context: ContextFactory) -> None:
    ctx, findings = await scan(web, make_context, CATALOGUE)

    closed = by_id(findings, "wordpress.closed.wp-gdpr-compliance")
    assert closed.severity is Severity.HIGH
    assert "güvenlik sorunu nedeniyle" in closed.title
    assert closed.details["Kaldırılma tarihi"] == "23.02.2024"

    outdated = by_id(findings, "wordpress.outdated")
    assert outdated.severity is Severity.MEDIUM
    # Elementor's readme is not reachable: the ?ver= of its stylesheet is used instead.
    assert outdated.details == {"Elementor": "3.10.0 → 4.3.6"}

    abandoned = by_id(findings, "wordpress.abandoned")
    assert abandoned.details == {"Old Slider": "Son güncelleme: 01.05.2019"}

    current = by_id(findings, "wordpress.current")
    assert current.details == {
        "Contact Form 7": "6.2.4",  # from readme.txt, not the core-like ?ver=6.8.1
        "Old Slider": "1.0",
        "Astra": "4.14.2",
    }

    detected = {s.product: s.version for s in ctx.software}
    assert detected["wp-plugin:premium-thing"] == "9.9.9"  # unknown to WordPress.org: listed only
    assert detected["wp-theme:astra"] == "4.14.2"


async def test_closed_for_other_reasons_is_medium(
    web: FakeWeb, make_context: ContextFactory
) -> None:
    catalogue = dict(CATALOGUE)
    catalogue[("plugin", "wp-gdpr-compliance")] = WpInfo(
        "wp-gdpr-compliance", "WP GDPR Compliance", None, None, True, "author-request"
    )
    _, findings = await scan(web, make_context, catalogue)
    closed = by_id(findings, "wordpress.closed.wp-gdpr-compliance")
    assert closed.severity is Severity.MEDIUM
    assert closed.details["Kaldırılma tarihi"] == "-"


async def test_catalogue_outage_does_not_fail(web: FakeWeb, make_context: ContextFactory) -> None:
    async def broken(kind: str, slug: str) -> WpInfo:
        raise RuntimeError("api down")

    web.add("https://example.com/", Page(body=HOMEPAGE, headers={"Content-Type": "text/html"}))
    ctx = make_context(wordpress=broken)
    await http.run(ctx)
    assert await wordpress.run(ctx) == []
    assert any(s.product == "wp-plugin:elementor" for s in ctx.software)


async def test_not_wordpress(web: FakeWeb, make_context: ContextFactory) -> None:
    web.add(
        "https://example.com/",
        Page(body="<html>Merhaba</html>", headers={"Content-Type": "text/html"}),
    )
    ctx = make_context(wordpress=fake_wordpress(CATALOGUE))
    await http.run(ctx)
    assert await wordpress.run(ctx) == []


def test_discover_limits_and_hints() -> None:
    body = "".join(
        f'<script src="/wp-content/plugins/p{i}/a.js?ver={i}.0"></script>' for i in range(20)
    )
    plugins, themes = wordpress.discover(body + '<link href="/wp-content/themes/t/s.css">')
    assert len(plugins) == wordpress.MAX_PLUGINS
    assert plugins["p0"] == "0.0"
    assert themes == {"t": None}


def test_assess_ignores_unknown_versions() -> None:
    component = wordpress.Component("plugin", "x", None, CATALOGUE[("plugin", "elementor")])
    assert wordpress.assess([component], TODAY) == []


# --- WordPress.org client -----------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (
            {
                "name": "Elementor &#8211; builder",
                "version": "4.3.6",
                "last_updated": "2026-10-30 9:37am GMT",
            },
            WpInfo("elementor", "Elementor – builder", "4.3.6", date(2026, 10, 30)),
        ),
        (
            {
                "error": "closed",
                "closed": True,
                "closed_date": "2024-02-23",
                "reason": "security-issue",
            },
            WpInfo("elementor", "elementor", None, date(2024, 2, 23), True, "security-issue"),
        ),
        ({"error": "Plugin not found."}, None),
        ({"name": "x"}, None),
    ],
)
def test_parse_info(data: dict[str, Any], expected: WpInfo | None) -> None:
    assert parse_info("elementor", data) == expected


async def test_wordpress_org_client_caches() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            200, json={"name": "Astra", "version": "4.14.2", "last_updated": "2026-10-29"}
        )

    client = WordPressOrg(transport=httpx.MockTransport(handler))
    first = await client("theme", "astra")
    second = await client("theme", "astra")
    assert first == second == WpInfo("astra", "Astra", "4.14.2", date(2026, 10, 29))
    assert len(calls) == 1
    assert calls[0].url.path == "/themes/info/1.2/"
    assert calls[0].url.params["request[slug]"] == "astra"


async def test_wordpress_org_errors_are_not_cached() -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise httpx.ConnectError("down", request=request)
        return httpx.Response(200, text="not json")

    client = WordPressOrg(transport=httpx.MockTransport(handler))
    assert await client("plugin", "x") is None
    assert await client("plugin", "x") is None
    assert attempts == 2
