from __future__ import annotations

import pytest
from conftest import ContextFactory, FakeWeb, Page, by_id, finding_ids

from kalkan.scanner.checks import exposure, http
from kalkan.scanner.models import DetectedSoftware, Severity

ENV_FILE = "APP_ENV=production\nDB_HOST=localhost\nDB_PASSWORD=hunter2\n"


async def _context_with_homepage(
    web: FakeWeb, make_context: ContextFactory, body: str = "<html></html>"
) -> object:
    web.add("https://example.com/", body=body, headers={"Content-Type": "text/html"})
    ctx = make_context()
    await http.run(ctx)
    return ctx


async def test_nothing_exposed(web: FakeWeb, make_context: ContextFactory) -> None:
    ctx = await _context_with_homepage(web, make_context)
    findings = await exposure.run(ctx)  # type: ignore[arg-type]
    assert finding_ids(findings) == {"exposure.ok"}


@pytest.mark.parametrize(
    ("path", "body", "finding_id", "severity"),
    [
        ("/.env", ENV_FILE, "exposure.env", Severity.CRITICAL),
        ("/.git/HEAD", "ref: refs/heads/main\n", "exposure.git", Severity.CRITICAL),
        ("/.git/HEAD", "a" * 40, "exposure.git", Severity.CRITICAL),
        (
            "/wp-config.php.bak",
            "<?php define('DB_PASSWORD', 'x');",
            "exposure.wp_config_backup",
            Severity.CRITICAL,
        ),
        (
            "/backup.sql",
            "-- MySQL dump 10.13\nCREATE TABLE users",
            "exposure.sql_dump",
            Severity.CRITICAL,
        ),
        (
            "/phpinfo.php",
            "<title>phpinfo()</title> PHP Version 7.4",
            "exposure.phpinfo",
            Severity.MEDIUM,
        ),
        (
            "/server-status",
            "<h1>Apache Server Status for x</h1>",
            "exposure.server_status",
            Severity.MEDIUM,
        ),
        ("/.DS_Store", "\x00\x00\x00\x01Bud1\x00", "exposure.ds_store", Severity.LOW),
    ],
)
async def test_detects_exposed_file(
    web: FakeWeb,
    make_context: ContextFactory,
    path: str,
    body: str,
    finding_id: str,
    severity: Severity,
) -> None:
    web.add(f"https://example.com{path}", body=body)
    ctx = await _context_with_homepage(web, make_context)
    findings = await exposure.run(ctx)  # type: ignore[arg-type]
    finding = by_id(findings, finding_id)
    assert finding.severity is severity
    assert finding.details["Adres"] == f"https://example.com{path}"
    assert finding.recommendation


async def test_soft_404_pages_are_not_findings(web: FakeWeb, make_context: ContextFactory) -> None:
    """Many hosts answer every URL with 200 and an HTML page; that is not an exposure."""
    soft_404 = "<html><title>Sayfa bulunamadı</title><body>APP_KEY=? DB_PASSWORD</body></html>"
    for probe in exposure.PROBES:
        web.add(f"https://example.com{probe.path}", body=soft_404)
    ctx = await _context_with_homepage(web, make_context)
    findings = await exposure.run(ctx)  # type: ignore[arg-type]
    assert finding_ids(findings) == {"exposure.ok"}


async def test_non_200_is_ignored(web: FakeWeb, make_context: ContextFactory) -> None:
    web.add("https://example.com/.env", Page(status=403, body=ENV_FILE))
    ctx = await _context_with_homepage(web, make_context)
    assert finding_ids(await exposure.run(ctx)) == {"exposure.ok"}  # type: ignore[arg-type]


async def test_duplicate_probes_report_once(web: FakeWeb, make_context: ContextFactory) -> None:
    web.add("https://example.com/phpinfo.php", body="phpinfo() PHP Version 8")
    web.add("https://example.com/info.php", body="phpinfo() PHP Version 8")
    ctx = await _context_with_homepage(web, make_context)
    findings = await exposure.run(ctx)  # type: ignore[arg-type]
    assert [f.id for f in findings] == ["exposure.phpinfo"]


async def test_wordpress_upload_listing(web: FakeWeb, make_context: ContextFactory) -> None:
    web.add(
        "https://example.com/wp-content/uploads/",
        body="<title>Index of /wp-content/uploads</title>",
    )
    ctx = await _context_with_homepage(web, make_context)
    assert finding_ids(await exposure.run(ctx)) == {"exposure.ok"}  # type: ignore[arg-type]
    ctx.software.append(DetectedSoftware("wordpress", "WordPress", None, "test"))  # type: ignore[attr-defined]
    assert "exposure.dir_listing" in finding_ids(await exposure.run(ctx))  # type: ignore[arg-type]


async def test_directory_listing_on_homepage(web: FakeWeb, make_context: ContextFactory) -> None:
    ctx = await _context_with_homepage(web, make_context, body="<title>Index of /</title>")
    findings = await exposure.run(ctx)  # type: ignore[arg-type]
    assert by_id(findings, "exposure.dir_listing").title == "Ana sayfada klasör listesi görünüyor"


async def test_without_homepage_nothing_is_probed(
    web: FakeWeb, make_context: ContextFactory
) -> None:
    assert await exposure.run(make_context()) == []
    assert web.requests == []
