from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from conftest import (
    PUBLIC_IP,
    TODAY,
    FakeWeb,
    Page,
    fake_dns,
    fake_resolver,
    fake_wordpress,
    finding_ids,
)

from kalkan.scanner import engine
from kalkan.scanner.checks import CHECKS, CheckSpec
from kalkan.scanner.context import ScanContext, ScanOptions
from kalkan.scanner.models import Category, Finding, Severity
from kalkan.scanner.scoring import compute_score, grade_for
from kalkan.scanner.target import TargetError


def f(severity: Severity) -> Finding:
    return Finding(f"x.{severity.value}", Category.HTTP, severity, "x")


@pytest.mark.parametrize(
    ("severities", "score", "grade"),
    [
        ([], 100, "A"),
        ([Severity.PASS, Severity.INFO], 100, "A"),
        ([Severity.LOW] * 3, 94, "A"),
        ([Severity.MEDIUM, Severity.MEDIUM, Severity.LOW], 84, "B"),
        ([Severity.HIGH], 79, "C"),  # one high-severity problem caps at C
        ([Severity.HIGH, Severity.HIGH, Severity.MEDIUM], 63, "D"),
        ([Severity.CRITICAL], 49, "F"),  # any critical problem means F
        ([Severity.CRITICAL] * 4, 0, "F"),
    ],
)
def test_compute_score(severities: list[Severity], score: int, grade: str) -> None:
    assert compute_score(f(s) for s in severities) == (score, grade)


def test_grade_boundaries() -> None:
    assert [grade_for(s) for s in (100, 90, 89, 80, 79, 65, 64, 50, 49, 0)] == list("AABBCCDDFF")


def test_severity_helpers() -> None:
    assert Severity.CRITICAL.rank < Severity.LOW.rank < Severity.PASS.rank
    assert Severity.HIGH.label == "Yüksek"
    assert Severity.MEDIUM.is_problem and not Severity.INFO.is_problem
    assert Category.EMAIL.label == "E-posta güvenliği"


def options(web: FakeWeb, **overrides: object) -> ScanOptions:
    defaults: dict[str, object] = {
        "checks": frozenset({"http", "email", "exposure", "software"}),
        "resolver": fake_resolver({"example.com": [PUBLIC_IP]}),
        "dns": fake_dns(txt={"example.com": ["v=spf1 -all"]}, zone="example.com"),
        "wordpress": fake_wordpress(),
        "http_transport": web.transport,
        "today": TODAY,
    }
    defaults.update(overrides)
    return ScanOptions(**defaults)  # type: ignore[arg-type]


async def test_full_scan_assembles_report(web: FakeWeb) -> None:
    web.redirect("http://example.com/", "https://example.com/")
    web.add(
        "https://example.com/",
        Page(
            headers={
                "Content-Type": "text/html",
                "Server": "Apache/2.2.34",
                "X-Powered-By": "PHP/7.4.33",
            }
        ),
    )
    web.add("https://example.com/.env", body="DB_PASSWORD=x\nAPP_KEY=y\n")
    report = await engine.scan("https://example.com/", options(web))

    assert report.target == "example.com"
    assert report.addresses == [PUBLIC_IP]
    assert report.errors == []
    ids = finding_ids(report.findings)
    assert {
        "exposure.env",
        "software.eol.php",
        "software.eol.apache",
        "email.spf_ok",
        "email.dmarc_missing",
    } <= ids
    ranks = [x.severity.rank for x in report.findings]
    assert ranks == sorted(ranks)  # most severe first
    assert report.findings[0].id == "exposure.env"
    assert (report.score, report.grade) == compute_score(report.findings)
    assert report.grade == "F"
    assert {s.product for s in report.software} == {"apache", "php"}
    assert report.finished_at >= report.started_at
    assert report.worst_severity() is Severity.CRITICAL


async def test_failing_check_becomes_an_error_not_a_crash(
    web: FakeWeb, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def explode(ctx: ScanContext) -> list[Finding]:
        raise RuntimeError("boom")

    async def slow(ctx: ScanContext) -> list[Finding]:
        await asyncio.sleep(5)
        return []

    monkeypatch.setattr(
        engine,
        "CHECKS",
        (
            *CHECKS,
            CheckSpec("explode", 1, explode, "Patlayan"),
            CheckSpec("slow", 1, slow, "Yavaş"),
        ),
    )
    monkeypatch.setattr(engine, "CHECK_TIMEOUT", 0.05)
    report = await engine.scan(
        "example.com", options(web, checks=frozenset({"explode", "slow", "email"}))
    )
    messages = sorted(str(e.message) for e in report.errors)
    assert messages == ["Patlayan: RuntimeError: boom", "Yavaş: zaman aşımı"]
    assert "email.spf_ok" in finding_ids(report.findings)


async def test_scan_rejects_private_targets(web: FakeWeb) -> None:
    with pytest.raises(TargetError):
        await engine.scan(
            "router.example.com",
            options(web, resolver=fake_resolver({"router.example.com": ["192.168.1.1"]})),
        )


def test_options_helpers() -> None:
    opts = ScanOptions(checks=frozenset({"tls"}), today=TODAY)
    assert opts.wants("tls") and not opts.wants("ports")
    assert ScanOptions().wants("ports")
    assert opts.current_date() == TODAY
    assert ScanOptions().current_date() == datetime.now(UTC).date()
