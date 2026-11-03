from __future__ import annotations

import pytest
from conftest import ContextFactory, by_id, finding_ids

from kalkan.scanner.checks import email
from kalkan.scanner.models import Severity


async def run(make_context: ContextFactory, spf: list[str], dmarc: list[str]) -> list[object]:
    ctx = make_context("www.example.com", txt={"example.com": spf, "_dmarc.example.com": dmarc})
    return await email.run(ctx)  # type: ignore[return-value]


async def test_well_protected_domain(make_context: ContextFactory) -> None:
    findings = await run(
        make_context,
        ["google-site-verification=abc", "v=spf1 include:_spf.google.com -all"],
        ["v=DMARC1; p=reject; rua=mailto:d@example.com"],
    )
    assert finding_ids(findings) == {"email.spf_ok", "email.dmarc_ok"}  # type: ignore[arg-type]


async def test_missing_records(make_context: ContextFactory) -> None:
    findings = await run(make_context, [], [])
    assert finding_ids(findings) == {"email.spf_missing", "email.dmarc_missing"}  # type: ignore[arg-type]
    spf = by_id(findings, "email.spf_missing")  # type: ignore[arg-type]
    assert spf.severity is Severity.MEDIUM
    assert "'example.com'" in spf.recommendation  # www stripped: protects info@example.com


@pytest.mark.parametrize(
    ("record", "finding_id", "severity"),
    [
        ("v=spf1 +all", "email.spf_permissive", Severity.HIGH),
        ("v=spf1 a mx all", "email.spf_permissive", Severity.HIGH),
        ("v=spf1 mx ?all", "email.spf_neutral", Severity.LOW),
        ("v=spf1 mx", "email.spf_neutral", Severity.LOW),
        ("v=spf1 ~all", "email.spf_ok", Severity.PASS),
        ("v=spf1 redirect=_spf.example.net", "email.spf_ok", Severity.PASS),
        ("V=SPF1 MX -ALL", "email.spf_ok", Severity.PASS),
    ],
)
async def test_spf_variants(
    make_context: ContextFactory, record: str, finding_id: str, severity: Severity
) -> None:
    findings = await run(make_context, [record], ["v=DMARC1; p=quarantine"])
    assert by_id(findings, finding_id).severity is severity  # type: ignore[arg-type]


async def test_multiple_spf_records_are_invalid(make_context: ContextFactory) -> None:
    findings = await run(make_context, ["v=spf1 -all", "v=spf1 mx -all"], [])
    finding = by_id(findings, "email.spf_multiple")  # type: ignore[arg-type]
    assert finding.details == {"SPF #1": "v=spf1 -all", "SPF #2": "v=spf1 mx -all"}


@pytest.mark.parametrize(
    ("record", "finding_id"),
    [
        ("v=DMARC1; p=none; rua=mailto:x@example.com", "email.dmarc_monitor_only"),
        ("v=DMARC1", "email.dmarc_monitor_only"),
        ("v=DMARC1; p=quarantine", "email.dmarc_ok"),
        ("v = DMARC1 ; p = reject", "email.dmarc_ok"),
    ],
)
async def test_dmarc_variants(make_context: ContextFactory, record: str, finding_id: str) -> None:
    findings = await run(make_context, ["v=spf1 -all"], [record])
    assert finding_id in finding_ids(findings)  # type: ignore[arg-type]


async def test_ip_targets_are_skipped(make_context: ContextFactory) -> None:
    assert await email.run(make_context("93.184.216.34")) == []


async def test_subdomains_use_the_zone_policy(make_context: ContextFactory) -> None:
    """blog.firma.com.tr is protected by the SPF/DMARC records of firma.com.tr."""
    ctx = make_context(
        "blog.firma.com.tr",
        zone="firma.com.tr",
        txt={"firma.com.tr": ["v=spf1 -all"], "_dmarc.firma.com.tr": ["v=DMARC1; p=reject"]},
    )
    findings = await email.run(ctx)
    assert finding_ids(findings) == {"email.spf_ok", "email.dmarc_ok"}
