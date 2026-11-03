from __future__ import annotations

from conftest import ContextFactory, by_id, finding_ids

from kalkan.scanner.checks import software
from kalkan.scanner.models import DetectedSoftware, Severity
from kalkan.scanner.softwaredb import SoftwareDatabase

DB = SoftwareDatabase.from_dict(
    {
        "products": {
            "php": {
                "name": "PHP",
                "cycles": [
                    {"cycle": "8.4", "eol": "2028-12-31", "latest": "8.4.27"},
                    {"cycle": "8.3", "eol": "2027-12-31", "latest": "8.3.36"},
                    {"cycle": "7.4", "eol": "2022-11-28", "latest": "7.4.33"},
                ],
            },
            "openssh": {
                "name": "OpenSSH",
                "cycles": [{"cycle": "", "eol": False, "latest": "10.6"}],
                "minimum_safe": "9.8",
                "minimum_safe_reason": "CVE-2024-6387 (regreSSHion)",
            },
            "wordpress": {
                "name": "WordPress",
                "cycles": [{"cycle": "7.1", "eol": False, "latest": "7.1.4"}],
            },
        }
    }
)


def item(product: str, version: str | None, distro: str | None = None) -> DetectedSoftware:
    return DetectedSoftware(product, product.upper(), version, "test", distro)


async def run(make_context: ContextFactory, *items: DetectedSoftware) -> list[object]:
    ctx = make_context(software_db=DB)
    ctx.software_db = DB
    ctx.software.extend(items)
    return await software.run(ctx)  # type: ignore[return-value]


async def test_eol_php(make_context: ContextFactory) -> None:
    findings = await run(make_context, item("php", "7.4.33"))
    finding = by_id(findings, "software.eol.php")  # type: ignore[arg-type]
    assert finding.severity is Severity.HIGH
    assert finding.title == "PHP 7.4 artık güvenlik güncellemesi almıyor"
    assert "11.2022" in finding.description
    assert "Desteklenen sürümler: 8.4, 8.3" in finding.recommendation
    assert "MultiPHP" in finding.recommendation


async def test_outdated_and_current(make_context: ContextFactory) -> None:
    findings = await run(make_context, item("php", "8.3.10"), item("wordpress", "7.1.4"))
    outdated = by_id(findings, "software.outdated.php")  # type: ignore[arg-type]
    assert outdated.severity is Severity.MEDIUM
    assert outdated.details["Bu serinin son sürümü"] == "8.3.36"
    assert by_id(findings, "software.current.wordpress").severity is Severity.PASS  # type: ignore[arg-type]


async def test_vulnerable_openssh(make_context: ContextFactory) -> None:
    findings = await run(make_context, item("openssh", "8.9p1"))
    finding = by_id(findings, "software.vulnerable.openssh")  # type: ignore[arg-type]
    assert finding.severity is Severity.HIGH
    assert "regreSSHion" in finding.description
    assert "9.8" in finding.recommendation


async def test_distro_packages_are_downgraded(make_context: ContextFactory) -> None:
    findings = await run(
        make_context,
        item("php", "7.4.3", distro="Ubuntu"),
        item("openssh", "10.2p1", distro="Debian"),
    )
    eol = by_id(findings, "software.eol.php")  # type: ignore[arg-type]
    assert eol.severity is Severity.MEDIUM
    assert "Ubuntu" in eol.description and eol.details["Dağıtım"] == "Ubuntu"
    assert by_id(findings, "software.outdated.openssh").severity is Severity.LOW  # type: ignore[arg-type]


async def test_unknown_products_and_versions_are_skipped(make_context: ContextFactory) -> None:
    findings = await run(
        make_context, item("litespeed", "6.0"), item("php", None), item("php", "8.0.1")
    )
    assert findings == []


async def test_bundled_database_is_the_default(make_context: ContextFactory) -> None:
    ctx = make_context()
    ctx.software.append(item("php", "5.6.40"))
    findings = await software.run(ctx)
    assert finding_ids(findings) == {"software.eol.php"}
