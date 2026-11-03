from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest
from conftest import ContextFactory, by_id, finding_ids

from kalkan.scanner.checks import ports
from kalkan.scanner.models import Severity


@pytest.fixture
async def banner_server() -> AsyncIterator[int]:
    async def greet(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(greet, "127.0.0.1", 0)
    yield server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()


async def test_scan_ports_detects_open_and_closed(banner_server: int, free_port: int) -> None:
    results = await ports.scan_ports("127.0.0.1", (banner_server, free_port), wait=2)
    assert results[0][:2] == (banner_server, True)
    assert results[1] == (free_port, False, b"")


async def test_banner_is_read_for_greeting_services(banner_server: int) -> None:
    is_open, banner = await ports._probe("127.0.0.1", banner_server, 2, read_banner=True)
    assert is_open
    assert banner.startswith(b"SSH-2.0-OpenSSH_8.2p1")


async def test_run_records_open_ports(
    make_context: ContextFactory, banner_server: int, free_port: int
) -> None:
    ctx = make_context(
        "localhost", "127.0.0.1", allow_private=True, ports=(banner_server, free_port)
    )
    findings = await ports.run(ctx)
    assert ctx.facts.open_ports == [banner_server]
    assert finding_ids(findings) == {"ports.ok"}  # a random high port has no rule


def test_assess_reports_risky_ports() -> None:
    findings, notes = ports.assess([22, 80, 443, 3306, 3389, 27017], cdn=None, scanned=40)
    assert finding_ids(findings) == {
        "ports.open_22",
        "ports.open_3306",
        "ports.open_3389",
        "ports.open_27017",
    }
    assert by_id(findings, "ports.open_27017").severity is Severity.CRITICAL
    assert by_id(findings, "ports.open_3389").severity is Severity.HIGH
    assert (
        by_id(findings, "ports.open_3389").title == "Uzak Masaüstü (RDP) internete açık (port 3389)"
    )
    assert any("Paylaşımlı hosting" in n for n in notes)


def test_assess_info_ports_still_pass() -> None:
    findings, notes = ports.assess([80, 443, 2083], cdn=None, scanned=40)
    assert by_id(findings, "ports.open_2083").severity is Severity.INFO
    assert by_id(findings, "ports.open_2083").title == "cPanel açık (port 2083)"
    assert by_id(findings, "ports.ok").details["Açık portlar"] == "80, 443, 2083"
    assert notes == []


def test_assess_ignores_cdn_edge_ports() -> None:
    findings, notes = ports.assess([80, 443, 2082, 2083, 8080, 8443], cdn="Cloudflare", scanned=40)
    assert finding_ids(findings) == {"ports.ok"}
    assert "Cloudflare" in findings[0].title
    assert any("Cloudflare arkasında" in n for n in notes)


def test_assess_cdn_does_not_hide_non_web_ports() -> None:
    findings, _ = ports.assess([443, 3389], cdn="Cloudflare", scanned=40)
    assert finding_ids(findings) == {"ports.open_3389"}


def test_default_port_list_covers_every_rule() -> None:
    assert {r.port for r in ports.PORT_RULES} <= set(ports.DEFAULT_PORTS)
    assert 80 in ports.DEFAULT_PORTS and 443 in ports.DEFAULT_PORTS
