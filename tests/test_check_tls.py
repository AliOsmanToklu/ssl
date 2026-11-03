from __future__ import annotations

import ssl
import warnings
from datetime import UTC, datetime, timedelta

import pytest
from conftest import ContextFactory, TlsServerFactory, by_id, finding_ids, make_cert

from kalkan.scanner.checks import tls
from kalkan.scanner.models import Severity

HOST = "shop.example.com"


def context_for(make_context: ContextFactory, port: int) -> object:
    return make_context(HOST, "127.0.0.1", allow_private=True, tls_port=port, timeout=5)


async def test_self_signed_certificate(
    make_context: ContextFactory, tls_server: TlsServerFactory
) -> None:
    port = await tls_server(make_cert(HOST, [HOST]))
    ctx = context_for(make_context, port)
    findings = await tls.run(ctx)  # type: ignore[arg-type]
    ids = finding_ids(findings)
    assert "tls.cert_valid" in ids
    assert "tls.hostname_mismatch" not in ids
    assert by_id(findings, "tls.self_signed").severity is Severity.HIGH
    assert ctx.facts.https_ok is True  # type: ignore[attr-defined]
    valid = by_id(findings, "tls.cert_valid")
    assert valid.details["Kapsanan alan adları"] == HOST
    assert valid.details["Anahtar"] == "ECDSA secp256r1"


async def test_modern_server_passes_protocol_check(
    make_context: ContextFactory, tls_server: TlsServerFactory
) -> None:
    port = await tls_server(make_cert(HOST, [HOST]), minimum=ssl.TLSVersion.TLSv1_2)
    findings = await tls.run(context_for(make_context, port))  # type: ignore[arg-type]
    passed = by_id(findings, "tls.protocols_ok")
    assert passed.details["TLS 1.3"] == "açık"
    assert passed.details["TLS 1.0"] in ("kapalı", "test edilemedi")
    assert "tls.legacy_protocols" not in finding_ids(findings)


async def test_tls12_only_server(
    make_context: ContextFactory, tls_server: TlsServerFactory
) -> None:
    port = await tls_server(make_cert(HOST, [HOST]), maximum=ssl.TLSVersion.TLSv1_2)
    findings = await tls.run(context_for(make_context, port))  # type: ignore[arg-type]
    assert by_id(findings, "tls.no_tls13").severity is Severity.LOW
    assert "tls.protocols_ok" not in finding_ids(findings)


async def test_legacy_protocols_are_flagged(
    make_context: ContextFactory, tls_server: TlsServerFactory
) -> None:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            port = await tls_server(
                make_cert(HOST, [HOST]), minimum=ssl.TLSVersion.TLSv1, legacy=True
            )
    except (ValueError, ssl.SSLError):
        pytest.skip("this OpenSSL build cannot serve TLS 1.0")
    findings = await tls.run(context_for(make_context, port))  # type: ignore[arg-type]
    protocol_ids = finding_ids(findings) & {"tls.legacy_protocols", "tls.protocols_ok"}
    if protocol_ids == {"tls.protocols_ok"}:
        pytest.skip("this OpenSSL build refuses TLS 1.0 even at security level 0")
    finding = by_id(findings, "tls.legacy_protocols")
    assert finding.severity is Severity.MEDIUM
    assert "TLS 1.0" in finding.title


async def test_expired_certificate(
    make_context: ContextFactory, tls_server: TlsServerFactory
) -> None:
    now = datetime.now(UTC)
    bundle = make_cert(
        HOST, [HOST], not_before=now - timedelta(days=100), not_after=now - timedelta(days=3)
    )
    findings = await tls.run(context_for(make_context, await tls_server(bundle)))  # type: ignore[arg-type]
    assert by_id(findings, "tls.cert_expired").severity is Severity.CRITICAL
    assert "tls.cert_valid" not in finding_ids(findings)


async def test_not_yet_valid_certificate(
    make_context: ContextFactory, tls_server: TlsServerFactory
) -> None:
    now = datetime.now(UTC)
    bundle = make_cert(
        HOST, [HOST], not_before=now + timedelta(days=2), not_after=now + timedelta(days=60)
    )
    findings = await tls.run(context_for(make_context, await tls_server(bundle)))  # type: ignore[arg-type]
    assert by_id(findings, "tls.cert_not_yet_valid").severity is Severity.HIGH


@pytest.mark.parametrize(("days", "severity"), [(5, Severity.HIGH), (12, Severity.MEDIUM)])
async def test_expiring_certificate(
    make_context: ContextFactory, tls_server: TlsServerFactory, days: int, severity: Severity
) -> None:
    bundle = make_cert(HOST, [HOST], not_after=datetime.now(UTC) + timedelta(days=days, hours=1))
    findings = await tls.run(context_for(make_context, await tls_server(bundle)))  # type: ignore[arg-type]
    finding = by_id(findings, "tls.cert_expiring")
    assert finding.severity is severity
    assert f"{days} gün" in finding.title


async def test_hostname_mismatch(
    make_context: ContextFactory, tls_server: TlsServerFactory
) -> None:
    port = await tls_server(make_cert("other.example.org", ["other.example.org"]))
    findings = await tls.run(context_for(make_context, port))  # type: ignore[arg-type]
    assert by_id(findings, "tls.hostname_mismatch").severity is Severity.HIGH


async def test_missing_intermediate(
    make_context: ContextFactory, tls_server: TlsServerFactory
) -> None:
    ca = make_cert("Kalkan Test CA", [], is_ca=True)
    leaf = make_cert(HOST, [HOST], issuer=ca)
    findings = await tls.run(context_for(make_context, await tls_server(leaf)))  # type: ignore[arg-type]
    finding = by_id(findings, "tls.incomplete_chain")
    assert finding.severity is Severity.MEDIUM
    assert finding.details["Sertifikayı veren"] == "Kalkan Test CA"


async def test_no_https(make_context: ContextFactory, free_port: int) -> None:
    ctx = context_for(make_context, free_port)
    findings = await tls.run(ctx)  # type: ignore[arg-type]
    assert finding_ids(findings) == {"tls.no_https"}
    assert by_id(findings, "tls.no_https").severity is Severity.CRITICAL
    assert ctx.facts.https_ok is False  # type: ignore[attr-defined]


async def test_plain_tcp_service_on_443(make_context: ContextFactory) -> None:
    import asyncio

    async def plain(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(plain, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        findings = await tls.run(context_for(make_context, port))  # type: ignore[arg-type]
    finally:
        server.close()
        await server.wait_closed()
    assert finding_ids(findings) == {"tls.handshake_failed"}


@pytest.mark.parametrize(
    ("host", "names", "matches"),
    [
        ("example.com", ["example.com"], True),
        ("www.example.com", ["*.example.com"], True),
        ("a.b.example.com", ["*.example.com"], False),
        ("example.com", ["*.example.com"], False),
        ("EXAMPLE.com.", ["example.com"], True),
        ("example.com", ["www.example.com"], False),
    ],
)
def test_hostname_matches(host: str, names: list[str], matches: bool) -> None:
    assert tls.hostname_matches(host, names) is matches


def test_protocol_findings_with_untestable_versions() -> None:
    findings = tls._protocol_findings(
        {"TLS 1.0": None, "TLS 1.1": None, "TLS 1.2": True, "TLS 1.3": True}, "TLSv1.3"
    )
    finding = by_id(findings, "tls.protocols_ok")
    assert finding.details["TLS 1.0"] == "test edilemedi"
    assert finding.details["Varsayılan"] == "TLSv1.3"
