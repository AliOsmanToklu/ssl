from __future__ import annotations

import asyncio
import os
import ssl
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from kalkan.scanner.context import ScanContext, ScanOptions
from kalkan.scanner.dnsutil import DnsLookup
from kalkan.scanner.http_client import PinnedHttpClient
from kalkan.scanner.models import (
    Category,
    DetectedSoftware,
    Finding,
    ScanReport,
    Severity,
)
from kalkan.scanner.softwaredb import SoftwareDatabase
from kalkan.scanner.target import Target, display_hostname
from kalkan.scanner.wporg import Kind, WpInfo, WpLookup
from kalkan.web.app import create_app
from kalkan.web.mail import MemoryMailer

PUBLIC_IP = "93.184.216.34"
# Set to run the database tests against PostgreSQL, e.g.
#   postgresql+psycopg://kalkan:test@127.0.0.1:55432/kalkan_test
TEST_DATABASE_URL = os.environ.get("KALKAN_TEST_DATABASE_URL")


@pytest.fixture
def database_url(tmp_path: Path) -> Iterator[str]:
    """An empty database: a SQLite file by default, a wiped PostgreSQL schema in CI."""
    if TEST_DATABASE_URL:
        engine = create_engine(TEST_DATABASE_URL)
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
        engine.dispose()
        yield TEST_DATABASE_URL
    else:
        yield f"sqlite:///{(tmp_path / 'kalkan.db').as_posix()}"


TODAY = date(2026, 11, 3)


def fake_resolver(mapping: dict[str, list[str]]) -> Callable[[str], Awaitable[list[str]]]:
    async def resolve(hostname: str) -> list[str]:
        return list(mapping.get(hostname, []))

    return resolve


def fake_txt(records: dict[str, list[str]]) -> Callable[[str], Awaitable[list[str]]]:
    async def lookup(name: str) -> list[str]:
        return list(records.get(name, []))

    return lookup


SOA = "ns1.example.net. hostmaster.example.net. 1 7200 3600 1209600 300"


def fake_dns(
    records: dict[tuple[str, str], list[str]] | None = None,
    *,
    txt: dict[str, list[str]] | None = None,
    zone: str | None = None,
) -> DnsLookup:
    """DNS answers keyed by (name, type); ``txt`` is a shortcut for TXT records and
    ``zone`` gets an SOA record so zone-apex detection finds it."""
    table: dict[tuple[str, str], list[str]] = dict(records or {})
    for name, values in (txt or {}).items():
        table[(name, "TXT")] = values
    if zone:
        table.setdefault((zone, "SOA"), [SOA])

    async def lookup(name: str, rdtype: str) -> list[str]:
        return list(table.get((name, rdtype), []))

    return lookup


def fake_wordpress(catalogue: dict[tuple[str, str], WpInfo] | None = None) -> WpLookup:
    async def lookup(kind: Kind, slug: str) -> WpInfo | None:
        return (catalogue or {}).get((kind, slug))

    return lookup


@dataclass
class Page:
    status: int = 200
    body: str | bytes = ""
    headers: dict[str, str] | list[tuple[str, str]] = field(default_factory=dict)


class FakeWeb:
    """An in-memory set of websites served through ``httpx.MockTransport``.

    Routes are keyed by (scheme, Host header, path), which is exactly what the
    pinned client sends, so tests also prove the Host/SNI pinning works.
    """

    def __init__(self) -> None:
        self.pages: dict[tuple[str, str, str], Page] = {}
        self.requests: list[httpx.Request] = []
        self.transport = httpx.MockTransport(self._handle)

    def add(self, url: str, page: Page | None = None, **kwargs: object) -> None:
        parsed = httpx.URL(url)
        host = parsed.host if parsed.port is None else f"{parsed.host}:{parsed.port}"
        self.pages[(parsed.scheme, host, parsed.path)] = page or Page(**kwargs)  # type: ignore[arg-type]

    def redirect(self, url: str, location: str, status: int = 301) -> None:
        self.add(url, Page(status=status, headers={"Location": location}))

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        scheme, host = request.url.scheme, request.headers["host"]
        if not any(s == scheme and h == host for s, h, _ in self.pages):
            # nothing listens there, like a closed port
            raise httpx.ConnectError("connection refused", request=request)
        page = self.pages.get((scheme, host, request.url.path))
        if page is None:
            return httpx.Response(404, text="<html><title>Bulunamadı</title></html>")
        content = page.body.encode() if isinstance(page.body, str) else page.body
        return httpx.Response(page.status, headers=page.headers, content=content)


@pytest.fixture
def web() -> FakeWeb:
    return FakeWeb()


ContextFactory = Callable[..., ScanContext]


@pytest.fixture
async def make_context(web: FakeWeb) -> AsyncIterator[ContextFactory]:
    clients: list[PinnedHttpClient] = []

    def factory(
        hostname: str = "example.com",
        ip: str = PUBLIC_IP,
        *,
        txt: dict[str, list[str]] | None = None,
        dns: dict[tuple[str, str], list[str]] | None = None,
        zone: str | None = None,
        **option_overrides: object,
    ) -> ScanContext:
        resolver = fake_resolver({hostname: [ip], f"www.{hostname}": [ip]})
        option_overrides.setdefault("http_transport", web.transport)
        option_overrides.setdefault(
            "dns", fake_dns(dns, txt=txt, zone=zone or hostname.removeprefix("www."))
        )
        option_overrides.setdefault("wordpress", fake_wordpress())  # never the real API
        options = ScanOptions(
            resolver=resolver,
            today=TODAY,
            **option_overrides,  # type: ignore[arg-type]
        )
        client = PinnedHttpClient(
            resolver=resolver,
            allow_private=options.allow_private,
            transport=options.http_transport,
        )
        clients.append(client)
        target = Target(hostname, display_hostname(hostname), (ip,))
        return ScanContext(target, options, client, SoftwareDatabase.bundled())

    yield factory
    for client in clients:
        await client.aclose()


def finding_ids(findings: list[Finding]) -> set[str]:
    return {f.id for f in findings}


def by_id(findings: list[Finding], finding_id: str) -> Finding:
    matches = [f for f in findings if f.id == finding_id]
    assert matches, f"{finding_id} not in {[f.id for f in findings]}"
    return matches[0]


def make_report(**overrides: object) -> ScanReport:
    now = datetime(2026, 11, 3, 10, 0, tzinfo=UTC)
    data: dict[str, object] = {
        "target": "example.com",
        "display_name": "example.com",
        "addresses": [PUBLIC_IP],
        "started_at": now,
        "finished_at": now + timedelta(seconds=12),
        "findings": [
            Finding(
                "software.eol.php",
                Category.SOFTWARE,
                Severity.HIGH,
                "PHP 7.4 artık güvenlik güncellemesi almıyor",
                "Bu sürüm desteklenmiyor.",
                "Desteklenen bir sürüme yükseltin.",
                {"Tespit edilen": "PHP 7.4.33"},
            ),
            Finding("email.spf_ok", Category.EMAIL, Severity.PASS, "SPF kaydı doğru ayarlanmış"),
        ],
        "software": [DetectedSoftware("php", "PHP", "7.4.33", "HTTP başlığı (X-Powered-By)")],
        "open_ports": [80, 443],
        "errors": [],
        "score": 79,
        "grade": "C",
        "tool_version": "0.1.0",
        "notes": [],
    }
    data.update(overrides)
    return ScanReport(**data)  # type: ignore[arg-type]


# --- TLS test server ----------------------------------------------------------


@dataclass
class CertBundle:
    cert_pem: bytes
    key_pem: bytes
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey


def make_cert(
    common_name: str,
    sans: list[str],
    *,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    issuer: CertBundle | None = None,
    is_ca: bool = False,
) -> CertBundle:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.cert.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - timedelta(days=1))
        .not_valid_after(not_after or now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]), critical=False
        )
    # RFC 5280 extensions: Python >= 3.13 verifies with VERIFY_X509_STRICT by default.
    signing_key = issuer.key if issuer else key
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()),
        critical=False,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=not is_ca,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=is_ca,
            crl_sign=is_ca,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    if not is_ca:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    cert = builder.sign(signing_key, hashes.SHA256())
    return CertBundle(
        cert_pem=cert.public_bytes(serialization.Encoding.PEM),
        key_pem=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        cert=cert,
        key=key,
    )


TlsServerFactory = Callable[..., Awaitable[int]]


@pytest.fixture
async def tls_server(tmp_path: Path) -> AsyncIterator[TlsServerFactory]:
    servers: list[asyncio.Server] = []

    async def start(
        bundle: CertBundle,
        *,
        minimum: ssl.TLSVersion | None = None,
        maximum: ssl.TLSVersion | None = None,
        legacy: bool = False,
    ) -> int:
        cert_file = tmp_path / f"cert{len(servers)}.pem"
        key_file = tmp_path / f"key{len(servers)}.pem"
        cert_file.write_bytes(bundle.cert_pem)
        key_file.write_bytes(bundle.key_pem)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        if legacy:
            context.set_ciphers("ALL:@SECLEVEL=0")
        if minimum is not None:
            context.minimum_version = minimum
        if maximum is not None:
            context.maximum_version = maximum

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
        servers.append(server)
        port: int = server.sockets[0].getsockname()[1]
        return port

    yield start
    for server in servers:
        server.close()
        await server.wait_closed()


@pytest.fixture
def free_port() -> Iterator[int]:
    """A local port with nothing listening on it."""
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
    yield port


# --- web app ------------------------------------------------------------------


@pytest.fixture
def mailer() -> MemoryMailer:
    return MemoryMailer()


AppFactory = Callable[..., FastAPI]


@pytest.fixture
def make_app(database_url: str, mailer: MemoryMailer) -> AppFactory:
    from web_helpers import fake_scanner, settings_for

    def factory(**overrides: object) -> FastAPI:
        return create_app(
            settings_for(database_url, **overrides), scanner=fake_scanner, mailer=mailer
        )

    return factory


@pytest.fixture
def app(make_app: AppFactory) -> FastAPI:
    return make_app()


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client
