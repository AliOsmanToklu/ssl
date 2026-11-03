from __future__ import annotations

import asyncio
import base64
import ssl
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import certifi
import dns.resolver
import pytest
from conftest import SOA, CertBundle, ContextFactory, by_id, fake_dns, finding_ids, make_cert
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from kalkan.i18n import LocalizedValue
from kalkan.scanner import dnsutil
from kalkan.scanner.checks import dns as dns_check
from kalkan.scanner.checks import email, mailserver
from kalkan.scanner.dnsutil import MxHost, parse_mx, zone_apex
from kalkan.scanner.models import Severity

# --- DNS helpers ----------------------------------------------------------------


async def test_zone_apex_walks_up_to_the_soa() -> None:
    lookup = fake_dns({("firma.com.tr", "SOA"): [SOA], ("com.tr", "SOA"): [SOA]})
    assert await zone_apex(lookup, "shop.eu.firma.com.tr") == "firma.com.tr"
    assert await zone_apex(lookup, "firma.com.tr.") == "firma.com.tr"
    assert await zone_apex(fake_dns(), "a.b.example") == "a.b.example"  # nothing found


async def test_zone_apex_skips_broken_names() -> None:
    async def lookup(name: str, rdtype: str) -> list[str]:
        if name == "www.example.com":
            raise dns.resolver.NoNameservers
        return [SOA] if name == "example.com" else []

    assert await zone_apex(lookup, "www.example.com") == "example.com"


def test_parse_mx() -> None:
    records = ["20 mx2.example.com.", "10 MX1.example.com.", "0 .", "bozuk", "x mx.example.com."]
    assert parse_mx(records) == [MxHost(10, "mx1.example.com"), MxHost(20, "mx2.example.com")]


class _FakeAnswer:
    def __init__(self, rdatas: list[Any], *, qname: str = "a", canonical: str = "a") -> None:
        self._rdatas, self.qname, self.canonical_name = rdatas, qname, canonical

    def __iter__(self) -> Any:
        return iter(self._rdatas)


class _Rdata:
    def __init__(self, text: str, strings: tuple[bytes, ...] = ()) -> None:
        self._text, self.strings = text, strings

    def to_text(self) -> str:
        return self._text


async def test_system_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    answers: dict[tuple[str, str], Any] = {
        ("example.com", "TXT"): _FakeAnswer([_Rdata("", (b"v=spf1 ", b"-all"))]),
        ("example.com", "MX"): _FakeAnswer([_Rdata("10 mx.example.com.")]),
        ("www.example.com", "SOA"): _FakeAnswer([_Rdata(SOA)], qname="www", canonical="cdn"),
    }

    async def resolve(self: Any, name: str, rdtype: str) -> Any:
        if (name, rdtype) not in answers:
            raise dns.resolver.NXDOMAIN
        return answers[(name, rdtype)]

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", resolve)
    assert await dnsutil.system_dns("example.com", "TXT") == ["v=spf1 -all"]
    assert await dnsutil.dns_txt_resolver("example.com") == ["v=spf1 -all"]
    assert await dnsutil.system_dns("example.com", "MX") == ["10 mx.example.com."]
    assert await dnsutil.system_dns("www.example.com", "SOA") == []  # SOA of a CNAME target
    assert await dnsutil.system_dns("yok.example.com", "A") == []


# --- DKIM -----------------------------------------------------------------------


def dkim_record(bits: int | None = 2048, *, key_type: str = "rsa") -> str:
    if key_type == "ed25519":
        public = ed25519.Ed25519PrivateKey.generate().public_key()
        raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return f"v=DKIM1; k=ed25519; p={base64.b64encode(raw).decode()}"
    if bits is not None and bits < 1024:
        # cryptography refuses to generate such keys; build one from numbers instead
        public_key = rsa.RSAPublicNumbers(65537, (1 << (bits - 1)) | 1).public_key()
    else:
        public_key = rsa.generate_private_key(65537, bits or 2048).public_key()
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    encoded = base64.b64encode(der).decode()
    # long TXT values are split in chunks; whitespace inside p= must be ignored
    return f"v=DKIM1; k=rsa; p={encoded[:40]} {encoded[40:]}"


MAIL = {("example.com", "MX"): ["10 mx.example.com."]}


async def run_email(make_context: ContextFactory, **extra: list[str]) -> list[Any]:
    records = dict(MAIL)
    records.update({(name, "TXT"): values for name, values in extra.items()})
    return await email.run(make_context(dns=records))


@pytest.mark.parametrize(
    ("bits", "finding_id", "severity"),
    [
        (2048, "email.dkim_ok", Severity.PASS),
        (1024, "email.dkim_1024", Severity.LOW),
        (512, "email.dkim_weak", Severity.MEDIUM),
    ],
)
async def test_dkim_key_strength(
    make_context: ContextFactory, bits: int, finding_id: str, severity: Severity
) -> None:
    findings = await run_email(
        make_context, **{"google._domainkey.example.com": [dkim_record(bits)]}
    )
    finding = by_id(findings, finding_id)
    assert finding.severity is severity
    assert finding.details == {"google._domainkey.example.com": f"RSA {bits} bit"}


async def test_dkim_ed25519_and_several_selectors(make_context: ContextFactory) -> None:
    findings = await run_email(
        make_context,
        **{
            "selector1._domainkey.example.com": [dkim_record(key_type="ed25519")],
            "default._domainkey.example.com": [dkim_record(2048)],
        },
    )
    assert set(by_id(findings, "email.dkim_ok").details.values()) == {"ED25519", "RSA 2048 bit"}


@pytest.mark.parametrize(
    "record",
    ["v=DKIM1; k=rsa; p=", "v=spf1 -all", "v=DKIM2; p=abc", "v=DKIM1; p=bozuk-base64!"],
)
async def test_unusable_dkim_records(make_context: ContextFactory, record: str) -> None:
    findings = await run_email(make_context, **{"default._domainkey.example.com": [record]})
    if record.endswith("bozuk-base64!"):
        # a key we cannot parse still proves DKIM is configured
        assert by_id(findings, "email.dkim_ok").details == {"default._domainkey.example.com": "RSA"}
    else:
        assert by_id(findings, "email.dkim_not_found").severity is Severity.INFO


async def test_no_dkim_lookup_without_mail_servers(make_context: ContextFactory) -> None:
    findings = await email.run(make_context(txt={"example.com": ["v=spf1 -all"]}))
    assert not {f.id for f in findings} & {"email.dkim_ok", "email.dkim_not_found"}


# --- DNSSEC and CAA ---------------------------------------------------------------


async def test_dnssec_and_caa_present(make_context: ContextFactory) -> None:
    ctx = make_context(
        "www.example.com",
        zone="example.com",
        dns={
            ("example.com", "DS"): ["2371 13 2 1F987CC6583E92DF0890718C42"],
            ("example.com", "CAA"): ['0 issue "letsencrypt.org"', '0 iodef "mailto:a@b.c"'],
        },
    )
    findings = await dns_check.run(ctx)
    assert by_id(findings, "dns.dnssec_ok").details["DS kayıtları"] == "1"
    caa = by_id(findings, "dns.caa_ok")
    assert caa.details == {"Kayıt sahibi": "example.com", "İzin verilen": "letsencrypt.org"}


async def test_closest_caa_record_wins(make_context: ContextFactory) -> None:
    ctx = make_context(
        "shop.example.com",
        zone="example.com",
        dns={
            ("shop.example.com", "CAA"): ['0 issue ";"'],
            ("example.com", "CAA"): ['0 issue "digicert.com"'],
        },
    )
    caa = by_id(await dns_check.run(ctx), "dns.caa_ok")
    assert caa.details["Kayıt sahibi"] == "shop.example.com"
    assert caa.details["İzin verilen"] == ";"


async def test_dnssec_and_caa_missing(make_context: ContextFactory) -> None:
    findings = await dns_check.run(make_context("www.example.com", zone="example.com"))
    assert finding_ids(findings) == {"dns.dnssec_off", "dns.caa_missing"}
    assert all(f.severity is Severity.INFO for f in findings)


async def test_dns_checks_skip_ip_targets(make_context: ContextFactory) -> None:
    ctx = make_context("93.184.216.34")
    assert await dns_check.run(ctx) == []
    assert await email.run(ctx) == []
    assert await mailserver.run(ctx) == []
    assert await ctx.zone() == "93.184.216.34"


# --- SMTP STARTTLS ----------------------------------------------------------------

SmtpFactory = Callable[..., Awaitable[int]]


@pytest.fixture
async def smtp_server(tmp_path: Path) -> AsyncIterator[SmtpFactory]:
    servers: list[asyncio.Server] = []

    async def start(
        *, starttls: bool = True, cert: CertBundle | None = None, banner: str = "220"
    ) -> int:
        context = None
        if cert is not None:
            (tmp_path / "c.pem").write_bytes(cert.cert_pem)
            (tmp_path / "k.pem").write_bytes(cert.key_pem)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")

        async def session(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                writer.write(f"{banner} mx.example.com ESMTP test\r\n".encode())
                while line := await reader.readline():
                    command = line.decode().strip().upper()
                    if command.startswith("EHLO"):
                        extra = (
                            "250-PIPELINING\r\n250 STARTTLS\r\n"
                            if starttls
                            else "250 SIZE 1000\r\n"
                        )
                        writer.write(b"250-mx.example.com\r\n" + extra.encode())
                    elif command == "STARTTLS" and context is not None:
                        writer.write(b"220 Go ahead\r\n")
                        await writer.drain()
                        await writer.start_tls(context)
                    elif command == "QUIT":
                        writer.write(b"221 Bye\r\n")
                        await writer.drain()
                        break
                    else:
                        writer.write(b"502 Unknown\r\n")
                    await writer.drain()
            except (OSError, ssl.SSLError):
                pass
            finally:
                writer.close()

        server = await asyncio.start_server(session, "127.0.0.1", 0)
        servers.append(server)
        port: int = server.sockets[0].getsockname()[1]
        return port

    yield start
    for server in servers:
        server.close()
        await server.wait_closed()


def smtp_context(make_context: ContextFactory, port: int, mx: str = "mx.example.com") -> Any:
    ctx = make_context(
        "example.com", dns={("example.com", "MX"): [f"10 {mx}."]}, smtp_port=port, timeout=5
    )
    ctx.options.resolver = _resolver_with(mx, "127.0.0.1")
    ctx.options.allow_private = True
    return ctx


def _resolver_with(host: str, ip: str) -> Callable[[str], Awaitable[list[str]]]:
    async def resolve(name: str) -> list[str]:
        return [ip] if name == host else []

    return resolve


async def test_starttls_with_trusted_certificate(
    make_context: ContextFactory,
    smtp_server: SmtpFactory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ca = make_cert("Kalkan Test CA", [], is_ca=True)
    (tmp_path / "ca.pem").write_bytes(ca.cert_pem)
    monkeypatch.setattr(certifi, "where", lambda: str(tmp_path / "ca.pem"))
    port = await smtp_server(cert=make_cert("mx.example.com", ["mx.example.com"], issuer=ca))
    findings = await mailserver.run(smtp_context(make_context, port))
    ok = by_id(findings, "email.starttls_ok")
    assert ok.details == {"mx.example.com": "STARTTLS var, sertifika geçerli"}


async def test_starttls_with_self_signed_certificate(
    make_context: ContextFactory, smtp_server: SmtpFactory
) -> None:
    port = await smtp_server(cert=make_cert("mx.example.com", ["mx.example.com"]))
    findings = await mailserver.run(smtp_context(make_context, port))
    assert finding_ids(findings) == {"email.mx_certificate"}
    assert by_id(findings, "email.mx_certificate").severity is Severity.LOW


async def test_no_starttls(make_context: ContextFactory, smtp_server: SmtpFactory) -> None:
    port = await smtp_server(starttls=False)
    findings = await mailserver.run(smtp_context(make_context, port))
    finding = by_id(findings, "email.no_starttls")
    assert finding.severity is Severity.MEDIUM
    assert finding.details == {"mx.example.com": "STARTTLS yok (şifresiz)"}


async def test_unfriendly_greeting(make_context: ContextFactory, smtp_server: SmtpFactory) -> None:
    port = await smtp_server(banner="554")
    ctx = smtp_context(make_context, port)
    assert await mailserver.run(ctx) == []
    assert any("bağlanılamadı" in note for note in ctx.notes)


async def test_unreachable_mail_server_is_a_note(
    make_context: ContextFactory, free_port: int
) -> None:
    ctx = smtp_context(make_context, free_port)
    assert await mailserver.run(ctx) == []
    assert any("25 numaralı port" in note for note in ctx.notes)


async def test_private_mx_is_not_contacted(make_context: ContextFactory, free_port: int) -> None:
    ctx = smtp_context(make_context, free_port)
    ctx.options.allow_private = False
    result = await mailserver.probe(ctx, MxHost(10, "mx.example.com"))
    assert result.status is mailserver.TlsStatus.BLOCKED


async def test_no_mx_means_no_mail_checks(make_context: ContextFactory) -> None:
    assert await mailserver.run(make_context()) == []


def test_assess_mixed_results() -> None:
    results = [
        mailserver.MxResult("mx1.example.com", mailserver.TlsStatus.NO_STARTTLS),
        mailserver.MxResult("mx2.example.com", mailserver.TlsStatus.TLS_UNTRUSTED),
        mailserver.MxResult("mx3.example.com", mailserver.TlsStatus.UNREACHABLE),
    ]
    notes: list[LocalizedValue] = []
    findings = mailserver.assess(results, notes)
    assert finding_ids(findings) == {"email.no_starttls", "email.mx_certificate"}
    assert findings[0].details["mx3.example.com"] == "bağlanılamadı"
    assert notes == []


async def test_read_reply_rejects_endless_replies() -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(b"250-x\r\n" * 150)
    with pytest.raises(ConnectionError):
        await mailserver.read_reply(reader, 1)
    closed = asyncio.StreamReader()
    closed.feed_eof()
    with pytest.raises(ConnectionError):
        await mailserver.read_reply(closed, 1)
