"""Does the domain's mail server accept encrypted connections (SMTP STARTTLS)?

Only the greeting, EHLO and STARTTLS are exchanged; no mail is sent. Many cloud
networks block outgoing port 25, so an unreachable server becomes a report note,
not a finding.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import ssl
from dataclasses import dataclass

import certifi

from kalkan.i18n import LocalizedValue, T
from kalkan.scanner.context import ScanContext
from kalkan.scanner.dnsutil import MxHost
from kalkan.scanner.models import Category, Finding, Severity
from kalkan.scanner.target import TargetError, resolve_host

NAME = "mailserver"
MAX_HOSTS = 2
EHLO_NAME = "kalkan-scanner.invalid"


class TlsStatus(enum.StrEnum):
    TLS_OK = "tls_ok"
    TLS_UNTRUSTED = "tls_untrusted"  # STARTTLS works but the certificate does not verify
    NO_STARTTLS = "no_starttls"
    UNREACHABLE = "unreachable"
    BLOCKED = "blocked"  # resolves to a private address


_LABELS = {
    TlsStatus.TLS_OK: T("STARTTLS var, sertifika geçerli"),
    TlsStatus.TLS_UNTRUSTED: T("STARTTLS var, sertifika doğrulanamadı"),
    TlsStatus.NO_STARTTLS: T("STARTTLS yok (şifresiz)"),
    TlsStatus.UNREACHABLE: T("bağlanılamadı"),
    TlsStatus.BLOCKED: T("iç ağ adresi, taranmadı"),
}


@dataclass(frozen=True, slots=True)
class MxResult:
    host: str
    status: TlsStatus


async def read_reply(reader: asyncio.StreamReader, wait: float) -> tuple[int, list[str]]:
    """Read one (possibly multi-line) SMTP reply: ``250-a``, ``250-b``, ``250 c``."""
    lines: list[str] = []
    while True:
        raw = await asyncio.wait_for(reader.readline(), wait)
        if not raw:
            raise ConnectionError("connection closed")
        line = raw.decode("latin-1").rstrip("\r\n")
        lines.append(line)
        if len(line) < 4 or line[3] != "-":
            break
        if len(lines) > 100:
            raise ConnectionError("reply too long")
    code = int(lines[-1][:3]) if lines[-1][:3].isdigit() else 0
    return code, lines


async def _command(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, line: str, wait: float
) -> tuple[int, list[str]]:
    writer.write(line.encode("ascii") + b"\r\n")
    await writer.drain()
    return await read_reply(reader, wait)


async def probe(ctx: ScanContext, mx: MxHost) -> MxResult:
    options = ctx.options
    try:
        addresses = await resolve_host(
            mx.host, resolver=options.resolver, allow_private=options.allow_private
        )
    except TargetError:
        return MxResult(mx.host, TlsStatus.BLOCKED)
    timeout = options.timeout
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(addresses[0], options.smtp_port), timeout
        )
    except (OSError, TimeoutError):
        return MxResult(mx.host, TlsStatus.UNREACHABLE)
    try:
        code, _ = await read_reply(reader, timeout)
        if code != 220:
            return MxResult(mx.host, TlsStatus.UNREACHABLE)
        _, capabilities = await _command(reader, writer, f"EHLO {EHLO_NAME}", timeout)
        if not any(line[4:].strip().upper() == "STARTTLS" for line in capabilities):
            with contextlib.suppress(Exception):
                await _command(reader, writer, "QUIT", timeout)
            return MxResult(mx.host, TlsStatus.NO_STARTTLS)
        code, _ = await _command(reader, writer, "STARTTLS", timeout)
        if code != 220:
            return MxResult(mx.host, TlsStatus.NO_STARTTLS)
        context = ssl.create_default_context(cafile=certifi.where())
        try:
            await writer.start_tls(context, server_hostname=mx.host, ssl_handshake_timeout=timeout)
        except ssl.SSLCertVerificationError:
            return MxResult(mx.host, TlsStatus.TLS_UNTRUSTED)
        with contextlib.suppress(Exception):
            await _command(reader, writer, "QUIT", timeout)
        return MxResult(mx.host, TlsStatus.TLS_OK)
    except (OSError, TimeoutError, ValueError, ssl.SSLError):
        return MxResult(mx.host, TlsStatus.UNREACHABLE)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), 2)


async def run(ctx: ScanContext) -> list[Finding]:
    if ctx.target.is_ip:
        return []
    hosts = (await ctx.mx_hosts())[:MAX_HOSTS]
    if not hosts:
        return []
    results = await asyncio.gather(*(probe(ctx, mx) for mx in hosts))
    return assess(results, ctx.notes)


def assess(results: list[MxResult], notes: list[LocalizedValue]) -> list[Finding]:
    details = {r.host: _LABELS[r.status] for r in results}
    statuses = {r.status for r in results}
    reachable = statuses - {TlsStatus.UNREACHABLE, TlsStatus.BLOCKED}
    if not reachable:
        notes.append(
            T(
                "E-posta sunucularınıza 25 numaralı porttan bağlanılamadı; şifreleme "
                "(STARTTLS) kontrol edilemedi. Bu, tarayıcının bulunduğu ağın e-posta "
                "portunu engellemesinden kaynaklanabilir."
            )
        )
        return []
    findings: list[Finding] = []
    if TlsStatus.NO_STARTTLS in statuses:
        findings.append(
            Finding(
                id="email.no_starttls",
                category=Category.EMAIL,
                severity=Severity.MEDIUM,
                title=T("E-posta sunucunuz şifreli bağlantıyı (STARTTLS) desteklemiyor"),
                description=(
                    T(
                        "Size gönderilen e-postalar internette şifresiz taşınıyor; aradaki bir "
                        "saldırgan içeriği okuyabilir."
                    )
                ),
                recommendation=(
                    T(
                        "E-posta sunucunuzda TLS'i etkinleştirin. Hosting firmanızın e-posta "
                        "hizmetini kullanıyorsanız onlardan STARTTLS desteğini açmalarını "
                        "isteyin."
                    )
                ),
                details=details,
            )
        )
    if TlsStatus.TLS_UNTRUSTED in statuses:
        findings.append(
            Finding(
                id="email.mx_certificate",
                category=Category.EMAIL,
                severity=Severity.LOW,
                title=T("E-posta sunucusunun sertifikası doğrulanamıyor"),
                description=(
                    T(
                        "Bağlantı şifreleniyor ancak sertifika güvenilir bir kuruluştan "
                        "değil veya sunucu adıyla eşleşmiyor. Sıkı güvenlik kullanan "
                        "alıcılar (MTA-STS) e-posta teslim etmeyebilir."
                    )
                ),
                recommendation=(
                    T(
                        "E-posta sunucusu için alan adıyla eşleşen geçerli bir sertifika kurun "
                        "(ücretsiz Let's Encrypt de olur)."
                    )
                ),
                details=details,
            )
        )
    if not findings:
        findings.append(
            Finding(
                id="email.starttls_ok",
                category=Category.EMAIL,
                severity=Severity.PASS,
                title=T("E-posta sunucularınız şifreli bağlantı (STARTTLS) kullanıyor"),
                details=details,
            )
        )
    return findings
