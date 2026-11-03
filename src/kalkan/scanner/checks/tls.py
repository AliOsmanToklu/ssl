"""SSL/TLS certificate and protocol checks."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import warnings
from dataclasses import dataclass
from datetime import UTC, datetime

import certifi
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from kalkan.i18n import N_, LocalizedValue, T
from kalkan.scanner.context import ScanContext
from kalkan.scanner.models import Category, Finding, Severity

NAME = "tls"

# OpenSSL flag (not exposed by the ssl module): skip validity-period checks so a
# chain-of-trust test is not masked by an expired certificate.
_X509_V_FLAG_NO_CHECK_TIME = 0x200000

# X509 verify codes we explain in plain language
_SELF_SIGNED = {18, 19}  # depth-zero self-signed / self-signed in chain
_INCOMPLETE_CHAIN = {20, 21}  # unable to get local issuer / verify leaf


@dataclass(slots=True)
class CertInfo:
    subject_cn: str | None
    issuer: str
    sans: list[str]
    not_before: datetime
    not_after: datetime
    self_signed: bool
    key_description: str
    weak_key: bool
    signature_hash: str | None

    @classmethod
    def from_der(cls, der: bytes) -> CertInfo:
        cert = x509.load_der_x509_certificate(der)
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = san_ext.value.get_values_for_type(x509.DNSName)  # type: ignore[attr-defined]
        except x509.ExtensionNotFound:
            sans = []
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            key_description, weak = f"RSA {key.key_size} bit", key.key_size < 2048
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key_description, weak = f"ECDSA {key.curve.name}", key.curve.key_size < 224
        elif isinstance(key, dsa.DSAPublicKey):
            key_description, weak = f"DSA {key.key_size} bit", True
        else:
            key_description, weak = type(key).__name__.removesuffix("PublicKey"), False
        hash_alg = cert.signature_hash_algorithm
        return cls(
            subject_cn=_first_attr(cert.subject, NameOID.COMMON_NAME),
            issuer=_first_attr(cert.issuer, NameOID.ORGANIZATION_NAME)
            or _first_attr(cert.issuer, NameOID.COMMON_NAME)
            or cert.issuer.rfc4514_string(),
            sans=list(sans),
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            self_signed=cert.issuer == cert.subject,
            key_description=key_description,
            weak_key=weak,
            signature_hash=hash_alg.name if hash_alg else None,
        )


def _first_attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    if not attrs:
        return None
    value = attrs[0].value
    return value if isinstance(value, str) else value.decode("utf-8", errors="replace")


def hostname_matches(hostname: str, names: list[str]) -> bool:
    """RFC 6125 matching: exact name or a single left-most wildcard label."""
    host = hostname.lower().rstrip(".")
    for name in names:
        pattern = name.lower().rstrip(".")
        if pattern == host:
            return True
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".example.com"
            head, dot, rest = host.partition(".")
            if head and dot and "." + rest == suffix:
                return True
    return False


async def _handshake(
    ctx: ScanContext, context: ssl.SSLContext
) -> tuple[ssl.SSLObject, asyncio.StreamWriter]:
    target = ctx.target
    server_hostname = None if target.is_ip else target.hostname
    _reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            target.primary_ip,
            ctx.options.tls_port,
            ssl=context,
            server_hostname=server_hostname,
            ssl_handshake_timeout=ctx.options.timeout,
        ),
        timeout=ctx.options.timeout + 1,
    )
    ssl_object = writer.get_extra_info("ssl_object")
    if not isinstance(ssl_object, ssl.SSLObject):
        writer.close()
        raise ssl.SSLError("TLS session was not established")
    return ssl_object, writer


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(OSError, TimeoutError, ssl.SSLError):
        await asyncio.wait_for(writer.wait_closed(), timeout=2)


def _insecure_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


async def _fetch_certificate(ctx: ScanContext) -> tuple[bytes, str | None]:
    ssl_object, writer = await _handshake(ctx, _insecure_context())
    try:
        der = ssl_object.getpeercert(binary_form=True)
        if not der:
            raise ssl.SSLError("server sent no certificate")
        return der, ssl_object.version()
    finally:
        await _close(writer)


async def _verify_chain(ctx: ScanContext) -> ssl.SSLCertVerificationError | None:
    """Return the verification error of the certificate chain, ignoring dates and name."""
    context = ssl.create_default_context(cafile=certifi.where())
    context.check_hostname = False
    context.verify_flags |= _X509_V_FLAG_NO_CHECK_TIME
    try:
        _ssl_object, writer = await _handshake(ctx, context)
    except ssl.SSLCertVerificationError as exc:
        return exc
    except (OSError, TimeoutError):
        return None  # the handshake itself failed; nothing to say about the chain
    await _close(writer)
    return None


_PROTOCOLS = [
    ("TLS 1.0", "TLSv1"),
    ("TLS 1.1", "TLSv1_1"),
    ("TLS 1.2", "TLSv1_2"),
    ("TLS 1.3", "TLSv1_3"),
]


async def _supports(ctx: ScanContext, version_name: str) -> bool | None:
    """True/False if the server accepts only this protocol; None if we cannot test it."""
    context = _insecure_context()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            version = getattr(ssl.TLSVersion, version_name)
            context.minimum_version = version
            context.maximum_version = version
            if version_name in ("TLSv1", "TLSv1_1"):
                context.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    try:
        _ssl_object, writer = await _handshake(ctx, context)
    except ssl.SSLError as exc:
        if exc.reason == "NO_PROTOCOLS_AVAILABLE":
            return None  # our OpenSSL build cannot speak this version
        return False
    except (OSError, TimeoutError):
        return False
    await _close(writer)
    return True


async def _tcp_open(ctx: ScanContext) -> bool:
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ctx.target.primary_ip, ctx.options.tls_port),
            timeout=ctx.options.timeout,
        )
    except (OSError, TimeoutError):
        return False
    await _close(writer)
    return True


async def run(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    if not await _tcp_open(ctx):
        ctx.facts.https_ok = False
        return [_no_https()]
    try:
        der, negotiated = await _fetch_certificate(ctx)
    except (OSError, TimeoutError) as exc:
        ctx.facts.https_ok = False
        return [_handshake_failed(f"{type(exc).__name__}: {exc}")]
    ctx.facts.https_ok = True
    info = CertInfo.from_der(der)
    findings.extend(_certificate_findings(ctx, info))

    chain_error = await _verify_chain(ctx)
    if chain_error is not None:
        findings.append(_chain_finding(chain_error, info))

    supported = dict(
        zip(
            [label for label, _ in _PROTOCOLS],
            await asyncio.gather(*(_supports(ctx, name) for _, name in _PROTOCOLS)),
            strict=True,
        )
    )
    findings.extend(_protocol_findings(supported, negotiated))
    return findings


def _no_https() -> Finding:
    return Finding(
        id="tls.no_https",
        category=Category.TLS,
        severity=Severity.CRITICAL,
        title=T("Siteniz şifreli bağlantı (HTTPS) kullanmıyor"),
        description=(
            T(
                "Ziyaretçilerinizin sitenize gönderdiği bilgiler (iletişim formları, "
                "şifreler, sipariş bilgileri) şifrelenmeden iletiliyor ve aynı ağdaki "
                "biri tarafından okunabilir. Tarayıcılar sitenizi 'Güvenli değil' olarak "
                "gösteriyor."
            )
        ),
        recommendation=(
            T(
                "Hosting firmanızdan ücretsiz bir Let's Encrypt SSL sertifikası "
                "etkinleştirmesini isteyin. cPanel ve Plesk gibi panellerde bu genellikle "
                "tek tıkla yapılır."
            )
        ),
    )


def _handshake_failed(error: str) -> Finding:
    return Finding(
        id="tls.handshake_failed",
        category=Category.TLS,
        severity=Severity.HIGH,
        title=T("HTTPS bağlantısı kurulamıyor"),
        description=(
            T(
                "443 numaralı port açık ancak güvenli bağlantı kurulamadı. "
                "Ziyaretçileriniz sitenizi HTTPS ile açtığında hata görüyor olabilir."
            )
        ),
        recommendation=T(
            "Sunucunuzun SSL/TLS ayarlarını hosting firmanızla birlikte kontrol edin."
        ),
        details={N_("Hata"): error},
    )


def _certificate_findings(ctx: ScanContext, info: CertInfo) -> list[Finding]:
    findings: list[Finding] = []
    now = datetime.now(UTC)
    days_left = (info.not_after - now).days
    details = {
        N_("Sertifikayı veren"): info.issuer,
        N_("Geçerlilik bitişi"): info.not_after.strftime("%d.%m.%Y"),
        N_("Kapsanan alan adları"): ", ".join(info.sans[:10]) or (info.subject_cn or "-"),
        N_("Anahtar"): info.key_description,
    }

    if now > info.not_after:
        findings.append(
            Finding(
                id="tls.cert_expired",
                category=Category.TLS,
                severity=Severity.CRITICAL,
                title=T("SSL sertifikanızın süresi dolmuş"),
                description=(
                    T(
                        (
                            "Sertifika {not_after:%d.%m.%Y} tarihinde sona erdi. Tarayıcılar "
                            "ziyaretçilerinize büyük bir güvenlik uyarısı gösteriyor ve çoğu kişi "
                            "sitenizden çıkıyor."
                        ),
                        not_after=info.not_after,
                    )
                ),
                recommendation=(
                    T(
                        "Sertifikayı hemen yenileyin ve hosting panelinizden otomatik "
                        "yenilemeyi açın (Let's Encrypt ücretsiz ve otomatik "
                        "yenilenir)."
                    )
                ),
                details=details,
            )
        )
    elif now < info.not_before:
        findings.append(
            Finding(
                id="tls.cert_not_yet_valid",
                category=Category.TLS,
                severity=Severity.HIGH,
                title=T("SSL sertifikası henüz geçerli değil"),
                description=T("Sertifikanın başlangıç tarihi ileride; tarayıcılar uyarı gösterir."),
                recommendation=T("Sunucu saatini ve kurulan sertifikayı kontrol edin."),
                details=details,
            )
        )
    elif days_left <= 14:
        findings.append(
            Finding(
                id="tls.cert_expiring",
                category=Category.TLS,
                severity=Severity.HIGH if days_left <= 7 else Severity.MEDIUM,
                title=T(
                    "SSL sertifikanızın süresi {days_left} gün içinde doluyor", days_left=days_left
                ),
                description=(
                    T(
                        "Sertifika süresi dolduğunda ziyaretçileriniz güvenlik uyarısı "
                        "görecek. Otomatik yenileme çalışıyorsa bu süre genellikle daha "
                        "uzun olur."
                    )
                ),
                recommendation=(
                    T("Sertifikanın otomatik yenilendiğinden emin olun; değilse hemen yenileyin.")
                ),
                details=details,
            )
        )
    else:
        findings.append(
            Finding(
                id="tls.cert_valid",
                category=Category.TLS,
                severity=Severity.PASS,
                title=T("SSL sertifikası geçerli ({days_left} gün kaldı)", days_left=days_left),
                details=details,
            )
        )

    if not ctx.target.is_ip and not hostname_matches(
        ctx.target.hostname, info.sans or ([info.subject_cn] if info.subject_cn else [])
    ):
        findings.append(
            Finding(
                id="tls.hostname_mismatch",
                category=Category.TLS,
                severity=Severity.HIGH,
                title=T("SSL sertifikası bu alan adına ait değil"),
                description=(
                    T(
                        (
                            "Sertifika '{display_name}' adresini kapsamıyor. Tarayıcılar "
                            "ziyaretçilere 'bağlantınız gizli değil' uyarısı gösterir."
                        ),
                        display_name=ctx.target.display_name,
                    )
                ),
                recommendation=(
                    T(
                        "Sertifikayı hem 'firmaniz.com' hem 'www.firmaniz.com' adreslerini "
                        "kapsayacak şekilde yeniden oluşturun."
                    )
                ),
                details=details,
            )
        )

    if info.weak_key:
        findings.append(
            Finding(
                id="tls.weak_key",
                category=Category.TLS,
                severity=Severity.MEDIUM,
                title=T("SSL sertifikasının şifreleme anahtarı zayıf"),
                description=(
                    T(
                        "Sertifika {key_description} anahtar kullanıyor; bu artık yetersiz.",
                        key_description=info.key_description,
                    )
                ),
                recommendation=T("Sertifikayı en az 2048 bit RSA veya ECDSA anahtarla yenileyin."),
                details=details,
            )
        )
    if info.signature_hash in ("md5", "sha1"):
        findings.append(
            Finding(
                id="tls.weak_signature",
                category=Category.TLS,
                severity=Severity.MEDIUM,
                title=T("SSL sertifikası eski bir imza algoritması kullanıyor"),
                description=T(
                    "Sertifika {upper} ile imzalanmış; kırılabilir.",
                    upper=info.signature_hash.upper(),
                ),
                recommendation=T("Sertifikayı SHA-256 imzalı yeni bir sertifikayla değiştirin."),
                details=details,
            )
        )
    return findings


def _chain_finding(error: ssl.SSLCertVerificationError, info: CertInfo) -> Finding:
    details = {
        N_("Doğrulama hatası"): str(error.verify_message),
        N_("Sertifikayı veren"): info.issuer,
    }
    if error.verify_code in _SELF_SIGNED or info.self_signed:
        return Finding(
            id="tls.self_signed",
            category=Category.TLS,
            severity=Severity.HIGH,
            title=T("SSL sertifikası güvenilir bir kuruluş tarafından verilmemiş"),
            description=(
                T(
                    "Sertifika 'kendinden imzalı'; tarayıcılar bunu tanımaz ve "
                    "ziyaretçilerinize güvenlik uyarısı gösterir."
                )
            ),
            recommendation=(
                T(
                    "Ücretsiz Let's Encrypt veya bilinen bir sertifika sağlayıcısından "
                    "sertifika alın."
                )
            ),
            details=details,
        )
    if error.verify_code in _INCOMPLETE_CHAIN:
        return Finding(
            id="tls.incomplete_chain",
            category=Category.TLS,
            severity=Severity.MEDIUM,
            title=T("SSL sertifika zinciri eksik (ara sertifika yüklenmemiş)"),
            description=(
                T(
                    "Sunucu, sertifikanın güvenilirliğini kanıtlayan ara sertifikayı "
                    "göndermiyor. Bazı telefonlar, eski tarayıcılar ve uygulamalar sitenize "
                    "bağlanamaz."
                )
            ),
            recommendation=(
                T(
                    "Sertifika sağlayıcınızın verdiği 'CA bundle / ara sertifika' dosyasını "
                    "sunucuya yükleyin (Let's Encrypt'te 'fullchain.pem' kullanın)."
                )
            ),
            details=details,
        )
    return Finding(
        id="tls.untrusted",
        category=Category.TLS,
        severity=Severity.HIGH,
        title=T("SSL sertifikası doğrulanamıyor"),
        description=T("Tarayıcılar bu sertifikaya güvenmiyor ve ziyaretçilere uyarı gösteriyor."),
        recommendation=T(
            "Sertifikayı güvenilir bir sağlayıcıdan yeniden alıp doğru şekilde kurun."
        ),
        details=details,
    )


def _protocol_findings(supported: dict[str, bool | None], negotiated: str | None) -> list[Finding]:
    findings: list[Finding] = []
    detail: dict[str, LocalizedValue] = {
        label: (T("açık") if ok else T("kapalı") if ok is False else T("test edilemedi"))
        for label, ok in supported.items()
    }
    if negotiated:
        detail[N_("Varsayılan")] = negotiated
    legacy = [label for label in ("TLS 1.0", "TLS 1.1") if supported.get(label)]
    if legacy:
        findings.append(
            Finding(
                id="tls.legacy_protocols",
                category=Category.TLS,
                severity=Severity.MEDIUM,
                title=T(
                    "Eski ve güvensiz şifreleme sürümleri açık ({join})", join=", ".join(legacy)
                ),
                description=(
                    T(
                        "Bu sürümler 2021'de resmi olarak kullanımdan kaldırıldı ve bilinen "
                        "zayıflıkları var. Kredi kartı işlemleri için (PCI DSS) de kabul "
                        "edilmiyor."
                    )
                ),
                recommendation=(
                    T("Sunucu veya hosting ayarlarından yalnızca TLS 1.2 ve TLS 1.3'e izin verin.")
                ),
                details=detail,
            )
        )
    if supported.get("TLS 1.3") is False:
        findings.append(
            Finding(
                id="tls.no_tls13",
                category=Category.TLS,
                severity=Severity.LOW,
                title=T("Modern TLS 1.3 desteklenmiyor"),
                description=T("TLS 1.3 daha hızlı ve daha güvenli bağlantı sağlar."),
                recommendation=T("Sunucu yazılımınızı güncelleyip TLS 1.3'ü etkinleştirin."),
                details=detail,
            )
        )
    if not legacy and supported.get("TLS 1.3"):
        findings.append(
            Finding(
                id="tls.protocols_ok",
                category=Category.TLS,
                severity=Severity.PASS,
                title=T("Yalnızca güncel şifreleme sürümleri kullanılıyor"),
                details=detail,
            )
        )
    return findings
