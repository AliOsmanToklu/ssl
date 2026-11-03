"""E-mail authentication of the organisation's domain: SPF, DMARC and DKIM."""

from __future__ import annotations

import asyncio
import base64
import binascii
import re
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from kalkan.i18n import N_, T
from kalkan.scanner.context import ScanContext
from kalkan.scanner.models import Category, Finding, Severity

NAME = "email"

_SPOOFING_RISK = T(
    "Dolandırıcılar firmanızın adresinden (ör. muhasebe@firmaniz.com) sahte "
    "fatura veya ödeme talebi gönderebilir ve bu e-postalar alıcıya gerçekmiş "
    "gibi ulaşır."
)

# DKIM keys live at <selector>._domainkey.<domain>; selectors are free-form, so only
# the ones that common providers use can be discovered.
DKIM_SELECTORS = (
    "google",  # Google Workspace
    "selector1",  # Microsoft 365
    "selector2",
    "default",  # cPanel / Plesk
    "dkim",
    "mail",  # Yandex
    "zoho",
    "zmail",
    "k1",  # Mailchimp / Mandrill
    "k2",
    "mandrill",
    "s1",  # SendGrid
    "s2",
    "pm",  # Postmark
    "smtp",
    "protonmail",
)


async def run(ctx: ScanContext) -> list[Finding]:
    if ctx.target.is_ip:
        return []
    domain = await ctx.zone()
    spf_txt, dmarc_txt, mx = await asyncio.gather(
        ctx.options.dns(domain, "TXT"), ctx.options.dns(f"_dmarc.{domain}", "TXT"), ctx.mx_hosts()
    )
    spf_records = [t for t in spf_txt if t.lower().startswith("v=spf1")]
    dmarc_records = [t for t in dmarc_txt if t.lower().replace(" ", "").startswith("v=dmarc1")]
    findings = [_spf_finding(domain, spf_records), _dmarc_finding(domain, dmarc_records)]
    if mx:  # DKIM only matters for a domain that handles e-mail
        findings.append(_dkim_finding(domain, await _dkim_keys(ctx, domain)))
    return findings


@dataclass(frozen=True, slots=True)
class DkimKey:
    selector: str
    key_type: str
    bits: int | None  # RSA modulus size; None for Ed25519 or unparseable keys


def parse_dkim(selector: str, record: str) -> DkimKey | None:
    tags = {}
    for part in record.split(";"):
        name, sep, value = part.partition("=")
        if sep:
            tags[name.strip().lower()] = "".join(value.split())
    if "p" not in tags or ("v" in tags and tags["v"].upper() != "DKIM1"):
        return None
    if not tags["p"]:
        return None  # empty p= means the key was revoked
    key_type = tags.get("k", "rsa").lower()
    bits = None
    if key_type == "rsa":
        try:
            key = load_der_public_key(base64.b64decode(tags["p"]))
        except (ValueError, binascii.Error):
            key = None
        if isinstance(key, rsa.RSAPublicKey):
            bits = key.key_size
    return DkimKey(selector, key_type, bits)


async def _dkim_keys(ctx: ScanContext, domain: str) -> list[DkimKey]:
    async def lookup(selector: str) -> list[DkimKey]:
        try:
            records = await ctx.options.dns(f"{selector}._domainkey.{domain}", "TXT")
        except Exception:
            return []
        return [k for k in (parse_dkim(selector, r) for r in records) if k]

    found = await asyncio.gather(*(lookup(s) for s in DKIM_SELECTORS))
    return [key for keys in found for key in keys]


def _dkim_finding(domain: str, keys: list[DkimKey]) -> Finding:
    if not keys:
        return Finding(
            id="email.dkim_not_found",
            category=Category.EMAIL,
            severity=Severity.INFO,
            title=T("Yaygın DKIM ayarlarında imza anahtarı bulunamadı"),
            description=(
                T(
                    "DKIM, e-postalarınızın sizden çıktığını ve yolda değiştirilmediğini "
                    "kanıtlar. Anahtarınız farklı bir adla tanımlanmış olabilir; bu yüzden bu "
                    "bir sorun değil, kontrol önerisidir."
                )
            ),
            recommendation=(
                T(
                    "E-posta sağlayıcınızın panelinde (Google Workspace, Microsoft 365, "
                    "cPanel) DKIM imzalamanın açık olduğunu kontrol edin."
                )
            ),
        )
    details = {
        f"{k.selector}._domainkey.{domain}": (
            f"{k.key_type.upper()} {k.bits} bit" if k.bits else k.key_type.upper()
        )
        for k in keys
    }
    weakest = min((k.bits for k in keys if k.bits), default=None)
    if weakest is not None and weakest < 1024:
        return Finding(
            id="email.dkim_weak",
            category=Category.EMAIL,
            severity=Severity.MEDIUM,
            title=T("DKIM anahtarı çok kısa ({weakest} bit)", weakest=weakest),
            description=(
                T(
                    "Bu uzunluktaki anahtarlar kırılabilir; e-posta sağlayıcıları bu imzaları "
                    "geçersiz sayabilir."
                )
            ),
            recommendation=(
                T("E-posta sağlayıcınızın panelinden 2048 bit yeni bir DKIM anahtarı oluşturun.")
            ),
            details=details,
        )
    if weakest is not None and weakest < 2048:
        return Finding(
            id="email.dkim_1024",
            category=Category.EMAIL,
            severity=Severity.LOW,
            title=T("DKIM anahtarı 1024 bit; 2048 bit önerilir"),
            description=T("1024 bit anahtarlar hâlâ kabul ediliyor ancak artık zayıf sayılıyor."),
            recommendation=T("Bir sonraki anahtar yenilemesinde 2048 bit anahtara geçin."),
            details=details,
        )
    return Finding(
        id="email.dkim_ok",
        category=Category.EMAIL,
        severity=Severity.PASS,
        title=T("E-postalarınız DKIM ile imzalanıyor"),
        details=details,
    )


def _spf_finding(domain: str, records: list[str]) -> Finding:
    if not records:
        return Finding(
            id="email.spf_missing",
            category=Category.EMAIL,
            severity=Severity.MEDIUM,
            title=T("Sahte e-posta koruması (SPF kaydı) yok"),
            description=_SPOOFING_RISK,
            recommendation=(
                T(
                    (
                        "'{domain}' için DNS'e bir SPF kaydı ekleyin. E-posta sağlayıcınız bu "
                        "kaydı verir; örneğin Google Workspace için: 'v=spf1 "
                        "include:_spf.google.com ~all'. Alan adınızdan hiç e-posta "
                        "gönderilmiyorsa: 'v=spf1 -all'."
                    ),
                    domain=domain,
                )
            ),
        )
    if len(records) > 1:
        return Finding(
            id="email.spf_multiple",
            category=Category.EMAIL,
            severity=Severity.MEDIUM,
            title=T("Birden fazla SPF kaydı var (geçersiz)"),
            description=(
                T(
                    "Bir alan adında yalnızca bir SPF kaydı olabilir; birden fazla kayıt "
                    "olduğunda e-posta sunucuları hepsini yok sayar ve koruma çalışmaz."
                )
            ),
            recommendation=T("SPF kayıtlarını tek bir kayıtta birleştirin."),
            details={f"SPF #{i}": r for i, r in enumerate(records, start=1)},
        )
    record = records[0]
    details = {N_("SPF kaydı"): record}
    qualifier = _all_qualifier(record)
    if qualifier == "+":
        return Finding(
            id="email.spf_permissive",
            category=Category.EMAIL,
            severity=Severity.HIGH,
            title=T("SPF kaydı herkesin sizin adınıza e-posta göndermesine izin veriyor"),
            description=(
                T(
                    "Kaydın sonundaki '+all', dünyadaki her sunucuyu yetkili sayar; SPF kaydı "
                    "hiç olmamasından daha kötüdür. "
                )
                + _SPOOFING_RISK
            ),
            recommendation=T("Kaydın sonundaki '+all' ifadesini '~all' veya '-all' yapın."),
            details=details,
        )
    if qualifier in ("?", None):
        return Finding(
            id="email.spf_neutral",
            category=Category.EMAIL,
            severity=Severity.LOW,
            title=T("SPF kaydı yetkisiz e-postaları engellemiyor"),
            description=(
                T(
                    "Kayıt, yetkisiz sunuculardan gelen e-postalar için 'tarafsız' "
                    "davranıyor; sahte e-postalar yine de teslim edilebilir."
                )
            ),
            recommendation=T("Kaydın sonuna '~all' (veya emin olduğunuzda '-all') ekleyin."),
            details=details,
        )
    return Finding(
        id="email.spf_ok",
        category=Category.EMAIL,
        severity=Severity.PASS,
        title=T("SPF kaydı doğru ayarlanmış"),
        details=details,
    )


def _all_qualifier(record: str) -> str | None:
    if re.search(r"\bredirect=", record, re.I):
        return "~"  # policy delegated to another domain; treat as configured
    match = re.search(r"(?:^|\s)([+\-~?]?)all\b", record, re.I)
    if not match:
        return None
    return match.group(1) or "+"


def _dmarc_finding(domain: str, records: list[str]) -> Finding:
    if not records:
        return Finding(
            id="email.dmarc_missing",
            category=Category.EMAIL,
            severity=Severity.MEDIUM,
            title=T("DMARC kaydı yok"),
            description=(
                T(
                    "DMARC, alıcı e-posta sunucularına sizin adınıza gelen sahte e-postaları "
                    "ne yapacaklarını söyler. Gmail ve Outlook toplu gönderimlerde DMARC "
                    "şartı arıyor."
                )
            ),
            recommendation=(
                T(
                    (
                        "DNS'e '_dmarc.{domain}' adıyla şu TXT kaydını ekleyin: 'v=DMARC1; "
                        "p=quarantine; rua=mailto:dmarc@{domain}'. Emin değilseniz önce 'p=none' "
                        "ile başlayıp raporları izleyin."
                    ),
                    domain=domain,
                )
            ),
        )
    record = records[0]
    policy_match = re.search(r"(?:^|;)\s*p\s*=\s*(\w+)", record, re.I)
    policy = policy_match.group(1).lower() if policy_match else "none"
    details = {N_("DMARC kaydı"): record}
    if policy == "none":
        return Finding(
            id="email.dmarc_monitor_only",
            category=Category.EMAIL,
            severity=Severity.LOW,
            title=T("DMARC yalnızca izleme modunda (p=none)"),
            description=(
                T("Sahte e-postalar raporlanıyor ama engellenmiyor; alıcılara yine de ulaşabilir.")
            ),
            recommendation=(
                T(
                    "Raporları birkaç hafta izledikten sonra politikayı 'p=quarantine', "
                    "ardından 'p=reject' yapın."
                )
            ),
            details=details,
        )
    return Finding(
        id="email.dmarc_ok",
        category=Category.EMAIL,
        severity=Severity.PASS,
        title=T("DMARC sahte e-postaları engelliyor (p={policy})", policy=policy),
        details=details,
    )
