"""DNS hardening of the domain: DNSSEC and CAA."""

from __future__ import annotations

import asyncio
import re

from kalkan.i18n import N_, T
from kalkan.scanner.context import ScanContext
from kalkan.scanner.models import Category, Finding, Severity

NAME = "dns"

_CAA_RE = re.compile(r'^\d+\s+(issue|issuewild|iodef)\s+"?([^"]*)"?$', re.I)


async def run(ctx: ScanContext) -> list[Finding]:
    if ctx.target.is_ip:
        return []
    zone = await ctx.zone()
    ds_records, (caa_owner, caa_records) = await asyncio.gather(
        ctx.options.dns(zone, "DS"), find_caa(ctx, zone)
    )
    return [_dnssec_finding(zone, ds_records), _caa_finding(caa_owner, caa_records)]


async def find_caa(ctx: ScanContext, zone: str) -> tuple[str | None, list[str]]:
    """RFC 8659 "tree climbing": the closest name (up to the zone) with CAA records wins."""
    name = ctx.target.hostname
    while True:
        records = await ctx.options.dns(name, "CAA")
        if records:
            return name, records
        if name == zone or "." not in name:
            return None, []
        name = name.split(".", 1)[1]


def _dnssec_finding(zone: str, ds_records: list[str]) -> Finding:
    if ds_records:
        return Finding(
            id="dns.dnssec_ok",
            category=Category.DNS,
            severity=Severity.PASS,
            title=T("Alan adınız DNSSEC ile korunuyor"),
            details={N_("Alan adı"): zone, N_("DS kayıtları"): str(len(ds_records))},
        )
    return Finding(
        id="dns.dnssec_off",
        category=Category.DNS,
        severity=Severity.INFO,
        title=T("DNSSEC etkin değil"),
        description=(
            T(
                "DNSSEC, alan adınızın DNS yanıtlarını dijital olarak imzalar; "
                "saldırganların ziyaretçileri sahte sunuculara yönlendirmesini (DNS "
                "zehirleme) zorlaştırır."
            )
        ),
        recommendation=(
            T(
                "Alan adınızı aldığınız firma veya DNS sağlayıcınız (ör. Cloudflare) "
                "destekliyorsa panelden DNSSEC'i tek tıkla etkinleştirebilirsiniz."
            )
        ),
        details={N_("Alan adı"): zone},
    )


def _caa_finding(owner: str | None, records: list[str]) -> Finding:
    if owner is None:
        return Finding(
            id="dns.caa_missing",
            category=Category.DNS,
            severity=Severity.INFO,
            title=T("SSL sertifikası verebilecek kuruluşlar sınırlandırılmamış (CAA)"),
            description=(
                T(
                    "CAA kaydı, alan adınız için yalnızca sizin seçtiğiniz kuruluşların "
                    "sertifika vermesine izin verir; başka biri adınıza sertifika çıkaramaz."
                )
            ),
            recommendation=(
                T(
                    "DNS'e kullandığınız sağlayıcı için bir CAA kaydı ekleyin; örneğin Let's "
                    'Encrypt için: 0 issue "letsencrypt.org".'
                )
            ),
        )
    issuers = sorted(
        {
            match.group(2) or ";"
            for record in records
            if (match := _CAA_RE.match(record.strip())) and match.group(1).lower() != "iodef"
        }
    )
    return Finding(
        id="dns.caa_ok",
        category=Category.DNS,
        severity=Severity.PASS,
        title=T("Sertifika verebilecek kuruluşlar sınırlandırılmış (CAA)"),
        details={N_("Kayıt sahibi"): owner, N_("İzin verilen"): ", ".join(issuers) or "-"},
    )
