"""Registry of checks. Checks in the same stage run concurrently; later stages
may use facts (homepage, CDN, open ports, detected software) from earlier ones."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from kalkan.i18n import N_
from kalkan.scanner.checks import (
    dns,
    email,
    exposure,
    http,
    mailserver,
    ports,
    software,
    tls,
    wordpress,
)
from kalkan.scanner.context import ScanContext
from kalkan.scanner.models import Finding

CheckFn = Callable[[ScanContext], Awaitable[list[Finding]]]


@dataclass(frozen=True, slots=True)
class CheckSpec:
    name: str
    stage: int
    run: CheckFn
    label: str


CHECKS: tuple[CheckSpec, ...] = (
    CheckSpec(tls.NAME, 1, tls.run, N_("SSL/TLS sertifikası ve protokoller")),
    CheckSpec(http.NAME, 1, http.run, N_("Web sunucusu ayarları")),
    CheckSpec(email.NAME, 1, email.run, N_("E-posta sahteciliği koruması (SPF/DMARC/DKIM)")),
    CheckSpec(mailserver.NAME, 1, mailserver.run, N_("E-posta sunucusu şifrelemesi (STARTTLS)")),
    CheckSpec(dns.NAME, 1, dns.run, N_("Alan adı ayarları (DNSSEC/CAA)")),
    CheckSpec(ports.NAME, 2, ports.run, N_("Açık portlar")),
    CheckSpec(exposure.NAME, 2, exposure.run, N_("Açıkta kalan hassas dosyalar")),
    CheckSpec(wordpress.NAME, 2, wordpress.run, N_("WordPress eklenti ve temaları")),
    CheckSpec(software.NAME, 3, software.run, N_("Yazılım sürümleri")),
)

CHECK_NAMES = tuple(spec.name for spec in CHECKS)
