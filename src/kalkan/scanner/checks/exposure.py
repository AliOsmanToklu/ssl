"""Publicly reachable files that should never be on a web server.

Each probe validates the *content* of the response, not only the status code:
many hosting setups answer every URL with "200 OK" and a pretty error page.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass

from kalkan.i18n import N_, LocalizedValue, T
from kalkan.scanner.context import ScanContext
from kalkan.scanner.http_client import FetchError, FetchResult
from kalkan.scanner.models import Category, Finding, Severity

NAME = "exposure"

_ENV_LINE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}=", re.M)
_SECRET_KEY = re.compile(r"PASS|SECRET|KEY|TOKEN|DB_", re.I)


def _is_git_head(page: FetchResult) -> bool:
    text = page.body.strip()
    return text.startswith("ref: refs/") or bool(re.fullmatch(r"[0-9a-f]{40}", text))


def _is_env_file(page: FetchResult) -> bool:
    if "<html" in page.body[:2000].lower():
        return False
    lines = _ENV_LINE.findall(page.body)
    return len(lines) >= 2 and bool(_SECRET_KEY.search(page.body))


def _is_wp_config(page: FetchResult) -> bool:
    return "DB_PASSWORD" in page.body and "define(" in page.body


def _is_phpinfo(page: FetchResult) -> bool:
    return "phpinfo()" in page.body and "PHP Version" in page.body


def _is_server_status(page: FetchResult) -> bool:
    return "Apache Server Status" in page.body


def _is_sql_dump(page: FetchResult) -> bool:
    head = page.body[:5000]
    return "CREATE TABLE" in head or ("-- MySQL dump" in head) or ("INSERT INTO" in head)


def _is_ds_store(page: FetchResult) -> bool:
    return "Bud1" in page.body[:16]


def _is_dir_listing(page: FetchResult) -> bool:
    return bool(re.search(r"<title>\s*Index of /", page.body, re.I))


@dataclass(frozen=True, slots=True)
class Probe:
    path: str
    matches: Callable[[FetchResult], bool]
    finding_id: str
    severity: Severity
    title: LocalizedValue
    description: LocalizedValue
    recommendation: LocalizedValue


_LEAK_FIX = T(
    "Dosyayı sunucudan hemen kaldırın veya web erişimini engelleyin. İçindeki "
    "tüm şifre ve anahtarları (veritabanı, e-posta, API) DEĞİŞTİRİN; çünkü "
    "zaten kopyalanmış olabilirler."
)

PROBES: tuple[Probe, ...] = (
    Probe(
        "/.env",
        _is_env_file,
        "exposure.env",
        Severity.CRITICAL,
        T("Gizli ayar dosyası (.env) herkese açık"),
        T(
            "Bu dosya genellikle veritabanı şifreleri, e-posta şifreleri ve API "
            "anahtarları içerir. Otomatik botlar bu dosyayı her gün binlerce sitede "
            "arıyor."
        ),
        _LEAK_FIX,
    ),
    Probe(
        "/.git/HEAD",
        _is_git_head,
        "exposure.git",
        Severity.CRITICAL,
        T("Sitenin kaynak kodu (.git klasörü) herkese açık"),
        T("Saldırganlar sitenizin tüm kaynak kodunu ve içine yazılmış şifreleri indirebilir."),
        T(
            "Sunucudan .git klasörünü silin veya web erişimini engelleyin; kodda "
            "geçen şifreleri değiştirin."
        ),
    ),
    Probe(
        "/wp-config.php.bak",
        _is_wp_config,
        "exposure.wp_config_backup",
        Severity.CRITICAL,
        T("WordPress ayar dosyasının yedeği herkese açık"),
        T("Bu yedek dosya veritabanı şifrenizi düz metin olarak içeriyor."),
        _LEAK_FIX,
    ),
    Probe(
        "/wp-config.php~",
        _is_wp_config,
        "exposure.wp_config_backup",
        Severity.CRITICAL,
        T("WordPress ayar dosyasının yedeği herkese açık"),
        T("Bu yedek dosya veritabanı şifrenizi düz metin olarak içeriyor."),
        _LEAK_FIX,
    ),
    Probe(
        "/backup.sql",
        _is_sql_dump,
        "exposure.sql_dump",
        Severity.CRITICAL,
        T("Veritabanı yedeği herkese açık"),
        T(
            "Müşteri ve sipariş bilgileriniz dahil tüm veritabanı indirilebilir "
            "durumda. Bu durum KVKK kapsamında bir veri ihlali sayılabilir."
        ),
        T("Yedek dosyasını sunucudan hemen kaldırın; yedekleri web klasörü dışında saklayın."),
    ),
    Probe(
        "/phpinfo.php",
        _is_phpinfo,
        "exposure.phpinfo",
        Severity.MEDIUM,
        T("Sunucu bilgi sayfası (phpinfo) herkese açık"),
        T("Bu sayfa sunucunuzun yapılandırmasını, klasör yollarını ve sürümlerini gösterir."),
        T("phpinfo.php dosyasını sunucudan silin."),
    ),
    Probe(
        "/info.php",
        _is_phpinfo,
        "exposure.phpinfo",
        Severity.MEDIUM,
        T("Sunucu bilgi sayfası (phpinfo) herkese açık"),
        T("Bu sayfa sunucunuzun yapılandırmasını, klasör yollarını ve sürümlerini gösterir."),
        T("info.php dosyasını sunucudan silin."),
    ),
    Probe(
        "/server-status",
        _is_server_status,
        "exposure.server_status",
        Severity.MEDIUM,
        T("Apache sunucu durum sayfası herkese açık"),
        T("Bu sayfa ziyaretçilerin IP adreslerini ve açtıkları adresleri gerçek zamanlı gösterir."),
        T("Apache ayarlarında /server-status erişimini yalnızca localhost ile sınırlayın."),
    ),
    Probe(
        "/.DS_Store",
        _is_ds_store,
        "exposure.ds_store",
        Severity.LOW,
        T("Mac klasör bilgi dosyası (.DS_Store) herkese açık"),
        T("Bu dosya sunucudaki dosya ve klasör adlarını ortaya çıkarır."),
        T("Dosyayı silin ve dosya yüklerken .DS_Store'u hariç tutun."),
    ),
)

_WP_UPLOADS = Probe(
    "/wp-content/uploads/",
    _is_dir_listing,
    "exposure.dir_listing",
    Severity.MEDIUM,
    T("Klasör içerikleri listelenebiliyor"),
    T(
        "Ziyaretçiler yüklenen tüm dosyaların listesini görebiliyor; gizli "
        "kalması gereken belgeler (fatura, teklif, CV) bulunabilir."
    ),
    T("Sunucuda klasör listelemeyi kapatın (Apache: 'Options -Indexes')."),
)


async def run(ctx: ScanContext) -> list[Finding]:
    base = ctx.facts.base_url
    if base is None:
        return []
    findings: list[Finding] = []
    home = ctx.facts.homepage
    if home is not None and _is_dir_listing(home):
        findings.append(
            _finding(_WP_UPLOADS, home.url, title=T("Ana sayfada klasör listesi görünüyor"))
        )

    probes = list(PROBES)
    if any(s.product == "wordpress" for s in ctx.software):
        probes.append(_WP_UPLOADS)
    semaphore = asyncio.Semaphore(4)

    async def attempt(probe: Probe) -> tuple[Probe, FetchResult | None]:
        async with semaphore:
            try:
                page = await ctx.http.get(base + probe.path, max_body=64 * 1024)
            except FetchError:
                return probe, None
        return probe, page

    seen: set[str] = set()
    for probe, page in await asyncio.gather(*(attempt(p) for p in probes)):
        if page is None or page.status != 200 or probe.finding_id in seen:
            continue
        if probe.matches(page):
            seen.add(probe.finding_id)
            findings.append(_finding(probe, page.url))
    if not findings:
        findings.append(
            Finding(
                id="exposure.ok",
                category=Category.EXPOSURE,
                severity=Severity.PASS,
                title=T("Bilinen hassas dosyalar herkese açık değil"),
                details={N_("Kontrol edilen dosya sayısı"): str(len(probes))},
            )
        )
    return findings


def _finding(probe: Probe, url: str, *, title: LocalizedValue | None = None) -> Finding:
    return Finding(
        id=probe.finding_id,
        category=Category.EXPOSURE,
        severity=probe.severity,
        title=title or probe.title,
        description=probe.description,
        recommendation=probe.recommendation,
        details={N_("Adres"): url},
    )
