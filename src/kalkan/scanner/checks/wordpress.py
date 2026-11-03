"""WordPress plugins and themes: outdated, abandoned or pulled from WordPress.org.

Out-of-date plugins are the most common way WordPress sites get hacked. Components are
discovered from the homepage HTML; the installed version comes from the component's
own readme.txt / style.css (falling back to the ``?ver=`` of its assets) and is compared
with the latest release published on WordPress.org.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from datetime import date, timedelta

from kalkan.i18n import N_, T, Text
from kalkan.scanner.context import ScanContext
from kalkan.scanner.http_client import FetchError
from kalkan.scanner.models import Category, DetectedSoftware, Finding, Severity
from kalkan.scanner.versions import parse_version
from kalkan.scanner.wporg import Kind, WpInfo

NAME = "wordpress"
MAX_PLUGINS = 15
MAX_THEMES = 2
ABANDONED_AFTER = timedelta(days=730)

_PLUGIN_RE = re.compile(r"/wp-content/plugins/([a-z0-9_-]+)/[^\"'\s>)]*", re.I)
_THEME_RE = re.compile(r"/wp-content/themes/([a-z0-9_-]+)/[^\"'\s>)]*", re.I)
_VER_RE = re.compile(r"[?&]ver=([0-9][\w.-]*)")
_STABLE_TAG_RE = re.compile(r"^\s*Stable tag:\s*([0-9][\w.-]*)", re.I | re.M)
_THEME_VERSION_RE = re.compile(r"^\s*Version:\s*([0-9][\w.-]*)", re.I | re.M)
_KIND_LABEL = {"plugin": T("eklenti"), "theme": T("tema")}
_CLOSED_TITLE = {
    ("plugin", True): N_(
        "'{name}' eklentisi güvenlik sorunu nedeniyle WordPress.org'dan kaldırılmış"
    ),
    ("plugin", False): N_("'{name}' eklentisi WordPress.org'dan kaldırılmış"),
    ("theme", True): N_("'{name}' teması güvenlik sorunu nedeniyle WordPress.org'dan kaldırılmış"),
    ("theme", False): N_("'{name}' teması WordPress.org'dan kaldırılmış"),
}
_UPDATE_HINT = T(
    "WordPress yönetim panelinde Başlangıç > Güncellemeler sayfasından "
    "güncelleyin ve otomatik güncellemeleri açın. Kullanmadığınız eklenti ve "
    "temaları silin."
)


@dataclass(frozen=True, slots=True)
class Component:
    kind: Kind
    slug: str
    version: str | None
    info: WpInfo | None

    @property
    def name(self) -> str:
        return self.info.name if self.info else self.slug

    @property
    def label(self) -> Text:
        return T("{name} ({kind})", name=self.name, kind=_KIND_LABEL[self.kind])


def discover(body: str) -> tuple[dict[str, str | None], dict[str, str | None]]:
    """Plugin and theme slugs referenced by the page, with an asset ``?ver=`` hint."""

    def collect(pattern: re.Pattern[str], limit: int) -> dict[str, str | None]:
        found: dict[str, str | None] = {}
        for match in pattern.finditer(body):
            slug = match.group(1).lower()
            version = _VER_RE.search(match.group(0))
            if slug not in found and len(found) >= limit:
                continue
            if found.get(slug) is None:
                found[slug] = version.group(1) if version else None
        return found

    return collect(_PLUGIN_RE, MAX_PLUGINS), collect(_THEME_RE, MAX_THEMES)


async def _installed_version(ctx: ScanContext, base: str, kind: Kind, slug: str) -> str | None:
    if kind == "plugin":
        path, pattern = f"/wp-content/plugins/{slug}/readme.txt", _STABLE_TAG_RE
    else:
        path, pattern = f"/wp-content/themes/{slug}/style.css", _THEME_VERSION_RE
    try:
        page = await ctx.http.get(base + path, max_body=16 * 1024)
    except FetchError:
        return None
    if page.status != 200 or "<html" in page.body[:500].lower():
        return None
    match = pattern.search(page.body)
    return match.group(1) if match else None


async def run(ctx: ScanContext) -> list[Finding]:
    home, base = ctx.facts.homepage, ctx.facts.base_url
    wordpress = [s for s in ctx.software if s.product == "wordpress"]
    if home is None or base is None or not wordpress:
        return []
    plugins, themes = discover(home.body)
    core_version = next((s.version for s in wordpress if s.version), None)
    semaphore = asyncio.Semaphore(4)

    async def inspect(kind: Kind, slug: str, hint: str | None) -> Component:
        async with semaphore:
            version = await _installed_version(ctx, base, kind, slug)
        if version is None and hint and hint != core_version:
            version = hint  # WordPress stamps core assets with its own version: not useful
        try:
            info = await ctx.options.wordpress(kind, slug)
        except Exception:
            info = None
        return Component(kind, slug, version, info)

    components = await asyncio.gather(
        *(inspect("plugin", slug, hint) for slug, hint in plugins.items()),
        *(inspect("theme", slug, hint) for slug, hint in themes.items()),
    )
    for component in components:
        ctx.add_software(
            DetectedSoftware(
                product=f"wp-{component.kind}:{component.slug}",
                name=component.label,
                version=component.version,
                source=T("Sayfa kaynağı (wp-content)"),
            )
        )
    return assess(list(components), ctx.options.current_date())


def _is_outdated(component: Component) -> bool:
    if not component.version or not component.info or not component.info.latest:
        return False
    installed, latest = parse_version(component.version), parse_version(component.info.latest)
    return installed is not None and latest is not None and installed < latest


def assess(components: list[Component], today: date) -> list[Finding]:
    findings: list[Finding] = []
    closed = [c for c in components if c.info and c.info.closed]
    for component in closed:
        info = component.info
        if info is None:  # pragma: no cover - filtered above
            continue
        security = info.closed_reason == "security-issue"
        when = info.last_updated
        findings.append(
            Finding(
                id=f"wordpress.closed.{component.slug}",
                category=Category.SOFTWARE,
                severity=Severity.HIGH if security else Severity.MEDIUM,
                title=T(_CLOSED_TITLE[component.kind, security], name=component.name),
                description=(
                    T("Kaldırılan eklentiler artık güncelleme almaz; bilinen açıkları kapatılmaz.")
                    + (
                        T(" Bu eklenti bir güvenlik açığı nedeniyle kaldırıldı.")
                        if security
                        else ""
                    )
                ),
                recommendation=(
                    T(
                        "Eklentiyi devre dışı bırakıp silin ve güncel, bakımı süren bir "
                        "alternatifle değiştirin."
                    )
                ),
                details={
                    N_("Eklenti"): component.slug,
                    N_("Kaldırılma nedeni"): info.closed_reason or "-",
                    N_("Kaldırılma tarihi"): when.strftime("%d.%m.%Y") if when else "-",
                },
            )
        )

    outdated = [c for c in components if c not in closed and _is_outdated(c)]
    if outdated:
        findings.append(
            Finding(
                id="wordpress.outdated",
                category=Category.SOFTWARE,
                severity=Severity.MEDIUM,
                title=T("{n} WordPress eklentisi/teması güncel değil", n=len(outdated)),
                description=(
                    T(
                        "Güncellenmemiş eklentiler WordPress sitelerinin ele geçirilmesinin en "
                        "sık nedenidir; açıkları yayınlandıktan birkaç gün sonra otomatik "
                        "saldırılar başlar."
                    )
                ),
                recommendation=_UPDATE_HINT,
                details={c.name: f"{c.version} → {c.info.latest}" for c in outdated if c.info},
            )
        )

    abandoned = [
        c
        for c in components
        if c not in closed
        and c.info
        and c.info.last_updated
        and today - c.info.last_updated > ABANDONED_AFTER
    ]
    if abandoned:
        findings.append(
            Finding(
                id="wordpress.abandoned",
                category=Category.SOFTWARE,
                severity=Severity.LOW,
                title=T("{n} eklenti/tema 2 yıldır güncelleme almıyor", n=len(abandoned)),
                description=(
                    T(
                        "Geliştiricisi tarafından bırakılmış olabilir; yeni bir açık bulunursa "
                        "düzeltilmeyecektir."
                    )
                ),
                recommendation=T("Bakımı süren bir alternatife geçmeyi planlayın."),
                details={
                    c.name: T(
                        "Son güncelleme: {last_updated:%d.%m.%Y}", last_updated=c.info.last_updated
                    )
                    for c in abandoned
                    if c.info and c.info.last_updated
                },
            )
        )

    current = [
        c for c in components if c.info and not c.info.closed and c.version and c not in outdated
    ]
    if current:
        findings.append(
            Finding(
                id="wordpress.current",
                category=Category.SOFTWARE,
                severity=Severity.PASS,
                title=T("{n} WordPress eklentisi/teması güncel", n=len(current)),
                details={c.name: c.version or "-" for c in current},
            )
        )
    return findings
