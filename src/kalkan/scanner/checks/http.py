"""Web server configuration: HTTPS redirect, security headers, cookies, banners."""

from __future__ import annotations

import asyncio
import re
from html.parser import HTMLParser
from http.cookies import SimpleCookie

import httpx

from kalkan.i18n import N_, LocalizedValue, T
from kalkan.scanner import fingerprint
from kalkan.scanner.context import ScanContext
from kalkan.scanner.http_client import FetchError, FetchResult
from kalkan.scanner.models import Category, DetectedSoftware, Finding, Severity

NAME = "http"

# header -> (short Turkish name, why it matters)
_SECURITY_HEADERS = {
    "content-security-policy": (
        "Content-Security-Policy",
        T("sitenize zararlı kod enjekte edilmesini (XSS) zorlaştırır"),
    ),
    "x-frame-options": (
        "X-Frame-Options",
        T("sitenizin başka sitelerde gizlice çerçeve içinde açılmasını (clickjacking) engeller"),
    ),
    "x-content-type-options": (
        "X-Content-Type-Options",
        T("tarayıcının dosya türünü yanlış yorumlayıp zararlı içerik çalıştırmasını engeller"),
    ),
    "referrer-policy": (
        "Referrer-Policy",
        T("ziyaretçilerin hangi sayfadan geldiği bilgisinin dışarı sızmasını sınırlar"),
    ),
}


def detect_cdn(headers: httpx.Headers) -> str | None:
    server = headers.get("server", "").lower()
    via = headers.get("via", "").lower()
    if "cf-ray" in headers or server == "cloudflare":
        return "Cloudflare"
    if "x-amz-cf-id" in headers or "cloudfront" in via:
        return "Amazon CloudFront"
    if server.startswith("akamai") or "x-akamai-transformed" in headers:
        return "Akamai"
    if "x-fastly-request-id" in headers or (
        headers.get("x-served-by", "").startswith("cache-") and "varnish" in via
    ):
        return "Fastly"
    if "x-sucuri-id" in headers:
        return "Sucuri"
    return None


async def _try_get(ctx: ScanContext, url: str) -> FetchResult | None:
    try:
        return await ctx.http.get(url, max_redirects=5)
    except FetchError:
        return None


async def run(ctx: ScanContext) -> list[Finding]:
    host = f"[{ctx.target.hostname}]" if ":" in ctx.target.hostname else ctx.target.hostname
    https_home, http_home = await asyncio.gather(
        _try_get(ctx, f"https://{host}/"), _try_get(ctx, f"http://{host}/")
    )
    ctx.facts.http_ok = http_home is not None

    homepage = https_home or http_home
    if homepage is None:
        ctx.notes.append(T("Web sitesine HTTP veya HTTPS üzerinden ulaşılamadı."))
        return [
            Finding(
                id="http.unreachable",
                category=Category.HTTP,
                severity=Severity.INFO,
                title=T("Web sitesine ulaşılamadı"),
                description=(
                    T(
                        "Site, tarama sırasında yanıt vermedi; web sunucusu ayarları "
                        "kontrol edilemedi."
                    )
                ),
            )
        ]
    ctx.facts.homepage = homepage
    ctx.facts.cdn = detect_cdn(homepage.headers)
    _collect_software(ctx, homepage)

    findings: list[Finding] = []
    if https_home is not None and http_home is not None:
        findings.append(_redirect_finding(http_home))
    on_https = homepage.url.startswith("https://")
    if on_https:
        findings.append(_hsts_finding(homepage))
    findings.extend(_header_findings(homepage))
    findings.extend(_disclosure_findings(homepage))
    findings.extend(_cookie_findings(homepage, on_https))
    if on_https:
        findings.extend(mixed_content_findings(homepage))
    findings.append(await _security_txt_finding(ctx, homepage.origin))
    return findings


def _collect_software(ctx: ScanContext, page: FetchResult) -> None:
    for header in ("server", "x-powered-by"):
        for value in page.header_values(header):
            for item in fingerprint.from_header(header.title(), value):
                ctx.add_software(item)
    aspnet = page.headers.get("x-aspnet-version")
    if aspnet:
        ctx.add_software(
            DetectedSoftware("aspnet", "ASP.NET", aspnet, T("HTTP başlığı (X-AspNet-Version)"))
        )
    if "html" in page.headers.get("content-type", "html"):
        for item in fingerprint.from_html(page.body):
            ctx.add_software(item)


def _redirect_finding(http_home: FetchResult) -> Finding:
    if http_home.url.startswith("https://"):
        return Finding(
            id="http.redirect_ok",
            category=Category.HTTP,
            severity=Severity.PASS,
            title=T("Ziyaretçiler otomatik olarak HTTPS'e yönlendiriliyor"),
        )
    return Finding(
        id="http.no_https_redirect",
        category=Category.HTTP,
        severity=Severity.MEDIUM,
        title=T("Siteniz ziyaretçileri şifreli bağlantıya yönlendirmiyor"),
        description=(
            T(
                "Adresinizi 'http://' ile yazan ziyaretçiler şifresiz sayfada kalıyor; "
                "SSL sertifikanız olduğu halde bu ziyaretçiler korunmuyor."
            )
        ),
        recommendation=(
            T(
                "Hosting panelinizde 'HTTPS'e zorla / Force HTTPS' seçeneğini açın veya "
                "sunucuya http'den https'e kalıcı (301) yönlendirme ekleyin."
            )
        ),
        details={N_("Adres"): http_home.url, N_("Yanıt kodu"): str(http_home.status)},
    )


def _hsts_finding(page: FetchResult) -> Finding:
    value = page.headers.get("strict-transport-security")
    if value:
        match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
        max_age = int(match.group(1)) if match else 0
        if max_age >= 15_552_000:  # 180 days
            return Finding(
                id="http.hsts_ok",
                category=Category.HTTP,
                severity=Severity.PASS,
                title=T("Tarayıcılara yalnızca HTTPS kullanmaları söyleniyor (HSTS)"),
            )
        return Finding(
            id="http.hsts_short",
            category=Category.HTTP,
            severity=Severity.LOW,
            title=T("HTTPS zorlama (HSTS) süresi çok kısa"),
            description=T("HSTS etkin ancak süresi 6 aydan kısa, koruma kısa sürede kalkıyor."),
            recommendation=(
                T("Strict-Transport-Security başlığında max-age değerini en az 15552000 yapın.")
            ),
            details={N_("Strict-Transport-Security"): value},
        )
    return Finding(
        id="http.hsts_missing",
        category=Category.HTTP,
        severity=Severity.LOW,
        title=T("Tarayıcılara 'her zaman HTTPS kullan' talimatı verilmiyor (HSTS)"),
        description=(
            T(
                "HSTS olmadan, halka açık Wi-Fi gibi ağlarda bir saldırgan ziyaretçiyi "
                "sitenizin şifresiz sürümüne düşürebilir."
            )
        ),
        recommendation=(
            T(
                "Sunucunuza 'Strict-Transport-Security: max-age=31536000' başlığını "
                "ekleyin (Cloudflare kullanıyorsanız SSL/TLS > Edge Certificates > HSTS)."
            )
        ),
    )


def _header_findings(page: FetchResult) -> list[Finding]:
    if "html" not in page.headers.get("content-type", "html"):
        return []
    headers = page.headers
    missing = dict(_SECURITY_HEADERS)
    for name in list(missing):
        if name in headers:
            missing.pop(name)
    csp = headers.get("content-security-policy", "")
    if "frame-ancestors" in csp.lower():
        missing.pop("x-frame-options", None)
    if headers.get("x-content-type-options", "").lower().strip() != "nosniff":
        missing.setdefault("x-content-type-options", _SECURITY_HEADERS["x-content-type-options"])
    if not missing:
        return [
            Finding(
                id="http.security_headers_ok",
                category=Category.HTTP,
                severity=Severity.PASS,
                title=T("Tarayıcı güvenlik başlıkları ayarlanmış"),
            )
        ]
    names = [label for label, _ in missing.values()]
    return [
        Finding(
            id="http.security_headers_missing",
            category=Category.HTTP,
            severity=Severity.LOW,
            title=T("{n} tarayıcı güvenlik başlığı eksik", n=len(names)),
            description=(
                T(
                    "Güvenlik başlıkları, ziyaretçilerin tarayıcısına sitenizi nasıl "
                    "koruyacağını söyler. Tek başına acil değildir ancak saldırıları "
                    "zorlaştıran ücretsiz bir önlemdir."
                )
            ),
            recommendation=(
                T(
                    "Web geliştiricinizden veya hosting firmanızdan şu başlıkları eklemesini "
                    "isteyin: "
                )
                + ", ".join(names)
                + T(". WordPress için bu iş güvenlik eklentileriyle de yapılabilir.")
            ),
            details={label: T("Eksik: {why}", why=why) for label, why in missing.values()},
        )
    ]


def _disclosure_findings(page: FetchResult) -> list[Finding]:
    leaked: dict[str, str] = {}
    for header in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        for value in page.header_values(header):
            if header.startswith("x-aspnet") or fingerprint.server_version_disclosed(value):
                leaked[header.title()] = value
    if not leaked:
        return []
    return [
        Finding(
            id="http.version_disclosure",
            category=Category.HTTP,
            severity=Severity.LOW,
            title=T("Sunucu, kullandığı yazılım sürümlerini herkese gösteriyor"),
            description=(
                T(
                    "Saldırganlar bu bilgiyle sunucunuzdaki bilinen açıkları hızlıca "
                    "arayabilir. Sürümleri gizlemek açığı kapatmaz ama hedef olmayı "
                    "zorlaştırır."
                )
            ),
            recommendation=(
                T(
                    "Apache için 'ServerTokens Prod' ve 'ServerSignature Off', nginx için "
                    "'server_tokens off', PHP için php.ini'de 'expose_php = Off' ayarını "
                    "yapın."
                )
            ),
            details=leaked,
        )
    ]


def _cookie_findings(page: FetchResult, on_https: bool) -> list[Finding]:
    problems: dict[str, LocalizedValue] = {}
    for header in page.header_values("set-cookie"):
        cookie: SimpleCookie = SimpleCookie()
        try:
            cookie.load(header)
        except Exception:  # noqa: S112 - a malformed cookie is skipped, not fatal
            continue
        for name, morsel in cookie.items():
            missing: list[str] = []
            if on_https and not morsel["secure"]:
                missing.append("Secure")
            if not morsel["httponly"]:
                missing.append("HttpOnly")
            if not morsel["samesite"]:
                missing.append("SameSite")
            if missing:
                problems[name] = T("Eksik: {flags}", flags=", ".join(missing))
    if not problems:
        return []
    return [
        Finding(
            id="http.cookie_flags",
            category=Category.HTTP,
            severity=Severity.LOW,
            title=T("Çerezlerde güvenlik ayarları eksik"),
            description=(
                T(
                    "Oturum çerezleri doğru işaretlenmezse, zararlı bir betik veya şifresiz "
                    "bağlantı üzerinden çalınabilir ve hesaplar ele geçirilebilir."
                )
            ),
            recommendation=(
                T(
                    "Çerezleri 'Secure', 'HttpOnly' ve 'SameSite=Lax' ayarlarıyla gönderin "
                    "(PHP için php.ini: session.cookie_secure, session.cookie_httponly)."
                )
            ),
            details=problems,
        )
    ]


# --- mixed content ----------------------------------------------------------

# Browsers block these when loaded over http:// from an https:// page (the site breaks).
_ACTIVE = {"script", "iframe", "frame", "embed", "object", "stylesheet"}
# These still load but trigger a "not fully secure" warning.
_PASSIVE = {"img", "audio", "video", "source", "icon"}


class _ResourceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.resources: list[tuple[str, str]] = []  # (kind, url)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): (value or "").strip() for name, value in attrs}
        kind, url = tag, ""
        if tag in ("script", "iframe", "frame", "embed", "img", "audio", "video", "source"):
            url = values.get("src", "")
        elif tag == "object":
            url = values.get("data", "")
        elif tag == "form":
            url = values.get("action", "")
        elif tag == "link":
            rel = values.get("rel", "").lower().split()
            kind = "stylesheet" if "stylesheet" in rel else "icon" if "icon" in rel else ""
            url = values.get("href", "")
        if kind and url.lower().startswith("http://"):
            self.resources.append((kind, url))


def mixed_content_findings(page: FetchResult) -> list[Finding]:
    if "html" not in page.headers.get("content-type", "html"):
        return []
    parser = _ResourceParser()
    try:
        parser.feed(page.body)
        parser.close()
    except Exception:
        return []
    active = [url for kind, url in parser.resources if kind in _ACTIVE]
    passive = [url for kind, url in parser.resources if kind in _PASSIVE]
    forms = [url for kind, url in parser.resources if kind == "form"]
    findings: list[Finding] = []
    if forms:
        findings.append(
            Finding(
                id="http.insecure_form",
                category=Category.HTTP,
                severity=Severity.MEDIUM,
                title=T("Sayfadaki bir form bilgileri şifresiz gönderiyor"),
                description=(
                    T(
                        "Sayfanız şifreli olsa da formun gönderildiği adres 'http://' ile "
                        "başlıyor; ziyaretçilerin yazdığı bilgiler (iletişim, şifre) şifresiz "
                        "iletilir."
                    )
                ),
                recommendation=T(
                    "Formun 'action' adresini https:// ile başlayacak şekilde düzeltin."
                ),
                details={f"Form {i}": url for i, url in enumerate(forms[:5], start=1)},
            )
        )
    if active or passive:
        examples = (active + passive)[:5]
        findings.append(
            Finding(
                id="http.mixed_content",
                category=Category.HTTP,
                severity=Severity.MEDIUM if active else Severity.LOW,
                title=T("Sayfanızdaki bazı dosyalar şifresiz (http://) yükleniyor"),
                description=(
                    T(
                        "Tarayıcılar şifresiz yüklenen betik ve stil dosyalarını "
                        "engeller (site düzgün görünmeyebilir); şifresiz resimler için "
                        "de 'tam güvenli değil' uyarısı verir."
                    )
                    if active
                    else T(
                        "Şifresiz yüklenen resimler yüzünden tarayıcı adres çubuğunda 'tam "
                        "güvenli değil' uyarısı gösterebilir."
                    )
                ),
                recommendation=(
                    T(
                        "Sayfadaki bağlantıları https:// ile değiştirin. WordPress'te 'Better "
                        "Search Replace' gibi bir eklentiyle veritabanındaki http:// adresleri "
                        "toplu güncellenebilir."
                    )
                ),
                details={
                    N_("Engellenen (betik/stil)"): str(len(active)),
                    N_("Uyarı veren (resim/medya)"): str(len(passive)),
                    **{f"URL {i}": url for i, url in enumerate(examples, start=1)},
                },
            )
        )
    return findings


# --- security.txt -----------------------------------------------------------


async def _security_txt_finding(ctx: ScanContext, origin: str) -> Finding:
    try:
        page = await ctx.http.get(f"{origin}/.well-known/security.txt", max_body=32 * 1024)
    except FetchError:
        page = None
    if (
        page is not None
        and page.status == 200
        and "<html" not in page.body[:500].lower()
        and re.search(r"^\s*contact\s*:", page.body, re.I | re.M)
    ):
        return Finding(
            id="http.security_txt_ok",
            category=Category.HTTP,
            severity=Severity.PASS,
            title=T("Güvenlik iletişim dosyası (security.txt) yayında"),
        )
    return Finding(
        id="http.security_txt_missing",
        category=Category.HTTP,
        severity=Severity.INFO,
        title=T("Güvenlik iletişim dosyası (security.txt) yok"),
        description=(
            T(
                "Sitenizde bir güvenlik açığı bulan kişilerin size nasıl ulaşacağını "
                "bildiren standart bir dosyadır; açıkların sessizce satılması yerine size "
                "bildirilmesini sağlar."
            )
        ),
        recommendation=(
            T(
                "Sitenize /.well-known/security.txt dosyası ekleyin; içine en az "
                "'Contact: mailto:guvenlik@firmaniz.com' ve 'Expires:' satırlarını yazın."
            )
        ),
    )
