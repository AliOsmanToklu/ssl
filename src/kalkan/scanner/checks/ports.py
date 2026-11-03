"""TCP connect scan of ports that commonly put small businesses at risk.

This is deliberately a short, curated list (not a full nmap sweep): each port has
a plain-language explanation and a concrete fix, and the scan finishes in a few
seconds with a handful of connections.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass

from kalkan.i18n import N_, LocalizedValue, T
from kalkan.scanner import fingerprint
from kalkan.scanner.context import ScanContext
from kalkan.scanner.models import Category, Finding, Severity

NAME = "ports"


@dataclass(frozen=True, slots=True)
class PortRule:
    port: int
    service: LocalizedValue
    severity: Severity
    risk: LocalizedValue  # why it is dangerous
    fix: LocalizedValue
    banner: bool = False  # the service greets first; read it for fingerprinting


_DB_FIX = T(
    "Veritabanı portunu internete kapatın: yalnızca aynı sunucudaki uygulama "
    "(localhost) veya belirli IP adresleri erişebilsin. Hosting firmanızdan "
    "güvenlik duvarı kuralı isteyin."
)
_PANEL_FIX = T(
    "Yönetim panelini mümkünse yalnızca ofis IP adresinize açın, güçlü şifre "
    "ve iki aşamalı doğrulama kullanın."
)

PORT_RULES: tuple[PortRule, ...] = (
    PortRule(
        21,
        "FTP",
        Severity.MEDIUM,
        T("FTP dosyaları ve şifreleri şifrelemeden gönderir; şifreniz ağda okunabilir."),
        T("FTP yerine SFTP veya FTPS kullanın ve FTP servisini kapatın."),
        banner=True,
    ),
    PortRule(
        22,
        T("SSH (sunucu yönetimi)"),
        Severity.LOW,
        T("Sunucu yönetim kapısı internete açık ve sürekli şifre denemesi saldırısı alır."),
        T(
            "SSH'ı yalnızca belirli IP'lere açın, şifre yerine anahtar ile girişe "
            "geçin ve fail2ban gibi bir koruma kurun."
        ),
        banner=True,
    ),
    PortRule(
        23,
        "Telnet",
        Severity.HIGH,
        T("Telnet tamamen şifresizdir; yönetici şifreleri ağda düz metin olarak geçer."),
        T("Telnet servisini kapatın, gerekiyorsa SSH kullanın."),
    ),
    PortRule(
        25,
        "SMTP (e-posta)",
        Severity.INFO,
        T("E-posta sunucusu. Kendi e-posta sunucunuz varsa normaldir."),
        T("Bu sunucu e-posta göndermiyorsa servisi kapatın."),
        banner=True,
    ),
    PortRule(
        110,
        T("POP3 (şifresiz e-posta)"),
        Severity.LOW,
        T("E-postalar ve şifreler şifrelenmeden indirilebiliyor."),
        T(
            "E-posta programlarınızı şifreli POP3S (995) kullanacak şekilde ayarlayın "
            "ve 110 portunu kapatın."
        ),
    ),
    PortRule(
        143,
        T("IMAP (şifresiz e-posta)"),
        Severity.LOW,
        T("E-postalar ve şifreler şifrelenmeden okunabiliyor."),
        T(
            "E-posta programlarınızı şifreli IMAPS (993) kullanacak şekilde ayarlayın "
            "ve 143 portunu kapatın."
        ),
    ),
    PortRule(
        139,
        T("NetBIOS (Windows dosya paylaşımı)"),
        Severity.HIGH,
        T("Windows dosya paylaşımı internete açık; dosya ve şifre bilgileri sızabilir."),
        T("Bu portu güvenlik duvarında hemen kapatın."),
    ),
    PortRule(
        445,
        T("SMB (Windows dosya paylaşımı)"),
        Severity.CRITICAL,
        T("WannaCry gibi fidye yazılımları tam olarak bu port üzerinden yayıldı."),
        T(
            "SMB'yi internete asla açmayın; güvenlik duvarından hemen kapatın. "
            "Uzaktan erişim gerekiyorsa VPN kullanın."
        ),
    ),
    PortRule(
        1433,
        "Microsoft SQL Server",
        Severity.HIGH,
        T(
            "Veritabanınız internetten doğrudan erişilebilir; şifre deneme ve veri "
            "hırsızlığı riski var."
        ),
        _DB_FIX,
    ),
    PortRule(
        1521,
        T("Oracle veritabanı"),
        Severity.HIGH,
        T("Veritabanınız internetten doğrudan erişilebilir."),
        _DB_FIX,
    ),
    PortRule(
        1723,
        "PPTP VPN",
        Severity.MEDIUM,
        T("PPTP eski ve kırılmış bir VPN yöntemidir; trafik çözülebilir."),
        T("WireGuard, OpenVPN veya IPsec/IKEv2 tabanlı bir VPN'e geçin."),
    ),
    PortRule(
        2082,
        T("cPanel (şifresiz)"),
        Severity.LOW,
        T("Hosting yönetim paneli şifresiz bağlantıyla açık."),
        _PANEL_FIX,
    ),
    PortRule(
        2083,
        "cPanel",
        Severity.INFO,
        T("Hosting yönetim paneli internete açık (paylaşımlı hostingde normaldir)."),
        _PANEL_FIX,
    ),
    PortRule(
        2086,
        T("WHM (şifresiz)"),
        Severity.LOW,
        T("Sunucu yönetim paneli şifresiz bağlantıyla açık."),
        _PANEL_FIX,
    ),
    PortRule(2087, "WHM", Severity.INFO, T("Sunucu yönetim paneli internete açık."), _PANEL_FIX),
    PortRule(
        2222, "DirectAdmin", Severity.INFO, T("Hosting yönetim paneli internete açık."), _PANEL_FIX
    ),
    PortRule(
        2375,
        T("Docker API (şifresiz)"),
        Severity.CRITICAL,
        T("Docker yönetim arayüzü şifresiz açık; sunucunun tamamı ele geçirilebilir."),
        T("Docker API'sini internete kapatın veya TLS ile koruyun (2376)."),
    ),
    PortRule(
        3306,
        "MySQL / MariaDB",
        Severity.HIGH,
        T(
            "Veritabanınız internetten doğrudan erişilebilir; şifre deneme ve veri "
            "hırsızlığı riski var."
        ),
        _DB_FIX,
        banner=True,
    ),
    PortRule(
        3389,
        T("Uzak Masaüstü (RDP)"),
        Severity.HIGH,
        T(
            "İnternete açık Uzak Masaüstü, KOBİ'lere yönelik fidye yazılımı "
            "saldırılarında en sık kullanılan giriş kapısıdır."
        ),
        T(
            "RDP'yi internete kapatın ve yalnızca VPN üzerinden erişin. Mümkün "
            "değilse Ağ Düzeyinde Kimlik Doğrulama (NLA), güçlü şifre ve hesap "
            "kilitleme kullanın."
        ),
    ),
    PortRule(
        5432,
        "PostgreSQL",
        Severity.HIGH,
        T("Veritabanınız internetten doğrudan erişilebilir."),
        _DB_FIX,
    ),
    PortRule(
        5900,
        T("VNC (uzak masaüstü)"),
        Severity.HIGH,
        T("VNC çoğu zaman zayıf şifreyle korunur ve bilgisayarın tam kontrolünü verir."),
        T("VNC'yi internete kapatın ve yalnızca VPN üzerinden kullanın."),
    ),
    PortRule(
        5984,
        "CouchDB",
        Severity.CRITICAL,
        T("Bu veritabanı sıklıkla şifresiz kurulur; verileriniz herkes tarafından okunabilir."),
        _DB_FIX,
    ),
    PortRule(
        6379,
        "Redis",
        Severity.CRITICAL,
        T(
            "Redis varsayılan olarak şifresizdir; verileriniz okunabilir ve sunucu "
            "ele geçirilebilir."
        ),
        _DB_FIX,
    ),
    PortRule(
        8080,
        "Alternatif web servisi (8080)",
        Severity.LOW,
        T(
            "Ana siteniz dışında bir web servisi açık; genellikle test sitesi veya "
            "yönetim paneli olur ve unutulur."
        ),
        T("Bu servise ihtiyacınız yoksa kapatın, varsa şifreyle koruyun."),
    ),
    PortRule(
        8443,
        "Alternatif HTTPS / Plesk",
        Severity.INFO,
        T("Ek bir HTTPS servisi veya Plesk paneli açık."),
        _PANEL_FIX,
    ),
    PortRule(
        8888,
        "Alternatif web servisi (8888)",
        Severity.LOW,
        T("Genellikle test, geliştirme veya yönetim arayüzü olur ve unutulur."),
        T("Bu servise ihtiyacınız yoksa kapatın, varsa şifreyle koruyun."),
    ),
    PortRule(
        9200,
        "Elasticsearch",
        Severity.CRITICAL,
        T("Elasticsearch varsayılan olarak şifresiz gelebilir; tüm veriler okunabilir."),
        _DB_FIX,
    ),
    PortRule(10000, "Webmin", Severity.LOW, T("Sunucu yönetim paneli internete açık."), _PANEL_FIX),
    PortRule(
        11211,
        "Memcached",
        Severity.CRITICAL,
        T("Memcached şifresizdir; veriler okunabilir ve DDoS saldırılarında kullanılabilir."),
        _DB_FIX,
    ),
    PortRule(
        27017,
        "MongoDB",
        Severity.CRITICAL,
        T(
            "MongoDB sıklıkla şifresiz kurulur; binlerce firma veritabanı bu yolla "
            "fidye yazılımcıların eline geçti."
        ),
        _DB_FIX,
    ),
)

WEB_PORTS = (80, 443)
DEFAULT_PORTS = tuple(sorted({*WEB_PORTS, *(rule.port for rule in PORT_RULES)}))
_RULES = {rule.port: rule for rule in PORT_RULES}

# Ports a CDN edge answers on for every customer; they say nothing about the origin.
_CDN_EDGE_PORTS = {
    80,
    443,
    2052,
    2053,
    2082,
    2083,
    2086,
    2087,
    2095,
    2096,
    8080,
    8443,
    8880,
}


async def _probe(ip: str, port: int, wait: float, read_banner: bool) -> tuple[bool, bytes]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), wait)
    except (OSError, TimeoutError):
        return False, b""
    banner = b""
    try:
        if read_banner:
            try:
                banner = await asyncio.wait_for(reader.read(512), wait)
            except (OSError, TimeoutError):
                banner = b""
    finally:
        writer.close()
        with contextlib.suppress(OSError, TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), 1)
    return True, banner


async def scan_ports(ip: str, ports: tuple[int, ...], wait: float) -> list[tuple[int, bool, bytes]]:
    """Connect to each port; returns (port, is_open, banner) in input order."""
    semaphore = asyncio.Semaphore(32)

    async def probe(port: int) -> tuple[int, bool, bytes]:
        rule = _RULES.get(port)
        async with semaphore:
            is_open, banner = await _probe(ip, port, wait, bool(rule and rule.banner))
        return port, is_open, banner

    return list(await asyncio.gather(*(probe(p) for p in ports)))


def assess(
    open_ports: list[int], *, cdn: str | None, scanned: int
) -> tuple[list[Finding], list[LocalizedValue]]:
    """Turn the list of open ports into findings and report notes."""
    notes: list[LocalizedValue] = []
    if cdn:
        notes.append(
            T(
                (
                    "Siteniz {cdn} arkasında. Port taraması {cdn} sunucularını gösterir; asıl "
                    "sunucunuzun portları bu taramada görünmez."
                ),
                cdn=cdn,
            )
        )
    reportable = [p for p in open_ports if p in _RULES and not (cdn and p in _CDN_EDGE_PORTS)]
    findings = [_finding(_RULES[p]) for p in reportable]
    if not any(f.severity.is_problem for f in findings):
        findings.append(
            Finding(
                id="ports.ok",
                category=Category.PORTS,
                severity=Severity.PASS,
                title=(
                    T("Riskli bir port görünmüyor (site {cdn} arkasında)", cdn=cdn)
                    if cdn
                    else T("Riskli bir port internete açık değil")
                ),
                details={
                    N_("Taranan port sayısı"): str(scanned),
                    N_("Açık portlar"): ", ".join(map(str, open_ports)) or "-",
                },
            )
        )
    elif not cdn:
        notes.append(
            T(
                "Paylaşımlı hosting kullanıyorsanız açık portlar hosting firmanıza ait "
                "olabilir; bu durumda bulguları hosting firmanıza iletin."
            )
        )
    return findings, notes


async def run(ctx: ScanContext) -> list[Finding]:
    ports = ctx.options.ports or DEFAULT_PORTS
    results = await scan_ports(ctx.target.primary_ip, ports, ctx.options.port_timeout)
    open_ports = sorted(port for port, is_open, _ in results if is_open)
    ctx.facts.open_ports = open_ports
    for port, is_open, banner in results:
        if is_open and banner:
            for item in fingerprint.from_banner(port, banner):
                ctx.add_software(item)
    findings, notes = assess(open_ports, cdn=ctx.facts.cdn, scanned=len(ports))
    ctx.notes.extend(notes)
    return findings


def _finding(rule: PortRule) -> Finding:
    severity = rule.severity
    if severity is Severity.INFO:
        title = T("{service} açık (port {port})", service=rule.service, port=rule.port)
    else:
        title = T("{service} internete açık (port {port})", service=rule.service, port=rule.port)
    return Finding(
        id=f"ports.open_{rule.port}",
        category=Category.PORTS,
        severity=severity,
        title=title,
        description=rule.risk,
        recommendation=rule.fix,
        details={N_("Port"): str(rule.port), N_("Servis"): rule.service},
    )
