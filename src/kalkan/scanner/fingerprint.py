"""Extract product/version pairs from HTTP headers, HTML and service banners."""

from __future__ import annotations

import re
from html.parser import HTMLParser

from kalkan.i18n import LocalizedValue, T
from kalkan.scanner.models import DetectedSoftware

PRODUCT_NAMES = {
    "apache": "Apache HTTP Server",
    "nginx": "nginx",
    "iis": "Microsoft IIS",
    "litespeed": "LiteSpeed",
    "openresty": "OpenResty",
    "tomcat": "Apache Tomcat",
    "php": "PHP",
    "openssl": "OpenSSL",
    "aspnet": "ASP.NET",
    "express": "Express (Node.js)",
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "openssh": "OpenSSH",
    "proftpd": "ProFTPD",
    "vsftpd": "vsftpd",
    "pure-ftpd": "Pure-FTPd",
    "filezilla-server": "FileZilla Server",
    "exim": "Exim",
    "postfix": "Postfix",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "jquery": "jQuery",
    "bootstrap": "Bootstrap",
    "angularjs": "AngularJS",
    "vue": "Vue.js",
}

# token in a Server / X-Powered-By header -> product key
_HEADER_TOKENS = {
    "apache": "apache",
    "nginx": "nginx",
    "microsoft-iis": "iis",
    "litespeed": "litespeed",
    "openresty": "openresty",
    "apache-coyote": "tomcat",
    "php": "php",
    "openssl": "openssl",
    "asp.net": "aspnet",
    "express": "express",
}

# Distributions that backport security fixes without bumping upstream versions
_DISTRO_PATTERNS = [
    (re.compile(r"ubuntu", re.I), "Ubuntu"),
    (re.compile(r"debian|deb\d+u\d+|~deb\d+", re.I), "Debian"),
    (re.compile(r"red ?hat|rhel|\.el\d", re.I), "Red Hat"),
    (re.compile(r"centos", re.I), "CentOS"),
    (re.compile(r"almalinux", re.I), "AlmaLinux"),
    (re.compile(r"rocky", re.I), "Rocky Linux"),
    (re.compile(r"amazon", re.I), "Amazon Linux"),
    (re.compile(r"suse", re.I), "SUSE"),
    (re.compile(r"-fips\b", re.I), "Red Hat"),
]

_TOKEN_RE = re.compile(r"([A-Za-z][A-Za-z0-9.+_-]*)(?:/([0-9][^\s;,()]*))?")


def detect_distro(text: str) -> str | None:
    for pattern, name in _DISTRO_PATTERNS:
        if pattern.search(text):
            return name
    return None


def _make(
    product: str, version: str | None, source: LocalizedValue, distro: str | None
) -> DetectedSoftware:
    return DetectedSoftware(
        product=product,
        name=PRODUCT_NAMES.get(product, product),
        version=version,
        source=source,
        distro=distro,
    )


def from_header(header: str, value: str) -> list[DetectedSoftware]:
    """Parse ``Server``/``X-Powered-By`` style values like "Apache/2.4.41 (Ubuntu) PHP/8.1.2"."""
    distro = detect_distro(value)
    found: list[DetectedSoftware] = []
    source = T("HTTP başlığı ({header})", header=header)
    for token, version in _TOKEN_RE.findall(value):
        product = _HEADER_TOKENS.get(token.lower())
        if product is None:
            continue
        found.append(_make(product, version or None, source, distro))
    return found


def server_version_disclosed(value: str) -> bool:
    return bool(re.search(r"/\d", value))


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.generators: list[str] = []
        self.assets: list[str] = []  # script and stylesheet URLs

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {k.lower(): (v or "") for k, v in attrs}
        if tag == "meta":
            if attributes.get("name", "").lower() == "generator" and attributes.get("content"):
                self.generators.append(attributes["content"])
        elif tag == "script" and attributes.get("src"):
            self.assets.append(attributes["src"])
        elif tag == "link" and "stylesheet" in attributes.get("rel", "").lower():
            self.assets.append(attributes.get("href", ""))


_V = r"(\d+\.\d+\.\d+)"
# Version patterns in asset URLs: file names, CDN paths and WordPress' ?ver= for jQuery.
# Bootstrap's ?ver= is left out on purpose: themes put their own version there.
_LIBRARIES: list[tuple[str, list[re.Pattern[str]]]] = [
    (
        "jquery",
        [
            re.compile(rf"/jquery[.-]{_V}(?:\.slim)?(?:\.min)?\.js"),
            re.compile(rf"/jquery/{_V}/jquery(?:\.slim)?(?:\.min)?\.js"),
            re.compile(rf"/jquery@{_V}/"),
            re.compile(rf"/jquery(?:\.min)?\.js\?ver={_V}"),
        ],
    ),
    (
        "bootstrap",
        [
            re.compile(rf"/bootstrap@{_V}/"),
            re.compile(rf"/bootstrap/{_V}/"),
            re.compile(rf"/bootstrap[.-]{_V}(?:\.bundle)?(?:\.min)?\.(?:js|css)"),
        ],
    ),
    (
        "angularjs",
        [
            re.compile(r"/angular(?:\.js|js)/(1\.\d+\.\d+)/"),
            re.compile(r"/angular@(1\.\d+\.\d+)/"),
            re.compile(r"/angular[.-](1\.\d+\.\d+)(?:\.min)?\.js"),
        ],
    ),
    (
        "vue",
        [
            re.compile(rf"/vue@{_V}/"),
            re.compile(rf"/vue/{_V}/vue"),
            re.compile(rf"/vue[.-]{_V}(?:\.min)?\.js"),
        ],
    ),
]


def libraries_from_assets(urls: list[str]) -> list[DetectedSoftware]:
    found: list[DetectedSoftware] = []
    for product, patterns in _LIBRARIES:
        for url in urls:
            lowered = url.lower()
            match = next((m for p in patterns if (m := p.search(lowered))), None)
            if match:
                found.append(
                    _make(product, match.group(1), T("Sayfa kaynağı (JavaScript/CSS)"), None)
                )
                break
    return found


_GENERATORS = [
    (re.compile(r"WordPress\s*([\d.]+)?", re.I), "wordpress"),
    (re.compile(r"Joomla!?\s*([\d.]+)?", re.I), "joomla"),
    (re.compile(r"Drupal\s*([\d.]+)?", re.I), "drupal"),
]
_WP_VERSION_RE = re.compile(r"/wp-includes/[^\"'>]+\?ver=(\d+\.\d+(?:\.\d+)?)")
_WP_ASSET_RE = re.compile(r"/wp-(?:content|includes)/")


def from_html(body: str) -> list[DetectedSoftware]:
    parser = _PageParser()
    try:
        parser.feed(body)
        parser.close()
    except Exception:
        parser.generators, parser.assets = [], []
    found: list[DetectedSoftware] = []
    for content in parser.generators:
        for pattern, product in _GENERATORS:
            match = pattern.search(content)
            if match:
                # A major-only version ("Drupal 7") is still judged when the database
                # tracks that product by major release.
                version = (match.group(1) or "").strip(".") or None
                found.append(_make(product, version, T("Sayfa kaynağı (generator etiketi)"), None))
                break
    if not any(s.product == "wordpress" for s in found) and _WP_ASSET_RE.search(body):
        match = _WP_VERSION_RE.search(body)
        found.append(
            _make(
                "wordpress",
                match.group(1) if match else None,
                T("Sayfa kaynağı (wp-includes)"),
                None,
            )
        )
    found.extend(libraries_from_assets(parser.assets))
    return found


_SSH_RE = re.compile(r"^SSH-[\d.]+-OpenSSH_([\w.]+)(.*)$", re.M)
_FTP_PATTERNS = [
    (re.compile(r"ProFTPD\s+([\d.]+[a-z]?)", re.I), "proftpd"),
    (re.compile(r"vsFTPd\s+([\d.]+)", re.I), "vsftpd"),
    (re.compile(r"Pure-FTPd", re.I), "pure-ftpd"),
    (re.compile(r"FileZilla Server\s*([\d.]+)?", re.I), "filezilla-server"),
]
_SMTP_PATTERNS = [
    (re.compile(r"Exim\s+([\d.]+)", re.I), "exim"),
    (re.compile(r"Postfix", re.I), "postfix"),
]


def from_banner(port: int, banner: bytes) -> list[DetectedSoftware]:
    """Fingerprint the greeting a service sends right after connecting."""
    if port in (3306, 3307):
        return _from_mysql_handshake(banner)
    text = banner.decode("latin-1", errors="replace")
    source = T("Port {port} karşılama mesajı", port=port)
    match = _SSH_RE.search(text)
    if match:
        rest = match.group(2)
        return [_make("openssh", match.group(1), source, detect_distro(rest))]
    patterns = _FTP_PATTERNS if port in (21, 990) else _SMTP_PATTERNS
    for pattern, product in patterns:
        match = pattern.search(text)
        if match:
            version = match.group(1) if match.groups() else None
            return [_make(product, version, source, detect_distro(text))]
    return []


def _from_mysql_handshake(packet: bytes) -> list[DetectedSoftware]:
    # 3-byte length, 1-byte sequence id, protocol version 10, NUL-terminated version
    if len(packet) < 6 or packet[4] != 10:
        return []
    raw = packet[5:].split(b"\x00", 1)[0].decode("ascii", errors="replace")
    source = T("Port 3306 karşılama mesajı")
    if "mariadb" in raw.lower():
        # MariaDB < 11 prefixes the version with "5.5.5-" for client compatibility
        version = raw.removeprefix("5.5.5-").split("-", 1)[0]
        return [_make("mariadb", version, source, detect_distro(raw))]
    return [_make("mysql", raw.split("-", 1)[0], source, detect_distro(raw))]
