"""Target normalisation, DNS resolution and the SSRF guard.

Every network connection the scanner makes goes to an address returned by
:func:`resolve_host`, which refuses private, loopback, link-local and other
non-public ranges unless explicitly allowed. Connecting to the validated IP
(instead of letting a library resolve the name again) also closes the DNS
rebinding gap between "check" and "use".
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

import idna

from kalkan.i18n import LocalizedValue, T

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
AddressResolver = Callable[[str], Awaitable[list[str]]]

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class TargetError(ValueError):
    """The target cannot be scanned. ``text`` is shown to end users in their language."""

    def __init__(self, text: LocalizedValue) -> None:
        super().__init__(str(text))
        self.text = text


@dataclass(frozen=True, slots=True)
class Target:
    hostname: str  # ASCII (punycode), lower case, no trailing dot
    display_name: str  # Unicode form for reports, e.g. "örnek.com.tr"
    addresses: tuple[str, ...]  # validated, IPv4 first

    @property
    def primary_ip(self) -> str:
        return self.addresses[0]

    @property
    def is_ip(self) -> bool:
        return is_ip_literal(self.hostname)


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def normalize_hostname(raw: str) -> str:
    """Turn user input ("https://Örnek.com.tr/iletisim") into an ASCII hostname."""
    text = raw.strip()
    if not text:
        raise TargetError(T("Lütfen bir alan adı girin."))
    if "://" not in text:
        text = "//" + text
    try:
        parts = urlsplit(text)
        host = parts.hostname
        _ = parts.port  # raises ValueError on a malformed port
    except ValueError as exc:
        raise TargetError(T("Geçerli bir alan adı girin (örnek: firmaniz.com.tr).")) from exc
    if not host:
        raise TargetError(T("Geçerli bir alan adı girin (örnek: firmaniz.com.tr)."))
    host = host.rstrip(".")
    if is_ip_literal(host):
        return str(ipaddress.ip_address(host))
    try:
        ascii_host = idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        raise TargetError(T("'{host}' geçerli bir alan adı değil.", host=host)) from exc
    if len(ascii_host) > 253 or not all(_LABEL_RE.match(lbl) for lbl in ascii_host.split(".")):
        raise TargetError(T("'{host}' geçerli bir alan adı değil.", host=host))
    return ascii_host


def display_hostname(ascii_host: str) -> str:
    try:
        return idna.decode(ascii_host)
    except idna.IDNAError:
        return ascii_host


def is_public_ip(ip: IPAddress) -> bool:
    """True only for globally routable unicast addresses."""
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped or ip.sixtofour
        if mapped is not None:
            return is_public_ip(mapped)
    return ip.is_global and not ip.is_multicast and not ip.is_reserved


async def system_resolver(hostname: str) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


async def resolve_host(
    hostname: str,
    *,
    resolver: AddressResolver = system_resolver,
    allow_private: bool = False,
) -> tuple[str, ...]:
    """Resolve ``hostname`` and enforce the SSRF guard. IPv4 addresses come first."""
    if is_ip_literal(hostname):
        raw_addresses = [hostname]
    else:
        raw_addresses = await resolver(hostname)
    addresses: list[IPAddress] = []
    for raw in raw_addresses:
        try:
            addresses.append(ipaddress.ip_address(raw.split("%", 1)[0]))
        except ValueError:
            continue
    if not addresses:
        raise TargetError(
            T("'{value}' alan adı çözümlenemedi (DNS kaydı yok).", value=display_hostname(hostname))
        )
    if not allow_private:
        blocked = [ip for ip in addresses if not is_public_ip(ip)]
        if blocked:
            raise TargetError(
                T(
                    (
                        "'{value}' özel/iç ağ adresine ({value2}) çözümleniyor; yalnızca "
                        "internete açık adresler taranabilir."
                    ),
                    value=display_hostname(hostname),
                    value2=blocked[0],
                )
            )
    addresses.sort(key=lambda ip: ip.version)
    return tuple(str(ip) for ip in dict.fromkeys(addresses))


async def resolve_target(
    raw: str,
    *,
    resolver: AddressResolver = system_resolver,
    allow_private: bool = False,
) -> Target:
    hostname = normalize_hostname(raw)
    addresses = await resolve_host(hostname, resolver=resolver, allow_private=allow_private)
    return Target(hostname=hostname, display_name=display_hostname(hostname), addresses=addresses)
