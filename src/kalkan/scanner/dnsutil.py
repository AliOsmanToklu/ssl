"""DNS lookups behind one small, injectable interface: ``await lookup(name, rdtype)``."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import dns.asyncresolver
import dns.exception
import dns.resolver

DnsLookup = Callable[[str, str], Awaitable[list[str]]]
TxtResolver = Callable[[str], Awaitable[list[str]]]


async def system_dns(name: str, rdtype: str) -> list[str]:
    """Records of ``name`` as text; ``[]`` when the name or the record type does not exist.

    TXT strings are joined (a long SPF record arrives in 255-byte chunks). Other types use
    the zone-file presentation, e.g. ``10 mx.example.com.`` or ``0 issue "letsencrypt.org"``.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 8.0
    try:
        answer = await resolver.resolve(name, rdtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    if rdtype == "SOA" and answer.canonical_name != answer.qname:
        return []  # reached through a CNAME: the SOA belongs to another zone
    if rdtype == "TXT":
        return [b"".join(rdata.strings).decode("utf-8", errors="replace") for rdata in answer]
    return [rdata.to_text() for rdata in answer]


async def dns_txt_resolver(name: str) -> list[str]:
    return await system_dns(name, "TXT")


async def zone_apex(lookup: DnsLookup, hostname: str) -> str:
    """The zone that holds ``hostname`` (``shop.firma.com.tr`` -> ``firma.com.tr``).

    Mail policies (SPF, DMARC), DNSSEC and CAA are normally configured there. Found by
    walking up the labels to the first name that owns an SOA record.
    """
    labels = hostname.rstrip(".").split(".")
    for index in range(len(labels) - 1):
        candidate = ".".join(labels[index:])
        try:
            if await lookup(candidate, "SOA"):
                return candidate
        except dns.exception.DNSException:
            continue
    return hostname


@dataclass(frozen=True, slots=True, order=True)
class MxHost:
    preference: int
    host: str


def parse_mx(records: list[str]) -> list[MxHost]:
    hosts: list[MxHost] = []
    for record in records:
        parts = record.split()
        if len(parts) != 2 or not parts[0].isdigit():
            continue
        host = parts[1].rstrip(".").lower()
        if host:  # "0 ." is a null MX (RFC 7505): the domain accepts no mail
            hosts.append(MxHost(int(parts[0]), host))
    return sorted(hosts)
