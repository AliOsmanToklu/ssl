"""Options and shared state passed to every check during one scan."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, date, datetime

import httpx

from kalkan.i18n import LocalizedValue
from kalkan.scanner.dnsutil import DnsLookup, MxHost, parse_mx, system_dns, zone_apex
from kalkan.scanner.http_client import FetchResult, PinnedHttpClient
from kalkan.scanner.models import DetectedSoftware
from kalkan.scanner.softwaredb import SoftwareDatabase
from kalkan.scanner.target import AddressResolver, Target, system_resolver
from kalkan.scanner.wporg import WpLookup, wordpress_org


@dataclass(slots=True)
class ScanOptions:
    checks: frozenset[str] | None = None  # None runs every registered check
    allow_private: bool = False  # only for local testing; never in the SaaS
    timeout: float = 10.0  # per HTTP request / TLS handshake
    port_timeout: float = 2.0
    tls_port: int = 443
    smtp_port: int = 25
    ports: tuple[int, ...] | None = None  # override the default port list
    resolver: AddressResolver = system_resolver
    dns: DnsLookup = system_dns
    wordpress: WpLookup = wordpress_org
    http_transport: httpx.AsyncBaseTransport | None = None  # tests inject a mock
    software_db: SoftwareDatabase | None = None
    today: date | None = None

    def wants(self, check: str) -> bool:
        return self.checks is None or check in self.checks

    def current_date(self) -> date:
        return self.today or datetime.now(UTC).date()


@dataclass(slots=True)
class Facts:
    """Observations one check makes that later checks build on."""

    https_ok: bool | None = None
    http_ok: bool | None = None
    homepage: FetchResult | None = None
    cdn: str | None = None
    open_ports: list[int] = field(default_factory=list)

    @property
    def base_url(self) -> str | None:
        return self.homepage.origin if self.homepage else None


@dataclass(slots=True)
class ScanContext:
    target: Target
    options: ScanOptions
    http: PinnedHttpClient
    software_db: SoftwareDatabase
    facts: Facts = field(default_factory=Facts)
    software: list[DetectedSoftware] = field(default_factory=list)
    notes: list[LocalizedValue] = field(default_factory=list)
    _zone: asyncio.Future[str] | None = field(default=None, repr=False)
    _mx: asyncio.Future[list[MxHost]] | None = field(default=None, repr=False)

    def add_software(self, item: DetectedSoftware) -> None:
        for known in self.software:
            if known.product == item.product and known.version == item.version:
                return
            if known.product == item.product and known.version is None and item.version:
                self.software.remove(known)
                break
            if known.product == item.product and item.version is None:
                return
        self.software.append(item)

    async def zone(self) -> str:
        """The DNS zone of the target (shared by the e-mail and DNS checks)."""
        if self.target.is_ip:
            return self.target.hostname
        if self._zone is None:
            self._zone = asyncio.ensure_future(zone_apex(self.options.dns, self.target.hostname))
        return await self._zone

    async def mx_hosts(self) -> list[MxHost]:
        if self._mx is None:
            self._mx = asyncio.ensure_future(self._load_mx())
        return await self._mx

    async def _load_mx(self) -> list[MxHost]:
        return parse_mx(await self.options.dns(await self.zone(), "MX"))
