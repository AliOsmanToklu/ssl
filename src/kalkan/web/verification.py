"""Domain ownership verification (DNS TXT record or a file under /.well-known/).

Kalkan only scans domains whose owner proved control over them. Port scanning
and file probing someone else's site without permission is not acceptable,
and without this step the service could be abused to do exactly that.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from kalkan.i18n import LocalizedValue, T
from kalkan.scanner.dnsutil import TxtResolver, dns_txt_resolver
from kalkan.scanner.http_client import FetchError, PinnedHttpClient
from kalkan.scanner.target import AddressResolver, TargetError, system_resolver

TXT_PREFIX = "kalkan-site-verification="
FILE_PATH = "/.well-known/kalkan-verification.txt"


def txt_value(token: str) -> str:
    return f"{TXT_PREFIX}{token}"


def same_site(hostname: str, other: str) -> bool:
    base = hostname.removeprefix("www.")
    other = other.lower().rstrip(".")
    return other == base or other.endswith("." + base)


def txt_names(hostname: str) -> list[str]:
    """Where we look for the TXT record. ``www`` hosts are usually CNAMEs, which
    cannot carry TXT records, so the parent domain is accepted for them."""
    names = [hostname]
    if hostname.startswith("www."):
        names.append(hostname.removeprefix("www."))
    return names


@dataclass(frozen=True, slots=True)
class VerificationResult:
    method: str | None  # "dns" | "http" | None
    message: LocalizedValue

    @property
    def ok(self) -> bool:
        return self.method is not None


async def verify_ownership(
    hostname: str,
    token: str,
    *,
    txt_resolver: TxtResolver = dns_txt_resolver,
    resolver: AddressResolver = system_resolver,
    allow_private: bool = False,
    transport: httpx.AsyncBaseTransport | None = None,
) -> VerificationResult:
    expected = txt_value(token)
    for name in txt_names(hostname):
        try:
            records = await txt_resolver(name)
        except Exception:
            records = []
        if any(record.strip() == expected for record in records):
            return VerificationResult("dns", T("DNS kaydı bulundu."))

    async with PinnedHttpClient(
        resolver=resolver, allow_private=allow_private, timeout=10, transport=transport
    ) as client:
        for scheme in ("https", "http"):
            try:
                page = await client.get(f"{scheme}://{hostname}{FILE_PATH}", max_redirects=3)
            except (FetchError, TargetError):
                continue
            # Follow redirects only within the same domain (http->https, apex->www);
            # otherwise an open redirect on the victim's site could "verify" it for us.
            if not same_site(hostname, urlsplit(page.url).hostname or ""):
                continue
            if page.status == 200 and page.body.strip() == token:
                return VerificationResult("http", T("Doğrulama dosyası bulundu."))

    return VerificationResult(
        None,
        T(
            "Doğrulama kaydı veya dosyası bulunamadı. DNS değişikliklerinin yayılması birkaç "
            "dakika ile birkaç saat sürebilir; biraz sonra tekrar deneyin."
        ),
    )
