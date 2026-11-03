"""An HTTP client that only ever connects to SSRF-validated addresses.

Each request (and each redirect hop) resolves the hostname through
:func:`kalkan.scanner.target.resolve_host`, then connects to that IP while
sending the original ``Host`` header and TLS SNI name. A malicious site can
therefore not redirect the scanner to ``http://127.0.0.1`` or a cloud metadata
endpoint, and a DNS answer cannot change between validation and connection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from kalkan import __version__
from kalkan.scanner.target import AddressResolver, resolve_host, system_resolver

USER_AGENT = (
    f"Mozilla/5.0 (compatible; KalkanScanner/{__version__}; +https://github.com/AliOsmanToklu/ssl)"
)
_REDIRECT_CODES = {301, 302, 303, 307, 308}


class FetchError(Exception):
    """The URL could not be fetched (connection refused, TLS failure, timeout...)."""


@dataclass(slots=True)
class FetchResult:
    url: str  # final URL, hostname based
    status: int
    headers: httpx.Headers
    body: str
    redirects: list[str] = field(default_factory=list)  # URLs visited before ``url``

    @property
    def origin(self) -> str:
        parts = urlsplit(self.url)
        return f"{parts.scheme}://{parts.netloc}"

    def header_values(self, name: str) -> list[str]:
        return self.headers.get_list(name)


class PinnedHttpClient:
    def __init__(
        self,
        *,
        resolver: AddressResolver = system_resolver,
        allow_private: bool = False,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._resolver = resolver
        self._allow_private = allow_private
        self._dns_cache: dict[str, str] = {}
        # Certificate problems are reported by the TLS check; here we still want
        # to read headers from a site whose certificate is broken.
        self._client = httpx.AsyncClient(
            verify=False,  # noqa: S501
            follow_redirects=False,
            timeout=httpx.Timeout(timeout),
            transport=transport,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"},
        )

    async def __aenter__(self) -> PinnedHttpClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _pin(self, host: str) -> str:
        if host not in self._dns_cache:
            addresses = await resolve_host(
                host, resolver=self._resolver, allow_private=self._allow_private
            )
            self._dns_cache[host] = addresses[0]
        return self._dns_cache[host]

    async def get(
        self, url: str, *, max_redirects: int = 0, max_body: int = 512 * 1024
    ) -> FetchResult:
        visited: list[str] = []
        current = url
        while True:
            result = await self._get_once(current, max_body=max_body)
            location = result.headers.get("location")
            if result.status in _REDIRECT_CODES and location and len(visited) < max_redirects:
                visited.append(current)
                current = urljoin(current, location)
                if urlsplit(current).scheme not in ("http", "https"):
                    raise FetchError(f"Desteklenmeyen yönlendirme: {current}")
                continue
            result.redirects = visited
            return result

    async def _get_once(self, url: str, *, max_body: int) -> FetchResult:
        parts = urlsplit(url)
        host = parts.hostname
        if parts.scheme not in ("http", "https") or not host:
            raise FetchError(f"Geçersiz adres: {url}")
        ip = await self._pin(host)
        ip_netloc = f"[{ip}]" if ":" in ip else ip
        default_port = 443 if parts.scheme == "https" else 80
        port = parts.port or default_port
        host_header = host if port == default_port else f"{host}:{port}"
        pinned = urlunsplit(
            (parts.scheme, f"{ip_netloc}:{port}", parts.path or "/", parts.query, "")
        )
        extensions = {"sni_hostname": host} if parts.scheme == "https" else {}
        request = self._client.build_request(
            "GET", pinned, headers={"Host": host_header}, extensions=extensions
        )
        try:
            response = await self._client.send(request, stream=True)
            try:
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= max_body:
                        break
            finally:
                await response.aclose()
        except httpx.HTTPError as exc:
            raise FetchError(f"{url}: {type(exc).__name__}: {exc}") from exc
        body_bytes = b"".join(chunks)[:max_body]
        encoding = response.charset_encoding or "utf-8"
        try:
            body = body_bytes.decode(encoding, errors="replace")
        except LookupError:
            body = body_bytes.decode("utf-8", errors="replace")
        return FetchResult(
            url=url, status=response.status_code, headers=response.headers, body=body
        )
