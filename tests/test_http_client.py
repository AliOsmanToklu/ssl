from __future__ import annotations

import httpx
import pytest
from conftest import PUBLIC_IP, FakeWeb, Page, fake_resolver

from kalkan.scanner.http_client import FetchError, PinnedHttpClient
from kalkan.scanner.target import TargetError

RESOLVER = fake_resolver(
    {
        "example.com": [PUBLIC_IP],
        "www.example.com": [PUBLIC_IP],
        "evil.example.net": ["127.0.0.1"],
    }
)


async def test_connects_to_pinned_ip_with_host_header_and_sni(web: FakeWeb) -> None:
    web.add("https://example.com/", body="merhaba")
    async with PinnedHttpClient(resolver=RESOLVER, transport=web.transport) as client:
        page = await client.get("https://example.com/")
    assert page.status == 200
    assert page.body == "merhaba"
    request = web.requests[0]
    assert request.url.host == PUBLIC_IP  # the validated address, not a fresh DNS lookup
    assert request.headers["host"] == "example.com"
    assert request.extensions["sni_hostname"] == "example.com"
    assert "KalkanScanner" in request.headers["user-agent"]


async def test_follows_redirects_and_records_them(web: FakeWeb) -> None:
    web.redirect("http://example.com/", "https://www.example.com/")
    web.redirect("https://www.example.com/", "/tr/", status=302)
    web.add("https://www.example.com/tr/", body="ok")
    async with PinnedHttpClient(resolver=RESOLVER, transport=web.transport) as client:
        page = await client.get("http://example.com/", max_redirects=5)
    assert page.url == "https://www.example.com/tr/"
    assert page.origin == "https://www.example.com"
    assert page.redirects == ["http://example.com/", "https://www.example.com/"]


async def test_does_not_follow_redirects_by_default(web: FakeWeb) -> None:
    web.redirect("http://example.com/", "https://example.com/")
    async with PinnedHttpClient(resolver=RESOLVER, transport=web.transport) as client:
        page = await client.get("http://example.com/")
    assert page.status == 301


async def test_refuses_redirect_into_private_network(web: FakeWeb) -> None:
    web.redirect("https://example.com/", "http://evil.example.net/admin")
    async with PinnedHttpClient(resolver=RESOLVER, transport=web.transport) as client:
        with pytest.raises(TargetError):
            await client.get("https://example.com/", max_redirects=3)
    assert len(web.requests) == 1  # never connected to 127.0.0.1


async def test_refuses_redirect_to_ip_literal_metadata_endpoint(web: FakeWeb) -> None:
    web.redirect("https://example.com/", "http://169.254.169.254/latest/meta-data/")
    async with PinnedHttpClient(resolver=RESOLVER, transport=web.transport) as client:
        with pytest.raises(TargetError):
            await client.get("https://example.com/", max_redirects=3)


async def test_rejects_non_http_redirects_and_urls(web: FakeWeb) -> None:
    web.redirect("https://example.com/", "file:///etc/passwd")
    async with PinnedHttpClient(resolver=RESOLVER, transport=web.transport) as client:
        with pytest.raises(FetchError):
            await client.get("https://example.com/", max_redirects=3)
        with pytest.raises(FetchError):
            await client.get("ftp://example.com/")


async def test_truncates_large_bodies(web: FakeWeb) -> None:
    web.add("https://example.com/big", body="a" * 10_000)
    async with PinnedHttpClient(resolver=RESOLVER, transport=web.transport) as client:
        page = await client.get("https://example.com/big", max_body=1000)
    assert len(page.body) == 1000


async def test_decodes_declared_charset(web: FakeWeb) -> None:
    web.add(
        "https://example.com/",
        Page(
            body="Güvenlik".encode("iso-8859-9"),
            headers={"Content-Type": "text/html; charset=iso-8859-9"},
        ),
    )
    web.add(
        "https://example.com/bogus",
        Page(body=b"ok", headers={"Content-Type": "text/html; charset=nope-42"}),
    )
    async with PinnedHttpClient(resolver=RESOLVER, transport=web.transport) as client:
        assert (await client.get("https://example.com/")).body == "Güvenlik"
        assert (await client.get("https://example.com/bogus")).body == "ok"


async def test_network_errors_become_fetch_errors() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    transport = httpx.MockTransport(boom)
    async with PinnedHttpClient(resolver=RESOLVER, transport=transport) as client:
        with pytest.raises(FetchError, match="ConnectError"):
            await client.get("https://example.com/")


async def test_non_default_port_goes_into_host_header(web: FakeWeb) -> None:
    web.add("https://example.com:8443/", body="panel")
    async with PinnedHttpClient(resolver=RESOLVER, transport=web.transport) as client:
        page = await client.get("https://example.com:8443/")
    assert page.body == "panel"
    assert web.requests[0].headers["host"] == "example.com:8443"
