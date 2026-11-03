from __future__ import annotations

import pytest
from conftest import PUBLIC_IP, FakeWeb, fake_resolver, fake_txt

from kalkan.web.verification import FILE_PATH, same_site, txt_names, txt_value, verify_ownership

TOKEN = "0123456789abcdef0123456789abcdef"
RESOLVER = fake_resolver(
    {
        "example.com": [PUBLIC_IP],
        "www.example.com": [PUBLIC_IP],
        "attacker.example.net": [PUBLIC_IP],
    }
)


async def verify(
    hostname: str, web: FakeWeb, txt: dict[str, list[str]] | None = None
) -> str | None:
    result = await verify_ownership(
        hostname,
        TOKEN,
        txt_resolver=fake_txt(txt or {}),
        resolver=RESOLVER,
        transport=web.transport,
    )
    return result.method


async def test_dns_record(web: FakeWeb) -> None:
    assert (
        await verify("example.com", web, {"example.com": ["v=spf1 -all", txt_value(TOKEN)]})
        == "dns"
    )


async def test_dns_record_on_parent_of_www(web: FakeWeb) -> None:
    assert await verify("www.example.com", web, {"example.com": [txt_value(TOKEN)]}) == "dns"


async def test_wrong_dns_token(web: FakeWeb) -> None:
    assert await verify("example.com", web, {"example.com": [txt_value("baska")]}) is None


async def test_http_file(web: FakeWeb) -> None:
    web.add(f"https://example.com{FILE_PATH}", body=f"{TOKEN}\n")
    assert await verify("example.com", web) == "http"


async def test_http_file_after_same_site_redirect(web: FakeWeb) -> None:
    web.redirect(f"http://example.com{FILE_PATH}", f"https://www.example.com{FILE_PATH}")
    web.add(f"https://www.example.com{FILE_PATH}", body=TOKEN)
    assert await verify("example.com", web) == "http"


async def test_redirect_to_another_site_is_not_proof(web: FakeWeb) -> None:
    """An open redirect on the victim's site must not let an attacker verify it."""
    web.redirect(f"https://example.com{FILE_PATH}", f"https://attacker.example.net{FILE_PATH}")
    web.add(f"https://attacker.example.net{FILE_PATH}", body=TOKEN)
    assert await verify("example.com", web) is None


async def test_dns_errors_fall_back_to_http(web: FakeWeb) -> None:
    async def broken(name: str) -> list[str]:
        raise TimeoutError

    web.add(f"https://example.com{FILE_PATH}", body=TOKEN)
    result = await verify_ownership(
        "example.com", TOKEN, txt_resolver=broken, resolver=RESOLVER, transport=web.transport
    )
    assert result.ok and result.method == "http"


async def test_nothing_found(web: FakeWeb) -> None:
    web.add(f"https://example.com{FILE_PATH}", body="yanlis")
    result = await verify_ownership(
        "example.com", TOKEN, txt_resolver=fake_txt({}), resolver=RESOLVER, transport=web.transport
    )
    assert not result.ok
    assert "bulunamadı" in result.message


async def test_private_hosts_are_not_fetched(web: FakeWeb) -> None:
    result = await verify_ownership(
        "intranet.example.com",
        TOKEN,
        txt_resolver=fake_txt({}),
        resolver=fake_resolver({"intranet.example.com": ["10.0.0.1"]}),
        transport=web.transport,
    )
    assert not result.ok
    assert web.requests == []


@pytest.mark.parametrize(
    ("hostname", "other", "same"),
    [
        ("example.com", "example.com", True),
        ("example.com", "www.example.com", True),
        ("www.example.com", "example.com", True),
        ("example.com", "EXAMPLE.COM.", True),
        ("example.com", "notexample.com", False),
        ("example.com", "example.com.evil.net", False),
    ],
)
def test_same_site(hostname: str, other: str, same: bool) -> None:
    assert same_site(hostname, other) is same


def test_txt_names() -> None:
    assert txt_names("example.com") == ["example.com"]
    assert txt_names("www.example.com") == ["www.example.com", "example.com"]
