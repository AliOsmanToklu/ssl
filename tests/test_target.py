from __future__ import annotations

import ipaddress

import pytest
from conftest import PUBLIC_IP, fake_resolver

from kalkan.scanner.target import (
    TargetError,
    display_hostname,
    is_public_ip,
    normalize_hostname,
    resolve_target,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("  EXAMPLE.com.  ", "example.com"),
        ("https://www.example.com/iletisim?x=1", "www.example.com"),
        ("http://example.com:8080", "example.com"),
        ("örnek.com.tr", "xn--rnek-4qa.com.tr"),
        ("https://Şirket.com.tr", "xn--irket-idb.com.tr"),
        ("93.184.216.34", "93.184.216.34"),
        ("[2001:db8::1]", "2001:db8::1"),
    ],
)
def test_normalize_hostname(raw: str, expected: str) -> None:
    assert normalize_hostname(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "http://", "exa mple.com", "-bad-.com", "a" * 64 + ".com", "example.com:99999"],
)
def test_normalize_hostname_rejects_garbage(raw: str) -> None:
    with pytest.raises(TargetError):
        normalize_hostname(raw)


def test_display_hostname_round_trips_turkish_names() -> None:
    assert display_hostname(normalize_hostname("örnek.com.tr")) == "örnek.com.tr"


@pytest.mark.parametrize(
    ("ip", "public"),
    [
        ("93.184.216.34", True),
        ("2606:4700::6810:85e5", True),
        ("127.0.0.1", False),
        ("10.1.2.3", False),
        ("192.168.1.1", False),
        ("172.16.0.1", False),
        ("169.254.169.254", False),  # cloud metadata endpoint
        ("100.64.0.1", False),  # carrier-grade NAT
        ("0.0.0.0", False),
        ("224.0.0.1", False),
        ("::1", False),
        ("fe80::1", False),
        ("fd00::1", False),
        ("::ffff:127.0.0.1", False),  # IPv4-mapped loopback
        ("2002:7f00:1::", False),  # 6to4 wrapping 127.0.0.1
    ],
)
def test_is_public_ip(ip: str, public: bool) -> None:
    assert is_public_ip(ipaddress.ip_address(ip)) is public


async def test_resolve_target_orders_ipv4_first() -> None:
    resolver = fake_resolver({"example.com": ["2606:4700::6810:85e5", PUBLIC_IP]})
    target = await resolve_target("https://example.com/", resolver=resolver)
    assert target.hostname == "example.com"
    assert target.addresses == (PUBLIC_IP, "2606:4700::6810:85e5")
    assert target.primary_ip == PUBLIC_IP
    assert not target.is_ip


async def test_resolve_target_blocks_private_answers() -> None:
    resolver = fake_resolver({"intranet.example.com": [PUBLIC_IP, "10.0.0.5"]})
    with pytest.raises(TargetError, match="iç ağ"):
        await resolve_target("intranet.example.com", resolver=resolver)


async def test_resolve_target_allows_private_when_asked() -> None:
    resolver = fake_resolver({"localhost": ["127.0.0.1"]})
    target = await resolve_target("localhost", resolver=resolver, allow_private=True)
    assert target.addresses == ("127.0.0.1",)


async def test_resolve_target_ip_literal_skips_dns() -> None:
    target = await resolve_target("http://127.0.0.1/", allow_private=True)
    assert target.is_ip
    with pytest.raises(TargetError):
        await resolve_target("127.0.0.1")


async def test_resolve_target_unknown_domain() -> None:
    with pytest.raises(TargetError, match="çözümlenemedi"):
        await resolve_target("yok.example", resolver=fake_resolver({}))
