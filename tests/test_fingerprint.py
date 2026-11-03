from __future__ import annotations

import pytest

from kalkan.scanner import fingerprint
from kalkan.scanner.models import DetectedSoftware


def pairs(items: list[DetectedSoftware]) -> list[tuple[str, str | None]]:
    return [(s.product, s.version) for s in items]


@pytest.mark.parametrize(
    ("value", "expected", "distro"),
    [
        ("Apache/2.4.41 (Ubuntu)", [("apache", "2.4.41")], "Ubuntu"),
        (
            "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.33",
            [("apache", "2.4.6"), ("openssl", "1.0.2k-fips"), ("php", "7.4.33")],
            "CentOS",
        ),
        ("nginx/1.18.0", [("nginx", "1.18.0")], None),
        ("nginx", [("nginx", None)], None),
        ("Microsoft-IIS/8.5", [("iis", "8.5")], None),
        ("PHP/8.1.2-1ubuntu2.14", [("php", "8.1.2-1ubuntu2.14")], "Ubuntu"),
        ("PHP/8.2.7-1~deb12u1", [("php", "8.2.7-1~deb12u1")], "Debian"),
        ("ASP.NET", [("aspnet", None)], None),
        ("cloudflare", [], None),
    ],
)
def test_from_header(
    value: str, expected: list[tuple[str, str | None]], distro: str | None
) -> None:
    found = fingerprint.from_header("Server", value)
    assert pairs(found) == expected
    assert all(s.distro == distro for s in found)
    assert all(s.source == "HTTP başlığı (Server)" for s in found)


def test_server_version_disclosed() -> None:
    assert fingerprint.server_version_disclosed("Apache/2.4.41 (Ubuntu)")
    assert not fingerprint.server_version_disclosed("Apache")
    assert not fingerprint.server_version_disclosed("cloudflare")


@pytest.mark.parametrize(
    ("html", "expected"),
    [
        ('<meta name="generator" content="WordPress 6.4.2">', [("wordpress", "6.4.2")]),
        (
            "<META NAME='Generator' CONTENT='Joomla! - Open Source Content Management'>",
            [("joomla", None)],
        ),
        ('<meta name="generator" content="Drupal 7 (http://drupal.org)">', [("drupal", "7")]),
        (
            '<link href="/wp-includes/css/dist/block-library/style.min.css?ver=6.3.1">',
            [("wordpress", "6.3.1")],
        ),
        ('<img src="/wp-content/uploads/logo.png">', [("wordpress", None)]),
        ('<meta name="generator" content="Hugo 0.120">', []),
        ("<html><body>merhaba</body></html>", []),
    ],
)
def test_from_html(html: str, expected: list[tuple[str, str | None]]) -> None:
    assert pairs(fingerprint.from_html(html)) == expected


def test_from_html_survives_broken_markup() -> None:
    assert fingerprint.from_html("<meta name=generator content='WordPress 6.1'<<<>") is not None


@pytest.mark.parametrize(
    ("port", "banner", "expected", "distro"),
    [
        (22, b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n", [("openssh", "8.2p1")], "Ubuntu"),
        (22, b"SSH-2.0-OpenSSH_10.6\r\n", [("openssh", "10.6")], None),
        (22, b"SSH-2.0-dropbear_2022.83\r\n", [], None),
        (21, b"220 ProFTPD 1.3.5e Server (Debian)\r\n", [("proftpd", "1.3.5e")], "Debian"),
        (21, b"220 (vsFTPd 3.0.3)\r\n", [("vsftpd", "3.0.3")], None),
        (
            21,
            b"220---------- Welcome to Pure-FTPd [privsep] ----------\r\n",
            [("pure-ftpd", None)],
            None,
        ),
        (
            25,
            b"220 mail.example.com ESMTP Exim 4.96 Mon, 03 Nov 2026\r\n",
            [("exim", "4.96")],
            None,
        ),
        (25, b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n", [("postfix", None)], "Ubuntu"),
        (25, b"220 mx.example.com ESMTP\r\n", [], None),
    ],
)
def test_from_banner(
    port: int, banner: bytes, expected: list[tuple[str, str | None]], distro: str | None
) -> None:
    found = fingerprint.from_banner(port, banner)
    assert pairs(found) == expected
    assert all(s.distro == distro for s in found)


def _mysql_greeting(version: bytes) -> bytes:
    payload = b"\x0a" + version + b"\x00" + b"\x01\x00\x00\x00abcdefgh\x00"
    return len(payload).to_bytes(3, "little") + b"\x00" + payload


def test_from_banner_mysql_and_mariadb() -> None:
    assert pairs(fingerprint.from_banner(3306, _mysql_greeting(b"5.7.33-log"))) == [
        ("mysql", "5.7.33")
    ]
    assert pairs(fingerprint.from_banner(3306, _mysql_greeting(b"5.5.5-10.6.12-MariaDB"))) == [
        ("mariadb", "10.6.12")
    ]
    assert fingerprint.from_banner(3306, b"\x05\x00\x00\x00\xffoops") == []
