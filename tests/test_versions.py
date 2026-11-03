from __future__ import annotations

from datetime import date

import pytest
from conftest import TODAY

from kalkan.scanner.softwaredb import SoftwareDatabase, Status
from kalkan.scanner.versions import Version, parse_cycle, parse_version


def v(text: str) -> Version:
    parsed = parse_version(text)
    assert parsed is not None
    return parsed


@pytest.mark.parametrize(
    ("text", "parts", "raw"),
    [
        ("7.4.33", (7, 4, 33), "7.4.33"),
        ("8.1.2-1ubuntu2.14", (8, 1, 2), "8.1.2"),
        ("9.8p1", (9, 8), "9.8p1"),
        ("1.3.9e", (1, 3, 9), "1.3.9e"),
        ("10.6.12-MariaDB", (10, 6, 12), "10.6.12"),
        ("1.0.2k-fips", (1, 0, 2), "1.0.2k"),
        ("Apache/2.4.29", (2, 4, 29), "2.4.29"),
    ],
)
def test_parse_version(text: str, parts: tuple[int, ...], raw: str) -> None:
    parsed = v(text)
    assert parsed.parts == parts
    assert str(parsed) == raw


def test_parse_version_without_digits() -> None:
    assert parse_version("nginx") is None


@pytest.mark.parametrize(
    ("older", "newer"),
    [
        ("2.4.29", "2.4.69"),
        ("2.4", "2.4.1"),
        ("9.7p1", "9.8"),
        ("9.8", "9.8p1"),
        ("9.8p1", "9.8p2"),
        ("1.3.9", "1.3.9e"),
        ("1.3.9rc1", "1.3.9"),
        ("4.96", "4.100"),
    ],
)
def test_version_ordering(older: str, newer: str) -> None:
    assert v(older) < v(newer)
    assert v(newer) > v(older)


def test_trailing_zero_is_equal() -> None:
    assert v("2.4") == v("2.4.0")
    assert hash(v("2.4")) == hash(v("2.4.0"))
    assert v("2.4").__eq__("2.4") is NotImplemented
    assert v("2.4").__lt__("2.4") is NotImplemented


def test_parse_cycle() -> None:
    assert parse_cycle("8.1") == (8, 1)
    assert parse_cycle("") == ()


DB = SoftwareDatabase.from_dict(
    {
        "generated_at": "2026-11-01",
        "products": {
            "php": {
                "name": "PHP",
                "cycles": [
                    {"cycle": "8.4", "eol": "2028-12-31", "latest": "8.4.27"},
                    {"cycle": "8.3", "eol": "2027-12-31", "latest": "8.3.36"},
                    {"cycle": "7.4", "eol": "2022-11-28", "latest": "7.4.33"},
                ],
            },
            "openssh": {
                "name": "OpenSSH",
                "cycles": [{"cycle": "", "eol": False, "latest": "10.6"}],
                "minimum_safe": "9.8",
                "minimum_safe_reason": "regreSSHion",
            },
            "joomla": {
                "name": "Joomla",
                "cycles": [
                    {"cycle": "5", "eol": False, "latest": "5.3.1"},
                    {"cycle": "3", "eol": True},
                ],
            },
            "weird": {"name": "Weird", "cycles": [{"cycle": "1.0", "eol": "not-a-date"}]},
        },
    }
)


@pytest.mark.parametrize(
    ("product", "version", "status"),
    [
        ("php", "8.4.27", Status.CURRENT),
        ("php", "8.3.10", Status.OUTDATED),
        ("php", "7.4.33", Status.EOL),
        ("php", "5.6.40", Status.EOL),  # older than every tracked cycle
        ("php", "9.0.1", Status.CURRENT),  # newer than the database
        ("php", "8.0.1", Status.UNKNOWN),  # gap in the data
        ("openssh", "10.6p1", Status.CURRENT),
        ("openssh", "10.2p1", Status.OUTDATED),
        ("openssh", "8.9p1", Status.VULNERABLE),
        ("joomla", "3", Status.EOL),  # eol: true without a date
        ("joomla", "5.3.1", Status.CURRENT),
        ("weird", "1.0.1", Status.CURRENT),  # unparseable eol counts as supported
    ],
)
def test_evaluate(product: str, version: str, status: Status) -> None:
    evaluation = DB.evaluate(product, version, TODAY)
    assert evaluation is not None
    assert evaluation.status is status


def test_evaluate_unknown_inputs() -> None:
    assert DB.evaluate("nope", "1.0", TODAY) is None
    assert DB.evaluate("php", None, TODAY) is None
    assert DB.evaluate("php", "latest", TODAY) is None


def test_eol_depends_on_the_date() -> None:
    before = DB.evaluate("php", "8.3.36", date(2027, 6, 1))
    after = DB.evaluate("php", "8.3.36", date(2028, 1, 1))
    assert before is not None and before.status is Status.CURRENT
    assert after is not None and after.status is Status.EOL
    assert after.eol_date == date(2027, 12, 31)


def test_supported_cycles_newest_first() -> None:
    cycles = DB.products["php"].supported_cycles(TODAY)
    assert [c.cycle for c in cycles] == ["8.4", "8.3"]


def test_bundled_database_loads() -> None:
    db = SoftwareDatabase.bundled()
    assert db.generated_at is not None
    for key in ("php", "wordpress", "apache", "nginx", "openssh", "iis", "mysql"):
        assert key in db.products, key
    assert db.name_of("php") == "PHP"
    assert db.name_of("unknown") == "unknown"


def test_from_file(tmp_path: object) -> None:
    from pathlib import Path

    assert isinstance(tmp_path, Path)
    path = tmp_path / "db.json"
    path.write_text('{"products": {"x": {"cycles": [{"cycle": "1", "latest": "1.2"}]}}}')
    db = SoftwareDatabase.from_file(path)
    assert db.generated_at is None
    evaluation = db.evaluate("x", "1.1", TODAY)
    assert evaluation is not None and evaluation.status is Status.OUTDATED
    assert evaluation.latest_in_cycle == "1.2"
    assert evaluation.eol_date is None
