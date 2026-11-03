from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import make_report

from kalkan import cli
from kalkan.scanner import ScanOptions, ScanReport, TargetError


@pytest.fixture
def fake_scan(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ScanOptions]]:
    calls: list[tuple[str, ScanOptions]] = []

    async def scan(target: str, options: ScanOptions) -> ScanReport:
        calls.append((target, options))
        if target == "bad":
            raise TargetError("'bad' geçerli bir alan adı değil.")
        return make_report()

    monkeypatch.setattr(cli, "scan", scan)
    return calls


def test_text_output(
    fake_scan: list[tuple[str, ScanOptions]], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["scan", "example.com", "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "Kalkan güvenlik raporu: example.com" in out
    target, options = fake_scan[0]
    assert target == "example.com"
    assert options.checks is None and not options.allow_private


def test_json_output_and_options(
    fake_scan: list[tuple[str, ScanOptions]], capsys: pytest.CaptureFixture[str]
) -> None:
    code = cli.main(
        [
            "scan",
            "localhost",
            "-f",
            "json",
            "--checks",
            "tls,http",
            "--allow-private",
            "--timeout",
            "3",
        ]
    )
    assert code == 0
    assert json.loads(capsys.readouterr().out)["grade"] == "C"
    options = fake_scan[0][1]
    assert options.checks == frozenset({"tls", "http"})
    assert options.allow_private and options.timeout == 3


def test_html_to_file(
    fake_scan: list[tuple[str, ScanOptions]], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out_file = tmp_path / "rapor.html"
    assert cli.main(["scan", "example.com", "-f", "html", "-o", str(out_file)]) == 0
    assert "Güvenlik raporu" in out_file.read_text(encoding="utf-8")
    assert "not: C, puan: 79" in capsys.readouterr().out


@pytest.mark.parametrize(("threshold", "code"), [("critical", 0), ("high", 1), ("low", 1)])
def test_fail_on(fake_scan: list[tuple[str, ScanOptions]], threshold: str, code: int) -> None:
    assert cli.main(["scan", "example.com", "--no-color", "--fail-on", threshold]) == code


def test_bad_target(
    fake_scan: list[tuple[str, ScanOptions]], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["scan", "bad"]) == 2
    assert "geçerli bir alan adı değil" in capsys.readouterr().err


def test_unknown_check_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["scan", "example.com", "--checks", "tls,magic"])
    assert exc.value.code == 2
    assert "bilinmeyen kontrol: magic" in capsys.readouterr().err


def test_serve_starts_uvicorn(monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn

    from kalkan.web import observability

    seen: dict[str, object] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: seen.update(app=app, **kwargs))
    monkeypatch.setattr(observability, "configure_logging", lambda settings: None)
    assert cli.main(["serve", "--port", "9000"]) == 0
    assert seen["app"] == "kalkan.web.app:create_app"
    assert seen["factory"] is True and seen["port"] == 9000
    assert seen["server_header"] is False
    assert seen["log_config"] is None and seen["access_log"] is False


def test_worker_command(monkeypatch: pytest.MonkeyPatch) -> None:
    import kalkan.web.worker as worker

    called: list[bool] = []
    monkeypatch.setattr(worker, "run_standalone", lambda: called.append(True))
    assert cli.main(["worker"]) == 0
    assert called == [True]


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert "kalkan 0.3.0" in capsys.readouterr().out


def test_migrate_command(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("KALKAN_DATABASE_URL", database_url)
    assert cli.main(["migrate"]) == 0
    assert "sürümsüz → 0003" in capsys.readouterr().out
    assert cli.main(["migrate", "--revision", "0001"]) == 0  # already newer: no-op upgrade
    assert "0003 → 0003" in capsys.readouterr().out


def test_worker_refuses_an_unmigrated_database(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from kalkan.web import observability

    monkeypatch.setenv("KALKAN_DATABASE_URL", database_url)
    monkeypatch.setattr(observability, "configure_logging", lambda settings: None)
    assert cli.main(["worker"]) == 2
    assert "kalkan migrate" in capsys.readouterr().err
