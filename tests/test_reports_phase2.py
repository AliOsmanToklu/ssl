from __future__ import annotations

import io
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import make_report
from pypdf import PdfReader

from kalkan import cli
from kalkan.report import compare_reports, render_pdf
from kalkan.scanner import ScanOptions, ScanReport
from kalkan.scanner.models import Category, CheckError, DetectedSoftware, Finding, Severity
from kalkan.web.charts import BOTTOM, TOP, score_chart, y_of
from kalkan.web.models import Scan, ScanStatus


def problem(fid: str, severity: Severity, title: str | None = None) -> Finding:
    return Finding(fid, Category.PORTS, severity, title or fid, "açıklama", "öneri")


# --- comparison ---------------------------------------------------------------------


def test_compare_reports() -> None:
    before = make_report(
        findings=[
            problem("ports.open_3389", Severity.HIGH),
            problem("tls.cert_expiring", Severity.MEDIUM),
            problem("http.hsts_missing", Severity.LOW),
        ],
        score=70,
        grade="C",
    )
    after = make_report(
        findings=[
            problem("tls.cert_expiring", Severity.HIGH),  # got worse
            problem("http.hsts_missing", Severity.LOW),  # unchanged
            problem("email.spf_missing", Severity.MEDIUM),  # new
            Finding("tls.cert_valid", Category.TLS, Severity.PASS, "ok"),
        ],
        score=76,
        grade="C",
    )
    result = compare_reports(before, after)
    assert result.score_delta == 6
    assert (result.previous_grade, result.previous_score) == ("C", 70)
    assert [f.id for f in result.new_problems] == ["tls.cert_expiring", "email.spf_missing"]
    assert [f.id for f in result.resolved] == ["ports.open_3389"]
    assert not result.unchanged
    assert compare_reports(after, after).unchanged


# --- PDF ------------------------------------------------------------------------------


def pdf_text(data: bytes) -> str:
    reader = PdfReader(io.BytesIO(data))
    return "\n".join(page.extract_text() for page in reader.pages)


def test_pdf_report_contents() -> None:
    report = make_report(
        notes=["Siteniz Cloudflare arkasında."],
        errors=[CheckError("ports", "Açık portlar: zaman aşımı")],
        software=[DetectedSoftware("php", "PHP", "7.4.3", "HTTP başlığı", "Ubuntu")],
        findings=[
            *make_report().findings,
            Finding("dns.caa_missing", Category.DNS, Severity.INFO, "CAA kaydı yok", "", "ekleyin"),
        ],
    )
    data = render_pdf(report)
    assert data.startswith(b"%PDF-")
    reader = PdfReader(io.BytesIO(data))
    assert reader.metadata is not None and reader.metadata.title == "Güvenlik raporu: example.com"
    text = pdf_text(data)
    for expected in (
        "GÜVENLİK RAPORU",
        "example.com",
        "Önce bunları yapın",
        "PHP 7.4 artık güvenlik güncellemesi almıyor",
        "Ne yapmalısınız?",
        "Bilgi ve öneriler",
        "Siteniz Cloudflare arkasında.",
        "Başarılı kontroller",
        "Tespit edilen yazılımlar",
        "7.4.3 (Ubuntu)",
        "Tamamlanamayan kontroller",
        "Sayfa 1/",
    ):
        assert expected in text, expected


def test_pdf_survives_hostile_and_long_content() -> None:
    long_title = "Çok uzun bir başlık " * 40
    findings = [
        Finding(
            f"x.{i}",
            Category.HTTP,
            Severity.MEDIUM,
            long_title,
            "ğüşiöç İı " * 80,
            "öneri " * 60,
            {"Server": "Apache\x00\x07<script>", "Uzun": "a" * 500},
        )
        for i in range(12)
    ]
    data = render_pdf(make_report(findings=findings, software=[]))
    reader = PdfReader(io.BytesIO(data))
    assert len(reader.pages) > 3
    text = pdf_text(data)
    assert "Apache  <script>" in text  # control characters replaced, text kept as text
    assert "a" * 500 not in text  # long values are cut


def test_cli_pdf_output(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    async def fake_scan(target: str, options: ScanOptions) -> ScanReport:
        return make_report()

    monkeypatch.setattr(cli, "scan", fake_scan)
    out = tmp_path / "rapor.pdf"
    assert cli.main(["scan", "example.com", "-f", "pdf", "-o", str(out)]) == 0
    assert out.read_bytes().startswith(b"%PDF-")
    with pytest.raises(SystemExit):
        cli.main(["scan", "example.com", "-f", "pdf"])  # binary output needs a file


# --- score history chart --------------------------------------------------------


def scan(
    scan_id: int, score: int | None, days: float, status: ScanStatus = ScanStatus.DONE
) -> Scan:
    start = datetime(2026, 10, 1, tzinfo=UTC)
    return Scan(
        id=scan_id,
        status=status,
        score=score,
        grade="B" if score else None,
        finished_at=start + timedelta(days=days) if status is ScanStatus.DONE else None,
    )


def test_chart_needs_two_finished_scans() -> None:
    assert score_chart([]) is None
    assert score_chart([scan(1, 80, 0), scan(2, None, 1, ScanStatus.FAILED)]) is None


def test_chart_geometry_is_time_proportional() -> None:
    chart = score_chart([scan(3, 90, 30), scan(1, 50, 0), scan(2, 70, 10)])
    assert chart is not None
    assert [p.scan_id for p in chart.points] == [1, 2, 3]  # oldest first
    xs = [p.x for p in chart.points]
    assert xs[0] == 3.0 and xs[-1] == 97.0
    assert xs[1] == pytest.approx(3 + 94 / 3, abs=0.01)  # day 10 of 30
    assert [p.y for p in chart.points] == [y_of(50), y_of(70), y_of(90)]
    assert y_of(100) == TOP and y_of(0) == BOTTOM
    assert len(chart.segments) == 2
    assert (chart.first.score, chart.first.grade) == (50, "B")


def test_chart_same_instant_and_limit() -> None:
    same = score_chart([scan(1, 60, 0), scan(2, 80, 0)])
    assert same is not None and [p.x for p in same.points] == [3.0, 97.0]
    many = score_chart([scan(i, 50 + i, i) for i in range(1, 41)])
    assert many is not None and len(many.points) == 30
    assert many.first.scan_id == 11


def test_tooltip_flips_below_dots_near_the_top() -> None:
    chart = score_chart([scan(1, 100, 0), scan(2, 20, 1)])
    assert chart is not None
    high, low = chart.points
    assert high.tip_y > high.y  # below the dot
    assert low.tip_y < low.y  # above the dot
