from __future__ import annotations

import json
from datetime import UTC, datetime

from conftest import make_report

from kalkan.report import render_html, render_json, render_text
from kalkan.report.render import local_time, summary_sentence, top_actions
from kalkan.scanner.models import Category, CheckError, Finding, ScanReport, Severity


def test_json_round_trip() -> None:
    report = make_report(notes=["Not"], errors=[CheckError("tls", "TLS: zaman aşımı")])
    data = json.loads(render_json(report))
    assert data["grade"] == "C"
    assert data["summary"]["high"] == 1
    assert data["findings"][0]["title"] == "PHP 7.4 artık güvenlik güncellemesi almıyor"
    restored = ScanReport.from_dict(data)
    assert restored.to_dict() == report.to_dict()


def test_html_report_contents() -> None:
    page = render_html(make_report())
    assert page.startswith("<!doctype html>")
    assert '<html lang="tr">' in page
    assert "Önce bunları yapın" in page
    assert "PHP 7.4 artık güvenlik güncellemesi almıyor" in page
    assert "Ne yapmalısınız?" in page
    assert "Başarılı kontroller" in page
    assert "Tespit edilen yazılımlar" in page
    assert "k-grade-c" in page
    assert "<style>" in page  # self-contained: works when e-mailed or opened from disk


def test_html_report_escapes_scanned_content() -> None:
    """Banners and headers come from the scanned site: they must never become markup."""
    evil = '<script>alert("x")</script>'
    report = make_report(
        findings=[
            Finding(
                "http.version_disclosure",
                Category.HTTP,
                Severity.LOW,
                "Sunucu sürümü görünüyor",
                details={"Server": evil},
            )
        ],
        display_name=evil,
    )
    page = render_html(report)
    assert evil not in page
    assert "&lt;script&gt;" in page


def test_clean_report_has_no_action_list() -> None:
    report = make_report(
        findings=[Finding("tls.cert_valid", Category.TLS, Severity.PASS, "Sertifika geçerli")],
        score=100,
        grade="A",
    )
    page = render_html(report)
    assert "Önce bunları yapın" not in page
    assert summary_sentence(report) == "Tarama sırasında bir güvenlik sorunu bulunmadı."
    assert top_actions(report) == []


def test_summary_sentence_counts_by_severity() -> None:
    report = make_report(
        findings=[
            Finding("a", Category.TLS, Severity.CRITICAL, "a"),
            Finding("b", Category.TLS, Severity.MEDIUM, "b"),
            Finding("c", Category.TLS, Severity.MEDIUM, "c"),
        ]
    )
    assert summary_sentence(report) == "Taramada 1 acil, 2 orta öncelikli sorun bulundu."


def test_text_report() -> None:
    report = make_report(
        notes=["CDN notu"], errors=[CheckError("ports", "Açık portlar: zaman aşımı")]
    )
    text = render_text(report)
    assert "Kalkan güvenlik raporu: example.com" in text
    assert "[Yüksek] PHP 7.4" in text
    assert "Ne yapmalı: Desteklenen bir sürüme yükseltin." in text
    assert "✓ SPF kaydı doğru ayarlanmış" in text
    assert "CDN notu" in text
    assert "! Açık portlar: zaman aşımı" in text
    assert "\033[" not in text
    assert "\033[" in render_text(report, color=True)


def test_local_time_uses_turkey_time() -> None:
    assert local_time(datetime(2026, 11, 3, 9, 30, tzinfo=UTC)) == "03.11.2026 12:30"
