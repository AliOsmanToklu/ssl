"""PDF version of the report (fpdf2: pure Python, no browser or system libraries needed).

Fonts: DejaVu Sans is bundled (see fonts/LICENSE-DejaVu.txt) because the core PDF fonts
cannot render Turkish characters such as ğ, ş, ı and İ.
"""

from __future__ import annotations

import re
from importlib import resources
from typing import Any

from fpdf import FPDF
from fpdf.enums import XPos, YPos
from fpdf.fonts import FontFace

from kalkan.i18n import DEFAULT_LANGUAGE, localize, translate
from kalkan.report.render import (
    PROBLEM_SEVERITIES,
    grade_summary,
    local_time,
    summary_sentence,
    top_actions,
)
from kalkan.scanner.models import Finding, ScanReport, Severity

FONT = "DejaVu"
MARGIN = 18.0
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

INK = (16, 24, 40)
INK_2 = (52, 64, 84)
INK_3 = (102, 112, 133)
LINE = (228, 231, 236)
BRAND = (24, 73, 169)
SEVERITY_COLORS = {
    Severity.CRITICAL: (180, 35, 24),
    Severity.HIGH: (196, 50, 10),
    Severity.MEDIUM: (161, 92, 7),
    Severity.LOW: (23, 92, 211),
    Severity.INFO: (71, 84, 103),
    Severity.PASS: (6, 118, 71),
}
GRADE_COLORS = {
    "A": (6, 118, 71),
    "B": (6, 118, 71),
    "C": (181, 71, 8),
    "D": (196, 50, 10),
    "F": (180, 35, 24),
}


def _clean(text: Any, limit: int | None = None) -> str:
    """Scanned sites control some of this text: strip control characters, cap the length."""
    value = _CONTROL_CHARS.sub(" ", str(text))
    if limit is not None and len(value) > limit:
        value = value[: limit - 1] + "…"
    return value


class _ReportPdf(FPDF):
    def __init__(self, report: ScanReport, lang: str) -> None:
        super().__init__(format="A4")
        self.report = report
        self.lang = lang
        fonts = resources.files("kalkan.report").joinpath("fonts")
        with resources.as_file(fonts / "DejaVuSans.ttf") as regular:
            self.add_font(FONT, "", str(regular))
        with resources.as_file(fonts / "DejaVuSans-Bold.ttf") as bold:
            self.add_font(FONT, "B", str(bold))
        self.set_margins(MARGIN, 16, MARGIN)
        self.set_auto_page_break(True, margin=18)
        self.set_title(self._("Güvenlik raporu: {domain}", domain=report.display_name))
        self.set_author("Kalkan")
        self.set_creator(f"Kalkan {report.tool_version}")

    def header(self) -> None:
        if self.page_no() == 1:
            return
        self.set_font(FONT, "", 8)
        self.set_text_color(*INK_3)
        self.cell(
            0, 6, self._("Kalkan · {domain} güvenlik raporu", domain=self.report.display_name)
        )
        self.ln(10)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font(FONT, "", 8)
        self.set_text_color(*INK_3)
        self.cell(0, 6, local_time(self.report.finished_at))
        self.set_x(MARGIN)
        self.cell(
            0, 6, self._("Sayfa {page}/{total}", page=self.page_no(), total="{nb}"), align="R"
        )

    # -- building blocks -----------------------------------------------------

    def _(self, msgid: str, **params: Any) -> str:
        return translate(msgid, self.lang, **params)

    def loc(self, value: Any) -> str:
        return localize(value, self.lang)

    def text_block(
        self,
        text: str,
        *,
        size: float = 10,
        bold: bool = False,
        color: tuple[int, int, int] = INK,
        indent: float = 0,
        line: float = 5,
    ) -> None:
        self.set_font(FONT, "B" if bold else "", size)
        self.set_text_color(*color)
        self.set_x(MARGIN + indent)
        self.multi_cell(
            self.epw - indent,
            line,
            _clean(text),
            align="L",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )

    def measure(
        self,
        text: str,
        *,
        size: float = 10,
        bold: bool = False,
        indent: float = 0,
        line: float = 5,
        color: tuple[int, int, int] = INK,
    ) -> float:
        """Height ``text_block`` would take, without drawing anything."""
        self.set_font(FONT, "B" if bold else "", size)
        height = self.multi_cell(
            self.epw - indent, line, _clean(text), dry_run=True, output="HEIGHT"
        )
        if not isinstance(height, int | float):  # pragma: no cover - fixed by output="HEIGHT"
            raise TypeError(f"unexpected multi_cell result: {height!r}")
        return float(height)

    def section(self, title: str) -> None:
        if self.get_y() > self.h - 50:
            self.add_page()
        self.ln(4)
        self.text_block(title, size=13, bold=True, line=7)
        self.set_draw_color(*LINE)
        self.line(MARGIN, self.get_y() + 1, self.w - MARGIN, self.get_y() + 1)
        self.ln(4)


def _cover(pdf: _ReportPdf) -> None:
    report = pdf.report
    top = pdf.get_y()
    size = 30.0
    x = pdf.w - MARGIN - size
    pdf.set_fill_color(*GRADE_COLORS.get(report.grade, GRADE_COLORS["F"]))
    pdf.ellipse(x, top, size, size, style="F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font(FONT, "B", 26)
    pdf.set_xy(x, top + 5)
    pdf.cell(size, 12, report.grade, align="C")
    pdf.set_font(FONT, "", 8)
    pdf.set_xy(x, top + 18)
    pdf.cell(size, 5, f"{report.score}/100", align="C")

    pdf.set_xy(MARGIN, top)
    width = pdf.epw - size - 6
    pdf.set_font(FONT, "B", 11)
    pdf.set_text_color(*BRAND)
    pdf.cell(width, 6, "Kalkan", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font(FONT, "", 8)
    pdf.set_text_color(*INK_3)
    pdf.cell(width, 5, pdf._("GÜVENLİK RAPORU"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font(FONT, "B", 20)
    pdf.set_text_color(*INK)
    pdf.multi_cell(width, 9, _clean(report.display_name), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_y(max(pdf.get_y(), top + size) + 3)

    pdf.text_block(
        f"{grade_summary(report, pdf.lang)} {summary_sentence(report, pdf.lang)}", line=5.5
    )
    pdf.ln(1)
    pdf.set_font(FONT, "B", 9)
    for severity in (*PROBLEM_SEVERITIES, Severity.PASS):
        count = len(report.passed) if severity is Severity.PASS else report.count(severity)
        pdf.set_text_color(*(SEVERITY_COLORS[severity] if count else INK_3))
        pdf.write(5, f"{count} {severity.label_in(pdf.lang)}   ")
    pdf.ln(6)
    addresses = ", ".join(report.addresses)
    pdf.text_block(
        f"{pdf._('Tarama zamanı')}: {local_time(report.finished_at)} · IP: {addresses}",
        size=8,
        color=INK_3,
        line=4,
    )


def _finding(pdf: _ReportPdf, finding: Finding) -> None:
    color = SEVERITY_COLORS[finding.severity]
    severity, category = finding.severity.label_in(pdf.lang), finding.category.label_in(pdf.lang)
    blocks: list[tuple[str, dict[str, Any]]] = [
        (
            f"{severity.upper()} · {category}",
            {"size": 8, "bold": True, "color": color, "line": 4.5},
        ),
        (pdf.loc(finding.title), {"size": 11, "bold": True, "line": 5.5}),
    ]
    for label, text in (
        (pdf._("Ne anlama geliyor?"), finding.description),
        (pdf._("Ne yapmalısınız?"), finding.recommendation),
    ):
        if text:
            blocks.append((label, {"size": 8.5, "bold": True, "color": INK_2, "line": 4.5}))
            blocks.append((pdf.loc(text), {"size": 9.5, "color": INK_2, "line": 4.8}))
    for key, value in list(finding.details.items())[:6]:
        blocks.append(
            (
                f"{_clean(pdf.loc(key), 60)}: {_clean(pdf.loc(value), 160)}",
                {"size": 7.5, "color": INK_3, "line": 4},
            )
        )

    # Keep a finding on one page: measure it first, start a new page if it does not fit.
    height = sum(pdf.measure(text, indent=4, **style) for text, style in blocks)
    if pdf.get_y() + height > pdf.page_break_trigger and height < pdf.eph:
        pdf.add_page()
    start_page, start_y = pdf.page_no(), pdf.get_y()
    for text, style in blocks:
        pdf.text_block(text, indent=4, **style)
    if pdf.page_no() == start_page:
        pdf.set_fill_color(*color)
        pdf.rect(MARGIN, start_y, 1.2, pdf.get_y() - start_y, style="F")
    pdf.ln(4)


def render_pdf(report: ScanReport, lang: str = DEFAULT_LANGUAGE) -> bytes:
    pdf = _ReportPdf(report, lang)
    _ = pdf._
    pdf.add_page()
    _cover(pdf)

    actions = top_actions(report)
    if actions:
        pdf.section(_("Önce bunları yapın"))
        for number, finding in enumerate(actions, start=1):
            pdf.text_block(f"{number}. {pdf.loc(finding.title)}", size=10, bold=True, line=5.2)
            if finding.recommendation:
                pdf.text_block(
                    pdf.loc(finding.recommendation), size=9.5, color=INK_2, indent=4, line=4.8
                )
            pdf.ln(1.5)

    if report.problems:
        pdf.section(_("Bulunan sorunlar ({n})", n=len(report.problems)))
        for finding in report.problems:
            _finding(pdf, finding)

    if report.informational or report.notes:
        pdf.section(_("Bilgi ve öneriler"))
        for note in report.notes:
            pdf.text_block(f"• {pdf.loc(note)}", size=9.5, color=INK_2, line=4.8)
            pdf.ln(1)
        for finding in report.informational:
            _finding(pdf, finding)

    if report.passed:
        pdf.section(_("Başarılı kontroller"))
        for finding in report.passed:
            pdf.text_block(
                f"✓  {pdf.loc(finding.title)}", size=9.5, color=SEVERITY_COLORS[Severity.PASS]
            )

    if report.software:
        pdf.section(_("Tespit edilen yazılımlar"))
        pdf.set_font(FONT, "", 8.5)
        pdf.set_text_color(*INK)
        with pdf.table(
            col_widths=(55, 30, 70),
            line_height=5.5,
            headings_style=FontFace(emphasis="BOLD", color=INK_3),
            borders_layout="HORIZONTAL_LINES",
        ) as table:
            heading = table.row()
            for title in (_("Yazılım"), _("Sürüm"), _("Nerede görüldü")):
                heading.cell(title)
            for item in report.software:
                row = table.row()
                row.cell(_clean(pdf.loc(item.name), 60))
                version = item.version or _("gizli")
                row.cell(_clean(f"{version} ({item.distro})" if item.distro else version, 40))
                row.cell(_clean(pdf.loc(item.source), 80))

    if report.errors:
        pdf.section(_("Tamamlanamayan kontroller"))
        for error in report.errors:
            pdf.text_block(f"• {pdf.loc(error.message)}", size=9.5, color=INK_2)

    pdf.ln(6)
    pdf.text_block(
        _(
            "Bu rapor, sitenizin internetten görünen yüzüne yapılan otomatik bir taramaya "
            "dayanır ve sızma testinin yerini tutmaz."
        )
        + f" Kalkan {report.tool_version}",
        size=8,
        color=INK_3,
        line=4,
    )
    return bytes(pdf.output())
