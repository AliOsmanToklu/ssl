"""Render a :class:`ScanReport` as plain text, JSON or a self-contained HTML page.

Every renderer takes a ``lang``; findings are stored with all translations (see
:mod:`kalkan.i18n`), so the same report reads correctly in any supported language.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from functools import cache
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import jinja2
from markupsafe import Markup

from kalkan.i18n import DEFAULT_LANGUAGE, LANGUAGES, Text, localize, translate
from kalkan.scanner.models import Category, Finding, ScanReport, Severity
from kalkan.scanner.scoring import GRADE_SUMMARIES

PROBLEM_SEVERITIES = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


def _turkey_tz() -> ZoneInfo | None:
    try:
        return ZoneInfo("Europe/Istanbul")
    except ZoneInfoNotFoundError:  # Windows without the tzdata package
        return None


def local_time(value: datetime) -> str:
    tz = _turkey_tz()
    moment = value.astimezone(tz) if tz else value.astimezone(UTC)
    suffix = "" if tz else " UTC"
    return moment.strftime("%d.%m.%Y %H:%M") + suffix


def top_actions(report: ScanReport, limit: int = 3) -> list[Finding]:
    return [f for f in report.findings if f.severity.is_problem][:limit]


def summary_sentence(report: ScanReport, lang: str = DEFAULT_LANGUAGE) -> str:
    parts = [
        f"{report.count(s)} {s.label_in(lang).lower()}"
        for s in PROBLEM_SEVERITIES
        if report.count(s)
    ]
    if not parts:
        return translate("Tarama sırasında bir güvenlik sorunu bulunmadı.", lang)
    return translate("Taramada {parts} öncelikli sorun bulundu.", lang, parts=", ".join(parts))


def grade_summary(report: ScanReport, lang: str = DEFAULT_LANGUAGE) -> str:
    message = GRADE_SUMMARIES.get(report.grade)
    return translate(message, lang) if message else ""


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)


# --- Jinja --------------------------------------------------------------------


def _lang(ctx: jinja2.runtime.Context) -> str:
    value = ctx.get("lang")
    return value if isinstance(value, str) and value in LANGUAGES else DEFAULT_LANGUAGE


@jinja2.pass_context
def _gettext(ctx: jinja2.runtime.Context, msgid: str, **params: Any) -> str:
    return translate(msgid, _lang(ctx), **params)


@jinja2.pass_context
def _gettext_markup(ctx: jinja2.runtime.Context, msgid: str, **params: Any) -> Markup:
    """For our own catalog strings that contain simple HTML (``<strong>``); parameters are
    escaped like any other template value."""
    lang = _lang(ctx)
    template = translate(msgid, lang)
    values = {
        key: localize(value, lang) if isinstance(value, Text) else value
        for key, value in params.items()
    }
    return Markup(template).format(**values)  # noqa: S704 - our own catalog; params are escaped


@jinja2.pass_context
def _localize(ctx: jinja2.runtime.Context, value: Any) -> str:
    return localize(value, _lang(ctx))


@jinja2.pass_context
def _summary(ctx: jinja2.runtime.Context, report: ScanReport) -> str:
    return summary_sentence(report, _lang(ctx))


@jinja2.pass_context
def _grade_summary(ctx: jinja2.runtime.Context, report: ScanReport) -> str:
    return grade_summary(report, _lang(ctx))


@jinja2.pass_context
def _label(ctx: jinja2.runtime.Context, value: Severity | Category) -> str:
    return value.label_in(_lang(ctx))


@cache
def environment() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.PackageLoader("kalkan.report", "templates"),
        autoescape=jinja2.select_autoescape(("html", "htm", "xml"), default_for_string=True),
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=jinja2.StrictUndefined,
    )
    register_helpers(env)
    return env


def register_helpers(env: jinja2.Environment) -> None:
    env.filters.update(local_time=local_time, loc=_localize, label=_label)
    env.globals.update(
        _=_gettext,
        _m=_gettext_markup,
        Severity=Severity,
        Category=Category,
        LANGUAGES=LANGUAGES,
        PROBLEM_SEVERITIES=PROBLEM_SEVERITIES,
        top_actions=top_actions,
        summary_sentence=_summary,
        grade_summary=_grade_summary,
    )


def render_html(report: ScanReport, lang: str = DEFAULT_LANGUAGE) -> str:
    return environment().get_template("report.html").render(report=report, lang=lang)


# --- terminal ---------------------------------------------------------------

_ANSI = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[1;34m",
    Severity.INFO: "\033[2m",
    Severity.PASS: "\033[32m",
}
_GRADE_ANSI = {"A": "\033[1;32m", "B": "\033[1;32m", "C": "\033[1;33m", "D": "\033[1;31m"}
_RESET = "\033[0m"


def render_text(report: ScanReport, *, color: bool = False, lang: str = DEFAULT_LANGUAGE) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    def _(msgid: str, **params: Any) -> str:
        return translate(msgid, lang, **params)

    def loc(value: Any) -> str:
        return localize(value, lang)

    lines: list[str] = []
    grade_code = _GRADE_ANSI.get(report.grade, "\033[1;97;41m")
    lines.append(_("Kalkan güvenlik raporu: {domain}", domain=report.display_name))
    lines.append(
        _(
            "Not: {grade}  Puan: {score}/100  ({when})",
            grade=paint(f" {report.grade} ", grade_code),
            score=report.score,
            when=local_time(report.finished_at),
        )
    )
    lines.append(f"{grade_summary(report, lang)} {summary_sentence(report, lang)}")
    lines.append("")

    problems = report.problems
    if problems:
        lines.append(_("SORUNLAR"))
        for finding in problems:
            badge = paint(f"[{finding.severity.label_in(lang)}]", _ANSI[finding.severity])
            lines.append(f"  {badge} {loc(finding.title)}")
            if finding.recommendation:
                lines.append("      " + _("Ne yapmalı: {text}", text=loc(finding.recommendation)))
        lines.append("")
    if report.informational or report.notes:
        lines.append(_("BİLGİ"))
        lines.extend(f"  - {loc(f.title)}" for f in report.informational)
        lines.extend(f"  - {loc(note)}" for note in report.notes)
        lines.append("")
    if report.passed:
        lines.append(_("BAŞARILI KONTROLLER"))
        lines.extend(f"  {paint('✓', _ANSI[Severity.PASS])} {loc(f.title)}" for f in report.passed)
        lines.append("")
    if report.software:
        lines.append(_("TESPİT EDİLEN YAZILIMLAR"))
        for item in report.software:
            version = item.version or _("sürüm gizli")
            lines.append(f"  - {loc(item.name)} {version} ({loc(item.source)})")
        lines.append("")
    if report.errors:
        lines.append(_("TAMAMLANAMAYAN KONTROLLER"))
        lines.extend(f"  ! {loc(e.message)}" for e in report.errors)
        lines.append("")
    lines.append(_("Taranan adresler: {addresses}", addresses=", ".join(report.addresses)))
    return "\n".join(lines) + "\n"
