"""Report renderers (text, JSON, HTML, PDF) and scan comparison."""

from kalkan.report.compare import Comparison, compare_reports
from kalkan.report.pdf import render_pdf
from kalkan.report.render import render_html, render_json, render_text

__all__ = [
    "Comparison",
    "compare_reports",
    "render_html",
    "render_json",
    "render_pdf",
    "render_text",
]
