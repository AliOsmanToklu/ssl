"""Turn findings into a 0-100 score and an A-F grade owners can compare over time."""

from __future__ import annotations

from collections.abc import Iterable

from kalkan.i18n import N_
from kalkan.scanner.models import Finding, Severity

PENALTIES = {
    Severity.CRITICAL: 35,
    Severity.HIGH: 15,
    Severity.MEDIUM: 7,
    Severity.LOW: 2,
}
# The worst finding caps the score: one critical problem can't hide behind many passes.
CAPS = {
    Severity.CRITICAL: 49,
    Severity.HIGH: 79,
}
GRADES = ((90, "A"), (80, "B"), (65, "C"), (50, "D"), (0, "F"))

GRADE_SUMMARIES = {
    "A": N_("Siteniz çok iyi korunuyor."),
    "B": N_("Siteniz iyi durumda; birkaç küçük iyileştirme yapılabilir."),
    "C": N_("Sitenizde ilgilenmeniz gereken önemli sorunlar var."),
    "D": N_("Sitenizde ciddi güvenlik sorunları var; kısa sürede ele alınmalı."),
    "F": N_("Sitenizde acil müdahale gerektiren sorunlar var."),
}


def compute_score(findings: Iterable[Finding]) -> tuple[int, str]:
    items = list(findings)
    score = 100 - sum(PENALTIES.get(f.severity, 0) for f in items)
    for severity, cap in CAPS.items():
        if any(f.severity is severity for f in items):
            score = min(score, cap)
    score = max(0, min(100, score))
    return score, grade_for(score)


def grade_for(score: int) -> str:
    for threshold, grade in GRADES:
        if score >= threshold:
            return grade
    return "F"
