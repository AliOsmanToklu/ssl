"""Decide whether a finished scan is worth an e-mail, by comparing it to the previous one.

Only *new or worse* important problems alert, so an unfixed issue does not send the
same e-mail every week.
"""

from __future__ import annotations

from dataclasses import dataclass

from kalkan.scanner.models import Finding, ScanReport, Severity

ALERT_SEVERITIES = (Severity.CRITICAL, Severity.HIGH)
# Always worth an e-mail, whatever their severity: the site is about to break.
ALWAYS_ALERT = frozenset({"tls.cert_expiring", "tls.cert_expired"})
GRADES = "ABCDF"
ALERT_GRADES = frozenset("CDF")


@dataclass(frozen=True, slots=True)
class Alert:
    findings: list[Finding]
    grade_change: tuple[str, str] | None


def compute_alert(previous: ScanReport | None, current: ScanReport) -> Alert | None:
    before = {f.id: f.severity for f in previous.findings} if previous else {}
    new = [
        f
        for f in current.problems
        if (f.severity in ALERT_SEVERITIES or f.id in ALWAYS_ALERT)
        and (f.id not in before or f.severity.rank < before[f.id].rank)
    ]
    grade_change = None
    if (
        previous is not None
        and current.grade in ALERT_GRADES
        and GRADES.index(current.grade) > GRADES.index(previous.grade)
    ):
        grade_change = (previous.grade, current.grade)
    if not new and grade_change is None:
        return None
    return Alert(new, grade_change)
