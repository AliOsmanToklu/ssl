"""What changed between two scans of the same site: score, new and resolved problems."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from kalkan.scanner.models import Finding, ScanReport


@dataclass(frozen=True, slots=True)
class Comparison:
    previous_grade: str
    previous_score: int
    previous_at: datetime
    score_delta: int
    new_problems: list[Finding]  # appeared, or became more severe
    resolved: list[Finding]  # present last time, gone now

    @property
    def unchanged(self) -> bool:
        return not self.new_problems and not self.resolved and self.score_delta == 0


def compare_reports(previous: ScanReport, current: ScanReport) -> Comparison:
    before = {f.id: f for f in previous.problems}
    after = {f.id: f for f in current.problems}
    new = [
        f
        for f in current.problems
        if f.id not in before or f.severity.rank < before[f.id].severity.rank
    ]
    resolved = [f for f in previous.problems if f.id not in after]
    return Comparison(
        previous_grade=previous.grade,
        previous_score=previous.score,
        previous_at=previous.finished_at,
        score_delta=current.score - previous.score,
        new_problems=new,
        resolved=resolved,
    )
