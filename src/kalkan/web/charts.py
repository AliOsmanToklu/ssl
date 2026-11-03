"""Geometry for the score-history chart on the domain page.

Pure SVG, no JavaScript and no inline ``style`` attributes (the page's CSP allows
neither). The plot has a fixed pixel height; horizontal positions are percentages, so
the chart stretches to any width without distorting text or dots. Each point is a
nested ``<svg x="..%">`` whose children (dot, crosshair, tooltip) are drawn in pixels.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from kalkan.report.render import local_time
from kalkan.web.models import Scan, ScanStatus

MAX_POINTS = 30
HEIGHT = 200  # px, the whole chart
TOP, BOTTOM = 14, 176  # px, score 100 and score 0
X_PAD = 3.0  # % kept free at both ends so edge dots are not cut
GRADE_LINES = (90, 80, 65, 50)  # grade lower bounds, drawn as hairlines
GRADE_BANDS = (("A", 95), ("B", 85), ("C", 72.5), ("D", 57.5), ("F", 25))


def y_of(score: float) -> float:
    return round(TOP + (100 - score) * (BOTTOM - TOP) / 100, 1)


@dataclass(frozen=True, slots=True)
class ChartPoint:
    x: float  # % from the left
    y: float  # px from the top
    score: int
    grade: str
    when: str
    scan_id: int

    @property
    def tip_x(self) -> int:
        """Horizontal shift of the 112 px tooltip so it stays inside the plot near the edges
        (narrow screens included: the plot can be under 300 px wide)."""
        if self.x > 80:
            return -48
        if self.x < 20:
            return 48
        return 0

    @property
    def tip_y(self) -> float:
        """Tooltip anchor: above the dot, or below it when the dot is near the top."""
        return self.y - 12 if self.y > TOP + 44 else self.y + 48


@dataclass(frozen=True, slots=True)
class Segment:
    x1: float
    y1: float
    x2: float
    y2: float


@dataclass(frozen=True, slots=True)
class ScoreChart:
    points: list[ChartPoint]
    height: int = HEIGHT
    top: int = TOP
    bottom: int = BOTTOM

    @property
    def segments(self) -> list[Segment]:
        return [
            Segment(a.x, a.y, b.x, b.y) for a, b in zip(self.points, self.points[1:], strict=False)
        ]

    @property
    def gridlines(self) -> list[float]:
        return [y_of(score) for score in GRADE_LINES]

    @property
    def bands(self) -> list[tuple[float, str]]:
        return [(y_of(middle) + 4, grade) for grade, middle in GRADE_BANDS]

    @property
    def ticks(self) -> list[tuple[float, int]]:
        return [(y_of(score) + 4, score) for score in (100, 50, 0)]

    @property
    def first(self) -> ChartPoint:
        return self.points[0]

    @property
    def last(self) -> ChartPoint:
        return self.points[-1]


def score_chart(scans: Iterable[Scan]) -> ScoreChart | None:
    """Chart of the latest finished scans; ``None`` until there are two to connect."""
    done = sorted(
        (
            (s.finished_at, s.id, s.score, s.grade)
            for s in scans
            if s.status is ScanStatus.DONE and s.score is not None and s.finished_at is not None
        ),
    )[-MAX_POINTS:]
    if len(done) < 2:
        return None
    start, end = done[0][0], done[-1][0]
    span = (end - start).total_seconds()
    points = []
    for index, (finished_at, scan_id, score, grade) in enumerate(done):
        # time-proportional, so a gap between scans looks like a gap
        fraction = (
            (finished_at - start).total_seconds() / span if span > 0 else index / (len(done) - 1)
        )
        points.append(
            ChartPoint(
                x=round(X_PAD + fraction * (100 - 2 * X_PAD), 2),
                y=y_of(score),
                score=score,
                grade=grade or "-",
                when=local_time(finished_at),
                scan_id=scan_id,
            )
        )
    return ScoreChart(points)
