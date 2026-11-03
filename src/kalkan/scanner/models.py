"""Data model shared by the scanner, the report renderers and the web app.

User-facing text (titles, descriptions, recommendations) is Turkish because the
reports are written for Turkish small-business owners; identifiers stay English.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from kalkan.i18n import N_, LocalizedValue, from_json, to_json, translate


class Severity(enum.StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASS = "pass"  # noqa: S105 - a severity level, not a password

    @property
    def rank(self) -> int:
        """0 for the most severe; used for sorting."""
        return _SEVERITY_ORDER.index(self)

    @property
    def label(self) -> str:
        return _SEVERITY_LABELS[self]

    def label_in(self, lang: str) -> str:
        return translate(_SEVERITY_LABELS[self], lang)

    @property
    def is_problem(self) -> bool:
        return self not in (Severity.INFO, Severity.PASS)


_SEVERITY_ORDER = list(Severity)
_SEVERITY_LABELS = {
    Severity.CRITICAL: N_("Acil"),
    Severity.HIGH: N_("Yüksek"),
    Severity.MEDIUM: N_("Orta"),
    Severity.LOW: N_("Düşük"),
    Severity.INFO: N_("Bilgi"),
    Severity.PASS: N_("Başarılı"),
}


class Category(enum.StrEnum):
    TLS = "tls"
    HTTP = "http"
    EXPOSURE = "exposure"
    PORTS = "ports"
    SOFTWARE = "software"
    EMAIL = "email"
    DNS = "dns"

    @property
    def label(self) -> str:
        return _CATEGORY_LABELS[self]

    def label_in(self, lang: str) -> str:
        return translate(_CATEGORY_LABELS[self], lang)


_CATEGORY_LABELS = {
    Category.TLS: N_("SSL / TLS sertifikası"),
    Category.HTTP: N_("Web sunucusu ayarları"),
    Category.EXPOSURE: N_("Açıkta kalan dosyalar"),
    Category.PORTS: N_("Açık portlar"),
    Category.SOFTWARE: N_("Yazılım sürümleri"),
    Category.EMAIL: N_("E-posta güvenliği"),
    Category.DNS: N_("Alan adı (DNS) ayarları"),
}


@dataclass(slots=True)
class Finding:
    """One result of a check, written so a non-technical owner can act on it."""

    id: str
    category: Category
    severity: Severity
    title: LocalizedValue
    description: LocalizedValue = ""
    recommendation: LocalizedValue = ""
    # keys are fixed Turkish labels (translated when rendered); values may be Text
    details: Mapping[str, LocalizedValue] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": to_json(self.title),
            "description": to_json(self.description),
            "recommendation": to_json(self.recommendation),
            "details": {key: to_json(value) for key, value in self.details.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            id=data["id"],
            category=Category(data["category"]),
            severity=Severity(data["severity"]),
            title=from_json(data["title"]),
            description=from_json(data.get("description", "")),
            recommendation=from_json(data.get("recommendation", "")),
            details={str(k): from_json(v) for k, v in data.get("details", {}).items()},
        )


@dataclass(slots=True)
class DetectedSoftware:
    """A product/version pair fingerprinted from a header, banner or HTML."""

    product: str  # key in the software database, e.g. "php"
    name: LocalizedValue  # display name, e.g. "PHP"
    version: str | None
    source: LocalizedValue  # where it was seen, e.g. the header name
    distro: str | None = None  # e.g. "Ubuntu": distro packages often backport fixes

    def to_dict(self) -> dict[str, Any]:
        return {
            "product": self.product,
            "name": to_json(self.name),
            "version": self.version,
            "source": to_json(self.source),
            "distro": self.distro,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DetectedSoftware:
        return cls(
            product=data["product"],
            name=from_json(data["name"]),
            version=data.get("version"),
            source=from_json(data.get("source", "")),
            distro=data.get("distro"),
        )


@dataclass(slots=True)
class CheckError:
    """A check that could not complete; reported instead of failing the scan."""

    check: str
    message: LocalizedValue

    def to_dict(self) -> dict[str, Any]:
        return {"check": self.check, "message": to_json(self.message)}


@dataclass(slots=True)
class ScanReport:
    target: str
    display_name: str
    addresses: list[str]
    started_at: datetime
    finished_at: datetime
    findings: list[Finding]
    software: list[DetectedSoftware]
    open_ports: list[int]
    errors: list[CheckError]
    score: int
    grade: str
    tool_version: str
    notes: list[LocalizedValue] = field(default_factory=list)

    @property
    def problems(self) -> list[Finding]:
        return [f for f in self.findings if f.severity.is_problem]

    @property
    def passed(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.PASS]

    @property
    def informational(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.INFO]

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity is severity)

    def worst_severity(self) -> Severity:
        return min((f.severity for f in self.findings), key=lambda s: s.rank, default=Severity.PASS)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "display_name": self.display_name,
            "addresses": list(self.addresses),
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "score": self.score,
            "grade": self.grade,
            "tool_version": self.tool_version,
            "summary": {s.value: self.count(s) for s in Severity},
            "findings": [f.to_dict() for f in self.findings],
            "software": [s.to_dict() for s in self.software],
            "open_ports": list(self.open_ports),
            "errors": [e.to_dict() for e in self.errors],
            "notes": [to_json(note) for note in self.notes],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanReport:
        return cls(
            target=data["target"],
            display_name=data.get("display_name", data["target"]),
            addresses=list(data.get("addresses", [])),
            started_at=datetime.fromisoformat(data["started_at"]),
            finished_at=datetime.fromisoformat(data["finished_at"]),
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            software=[DetectedSoftware.from_dict(s) for s in data.get("software", [])],
            open_ports=[int(p) for p in data.get("open_ports", [])],
            errors=[
                CheckError(e["check"], from_json(e["message"])) for e in data.get("errors", [])
            ],
            score=int(data["score"]),
            grade=str(data["grade"]),
            tool_version=str(data.get("tool_version", "")),
            notes=[from_json(note) for note in data.get("notes", [])],
        )
