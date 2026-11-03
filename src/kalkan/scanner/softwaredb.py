"""Release/EOL knowledge base used to judge detected software versions.

The bundled ``data/software.json`` is generated from https://endoflife.date by
``scripts/update_software_db.py``; scans never need network access for it.
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass
from datetime import date
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any

from kalkan.i18n import LocalizedValue, from_json
from kalkan.scanner.versions import Version, parse_cycle, parse_version


class Status(enum.StrEnum):
    EOL = "eol"  # release line no longer receives security fixes
    VULNERABLE = "vulnerable"  # below the product's known minimum safe version
    OUTDATED = "outdated"  # supported line, but missing patch releases
    CURRENT = "current"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ReleaseCycle:
    cycle: str
    eol: date | bool  # False: supported, True: EOL with unknown date
    latest: str | None

    @property
    def prefix(self) -> tuple[int, ...]:
        return parse_cycle(self.cycle)

    def is_eol(self, today: date) -> bool:
        if isinstance(self.eol, bool):
            return self.eol
        return self.eol <= today


@dataclass(frozen=True, slots=True)
class ProductInfo:
    key: str
    name: str
    cycles: tuple[ReleaseCycle, ...]
    minimum_safe: str | None = None
    minimum_safe_reason: LocalizedValue | None = None

    def supported_cycles(self, today: date) -> list[ReleaseCycle]:
        live = [c for c in self.cycles if not c.is_eol(today)]
        return sorted(live, key=lambda c: c.prefix, reverse=True)


@dataclass(frozen=True, slots=True)
class Evaluation:
    status: Status
    product: ProductInfo
    version: Version
    cycle: ReleaseCycle | None = None

    @property
    def latest_in_cycle(self) -> str | None:
        return self.cycle.latest if self.cycle else None

    @property
    def eol_date(self) -> date | None:
        if self.cycle and isinstance(self.cycle.eol, date):
            return self.cycle.eol
        return None


def _parse_eol(value: Any) -> date | bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError:
            return False
    return False


class SoftwareDatabase:
    def __init__(self, products: dict[str, ProductInfo], generated_at: date | None = None) -> None:
        self.products = products
        self.generated_at = generated_at

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SoftwareDatabase:
        products: dict[str, ProductInfo] = {}
        for key, raw in data.get("products", {}).items():
            cycles = tuple(
                ReleaseCycle(
                    cycle=str(c.get("cycle", "")),
                    eol=_parse_eol(c.get("eol")),
                    latest=str(c["latest"]) if c.get("latest") else None,
                )
                for c in raw.get("cycles", [])
            )
            products[key] = ProductInfo(
                key=key,
                name=raw.get("name", key),
                cycles=cycles,
                minimum_safe=raw.get("minimum_safe"),
                minimum_safe_reason=(
                    from_json(raw["minimum_safe_reason"])
                    if raw.get("minimum_safe_reason")
                    else None
                ),
            )
        generated = data.get("generated_at")
        return cls(products, date.fromisoformat(generated) if generated else None)

    @classmethod
    def from_file(cls, path: Path) -> SoftwareDatabase:
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))

    @classmethod
    def bundled(cls) -> SoftwareDatabase:
        return _bundled()

    def name_of(self, key: str) -> str:
        product = self.products.get(key)
        return product.name if product else key

    def evaluate(self, key: str, version_text: str | None, today: date) -> Evaluation | None:
        product = self.products.get(key)
        if product is None or not version_text or not product.cycles:
            return None
        version = parse_version(version_text)
        if version is None:
            return None

        matches = [
            c
            for c in product.cycles
            if len(c.prefix) <= len(version.parts) and version.has_prefix(c.prefix)
        ]
        cycle = max(matches, key=lambda c: len(c.prefix)) if matches else None

        if cycle is not None and cycle.is_eol(today):
            return Evaluation(Status.EOL, product, version, cycle)
        if product.minimum_safe:
            minimum = parse_version(product.minimum_safe)
            if minimum is not None and version < minimum:
                return Evaluation(Status.VULNERABLE, product, version, cycle)
        if cycle is None:
            prefixes = [c.prefix for c in product.cycles if c.prefix]
            if prefixes and version.parts < min(prefixes):
                return Evaluation(Status.EOL, product, version, None)
            if prefixes and version.parts > max(prefixes):
                return Evaluation(Status.CURRENT, product, version, None)
            return Evaluation(Status.UNKNOWN, product, version, None)
        if cycle.latest:
            latest = parse_version(cycle.latest)
            if latest is not None and version < latest:
                return Evaluation(Status.OUTDATED, product, version, cycle)
        return Evaluation(Status.CURRENT, product, version, cycle)


@cache
def _bundled() -> SoftwareDatabase:
    text = resources.files("kalkan.scanner").joinpath("data/software.json").read_text("utf-8")
    return SoftwareDatabase.from_dict(json.loads(text))
