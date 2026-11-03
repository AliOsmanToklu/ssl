"""Lenient version parsing for banners such as "9.8p1", "1.3.9e" or "8.1.2-1ubuntu2"."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import total_ordering

_VERSION_RE = re.compile(r"(\d+(?:\.\d+)*)(?:[-_.]?([a-z]+)\.?(\d*))?", re.IGNORECASE)
_PRERELEASE = {"a", "alpha", "b", "beta", "rc", "pre", "dev", "preview"}
_PAD = 6


@total_ordering
@dataclass(frozen=True, slots=True)
class Version:
    parts: tuple[int, ...]
    suffix: str = ""  # letter patch level ("e" in 1.3.9e, "p" in 9.8p1) or pre-release tag
    suffix_number: int = 0
    raw: str = field(default="", compare=False)

    @property
    def is_prerelease(self) -> bool:
        return self.suffix in _PRERELEASE

    def _key(self) -> tuple[tuple[int, ...], int, str, int]:
        padded = self.parts + (0,) * (_PAD - len(self.parts))
        # pre-release < plain release < letter-patched release
        stage = 0 if self.is_prerelease else (1 if not self.suffix else 2)
        return padded[:_PAD], stage, self.suffix, self.suffix_number

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._key() < other._key()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._key() == other._key()

    def __hash__(self) -> int:
        return hash(self._key())

    def has_prefix(self, prefix: tuple[int, ...]) -> bool:
        return self.parts[: len(prefix)] == prefix

    def __str__(self) -> str:
        return self.raw or ".".join(map(str, self.parts))


def parse_version(text: str) -> Version | None:
    """Parse the first version-looking token in ``text``; ``None`` if there is none."""
    match = _VERSION_RE.search(text)
    if not match:
        return None
    parts = tuple(int(p) for p in match.group(1).split("."))
    suffix = (match.group(2) or "").lower()
    number = int(match.group(3)) if match.group(3) else 0
    raw = match.group(0)
    if suffix and suffix not in _PRERELEASE and len(suffix) > 2:
        # "10.6.12-MariaDB" / "8.1-ubuntu" style tags are not part of the upstream version
        suffix, number, raw = "", 0, match.group(1)
    return Version(parts=parts, suffix=suffix, suffix_number=number, raw=raw)


def parse_cycle(cycle: str) -> tuple[int, ...]:
    if not cycle:
        return ()
    return tuple(int(p) for p in re.findall(r"\d+", cycle))
