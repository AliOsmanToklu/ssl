"""Latest-version and status lookups for WordPress plugins and themes (api.wordpress.org).

The API host is fixed, so this client does not go through the SSRF-guarded pinned
client. Answers are cached per process: a worker scanning many WordPress sites asks
about popular plugins once every few hours, not on every scan.
"""

from __future__ import annotations

import html
import logging
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import date
from typing import Any, Literal

import httpx

from kalkan import __version__

log = logging.getLogger(__name__)

Kind = Literal["plugin", "theme"]
CACHE_SECONDS = 6 * 3600


@dataclass(frozen=True, slots=True)
class WpInfo:
    slug: str
    name: str
    latest: str | None
    last_updated: date | None = None
    closed: bool = False
    closed_reason: str | None = None  # e.g. "security-issue", "author-request"


WpLookup = Callable[[Kind, str], Awaitable[WpInfo | None]]

_DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")


def _date(value: Any) -> date | None:
    match = _DATE_RE.search(str(value or ""))
    return date.fromisoformat(match.group(1)) if match else None


def parse_info(slug: str, data: dict[str, Any]) -> WpInfo | None:
    """Turn an API answer into :class:`WpInfo`; ``None`` for unknown (e.g. premium) items."""
    if data.get("error") == "closed" or data.get("closed"):
        return WpInfo(
            slug=slug,
            name=html.unescape(str(data.get("name") or slug)),
            latest=None,
            last_updated=_date(data.get("closed_date")),
            closed=True,
            closed_reason=str(data.get("reason") or "") or None,
        )
    if "error" in data or not data.get("version"):
        return None
    return WpInfo(
        slug=slug,
        name=html.unescape(str(data.get("name") or slug)),
        latest=str(data["version"]),
        last_updated=_date(data.get("last_updated")),
    )


class WordPressOrg:
    URL = "https://api.wordpress.org/{kind}s/info/1.2/"

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport
        self._cache: dict[tuple[Kind, str], tuple[float, WpInfo | None]] = {}

    async def __call__(self, kind: Kind, slug: str) -> WpInfo | None:
        key = (kind, slug)
        cached = self._cache.get(key)
        if cached and cached[0] > time.monotonic():
            return cached[1]
        params = {
            "action": f"{kind}_information",
            "request[slug]": slug,
            "request[fields][sections]": "0",
            "request[fields][versions]": "0",
            "request[fields][reviews]": "0",
            "request[fields][screenshots]": "0",
        }
        try:
            async with httpx.AsyncClient(
                timeout=8.0,
                transport=self._transport,
                headers={"User-Agent": f"KalkanScanner/{__version__}"},
            ) as client:
                response = await client.get(self.URL.format(kind=kind), params=params)
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("wordpress.org lookup for %s %s failed: %s", kind, slug, exc)
            return None  # not cached: try again on the next scan
        info = parse_info(slug, data) if isinstance(data, dict) else None
        self._cache[key] = (time.monotonic() + CACHE_SECONDS, info)
        return info


wordpress_org = WordPressOrg()
