"""Run all checks against one target and assemble the report."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from kalkan import __version__
from kalkan.i18n import T
from kalkan.scanner.checks import CHECKS, CheckSpec
from kalkan.scanner.context import ScanContext, ScanOptions
from kalkan.scanner.http_client import PinnedHttpClient
from kalkan.scanner.models import CheckError, Finding, ScanReport
from kalkan.scanner.scoring import compute_score
from kalkan.scanner.softwaredb import SoftwareDatabase
from kalkan.scanner.target import resolve_target

log = logging.getLogger(__name__)

CHECK_TIMEOUT = 90.0
_CATEGORY_ORDER = {spec.name: index for index, spec in enumerate(CHECKS)}


async def _run_check(spec: CheckSpec, ctx: ScanContext) -> tuple[list[Finding], CheckError | None]:
    try:
        async with asyncio.timeout(CHECK_TIMEOUT):
            return await spec.run(ctx), None
    except TimeoutError:
        return [], CheckError(spec.name, T("{label}: zaman aşımı", label=T(spec.label)))
    except Exception as exc:
        log.exception("check %s failed for %s", spec.name, ctx.target.hostname)
        return [], CheckError(
            spec.name,
            T("{label}: {error}", label=T(spec.label), error=f"{type(exc).__name__}: {exc}"),
        )


async def scan(target: str, options: ScanOptions | None = None) -> ScanReport:
    """Scan ``target`` (a domain or URL). Raises ``TargetError`` for unscannable input."""
    options = options or ScanOptions()
    started = datetime.now(UTC)
    resolved = await resolve_target(
        target, resolver=options.resolver, allow_private=options.allow_private
    )
    findings: list[Finding] = []
    errors: list[CheckError] = []
    async with PinnedHttpClient(
        resolver=options.resolver,
        allow_private=options.allow_private,
        timeout=options.timeout,
        transport=options.http_transport,
    ) as client:
        ctx = ScanContext(
            target=resolved,
            options=options,
            http=client,
            software_db=options.software_db or SoftwareDatabase.bundled(),
        )
        for stage in sorted({spec.stage for spec in CHECKS}):
            specs = [s for s in CHECKS if s.stage == stage and options.wants(s.name)]
            for found, error in await asyncio.gather(*(_run_check(s, ctx) for s in specs)):
                findings.extend(found)
                if error is not None:
                    errors.append(error)

    findings.sort(
        key=lambda f: (f.severity.rank, _CATEGORY_ORDER.get(f.category.value, 99), str(f.title))
    )
    score, grade = compute_score(findings)
    return ScanReport(
        target=resolved.hostname,
        display_name=resolved.display_name,
        addresses=list(resolved.addresses),
        started_at=started,
        finished_at=datetime.now(UTC),
        findings=findings,
        software=list(ctx.software),
        open_ports=list(ctx.facts.open_ports),
        errors=errors,
        score=score,
        grade=grade,
        tool_version=__version__,
        notes=list(dict.fromkeys(ctx.notes)),
    )
