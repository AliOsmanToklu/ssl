"""Background worker: runs queued scans, schedules re-scans, sends alerts and onboarding mail.

The ``scans`` table is the queue. A worker claims a job with a conditional
``UPDATE ... WHERE status = 'queued'``; only one worker's update can match, so
any number of workers (threads, processes or containers) can share the queue
without Redis or row locks, on both SQLite and PostgreSQL. The scheduler uses
the same trick on ``domains.next_scan_at`` and ``users.onboarding_reminded_at``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session, sessionmaker

from kalkan.i18n import T, Text
from kalkan.scanner import ScanOptions, ScanReport, TargetError, scan
from kalkan.web.alerts import compute_alert
from kalkan.web.config import Settings
from kalkan.web.db import make_engine, make_session_factory, utcnow
from kalkan.web.emails import (
    first_report_email,
    onboarding_reminder_email,
    ownership_lost_email,
    scan_alert_email,
)
from kalkan.web.mail import Email, Mailer, deliver, make_mailer
from kalkan.web.metrics import (
    OWNERSHIP_CHECKS,
    SCAN_DURATION,
    SCAN_QUEUE,
    SCANS,
    SCHEDULED_SCANS,
)
from kalkan.web.migrate import ensure_current
from kalkan.web.models import (
    Domain,
    Membership,
    Organization,
    Role,
    Scan,
    ScanStatus,
    ScanTrigger,
    User,
)
from kalkan.web.services import has_active_scan
from kalkan.web.verification import VerificationResult, verify_ownership

log = logging.getLogger(__name__)

Scanner = Callable[[str, ScanOptions], Awaitable[ScanReport]]
Verifier = Callable[..., Awaitable[VerificationResult]]

OWNERSHIP_LOST_MESSAGE = T(
    "Alan adının size ait olduğunu gösteren DNS kaydı veya dosya artık bulunamadı. "
    "Taramaya devam etmek için alan adını yeniden doğrulayın."
)
CRASH_MESSAGE = T("Tarama sırasında beklenmeyen bir hata oluştu. Lütfen tekrar deneyin.")
ONBOARDING_AFTER = timedelta(days=2)


@dataclass(frozen=True, slots=True)
class Job:
    scan_id: int
    domain_id: int
    hostname: str
    trigger: ScanTrigger
    verification_token: str
    verified_at: datetime | None


def recipients(organization: Organization, least: Role = Role.MEMBER) -> list[User]:
    """Members with a verified address and at least the given role."""
    return [
        m.user for m in organization.memberships if m.role.at_least(least) and m.user.email_verified
    ]


class ScanWorker:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        settings: Settings,
        scanner: Scanner = scan,
        *,
        mailer: Mailer | None = None,
        verifier: Verifier = verify_ownership,
    ) -> None:
        self.session_factory = session_factory
        self.settings = settings
        self.scanner = scanner
        self.mailer = mailer or make_mailer(settings)
        self.verifier = verifier

    # -- queue (sync; run in a thread from the event loop) -----------------

    def claim(self) -> Job | None:
        with self.session_factory() as db:
            candidate = db.scalar(
                select(Scan.id)
                .where(Scan.status == ScanStatus.QUEUED)
                .order_by(Scan.created_at, Scan.id)
                .limit(1)
            )
            if candidate is None:
                return None
            claimed = db.execute(
                update(Scan)
                .where(Scan.id == candidate, Scan.status == ScanStatus.QUEUED)
                .values(status=ScanStatus.RUNNING, started_at=utcnow())
            )
            db.commit()
            if claimed.rowcount != 1:  # type: ignore[attr-defined]
                return None  # another worker won the race
            job = db.get(Scan, candidate)
            if job is None:  # domain (and its scans) deleted meanwhile
                return None
            return Job(
                scan_id=job.id,
                domain_id=job.domain_id,
                hostname=job.domain.hostname,
                trigger=job.trigger,
                verification_token=job.domain.verification_token,
                verified_at=job.domain.verified_at,
            )

    def complete(self, job: Job, report: ScanReport) -> list[Email]:
        """Store the report; returns the e-mails it should trigger."""
        with self.session_factory() as db:
            db.execute(
                update(Scan)
                .where(Scan.id == job.scan_id)
                .values(
                    status=ScanStatus.DONE,
                    finished_at=utcnow(),
                    score=report.score,
                    grade=report.grade,
                    report_data=report.to_dict(),
                    error=None,
                    error_detail=None,
                )
            )
            db.commit()
            scan_row = db.get(Scan, job.scan_id)
            domain = db.get(Domain, job.domain_id)
            if scan_row is None or domain is None:
                return []
            link = self.settings.link(f"/scans/{job.scan_id}")
            previous = db.scalar(
                select(Scan)
                .where(
                    Scan.domain_id == job.domain_id,
                    Scan.status == ScanStatus.DONE,
                    Scan.id != job.scan_id,
                )
                .order_by(Scan.finished_at.desc(), Scan.id.desc())
                .limit(1)
            )
            if previous is None:  # first report for this domain: a friendly summary
                if job.trigger is ScanTrigger.API or (
                    job.trigger is ScanTrigger.SCHEDULED and not domain.notify_email
                ):
                    return []
                people = (
                    [scan_row.requested_by]
                    if scan_row.requested_by is not None and scan_row.requested_by.email_verified
                    else recipients(domain.organization, Role.ADMIN)
                )
                return [first_report_email(u.email, report, link, u.locale) for u in people]
            if job.trigger is not ScanTrigger.SCHEDULED or not domain.notify_email:
                return []
            alert = compute_alert(previous.report, report)
            if alert is None:
                return []
            return [
                scan_alert_email(
                    u.email,
                    domain.display_name,
                    alert.findings,
                    alert.grade_change,
                    link,
                    u.locale,
                )
                for u in recipients(domain.organization)
            ]

    def fail(self, job: Job, message: Text | str) -> None:
        detail = message.to_json() if isinstance(message, Text) else None
        with self.session_factory() as db:
            db.execute(
                update(Scan)
                .where(Scan.id == job.scan_id)
                .values(
                    status=ScanStatus.FAILED,
                    finished_at=utcnow(),
                    error=str(message),
                    error_detail=detail,
                )
            )
            db.commit()

    def recover_stale(self) -> int:
        """Re-queue scans left 'running' by a worker that crashed or was killed."""
        cutoff = utcnow() - timedelta(minutes=self.settings.stale_scan_minutes)
        with self.session_factory() as db:
            result = db.execute(
                update(Scan)
                .where(Scan.status == ScanStatus.RUNNING, Scan.started_at < cutoff)
                .values(status=ScanStatus.QUEUED, started_at=None)
            )
            db.commit()
            count: int = result.rowcount  # type: ignore[attr-defined]
        if count:
            log.warning("re-queued %d stale scan(s)", count)
        return count

    # -- ownership re-check ------------------------------------------------

    def needs_reverification(self, job: Job) -> bool:
        if self.settings.skip_verification:
            return False
        if job.verified_at is None:
            return True  # verification was withdrawn after the scan was queued
        return utcnow() - job.verified_at > timedelta(days=self.settings.reverify_after_days)

    def ownership_confirmed(self, job: Job, method: str) -> None:
        with self.session_factory() as db:
            db.execute(
                update(Domain)
                .where(Domain.id == job.domain_id)
                .values(verified_at=utcnow(), verification_method=method)
            )
            db.commit()

    def ownership_lost(self, job: Job) -> list[Email]:
        """Withdraw verification, fail the scan and tell the people who can fix it."""
        with self.session_factory() as db:
            domain = db.get(Domain, job.domain_id)
            if domain is None:
                return []
            domain.verified_at = None
            domain.verification_method = None
            db.execute(
                update(Scan)
                .where(Scan.id == job.scan_id)
                .values(
                    status=ScanStatus.FAILED,
                    finished_at=utcnow(),
                    error=str(OWNERSHIP_LOST_MESSAGE),
                    error_detail=OWNERSHIP_LOST_MESSAGE.to_json(),
                )
            )
            db.commit()
            link = self.settings.link(f"/domains/{domain.id}")
            return [
                ownership_lost_email(u.email, domain.display_name, link, u.locale)
                for u in recipients(domain.organization, Role.ADMIN)
            ]

    async def _still_owned(self, job: Job) -> bool:
        result = await self.verifier(
            job.hostname,
            job.verification_token,
            allow_private=self.settings.allow_private_targets,
        )
        OWNERSHIP_CHECKS.labels("ok" if result.ok else "lost").inc()
        if result.ok:
            await asyncio.to_thread(self.ownership_confirmed, job, result.method or "unknown")
            return True
        log.warning("ownership of %s could not be confirmed", job.hostname)
        await self._send(await asyncio.to_thread(self.ownership_lost, job))
        return False

    async def _send(self, emails: list[Email]) -> None:
        for email in emails:
            await asyncio.to_thread(deliver, self.mailer, email)

    # -- scheduler ---------------------------------------------------------

    def schedule_due(self) -> int:
        """Queue scans for domains whose automatic re-scan is due. Returns how many."""
        now = utcnow()
        queued = 0
        with self.session_factory() as db:
            due = db.scalars(
                select(Domain)
                .where(Domain.scan_interval_days > 0, Domain.next_scan_at <= now)
                .order_by(Domain.next_scan_at)
                .limit(200)
            ).all()
            for domain in due:
                claimed = db.execute(
                    update(Domain)
                    .where(Domain.id == domain.id, Domain.next_scan_at == domain.next_scan_at)
                    .values(next_scan_at=now + timedelta(days=domain.scan_interval_days))
                )
                if claimed.rowcount != 1:  # type: ignore[attr-defined]
                    db.rollback()  # another scheduler took it
                    continue
                if self._may_schedule(db, domain):
                    db.add(Scan(domain_id=domain.id, trigger=ScanTrigger.SCHEDULED))
                    queued += 1
                db.commit()
        if queued:
            SCHEDULED_SCANS.inc(queued)
            log.info("scheduled %d automatic scan(s)", queued)
        return queued

    def _may_schedule(self, db: Session, domain: Domain) -> bool:
        if not domain.is_verified and not self.settings.skip_verification:
            return False
        organization = domain.organization
        if domain.scan_interval_days not in organization.limits.intervals:
            return False  # the plan no longer includes this schedule
        if self.settings.require_email_verification and not recipients(organization):
            return False
        return not has_active_scan(db, domain)

    def onboarding_reminders(self) -> list[Email]:
        """One nudge for people who signed up days ago but never verified a domain."""
        now = utcnow()
        emails: list[Email] = []
        with self.session_factory() as db:
            candidates = db.scalars(
                select(User)
                .where(
                    User.onboarding_reminded_at.is_(None),
                    User.email_verified_at.is_not(None),
                    User.created_at <= now - ONBOARDING_AFTER,
                )
                .limit(100)
            ).all()
            for user in candidates:
                claimed = db.execute(
                    update(User)
                    .where(User.id == user.id, User.onboarding_reminded_at.is_(None))
                    .values(onboarding_reminded_at=now)
                )
                db.commit()
                if claimed.rowcount != 1:  # type: ignore[attr-defined]
                    continue
                has_verified_domain = db.scalar(
                    select(func.count(Domain.id))
                    .join(Membership, Membership.organization_id == Domain.organization_id)
                    .where(Membership.user_id == user.id, Domain.verified_at.is_not(None))
                )
                if not has_verified_domain:
                    emails.append(
                        onboarding_reminder_email(
                            user.email, self.settings.link("/dashboard"), user.locale
                        )
                    )
        return emails

    def queue_depth(self) -> dict[str, int]:
        with self.session_factory() as db:
            rows = db.execute(
                select(Scan.status, func.count(Scan.id))
                .where(Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]))
                .group_by(Scan.status)
            ).all()
        depth = {ScanStatus.QUEUED.value: 0, ScanStatus.RUNNING.value: 0}
        depth.update({status.value: count for status, count in rows})
        for status, count in depth.items():
            SCAN_QUEUE.labels(status).set(count)
        return depth

    # -- event loop --------------------------------------------------------

    async def run_once(self) -> bool:
        """Process at most one job. Returns False when the queue was empty."""
        job = await asyncio.to_thread(self.claim)
        if job is None:
            return False
        log.info("scan %d started: %s (%s)", job.scan_id, job.hostname, job.trigger.value)
        if self.needs_reverification(job) and not await self._still_owned(job):
            SCANS.labels("ownership_lost", job.trigger.value).inc()
            return True
        options = ScanOptions(
            allow_private=self.settings.allow_private_targets, timeout=self.settings.scan_timeout
        )
        started = time.perf_counter()
        try:
            report = await self.scanner(job.hostname, options)
        except TargetError as exc:
            await asyncio.to_thread(self.fail, job, exc.text)
            SCANS.labels("failed", job.trigger.value).inc()
        except Exception:
            log.exception("scan %d crashed", job.scan_id)
            await asyncio.to_thread(self.fail, job, CRASH_MESSAGE)
            SCANS.labels("error", job.trigger.value).inc()
        else:
            SCAN_DURATION.observe(time.perf_counter() - started)
            emails = await asyncio.to_thread(self.complete, job, report)
            SCANS.labels("done", job.trigger.value).inc()
            log.info("scan %d finished: grade %s", job.scan_id, report.grade)
            await self._send(emails)
        return True

    async def _loop(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                processed = await self.run_once()
            except Exception:  # database hiccup: keep the worker alive
                log.exception("worker iteration failed")
                processed = False
            if not processed:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), self.settings.worker_poll_interval)

    async def _scheduler_loop(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                await asyncio.to_thread(self.schedule_due)
                await self._send(await asyncio.to_thread(self.onboarding_reminders))
                await asyncio.to_thread(self.queue_depth)
            except Exception:
                log.exception("scheduler iteration failed")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), self.settings.scheduler_interval)

    async def run_forever(self, stop: asyncio.Event) -> None:
        await asyncio.to_thread(self.recover_stale)
        async with asyncio.TaskGroup() as group:
            group.create_task(self._scheduler_loop(stop))
            for _ in range(max(1, self.settings.worker_concurrency)):
                group.create_task(self._loop(stop))


def run_standalone(settings: Settings | None = None) -> None:
    """Entry point of ``kalkan worker`` (a separate process/container)."""
    from prometheus_client import start_http_server

    from kalkan.web.observability import configure_logging

    settings = settings or Settings()
    configure_logging(settings)
    engine = make_engine(settings.database_url)
    try:
        ensure_current(engine)  # migrations are applied by `kalkan migrate` / the web app
        if settings.worker_metrics_port:
            start_http_server(settings.worker_metrics_port)
            log.info("worker metrics on :%d/metrics", settings.worker_metrics_port)
        worker = ScanWorker(make_session_factory(engine), settings)

        async def main() -> None:
            stop = asyncio.Event()
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                with contextlib.suppress(NotImplementedError):  # Windows
                    loop.add_signal_handler(sig, stop.set)
            log.info("worker started (concurrency=%d)", settings.worker_concurrency)
            await worker.run_forever(stop)

        with contextlib.suppress(KeyboardInterrupt):
            asyncio.run(main())
    finally:
        engine.dispose()
