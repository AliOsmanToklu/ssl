from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import timedelta

import prometheus_client
import pytest
from conftest import make_report
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from kalkan.scanner import ScanOptions, ScanReport, TargetError
from kalkan.web import observability
from kalkan.web import worker as worker_module
from kalkan.web.config import Settings
from kalkan.web.db import make_engine, make_session_factory, utcnow
from kalkan.web.migrate import SchemaOutdatedError, upgrade_database
from kalkan.web.models import Domain, Membership, Organization, Role, Scan, ScanStatus, User
from kalkan.web.worker import ScanWorker


@pytest.fixture
def session_factory(database_url: str) -> Iterator[sessionmaker[Session]]:
    engine = make_engine(database_url)
    upgrade_database(engine)
    yield make_session_factory(engine)
    engine.dispose()


def queue_scan(factory: sessionmaker[Session], hostname: str = "example.com") -> int:
    with factory() as db:
        organization = db.scalar(select(Organization))
        if organization is None:
            user = User(email="a@example.com", password_hash="x", email_verified_at=utcnow())
            organization = Organization(name="Örnek A.Ş.")
            db.add(Membership(user=user, organization=organization, role=Role.OWNER))
        domain = Domain(
            organization=organization,
            hostname=hostname,
            verification_token="t",
            verified_at=utcnow(),
        )
        scan = Scan(domain=domain)
        db.add_all([organization, domain, scan])
        db.commit()
        return scan.id


def load(factory: sessionmaker[Session], scan_id: int) -> Scan:
    with factory() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        return scan


async def ok_scanner(hostname: str, options: ScanOptions) -> ScanReport:
    return make_report(target=hostname)


def test_claim_is_exclusive(session_factory: sessionmaker[Session]) -> None:
    worker = ScanWorker(session_factory, Settings(), scanner=ok_scanner)
    assert worker.claim() is None
    scan_id = queue_scan(session_factory)
    job = worker.claim()
    assert job is not None and job.scan_id == scan_id and job.hostname == "example.com"
    assert worker.claim() is None  # a second worker gets nothing
    scan = load(session_factory, scan_id)
    assert scan.status is ScanStatus.RUNNING
    assert scan.started_at is not None and scan.started_at.tzinfo is not None


def test_jobs_are_processed_in_order(session_factory: sessionmaker[Session]) -> None:
    first = queue_scan(session_factory, "a.example.com")
    second = queue_scan(session_factory, "b.example.com")
    worker = ScanWorker(session_factory, Settings(), scanner=ok_scanner)
    jobs = [worker.claim(), worker.claim()]
    assert [j.scan_id for j in jobs if j] == [first, second]


async def test_run_once_stores_report(session_factory: sessionmaker[Session]) -> None:
    scan_id = queue_scan(session_factory)
    seen: list[ScanOptions] = []

    async def scanner(hostname: str, options: ScanOptions) -> ScanReport:
        seen.append(options)
        return make_report(target=hostname)

    settings = Settings(scan_timeout=7)
    assert await ScanWorker(session_factory, settings, scanner=scanner).run_once() is True
    scan = load(session_factory, scan_id)
    assert scan.status is ScanStatus.DONE
    assert (scan.grade, scan.score) == ("C", 79)
    assert scan.report is not None and scan.report.target == "example.com"
    assert scan.finished_at is not None
    assert seen[0].timeout == 7 and seen[0].allow_private is False


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (TargetError("'x' çözümlenemedi"), "'x' çözümlenemedi"),
        (RuntimeError("secret internals"), "beklenmeyen bir hata"),
    ],
)
async def test_run_once_records_failures(
    session_factory: sessionmaker[Session], error: Exception, message: str
) -> None:
    scan_id = queue_scan(session_factory)

    async def scanner(hostname: str, options: ScanOptions) -> ScanReport:
        raise error

    await ScanWorker(session_factory, Settings(), scanner=scanner).run_once()
    scan = load(session_factory, scan_id)
    assert scan.status is ScanStatus.FAILED
    assert scan.error is not None and message in scan.error
    assert "secret internals" not in scan.error


def test_recover_stale_scans(session_factory: sessionmaker[Session]) -> None:
    stale = queue_scan(session_factory, "stale.example.com")
    fresh = queue_scan(session_factory, "fresh.example.com")
    with session_factory() as db:
        for scan_id, age in ((stale, 60), (fresh, 1)):
            scan = db.get(Scan, scan_id)
            assert scan is not None
            scan.status = ScanStatus.RUNNING
            scan.started_at = utcnow() - timedelta(minutes=age)
        db.commit()
    worker = ScanWorker(session_factory, Settings(stale_scan_minutes=15), scanner=ok_scanner)
    assert worker.recover_stale() == 1
    assert load(session_factory, stale).status is ScanStatus.QUEUED
    assert load(session_factory, fresh).status is ScanStatus.RUNNING


async def test_run_forever_until_stopped(session_factory: sessionmaker[Session]) -> None:
    scan_ids = [queue_scan(session_factory, f"{n}.example.com") for n in range(3)]
    settings = Settings(worker_concurrency=2, worker_poll_interval=0.01)
    worker = ScanWorker(session_factory, settings, scanner=ok_scanner)
    stop = asyncio.Event()
    task = asyncio.create_task(worker.run_forever(stop))
    for _ in range(200):
        if all(load(session_factory, s).status is ScanStatus.DONE for s in scan_ids):
            break
        await asyncio.sleep(0.01)
    stop.set()
    await asyncio.wait_for(task, 2)
    assert all(load(session_factory, s).status is ScanStatus.DONE for s in scan_ids)


async def test_loop_survives_database_errors(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = ScanWorker(session_factory, Settings(worker_poll_interval=0.01), scanner=ok_scanner)
    calls = 0

    def flaky_claim() -> None:
        nonlocal calls
        calls += 1
        raise RuntimeError("database is locked")

    monkeypatch.setattr(worker, "claim", flaky_claim)
    stop = asyncio.Event()
    task = asyncio.create_task(worker._loop(stop))
    await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, 2)
    assert calls >= 2


def test_run_standalone(database_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    ran: list[Settings] = []
    started_metrics: list[int] = []

    async def fake_forever(self: ScanWorker, stop: asyncio.Event) -> None:
        ran.append(self.settings)

    monkeypatch.setattr(ScanWorker, "run_forever", fake_forever)
    monkeypatch.setattr(prometheus_client, "start_http_server", started_metrics.append)
    # configure_logging would replace pytest's log handlers for the rest of the run
    monkeypatch.setattr(observability, "configure_logging", lambda settings: None)
    settings = Settings(database_url=database_url, worker_metrics_port=9101)
    with pytest.raises(SchemaOutdatedError):  # the worker never migrates on its own
        worker_module.run_standalone(settings)
    engine = make_engine(database_url)
    upgrade_database(engine)
    engine.dispose()
    worker_module.run_standalone(settings)
    assert ran == [settings]
    assert started_metrics == [9101]
