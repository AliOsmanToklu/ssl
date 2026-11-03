from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta

import pytest
from conftest import make_report
from sqlalchemy.orm import Session, sessionmaker

from kalkan.scanner import ScanOptions, ScanReport
from kalkan.scanner.models import Category, Finding, Severity
from kalkan.web.alerts import compute_alert
from kalkan.web.config import Settings
from kalkan.web.db import make_engine, make_session_factory, utcnow
from kalkan.web.mail import MemoryMailer
from kalkan.web.migrate import upgrade_database
from kalkan.web.models import (
    Domain,
    Membership,
    Organization,
    Plan,
    Role,
    Scan,
    ScanStatus,
    ScanTrigger,
    User,
)
from kalkan.web.verification import VerificationResult
from kalkan.web.worker import OWNERSHIP_LOST_MESSAGE, ScanWorker


def finding(fid: str, severity: Severity, title: str = "x") -> Finding:
    return Finding(fid, Category.TLS, severity, title, recommendation="düzeltin")


def report(*findings: Finding, grade: str = "B") -> ScanReport:
    return make_report(findings=list(findings), grade=grade)


# --- alert rules (pure) -------------------------------------------------------


def test_first_scan_alerts_on_important_findings() -> None:
    alert = compute_alert(
        None,
        report(
            finding("ports.open_3389", Severity.HIGH),
            finding("http.hsts_missing", Severity.LOW),
            finding("tls.cert_expiring", Severity.MEDIUM),
        ),
    )
    assert alert is not None
    assert [f.id for f in alert.findings] == ["ports.open_3389", "tls.cert_expiring"]
    assert alert.grade_change is None


def test_unchanged_problems_do_not_alert_again() -> None:
    same = report(finding("ports.open_3389", Severity.HIGH), grade="C")
    assert compute_alert(same, same) is None


def test_worse_severity_alerts() -> None:
    before = report(finding("tls.cert_expiring", Severity.MEDIUM))
    after = report(finding("tls.cert_expiring", Severity.HIGH))
    alert = compute_alert(before, after)
    assert alert is not None and [f.id for f in alert.findings] == ["tls.cert_expiring"]


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [("A", "C", ("A", "C")), ("B", "F", ("B", "F")), ("A", "B", None), ("D", "C", None)],
)
def test_grade_drops_into_c_or_worse_alert(
    before: str, after: str, expected: tuple[str, str] | None
) -> None:
    alert = compute_alert(report(grade=before), report(grade=after))
    assert (alert.grade_change if alert else None) == expected


# --- worker integration --------------------------------------------------------


@pytest.fixture
def session_factory(database_url: str) -> Iterator[sessionmaker[Session]]:
    engine = make_engine(database_url)
    upgrade_database(engine)
    yield make_session_factory(engine)
    engine.dispose()


def add_domain(
    factory: sessionmaker[Session],
    *,
    interval: int = 7,
    due: bool = True,
    verified_days_ago: int | None = 1,
    email_verified: bool = True,
    notify: bool = True,
    hostname: str = "example.com",
    plan: Plan = Plan.PRO,
    locale: str | None = None,
) -> int:
    now = utcnow()
    with factory() as db:
        user = User(
            email=f"sahip@{hostname}",
            password_hash="x",
            email_verified_at=now if email_verified else None,
            locale=locale,
        )
        organization = Organization(name=hostname, plan=plan)
        domain = Domain(
            organization=organization,
            hostname=hostname,
            verification_token="tok",
            verified_at=None
            if verified_days_ago is None
            else now - timedelta(days=verified_days_ago),
            verification_method="dns",
            scan_interval_days=interval,
            next_scan_at=now - timedelta(minutes=1) if due else now + timedelta(days=3),
            notify_email=notify,
        )
        owner = Membership(user=user, organization=organization, role=Role.OWNER)
        db.add_all([user, organization, owner, domain])
        db.commit()
        return domain.id


def add_member(
    factory: sessionmaker[Session],
    domain_id: int,
    email: str,
    role: Role = Role.MEMBER,
    *,
    verified: bool = True,
    locale: str | None = None,
) -> None:
    with factory() as db:
        domain = db.get(Domain, domain_id)
        assert domain is not None
        user = User(
            email=email,
            password_hash="x",
            email_verified_at=utcnow() if verified else None,
            locale=locale,
        )
        db.add_all([user, Membership(user=user, organization_id=domain.organization_id, role=role)])
        db.commit()


def add_done_scan(factory: sessionmaker[Session], domain_id: int, done: ScanReport) -> None:
    with factory() as db:
        db.add(
            Scan(
                domain_id=domain_id,
                status=ScanStatus.DONE,
                finished_at=utcnow() - timedelta(days=7),
                score=done.score,
                grade=done.grade,
                report_data=done.to_dict(),
            )
        )
        db.commit()


def scans_of(factory: sessionmaker[Session], domain_id: int) -> list[Scan]:
    with factory() as db:
        domain = db.get(Domain, domain_id)
        assert domain is not None
        return list(domain.scans)


def make_worker(
    factory: sessionmaker[Session],
    mailer: MemoryMailer,
    reports: list[ScanReport] | None = None,
    owned: bool = True,
    **settings: object,
) -> ScanWorker:
    queue = list(reports or [report()])

    async def scanner(hostname: str, options: ScanOptions) -> ScanReport:
        return queue.pop(0) if len(queue) > 1 else queue[0]

    async def verifier(hostname: str, token: str, **kwargs: object) -> VerificationResult:
        return VerificationResult("dns" if owned else None, "")

    return ScanWorker(
        factory,
        Settings(public_url="https://kalkan.test", **settings),  # type: ignore[arg-type]
        scanner=scanner,
        mailer=mailer,
        verifier=verifier,
    )


def test_schedule_due_queues_and_advances(session_factory: sessionmaker[Session]) -> None:
    due = add_domain(session_factory, hostname="due.example.com")
    later = add_domain(session_factory, due=False, hostname="later.example.com")
    off = add_domain(session_factory, interval=0, hostname="off.example.com")
    worker = make_worker(session_factory, MemoryMailer())

    assert worker.schedule_due() == 1
    queued = scans_of(session_factory, due)
    assert [(s.status, s.trigger) for s in queued] == [(ScanStatus.QUEUED, ScanTrigger.SCHEDULED)]
    assert scans_of(session_factory, later) == [] and scans_of(session_factory, off) == []
    with session_factory() as db:
        domain = db.get(Domain, due)
        assert domain is not None and domain.next_scan_at is not None
        assert domain.next_scan_at > utcnow() + timedelta(days=6)
    assert worker.schedule_due() == 0  # not due any more
    assert worker.queue_depth() == {"queued": 1, "running": 0}


def test_schedule_skips_unready_domains(session_factory: sessionmaker[Session]) -> None:
    unverified = add_domain(session_factory, verified_days_ago=None, hostname="a.example.com")
    no_email = add_domain(session_factory, email_verified=False, hostname="b.example.com")
    worker = make_worker(session_factory, MemoryMailer())
    assert worker.schedule_due() == 0
    assert scans_of(session_factory, unverified) == [] and scans_of(session_factory, no_email) == []
    with session_factory() as db:  # the schedule still moves on instead of retrying every minute
        assert all(d.next_scan_at and d.next_scan_at > utcnow() for d in db.query(Domain))


def test_schedule_does_not_stack_on_an_active_scan(session_factory: sessionmaker[Session]) -> None:
    domain_id = add_domain(session_factory)
    with session_factory() as db:
        db.add(Scan(domain_id=domain_id))
        db.commit()
    assert make_worker(session_factory, MemoryMailer()).schedule_due() == 0
    assert len(scans_of(session_factory, domain_id)) == 1


def test_two_schedulers_queue_once(session_factory: sessionmaker[Session]) -> None:
    add_domain(session_factory)
    first = make_worker(session_factory, MemoryMailer())
    second = make_worker(session_factory, MemoryMailer())
    assert first.schedule_due() + second.schedule_due() == 1


async def test_scheduled_scan_sends_alert_only_for_news(
    session_factory: sessionmaker[Session],
) -> None:
    domain_id = add_domain(session_factory)
    add_done_scan(session_factory, domain_id, report())  # last week's clean report
    add_member(session_factory, domain_id, "uye@example.com")
    add_member(session_factory, domain_id, "dogrulanmamis@example.com", verified=False)
    mailer = MemoryMailer()
    rdp = finding("ports.open_3389", Severity.HIGH, "Uzak Masaüstü (RDP) internete açık")
    worker = make_worker(session_factory, mailer, reports=[report(rdp, grade="C")])

    worker.schedule_due()
    assert await worker.run_once() is True
    # every member with a verified address hears about it
    assert [(e.kind, e.to) for e in mailer.outbox] == [
        ("alert", "sahip@example.com"),
        ("alert", "uye@example.com"),
    ]
    alert = mailer.outbox[0]
    assert alert.subject == "Kalkan: example.com için 1 yeni önemli sorun"
    assert "[Yüksek] Uzak Masaüstü (RDP) internete açık" in alert.body
    scan_id = scans_of(session_factory, domain_id)[0].id
    assert f"https://kalkan.test/scans/{scan_id}" in alert.body
    mailer.outbox.clear()

    with session_factory() as db:  # run the schedule again right away
        domain = db.get(Domain, domain_id)
        assert domain is not None
        domain.next_scan_at = utcnow() - timedelta(minutes=1)
        db.commit()
    worker.schedule_due()
    await worker.run_once()
    assert mailer.outbox == []  # same problem, no second e-mail


async def test_no_alert_when_muted_or_manual(session_factory: sessionmaker[Session]) -> None:
    mailer = MemoryMailer()
    bad = report(finding("ports.open_445", Severity.CRITICAL), grade="F")
    muted = add_domain(session_factory, notify=False, hostname="muted.example.com")
    manual = add_domain(session_factory, due=False, hostname="manual.example.com")
    with session_factory() as db:
        db.add(Scan(domain_id=manual, trigger=ScanTrigger.MANUAL))
        db.commit()
    worker = make_worker(session_factory, mailer, reports=[bad])
    worker.schedule_due()
    while await worker.run_once():
        pass
    assert [s.status for s in scans_of(session_factory, muted)] == [ScanStatus.DONE]
    assert [s.status for s in scans_of(session_factory, manual)] == [ScanStatus.DONE]
    # muted: nothing at all; manual: the one-off first-report summary, never an alert
    assert [(e.kind, e.to) for e in mailer.outbox] == [("first-report", "sahip@manual.example.com")]


async def test_stale_verification_is_rechecked(session_factory: sessionmaker[Session]) -> None:
    domain_id = add_domain(session_factory, verified_days_ago=45)
    worker = make_worker(session_factory, MemoryMailer(), owned=True, reverify_after_days=30)
    worker.schedule_due()
    await worker.run_once()
    assert scans_of(session_factory, domain_id)[0].status is ScanStatus.DONE
    with session_factory() as db:
        domain = db.get(Domain, domain_id)
        assert domain is not None and domain.verified_at is not None
        assert utcnow() - domain.verified_at < timedelta(minutes=1)  # refreshed


async def test_lost_ownership_stops_scanning(session_factory: sessionmaker[Session]) -> None:
    domain_id = add_domain(session_factory, verified_days_ago=45)
    mailer = MemoryMailer()
    worker = make_worker(session_factory, mailer, owned=False, reverify_after_days=30)
    worker.schedule_due()
    await worker.run_once()

    scan = scans_of(session_factory, domain_id)[0]
    assert scan.status is ScanStatus.FAILED
    assert scan.error == OWNERSHIP_LOST_MESSAGE
    assert scan.report_data is None  # nothing was scanned
    with session_factory() as db:
        domain = db.get(Domain, domain_id)
        assert domain is not None and domain.verified_at is None
    assert [e.kind for e in mailer.outbox] == ["ownership-lost"]
    assert f"https://kalkan.test/domains/{domain_id}" in mailer.outbox[0].body

    # Without verification the scheduler stops queueing it.
    with session_factory() as db:
        domain = db.get(Domain, domain_id)
        assert domain is not None
        domain.next_scan_at = utcnow() - timedelta(minutes=1)
        db.commit()
    assert worker.schedule_due() == 0


async def test_failing_mail_server_does_not_break_the_worker(
    session_factory: sessionmaker[Session],
) -> None:
    class BrokenMailer(MemoryMailer):
        def send(self, email: object) -> None:
            raise ConnectionRefusedError("smtp down")

    domain_id = add_domain(session_factory)
    worker = make_worker(
        session_factory,
        BrokenMailer(),
        reports=[report(finding("ports.open_445", Severity.CRITICAL), grade="F")],
    )
    worker.schedule_due()
    assert await worker.run_once() is True
    assert scans_of(session_factory, domain_id)[0].status is ScanStatus.DONE


def test_schedule_follows_the_plan(session_factory: sessionmaker[Session]) -> None:
    weekly_free = add_domain(session_factory, plan=Plan.FREE, hostname="free.example.com")
    monthly_free = add_domain(
        session_factory, interval=30, plan=Plan.FREE, hostname="monthly.example.com"
    )
    assert make_worker(session_factory, MemoryMailer()).schedule_due() == 1
    assert scans_of(session_factory, weekly_free) == []  # weekly is a Pro feature
    assert len(scans_of(session_factory, monthly_free)) == 1


def test_schedule_needs_one_verified_member(session_factory: sessionmaker[Session]) -> None:
    domain_id = add_domain(session_factory, email_verified=False)
    worker = make_worker(session_factory, MemoryMailer())
    assert worker.schedule_due() == 0
    add_member(session_factory, domain_id, "uye@example.com")
    with session_factory() as db:
        domain = db.get(Domain, domain_id)
        assert domain is not None
        domain.next_scan_at = utcnow() - timedelta(minutes=1)
        db.commit()
    assert worker.schedule_due() == 1


async def test_first_report_goes_to_the_requester_in_their_language(
    session_factory: sessionmaker[Session],
) -> None:
    domain_id = add_domain(session_factory, due=False)
    add_member(session_factory, domain_id, "uye@example.com", locale="en")
    with session_factory() as db:
        member = db.query(User).filter_by(email="uye@example.com").one()
        db.add(Scan(domain_id=domain_id, requested_by_id=member.id))
        db.commit()
    mailer = MemoryMailer()
    rdp = finding("ports.open_3389", Severity.HIGH, "Uzak Masaüstü (RDP) internete açık")
    worker = make_worker(session_factory, mailer, reports=[report(rdp, grade="C")])
    await worker.run_once()

    [email] = mailer.outbox
    assert (email.kind, email.to) == ("first-report", "uye@example.com")
    assert email.subject == "Kalkan: your first report for example.com is ready (C)"
    assert "[High] Uzak Masaüstü (RDP) internete açık" in email.body  # title: test data
    scan_id = scans_of(session_factory, domain_id)[0].id
    assert f"https://kalkan.test/scans/{scan_id}" in email.body

    # API scans are for machines: no welcome summary
    other = add_domain(session_factory, due=False, hostname="api.example.com")
    with session_factory() as db:
        db.add(Scan(domain_id=other, trigger=ScanTrigger.API))
        db.commit()
    await worker.run_once()
    assert len(mailer.outbox) == 1


async def test_lost_ownership_is_reported_to_admins_only(
    session_factory: sessionmaker[Session],
) -> None:
    domain_id = add_domain(session_factory, verified_days_ago=45)
    add_member(session_factory, domain_id, "yonetici@example.com", Role.ADMIN)
    add_member(session_factory, domain_id, "uye@example.com", Role.MEMBER)
    mailer = MemoryMailer()
    worker = make_worker(session_factory, mailer, owned=False, reverify_after_days=30)
    worker.schedule_due()
    await worker.run_once()
    assert [e.to for e in mailer.outbox] == ["sahip@example.com", "yonetici@example.com"]
    scan = scans_of(session_factory, domain_id)[0]
    assert scan.error_detail is not None and set(scan.error_detail) == {"tr", "en"}


def test_onboarding_reminder_is_sent_once(session_factory: sessionmaker[Session]) -> None:
    now = utcnow()
    with session_factory() as db:
        old = now - timedelta(days=3)
        stuck = User(
            email="yeni@example.com",
            password_hash="x",
            created_at=old,
            email_verified_at=old,
            locale="en",
        )
        fresh = User(email="taze@example.com", password_hash="x", email_verified_at=now)
        unverified = User(email="dogrulamadi@example.com", password_hash="x", created_at=old)
        db.add_all([stuck, fresh, unverified])
        db.commit()
    add_domain(session_factory, hostname="hazir.example.com")  # has a verified domain
    with session_factory() as db:
        done = db.query(User).filter_by(email="sahip@hazir.example.com").one()
        done.created_at = now - timedelta(days=5)
        db.commit()

    worker = make_worker(session_factory, MemoryMailer())
    emails = worker.onboarding_reminders()
    assert [(e.kind, e.to) for e in emails] == [("onboarding", "yeni@example.com")]
    assert emails[0].subject == "Kalkan: one step left to scan your site"
    assert "https://kalkan.test/dashboard" in emails[0].body
    assert worker.onboarding_reminders() == []  # once only
