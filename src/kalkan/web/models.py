"""ORM models.

Organizations own domains; users join organizations through memberships with a role.
A domain must be verified before it is scanned. What an organization may do (how many
domains, scans per day, schedules, API access, members) is set by its plan.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    true,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kalkan.i18n import N_
from kalkan.scanner.models import ScanReport
from kalkan.scanner.target import display_hostname
from kalkan.web.db import Base, UTCDateTime, utcnow


def _enum(cls: type[enum.StrEnum]) -> Enum:
    return Enum(
        cls,
        native_enum=False,
        length=16,
        values_callable=lambda members: [m.value for m in members],
    )


class ScanStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"

    @property
    def label(self) -> str:
        return {
            ScanStatus.QUEUED: N_("Sırada"),
            ScanStatus.RUNNING: N_("Taranıyor"),
            ScanStatus.DONE: N_("Tamamlandı"),
            ScanStatus.FAILED: N_("Başarısız"),
        }[self]

    @property
    def is_active(self) -> bool:
        return self in (ScanStatus.QUEUED, ScanStatus.RUNNING)


class ScanTrigger(enum.StrEnum):
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    API = "api"

    @property
    def label(self) -> str:
        return {
            ScanTrigger.MANUAL: N_("Elle"),
            ScanTrigger.SCHEDULED: N_("Otomatik"),
            ScanTrigger.API: N_("API"),
        }[self]


SCAN_INTERVALS = {0: N_("Kapalı"), 7: N_("Haftalık"), 30: N_("Aylık")}


class Role(enum.StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"

    @property
    def rank(self) -> int:
        """Higher is more powerful."""
        return {Role.MEMBER: 1, Role.ADMIN: 2, Role.OWNER: 3}[self]

    def at_least(self, other: Role) -> bool:
        return self.rank >= other.rank

    @property
    def label(self) -> str:
        return {Role.OWNER: N_("Sahip"), Role.ADMIN: N_("Yönetici"), Role.MEMBER: N_("Üye")}[self]


class Plan(enum.StrEnum):
    FREE = "free"
    PRO = "pro"
    AGENCY = "agency"

    @property
    def limits(self) -> PlanLimits:
        return PLANS[self]


@dataclass(frozen=True, slots=True)
class PlanLimits:
    label: str
    domains: int
    scans_per_domain_per_day: int
    intervals: tuple[int, ...]  # allowed automatic scan intervals (days, 0 = off)
    api: bool
    members: int


PLANS: dict[Plan, PlanLimits] = {
    Plan.FREE: PlanLimits(N_("Ücretsiz"), 1, 2, (0, 30), api=False, members=1),
    Plan.PRO: PlanLimits(N_("Pro"), 5, 5, (0, 7, 30), api=True, members=3),
    Plan.AGENCY: PlanLimits(N_("Ajans"), 25, 10, (0, 7, 30), api=True, members=10),
}


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    email_verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    # Bumped on password change/reset; sessions carrying an older value are rejected.
    session_version: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    locale: Mapped[str | None] = mapped_column(String(8), default=None)
    onboarding_reminded_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)

    memberships: Mapped[list[Membership]] = relationship(
        back_populates="user", cascade="all, delete-orphan", order_by="Membership.id"
    )
    api_tokens: Mapped[list[ApiToken]] = relationship(
        back_populates="owner", cascade="all, delete-orphan", order_by="ApiToken.created_at"
    )

    @property
    def email_verified(self) -> bool:
        return self.email_verified_at is not None


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    plan: Mapped[Plan] = mapped_column(_enum(Plan), default=Plan.FREE, server_default="free")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    memberships: Mapped[list[Membership]] = relationship(
        back_populates="organization", cascade="all, delete-orphan", order_by="Membership.id"
    )
    domains: Mapped[list[Domain]] = relationship(
        back_populates="organization", cascade="all, delete-orphan", order_by="Domain.hostname"
    )
    invitations: Mapped[list[Invitation]] = relationship(
        back_populates="organization", cascade="all, delete-orphan", order_by="Invitation.id"
    )

    @property
    def limits(self) -> PlanLimits:
        return self.plan.limits

    @property
    def members(self) -> list[User]:
        return [m.user for m in self.memberships]


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("organization_id", "user_id", name="uq_membership"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role: Mapped[Role] = mapped_column(_enum(Role), default=Role.MEMBER)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    organization: Mapped[Organization] = relationship(back_populates="memberships")
    user: Mapped[User] = relationship(back_populates="memberships")


class Invitation(Base):
    """An e-mailed invitation to join an organization. Only a digest of the token is kept."""

    __tablename__ = "invitations"

    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    email: Mapped[str] = mapped_column(String(320))
    role: Mapped[Role] = mapped_column(_enum(Role), default=Role.MEMBER)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    invited_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    accepted_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)

    organization: Mapped[Organization] = relationship(back_populates="invitations")
    invited_by: Mapped[User | None] = relationship()

    def is_open(self, now: datetime) -> bool:
        return self.accepted_at is None and self.expires_at > now


class Domain(Base):
    __tablename__ = "domains"
    __table_args__ = (
        UniqueConstraint("organization_id", "hostname", name="uq_domain_per_organization"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    hostname: Mapped[str] = mapped_column(String(253))
    verification_token: Mapped[str] = mapped_column(String(64))
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    verification_method: Mapped[str | None] = mapped_column(String(16), default=None)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    # Automatic re-scans: 0 = off, otherwise every N days starting at next_scan_at.
    scan_interval_days: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    next_scan_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None, index=True)
    notify_email: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())

    organization: Mapped[Organization] = relationship(back_populates="domains")
    scans: Mapped[list[Scan]] = relationship(
        back_populates="domain",
        cascade="all, delete-orphan",
        order_by="Scan.created_at.desc()",
    )

    @property
    def is_verified(self) -> bool:
        return self.verified_at is not None

    @property
    def display_name(self) -> str:
        return display_hostname(self.hostname)

    @property
    def latest_finished_scan(self) -> Scan | None:
        return next((s for s in self.scans if s.status == ScanStatus.DONE), None)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)
    status: Mapped[ScanStatus] = mapped_column(
        _enum(ScanStatus), default=ScanStatus.QUEUED, index=True
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    score: Mapped[int | None] = mapped_column(Integer, default=None)
    grade: Mapped[str | None] = mapped_column(String(2), default=None)
    report_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    # error: Turkish text kept for older clients; error_detail: every language (Text JSON)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    error_detail: Mapped[dict[str, str] | None] = mapped_column(JSON, default=None)
    trigger: Mapped[ScanTrigger] = mapped_column(
        _enum(ScanTrigger),
        default=ScanTrigger.MANUAL,
        server_default=ScanTrigger.MANUAL.value,
    )
    requested_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )

    domain: Mapped[Domain] = relationship(back_populates="scans")
    requested_by: Mapped[User | None] = relationship()

    @property
    def report(self) -> ScanReport | None:
        return ScanReport.from_dict(self.report_data) if self.report_data else None

    @property
    def error_text(self) -> dict[str, str] | str | None:
        return self.error_detail or self.error


class ApiToken(Base):
    """A personal access token for the REST API, acting in one organization.
    Only a SHA-256 digest is stored."""

    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(100))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    prefix: Mapped[str] = mapped_column(String(16))  # shown in the UI to tell tokens apart
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)

    owner: Mapped[User] = relationship(back_populates="api_tokens")
    organization: Mapped[Organization] = relationship()
