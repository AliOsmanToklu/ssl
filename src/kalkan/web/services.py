"""Business rules, independent of HTTP.

Accounts, organizations (members, roles, invitations, plans), domains, verification,
scans and API tokens. The HTML pages and the REST API both call into this module, so a
rule is enforced in exactly one place. :class:`ServiceError` carries the message (in
every language) and the HTTP status the API uses.

Permissions: an action names the least role it needs (``require(membership, Role.X)``);
owner > admin > member. Members see reports and start scans, admins manage domains and
invite people, owners manage roles.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from kalkan import __version__
from kalkan.i18n import LANGUAGES, LocalizedValue, T
from kalkan.scanner.target import TargetError, is_ip_literal, normalize_hostname
from kalkan.web.config import Settings
from kalkan.web.db import utcnow
from kalkan.web.models import (
    SCAN_INTERVALS,
    ApiToken,
    Domain,
    Invitation,
    Membership,
    Organization,
    Plan,
    Role,
    Scan,
    ScanStatus,
    ScanTrigger,
    User,
)
from kalkan.web.security import hash_password, needs_rehash, verify_password
from kalkan.web.tokens import Signer, password_fingerprint
from kalkan.web.verification import VerificationResult, verify_ownership

MIN_PASSWORD_LENGTH = 10
API_TOKEN_PREFIX = "klk_"  # noqa: S105 - a public prefix, not a secret
INVITATION_DAYS = 7
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")


class ServiceError(Exception):
    """A rule was violated; ``text`` is shown to the user (in their language)."""

    def __init__(self, text: LocalizedValue, status_code: int = 400) -> None:
        super().__init__(str(text))
        self.text = text
        self.status_code = status_code


def _digest(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


# --- accounts ---------------------------------------------------------------


def normalize_email(email: str) -> str:
    value = email.strip().lower()
    if len(value) > 320 or not _EMAIL_RE.match(value):
        raise ServiceError(T("Geçerli bir e-posta adresi girin."), 422)
    return value


def _check_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ServiceError(T("Şifre en az {n} karakter olmalı.", n=MIN_PASSWORD_LENGTH), 422)


def register_user(
    db: Session,
    email: str,
    password: str,
    locale: str | None = None,
    plan: Plan = Plan.FREE,
) -> User:
    """Create the user together with a personal organization they own."""
    address = normalize_email(email)
    _check_password(password)
    if db.scalar(select(User.id).where(User.email == address)) is not None:
        raise ServiceError(T("Bu e-posta adresiyle zaten bir hesap var."), 409)
    user = User(
        email=address,
        password_hash=hash_password(password),
        locale=locale if locale in LANGUAGES else None,
    )
    organization = Organization(name=address[:100], plan=plan)
    owner = Membership(user=user, organization=organization, role=Role.OWNER)
    db.add_all([user, organization, owner])
    try:
        db.commit()
    except IntegrityError as exc:  # concurrent registration with the same address
        db.rollback()
        raise ServiceError(T("Bu e-posta adresiyle zaten bir hesap var."), 409) from exc
    return user


def authenticate(db: Session, email: str, password: str) -> User | None:
    try:
        address = normalize_email(email)
    except ServiceError:
        verify_password(None, password)
        return None
    user = db.scalar(select(User).where(User.email == address))
    if user is None:
        verify_password(None, password)  # same cost as a real check: no user enumeration
        return None
    if not verify_password(user.password_hash, password):
        return None
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        db.commit()
    return user


def find_user_by_email(db: Session, email: str) -> User | None:
    try:
        address = normalize_email(email)
    except ServiceError:
        return None
    return db.scalar(select(User).where(User.email == address))


def set_locale(db: Session, user: User, lang: str) -> None:
    if lang in LANGUAGES and user.locale != lang:
        user.locale = lang
        db.commit()


def confirm_email(db: Session, signer: Signer, token: str) -> tuple[User, bool]:
    """Returns the user and whether this link verified the address just now."""
    claims = signer.read_email_token(token)
    user = db.get(User, claims.user_id) if claims else None
    if claims is None or user is None or user.email != claims.check:
        raise ServiceError(T("Doğrulama bağlantısı geçersiz veya süresi dolmuş."), 400)
    if user.email_verified_at is not None:
        return user, False
    user.email_verified_at = utcnow()
    db.commit()
    return user, True


def _set_password(db: Session, user: User, new_password: str) -> None:
    _check_password(new_password)
    user.password_hash = hash_password(new_password)
    user.session_version += 1  # signs every other session out
    db.commit()


def change_password(db: Session, user: User, current: str, new_password: str) -> None:
    if not verify_password(user.password_hash, current):
        raise ServiceError(T("Mevcut şifreniz hatalı."), 403)
    _set_password(db, user, new_password)


def user_for_reset_token(db: Session, signer: Signer, token: str) -> User:
    claims = signer.read_reset_token(token)
    user = db.get(User, claims.user_id) if claims else None
    if (
        claims is None
        or user is None
        or not hmac.compare_digest(password_fingerprint(user.password_hash), claims.check)
    ):
        raise ServiceError(
            T("Şifre sıfırlama bağlantısı geçersiz, kullanılmış veya süresi dolmuş.")
        )
    return user


def reset_password(db: Session, signer: Signer, token: str, new_password: str) -> User:
    user = user_for_reset_token(db, signer, token)
    _set_password(db, user, new_password)
    if user.email_verified_at is None:  # the link proved control of the mailbox
        user.email_verified_at = utcnow()
        db.commit()
    return user


def delete_account(db: Session, user: User, password: str) -> None:
    """Delete the user. Organizations they were alone in go with them; elsewhere the
    longest-standing remaining member becomes owner if the user was the only one."""
    if not verify_password(user.password_hash, password):
        raise ServiceError(T("Şifreniz hatalı; hesap silinmedi."), 403)
    for membership in list(user.memberships):
        organization = membership.organization
        others = [m for m in organization.memberships if m.user_id != user.id]
        if not others:
            db.delete(organization)
        elif membership.role is Role.OWNER and not any(m.role is Role.OWNER for m in others):
            others[0].role = Role.OWNER
    db.delete(user)
    db.commit()


def export_user_data(user: User) -> dict[str, Any]:
    """Everything stored about the user (KVKK / GDPR data portability)."""

    def when(value: Any) -> str | None:
        return value.isoformat() if value else None

    return {
        "exported_at": utcnow().isoformat(),
        "tool_version": __version__,
        "account": {
            "email": user.email,
            "created_at": when(user.created_at),
            "email_verified_at": when(user.email_verified_at),
            "locale": user.locale,
        },
        "api_tokens": [
            {
                "name": t.name,
                "prefix": t.prefix,
                "organization": t.organization.name,
                "created_at": when(t.created_at),
                "last_used_at": when(t.last_used_at),
            }
            for t in user.api_tokens
        ],
        "organizations": [
            {
                "name": m.organization.name,
                "role": m.role.value,
                "plan": m.organization.plan.value,
                "domains": [
                    {
                        "hostname": d.hostname,
                        "created_at": when(d.created_at),
                        "verified_at": when(d.verified_at),
                        "verification_method": d.verification_method,
                        "scan_interval_days": d.scan_interval_days,
                        "notify_email": d.notify_email,
                        "scans": [
                            {
                                "id": s.id,
                                "status": s.status.value,
                                "trigger": s.trigger.value,
                                "created_at": when(s.created_at),
                                "finished_at": when(s.finished_at),
                                "grade": s.grade,
                                "score": s.score,
                                "report": s.report_data,
                            }
                            for s in d.scans
                        ],
                    }
                    for d in m.organization.domains
                ],
            }
            for m in user.memberships
        ],
    }


# --- organizations ------------------------------------------------------------


def require(membership: Membership, role: Role) -> None:
    if not membership.role.at_least(role):
        raise ServiceError(T("Bu işlem için yetkiniz yok."), 403)


def get_membership(db: Session, user: User, organization_id: int) -> Membership | None:
    return db.scalar(
        select(Membership).where(
            Membership.user_id == user.id, Membership.organization_id == organization_id
        )
    )


def current_membership(db: Session, user: User, preferred: int | None = None) -> Membership:
    """The organization the user is working in. Someone removed from every organization
    gets a fresh personal one, so the app never runs without a workspace."""
    if preferred is not None:
        membership = get_membership(db, user, preferred)
        if membership is not None:
            return membership
    if user.memberships:
        return user.memberships[0]
    organization = Organization(name=user.email[:100], plan=Plan.FREE)
    membership = Membership(user=user, organization=organization, role=Role.OWNER)
    db.add_all([organization, membership])
    db.commit()
    return membership


def rename_organization(db: Session, membership: Membership, name: str) -> None:
    require(membership, Role.OWNER)
    clean = " ".join(name.split())[:100]
    if not clean:
        raise ServiceError(T("Çalışma alanı için bir ad girin."), 422)
    membership.organization.name = clean
    db.commit()


def set_plan(db: Session, organization: Organization, plan: Plan) -> None:
    """Change the plan (administrators only, through ``kalkan admin``: no payments yet)."""
    organization.plan = plan
    for domain in organization.domains:  # schedules the new plan does not allow are paused
        if domain.scan_interval_days not in plan.limits.intervals:
            domain.scan_interval_days = 0
            domain.next_scan_at = None
    db.commit()


def find_organization(db: Session, reference: str) -> Organization | None:
    """By id, or by the e-mail address of one of its owners."""
    if reference.isdigit():
        return db.get(Organization, int(reference))
    user = find_user_by_email(db, reference)
    if user is None:
        return None
    owned = [m.organization for m in user.memberships if m.role is Role.OWNER]
    return owned[0] if owned else None


def _open_invitations(organization: Organization) -> list[Invitation]:
    now = utcnow()
    return [i for i in organization.invitations if i.is_open(now)]


def invite(db: Session, membership: Membership, email: str, role: Role) -> tuple[Invitation, str]:
    """Returns the invitation and the raw token (sent by e-mail, never stored)."""
    require(membership, Role.ADMIN)
    if role is Role.OWNER:
        raise ServiceError(T("Davetle yalnızca üye veya yönetici eklenebilir."), 422)
    address = normalize_email(email)
    organization = membership.organization
    if any(m.user.email == address for m in organization.memberships):
        raise ServiceError(T("Bu kişi zaten çalışma alanında."), 409)
    pending = [i for i in _open_invitations(organization) if i.email != address]
    if len(organization.memberships) + len(pending) >= organization.limits.members:
        raise ServiceError(
            T(
                "Planınız en fazla {n} kişilik ekibe izin veriyor.",
                n=organization.limits.members,
            ),
            409,
        )
    for old in organization.invitations:  # a new invitation replaces an open one
        if old.email == address and old.accepted_at is None:
            db.delete(old)
    raw = secrets.token_urlsafe(32)
    invitation = Invitation(
        organization=organization,
        email=address,
        role=role,
        token_hash=_digest(raw),
        invited_by_id=membership.user_id,
        expires_at=utcnow() + timedelta(days=INVITATION_DAYS),
    )
    db.add(invitation)
    db.commit()
    return invitation, raw


def revoke_invitation(db: Session, membership: Membership, invitation_id: int) -> bool:
    require(membership, Role.ADMIN)
    invitation = db.scalar(
        select(Invitation).where(
            Invitation.id == invitation_id,
            Invitation.organization_id == membership.organization_id,
        )
    )
    if invitation is None:
        return False
    db.delete(invitation)
    db.commit()
    return True


def invitation_for_token(db: Session, raw_token: str) -> Invitation | None:
    invitation = db.scalar(select(Invitation).where(Invitation.token_hash == _digest(raw_token)))
    if invitation is None or not invitation.is_open(utcnow()):
        return None
    return invitation


def accept_invitation(db: Session, user: User, raw_token: str) -> Membership:
    invitation = invitation_for_token(db, raw_token)
    if invitation is None:
        raise ServiceError(T("Davet bağlantısı geçersiz, kullanılmış veya süresi dolmuş."), 400)
    if invitation.email != user.email:
        raise ServiceError(
            T(
                "Bu davet {email} adresine gönderildi. O adresle giriş yapın.",
                email=invitation.email,
            ),
            403,
        )
    if user.email_verified_at is None:  # the link reached this inbox: the address is proven
        user.email_verified_at = utcnow()
    existing = get_membership(db, user, invitation.organization_id)
    if existing is None:
        existing = Membership(
            organization_id=invitation.organization_id, user_id=user.id, role=invitation.role
        )
        db.add(existing)
    invitation.accepted_at = utcnow()
    db.commit()
    db.refresh(existing)
    return existing


def _membership_in(db: Session, actor: Membership, membership_id: int) -> Membership:
    target = db.scalar(
        select(Membership).where(
            Membership.id == membership_id,
            Membership.organization_id == actor.organization_id,
        )
    )
    if target is None:
        raise ServiceError(T("Üye bulunamadı."), 404)
    return target


def _owners(organization: Organization) -> list[Membership]:
    return [m for m in organization.memberships if m.role is Role.OWNER]


def change_role(db: Session, actor: Membership, membership_id: int, role: Role) -> None:
    require(actor, Role.OWNER)
    target = _membership_in(db, actor, membership_id)
    if (
        target.role is Role.OWNER
        and role is not Role.OWNER
        and len(_owners(target.organization)) == 1
    ):
        raise ServiceError(T("Çalışma alanında en az bir sahip kalmalı."), 409)
    target.role = role
    db.commit()


def _drop_membership(db: Session, membership: Membership) -> None:
    for token in list(membership.user.api_tokens):  # tokens of this workspace stop working
        if token.organization_id == membership.organization_id:
            db.delete(token)
    db.delete(membership)
    db.commit()


def remove_member(db: Session, actor: Membership, membership_id: int) -> None:
    require(actor, Role.ADMIN)
    target = _membership_in(db, actor, membership_id)
    if target.id == actor.id:
        raise ServiceError(
            T("Kendinizi çıkarmak için 'Çalışma alanından ayrıl' seçeneğini kullanın."), 409
        )
    if target.role.at_least(Role.ADMIN) and actor.role is not Role.OWNER:
        raise ServiceError(T("Bu işlem için yetkiniz yok."), 403)
    if target.role is Role.OWNER and len(_owners(target.organization)) == 1:
        raise ServiceError(T("Çalışma alanında en az bir sahip kalmalı."), 409)
    _drop_membership(db, target)


def leave_organization(db: Session, membership: Membership) -> None:
    organization = membership.organization
    if len(organization.memberships) == 1:
        raise ServiceError(
            T("Bu çalışma alanının tek üyesisiniz; ayrılmak yerine hesabınızı silebilirsiniz."),
            409,
        )
    if membership.role is Role.OWNER and len(_owners(organization)) == 1:
        raise ServiceError(T("Ayrılmadan önce başka bir üyeyi sahip yapın."), 409)
    _drop_membership(db, membership)


# --- API tokens -------------------------------------------------------------


def create_api_token(
    db: Session, membership: Membership, name: str, settings: Settings
) -> tuple[ApiToken, str]:
    """Returns the stored token and the plain value, which is shown exactly once."""
    if not membership.organization.limits.api:
        raise ServiceError(T("API erişimi Pro ve Ajans planlarında kullanılabilir."), 403)
    label = name.strip()[:100]
    if not label:
        raise ServiceError(T("Token için bir ad girin (ör. 'CI hattı')."), 422)
    user = membership.user
    if len(user.api_tokens) >= settings.max_api_tokens_per_user:
        raise ServiceError(
            T("En fazla {n} API tokeni olabilir.", n=settings.max_api_tokens_per_user), 409
        )
    raw = API_TOKEN_PREFIX + secrets.token_urlsafe(32)
    token = ApiToken(
        user_id=user.id,
        organization_id=membership.organization_id,
        name=label,
        token_hash=_digest(raw),
        prefix=raw[:12],
    )
    db.add(token)
    db.commit()
    db.refresh(user)
    return token, raw


def delete_api_token(db: Session, user: User, token_id: int) -> bool:
    token = db.scalar(select(ApiToken).where(ApiToken.id == token_id, ApiToken.user_id == user.id))
    if token is None:
        return False
    db.delete(token)
    db.commit()
    return True


def membership_for_api_token(db: Session, raw_token: str) -> Membership | None:
    """The (user, organization) a token acts as; None if unknown or no longer a member."""
    if not raw_token.startswith(API_TOKEN_PREFIX):
        return None
    token = db.scalar(select(ApiToken).where(ApiToken.token_hash == _digest(raw_token)))
    if token is None:
        return None
    membership = get_membership(db, token.owner, token.organization_id)
    if membership is None:
        return None
    now = utcnow()
    if token.last_used_at is None or now - token.last_used_at > timedelta(minutes=1):
        token.last_used_at = now  # throttled so every request is not a write
        db.commit()
    return membership


# --- domains ----------------------------------------------------------------


def get_domain(db: Session, user: User, domain_id: int) -> tuple[Domain, Membership] | None:
    """Access is part of the lookup: domains of other organizations are "not found"."""
    row = db.execute(
        select(Domain, Membership)
        .join(Membership, Membership.organization_id == Domain.organization_id)
        .where(Domain.id == domain_id, Membership.user_id == user.id)
    ).first()
    return (row[0], row[1]) if row else None


def organization_domain(db: Session, membership: Membership, domain_id: int) -> Domain | None:
    """A domain of the membership's organization (API tokens act in one organization)."""
    return db.scalar(
        select(Domain).where(
            Domain.id == domain_id, Domain.organization_id == membership.organization_id
        )
    )


def add_domain(db: Session, membership: Membership, raw: str) -> Domain:
    require(membership, Role.ADMIN)
    try:
        hostname = normalize_hostname(raw)
    except TargetError as exc:
        raise ServiceError(exc.text, 422) from exc
    if is_ip_literal(hostname) or "." not in hostname:
        raise ServiceError(T("IP adresi değil, alan adı girin (örnek: firmaniz.com.tr)."), 422)
    organization = membership.organization
    count = (
        db.scalar(select(func.count(Domain.id)).where(Domain.organization_id == organization.id))
        or 0
    )
    if count >= organization.limits.domains:
        raise ServiceError(
            T("Planınız en fazla {n} alan adına izin veriyor.", n=organization.limits.domains),
            409,
        )
    existing = db.scalar(
        select(Domain).where(Domain.organization_id == organization.id, Domain.hostname == hostname)
    )
    if existing is not None:
        raise ServiceError(T("Bu alan adı zaten çalışma alanınızda ekli."), 409)
    domain = Domain(
        organization_id=organization.id,
        hostname=hostname,
        verification_token=secrets.token_hex(16),
    )
    db.add(domain)
    db.commit()
    return domain


def delete_domain(db: Session, membership: Membership, domain: Domain) -> None:
    require(membership, Role.ADMIN)
    db.delete(domain)
    db.commit()


async def verify_domain(
    db: Session, membership: Membership, domain: Domain, settings: Settings
) -> VerificationResult:
    require(membership, Role.ADMIN)
    result = await verify_ownership(
        domain.hostname, domain.verification_token, allow_private=settings.allow_private_targets
    )
    if result.ok:
        mark_verified(db, domain, result.method or "unknown")
    return result


def mark_verified(db: Session, domain: Domain, method: str) -> None:
    domain.verified_at = utcnow()
    domain.verification_method = method
    db.commit()


def update_domain_settings(
    db: Session, membership: Membership, domain: Domain, *, interval_days: int, notify_email: bool
) -> None:
    require(membership, Role.ADMIN)
    if interval_days not in SCAN_INTERVALS:
        raise ServiceError(T("Geçersiz tarama sıklığı."), 422)
    if interval_days not in membership.organization.limits.intervals:
        raise ServiceError(T("Bu tarama sıklığı planınızda yok."), 403)
    if interval_days != domain.scan_interval_days:
        domain.scan_interval_days = interval_days
        domain.next_scan_at = utcnow() + timedelta(days=interval_days) if interval_days else None
    domain.notify_email = notify_email
    db.commit()


# --- scans ------------------------------------------------------------------


def has_active_scan(db: Session, domain: Domain) -> bool:
    active = db.scalar(
        select(Scan.id).where(
            Scan.domain_id == domain.id,
            Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]),
        )
    )
    return active is not None


def request_scan(
    db: Session,
    membership: Membership,
    domain: Domain,
    settings: Settings,
    trigger: ScanTrigger = ScanTrigger.MANUAL,
) -> Scan:
    require(membership, Role.MEMBER)
    if not domain.is_verified and not settings.skip_verification:
        raise ServiceError(
            T("Taramadan önce alan adının size ait olduğunu doğrulamanız gerekiyor."), 403
        )
    if settings.require_email_verification and not membership.user.email_verified:
        raise ServiceError(T("Tarama başlatmadan önce e-posta adresinizi doğrulayın."), 403)
    if has_active_scan(db, domain):
        raise ServiceError(T("Bu alan adı için devam eden bir tarama var."), 409)
    per_day = membership.organization.limits.scans_per_domain_per_day
    since = utcnow() - timedelta(days=1)
    recent = (
        db.scalar(
            select(func.count(Scan.id)).where(Scan.domain_id == domain.id, Scan.created_at >= since)
        )
        or 0
    )
    if recent >= per_day:
        raise ServiceError(
            T("Planınızda bir alan adı günde en fazla {n} kez taranabilir.", n=per_day), 429
        )
    scan = Scan(
        domain_id=domain.id,
        status=ScanStatus.QUEUED,
        trigger=trigger,
        requested_by_id=membership.user_id,
    )
    db.add(scan)
    db.commit()
    return scan


def get_scan(db: Session, user: User, scan_id: int) -> tuple[Scan, Membership] | None:
    row = db.execute(
        select(Scan, Membership)
        .join(Domain, Domain.id == Scan.domain_id)
        .join(Membership, Membership.organization_id == Domain.organization_id)
        .where(Scan.id == scan_id, Membership.user_id == user.id)
    ).first()
    return (row[0], row[1]) if row else None


def organization_scan(db: Session, membership: Membership, scan_id: int) -> Scan | None:
    return db.scalar(
        select(Scan)
        .join(Domain, Domain.id == Scan.domain_id)
        .where(Scan.id == scan_id, Domain.organization_id == membership.organization_id)
    )


def list_scans(db: Session, domain: Domain, limit: int = 20) -> list[Scan]:
    return list(
        db.scalars(
            select(Scan)
            .where(Scan.domain_id == domain.id)
            .order_by(Scan.created_at.desc(), Scan.id.desc())
            .limit(limit)
        )
    )


def previous_scan(db: Session, scan: Scan) -> Scan | None:
    """The last finished scan of the same domain before ``scan`` (for comparisons)."""
    if scan.finished_at is None:
        return None
    return db.scalar(
        select(Scan)
        .where(
            Scan.domain_id == scan.domain_id,
            Scan.status == ScanStatus.DONE,
            Scan.id != scan.id,
            Scan.finished_at < scan.finished_at,
        )
        .order_by(Scan.finished_at.desc(), Scan.id.desc())
        .limit(1)
    )


def plan_usage(organization: Organization) -> dict[str, tuple[int, int]]:
    """Used / allowed, for the team page."""
    limits = organization.limits
    return {
        "domains": (len(organization.domains), limits.domains),
        "members": (
            len(organization.memberships) + len(_open_invitations(organization)),
            limits.members,
        ),
    }
