"""Team pages: the current organization, its members, invitations, plan and switching."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, Response

from kalkan.i18n import T
from kalkan.web import services
from kalkan.web.db import utcnow
from kalkan.web.deps import (
    CSRF,
    DB,
    AppMailer,
    AppSettings,
    CurrentMembership,
    CurrentUser,
    OptionalUser,
    flash,
    redirect,
    render,
    request_language,
)
from kalkan.web.emails import invitation_email
from kalkan.web.mail import deliver
from kalkan.web.models import PLANS, Role

router = APIRouter(include_in_schema=False)


@router.get("/team", response_class=HTMLResponse)
def team(request: Request, user: CurrentUser, membership: CurrentMembership) -> Response:
    organization = membership.organization
    now = utcnow()
    return render(
        request,
        "team.html",
        organization=organization,
        members=organization.memberships,
        invitations=[i for i in organization.invitations if i.is_open(now)],
        usage=services.plan_usage(organization),
        plans=PLANS,
        roles=[Role.MEMBER, Role.ADMIN, Role.OWNER],
        other_memberships=[m for m in user.memberships if m.id != membership.id],
    )


@router.post("/team/name", dependencies=CSRF)
def rename(
    request: Request, db: DB, membership: CurrentMembership, name: Annotated[str, Form()]
) -> Response:
    try:
        services.rename_organization(db, membership, name)
    except services.ServiceError as exc:
        flash(request, exc.text, "error")
    else:
        flash(request, T("Çalışma alanının adı değiştirildi."))
    return redirect("/team")


@router.post("/team/invitations", dependencies=CSRF)
def create_invitation(
    request: Request,
    db: DB,
    settings: AppSettings,
    mailer: AppMailer,
    membership: CurrentMembership,
    email: Annotated[str, Form()],
    role: Annotated[str, Form()] = Role.MEMBER.value,
) -> Response:
    try:
        invitation, raw = services.invite(db, membership, email, Role(role))
    except (services.ServiceError, ValueError) as exc:
        text = exc.text if isinstance(exc, services.ServiceError) else T("Geçersiz rol.")
        flash(request, text, "error")
        return redirect("/team")
    deliver(
        mailer,
        invitation_email(
            invitation.email,
            membership.user.email,
            membership.organization.name,
            settings.link(f"/invitations/{raw}"),
            request_language(request),
        ),
    )
    flash(request, T("{email} adresine davet gönderildi.", email=invitation.email))
    return redirect("/team")


@router.post("/team/invitations/{invitation_id}/revoke", dependencies=CSRF)
def revoke_invitation(
    request: Request, db: DB, membership: CurrentMembership, invitation_id: int
) -> Response:
    try:
        done = services.revoke_invitation(db, membership, invitation_id)
    except services.ServiceError as exc:
        flash(request, exc.text, "error")
        return redirect("/team")
    flash(
        request,
        T("Davet iptal edildi.") if done else T("Davet bulunamadı."),
        "success" if done else "error",
    )
    return redirect("/team")


@router.post("/team/members/{membership_id}/role", dependencies=CSRF)
def change_role(
    request: Request,
    db: DB,
    membership: CurrentMembership,
    membership_id: int,
    role: Annotated[str, Form()],
) -> Response:
    try:
        services.change_role(db, membership, membership_id, Role(role))
    except services.ServiceError as exc:
        flash(request, exc.text, "error")
    except ValueError:
        flash(request, T("Geçersiz rol."), "error")
    else:
        flash(request, T("Rol güncellendi."))
    return redirect("/team")


@router.post("/team/members/{membership_id}/remove", dependencies=CSRF)
def remove_member(
    request: Request, db: DB, membership: CurrentMembership, membership_id: int
) -> Response:
    try:
        services.remove_member(db, membership, membership_id)
    except services.ServiceError as exc:
        flash(request, exc.text, "error")
    else:
        flash(request, T("Üye çalışma alanından çıkarıldı."))
    return redirect("/team")


@router.post("/team/leave", dependencies=CSRF)
def leave(request: Request, db: DB, membership: CurrentMembership) -> Response:
    name = membership.organization.name
    try:
        services.leave_organization(db, membership)
    except services.ServiceError as exc:
        flash(request, exc.text, "error")
        return redirect("/team")
    request.session.pop("org", None)
    flash(request, T("{name} çalışma alanından ayrıldınız.", name=name))
    return redirect("/dashboard")


@router.post("/orgs/{organization_id}/switch", dependencies=CSRF)
def switch(request: Request, db: DB, user: CurrentUser, organization_id: int) -> Response:
    if services.get_membership(db, user, organization_id) is None:
        raise HTTPException(status_code=404)
    request.session["org"] = organization_id
    return redirect("/dashboard")


# --- accepting an invitation -------------------------------------------------


@router.get("/invitations/{token}", response_class=HTMLResponse)
def invitation_page(request: Request, db: DB, user: OptionalUser, token: str) -> Response:
    invitation = services.invitation_for_token(db, token)
    headers = {"Referrer-Policy": "no-referrer", "Cache-Control": "no-store"}
    if invitation is None:
        return render(request, "invitation.html", status_code=404, invitation=None, headers=headers)
    return render(
        request,
        "invitation.html",
        invitation=invitation,
        token=token,
        email_matches=user is not None and user.email == invitation.email,
        headers=headers,
    )


@router.post("/invitations/{token}/accept", dependencies=CSRF)
def accept(request: Request, db: DB, user: CurrentUser, token: str) -> Response:
    try:
        membership = services.accept_invitation(db, user, token)
    except services.ServiceError as exc:
        flash(request, exc.text, "error")
        return redirect("/dashboard")
    request.session["org"] = membership.organization_id
    flash(
        request,
        T("{name} çalışma alanına katıldınız.", name=membership.organization.name),
    )
    return redirect("/dashboard")
