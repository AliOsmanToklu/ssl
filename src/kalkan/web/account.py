"""Account pages: e-mail verification, password reset/change, API tokens, export, deletion."""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, Response

from kalkan.i18n import T
from kalkan.web import services
from kalkan.web.db import utcnow
from kalkan.web.deps import (
    CSRF,
    DB,
    AppMailer,
    AppSettings,
    AppSigner,
    CurrentMembership,
    CurrentUser,
    OptionalUser,
    client_ip,
    flash,
    redirect,
    render,
    request_language,
    start_session,
)
from kalkan.web.emails import (
    password_changed_email,
    reset_email,
    verification_email,
    welcome_email,
)
from kalkan.web.mail import deliver
from kalkan.web.security import SlidingWindowLimiter

router = APIRouter(include_in_schema=False)

# A reset link carries a secret in its URL: never leak it through the Referer header.
_NO_REFERRER = {"Referrer-Policy": "no-referrer"}


def _limiter(request: Request, name: str) -> SlidingWindowLimiter:
    limiter: SlidingWindowLimiter = getattr(request.app.state, name)
    return limiter


# --- e-mail verification ----------------------------------------------------


@router.get("/verify-email/{token}")
def verify_email(
    request: Request,
    db: DB,
    settings: AppSettings,
    signer: AppSigner,
    mailer: AppMailer,
    token: str,
) -> Response:
    try:
        user, first_time = services.confirm_email(db, signer, token)
    except services.ServiceError as exc:
        flash(request, exc.text, "error")
        return redirect("/account" if request.session.get("uid") else "/login")
    if first_time:  # say hello and show the way
        deliver(mailer, welcome_email(user.email, settings.link("/dashboard"), user.locale))
    flash(request, T("E-posta adresiniz doğrulandı. Teşekkürler!"))
    if request.session.get("uid") == user.id:
        return redirect("/dashboard")
    return redirect("/login")


@router.post("/verify-email/resend", dependencies=CSRF)
def resend_verification(
    request: Request,
    settings: AppSettings,
    signer: AppSigner,
    mailer: AppMailer,
    user: CurrentUser,
) -> Response:
    if user.email_verified:
        flash(request, T("E-posta adresiniz zaten doğrulanmış."))
    elif not _limiter(request, "resend_limiter").hit(f"user:{user.id}"):
        flash(request, T("Çok sık istek gönderildi. Lütfen biraz sonra tekrar deneyin."), "error")
    else:
        link = settings.link(f"/verify-email/{signer.email_token(user)}")
        deliver(mailer, verification_email(user.email, link, request_language(request)))
        flash(
            request,
            T("Doğrulama bağlantısını {email} adresine tekrar gönderdik.", email=user.email),
        )
    return redirect("/account")


# --- password reset ---------------------------------------------------------


@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_form(request: Request, user: OptionalUser) -> Response:
    return render(request, "forgot.html")


@router.post("/forgot-password", dependencies=CSRF)
def forgot(
    request: Request,
    db: DB,
    settings: AppSettings,
    signer: AppSigner,
    mailer: AppMailer,
    email: Annotated[str, Form()],
) -> Response:
    if not _limiter(request, "forgot_limiter").hit(client_ip(request)):
        return render(
            request,
            "forgot.html",
            status_code=429,
            error=T("Çok fazla istek gönderildi. Lütfen 15 dakika sonra tekrar deneyin."),
        )
    user = services.find_user_by_email(db, email)
    if user is not None:
        link = settings.link(f"/reset-password/{signer.reset_token(user)}")
        deliver(mailer, reset_email(user.email, link, user.locale or request_language(request)))
    # Same answer whether or not the account exists: no account enumeration.
    return render(
        request,
        "forgot.html",
        sent=T(
            "Bu adresle kayıtlı bir hesap varsa şifre sıfırlama bağlantısı gönderdik. "
            "Gelen kutunuzu (ve istenmeyen klasörünü) kontrol edin."
        ),
    )


@router.get("/reset-password/{token}", response_class=HTMLResponse)
def reset_form(request: Request, db: DB, signer: AppSigner, token: str) -> Response:
    try:
        services.user_for_reset_token(db, signer, token)
    except services.ServiceError as exc:
        return render(
            request, "reset.html", status_code=400, invalid=exc.text, headers=_NO_REFERRER
        )
    return render(request, "reset.html", token=token, headers=_NO_REFERRER)


@router.post("/reset-password/{token}", dependencies=CSRF)
def reset(
    request: Request,
    db: DB,
    signer: AppSigner,
    mailer: AppMailer,
    token: str,
    password: Annotated[str, Form()],
    password_confirm: Annotated[str, Form()],
) -> Response:
    if password != password_confirm:
        return render(
            request,
            "reset.html",
            status_code=400,
            token=token,
            error=T("Şifreler birbiriyle aynı değil."),
            headers=_NO_REFERRER,
        )
    try:
        user = services.reset_password(db, signer, token, password)
    except services.ServiceError as exc:
        return render(
            request,
            "reset.html",
            status_code=400,
            token=token,
            error=exc.text,
            headers=_NO_REFERRER,
        )
    deliver(mailer, password_changed_email(user.email, user.locale))
    start_session(request, user)
    flash(request, T("Şifreniz değiştirildi ve diğer tüm oturumlar kapatıldı."))
    return redirect("/dashboard")


# --- account settings -------------------------------------------------------


@router.get("/account", response_class=HTMLResponse)
def account(request: Request, user: CurrentUser, membership: CurrentMembership) -> Response:
    return render(request, "account.html", tokens=user.api_tokens)


@router.post("/account/password", dependencies=CSRF)
def change_password(
    request: Request,
    db: DB,
    mailer: AppMailer,
    user: CurrentUser,
    current_password: Annotated[str, Form()],
    password: Annotated[str, Form()],
    password_confirm: Annotated[str, Form()],
) -> Response:
    if password != password_confirm:
        flash(request, T("Yeni şifreler birbiriyle aynı değil."), "error")
        return redirect("/account")
    try:
        services.change_password(db, user, current_password, password)
    except services.ServiceError as exc:
        flash(request, exc.text, "error")
        return redirect("/account")
    deliver(mailer, password_changed_email(user.email, user.locale))
    start_session(request, user)  # keep this browser signed in with the new version
    flash(request, T("Şifreniz değiştirildi. Diğer cihazlardaki oturumlar kapatıldı."))
    return redirect("/account")


@router.post("/account/tokens", dependencies=CSRF)
def create_token(
    request: Request,
    db: DB,
    settings: AppSettings,
    user: CurrentUser,
    membership: CurrentMembership,
    name: Annotated[str, Form()],
) -> Response:
    try:
        token, raw = services.create_api_token(db, membership, name, settings)
    except services.ServiceError as exc:
        flash(request, exc.text, "error")
        return redirect("/account")
    # Rendered directly (not via a redirect + flash) so the secret never lands in the
    # session cookie. It is shown exactly once.
    return render(
        request,
        "account.html",
        status_code=201,
        tokens=user.api_tokens,
        new_token=raw,
        new_token_name=token.name,
        headers={"Cache-Control": "no-store"},
    )


@router.post("/account/tokens/{token_id}/delete", dependencies=CSRF)
def delete_token(request: Request, db: DB, user: CurrentUser, token_id: int) -> Response:
    if services.delete_api_token(db, user, token_id):
        flash(request, T("API tokeni silindi; artık kullanılamaz."))
    else:
        flash(request, T("Token bulunamadı."), "error")
    return redirect("/account")


@router.get("/account/export.json")
def export(user: CurrentUser) -> Response:
    payload = json.dumps(services.export_user_data(user), ensure_ascii=False, indent=2)
    filename = f"kalkan-verilerim-{utcnow():%Y%m%d}.json"
    return Response(
        payload,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


@router.post("/account/delete", dependencies=CSRF)
def delete_account(
    request: Request, db: DB, user: CurrentUser, password: Annotated[str, Form()]
) -> Response:
    try:
        services.delete_account(db, user, password)
    except services.ServiceError as exc:
        flash(request, exc.text, "error")
        return redirect("/account")
    lang = request.session.get("lang")
    request.session.clear()
    if isinstance(lang, str):
        request.session["lang"] = lang
    flash(request, T("Hesabınız ve tüm verileriniz kalıcı olarak silindi."))
    return redirect("/")
