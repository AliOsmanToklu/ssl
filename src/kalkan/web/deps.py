"""FastAPI dependencies and helpers shared by the page, account, team and API routers."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from kalkan.i18n import LANGUAGES, N_, LocalizedValue, best_language, from_json, localize, to_json
from kalkan.web import services
from kalkan.web.config import Settings
from kalkan.web.mail import Mailer
from kalkan.web.models import Domain, Membership, Scan, User
from kalkan.web.security import CSRF_FORM_FIELD, csrf_token, csrf_valid
from kalkan.web.tokens import Signer


class LoginRequired(Exception):
    pass


def get_db(request: Request) -> Iterator[Session]:
    with request.app.state.session_factory() as db:
        yield db


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_signer(request: Request) -> Signer:
    signer: Signer = request.app.state.signer
    return signer


def get_mailer(request: Request) -> Mailer:
    mailer: Mailer = request.app.state.mailer
    return mailer


DB = Annotated[Session, Depends(get_db)]
AppSettings = Annotated[Settings, Depends(get_settings)]
AppSigner = Annotated[Signer, Depends(get_signer)]
AppMailer = Annotated[Mailer, Depends(get_mailer)]


def request_language(request: Request) -> str:
    """The user's saved choice, then the session's, then the browser's, then Turkish."""
    user: User | None = getattr(request.state, "user", None)
    if user is not None and user.locale in LANGUAGES:
        return str(user.locale)
    chosen = request.session.get("lang")
    if isinstance(chosen, str) and chosen in LANGUAGES:
        return chosen
    return best_language(request.headers.get("accept-language"))


def current_user(request: Request, db: DB) -> User | None:
    uid = request.session.get("uid")
    user = db.get(User, uid) if isinstance(uid, int) else None
    if user is not None and request.session.get("sv") != user.session_version:
        request.session.clear()  # password changed elsewhere: this session is void
        user = None
    request.state.user = user
    return user


def require_user(user: Annotated[User | None, Depends(current_user)]) -> User:
    if user is None:
        raise LoginRequired
    return user


def require_session_api_user(user: Annotated[User | None, Depends(current_user)]) -> User:
    """For the page's own polling endpoint; the public API uses bearer tokens instead."""
    if user is None:
        raise HTTPException(status_code=401, detail=N_("Oturum açmanız gerekiyor."))
    return user


async def csrf_protect(request: Request) -> None:
    form = await request.form()
    if not csrf_valid(request, form.get(CSRF_FORM_FIELD)):
        raise HTTPException(
            status_code=403,
            detail=N_("Güvenlik doğrulaması başarısız. Sayfayı yenileyip tekrar deneyin."),
        )


OptionalUser = Annotated[User | None, Depends(current_user)]
CurrentUser = Annotated[User, Depends(require_user)]
CSRF = [Depends(csrf_protect)]


def current_membership(request: Request, db: DB, user: CurrentUser) -> Membership:
    """The organization the user works in right now (kept in the session)."""
    preferred = request.session.get("org")
    membership = services.current_membership(
        db, user, preferred if isinstance(preferred, int) else None
    )
    request.session["org"] = membership.organization_id
    request.state.membership = membership
    return membership


CurrentMembership = Annotated[Membership, Depends(current_membership)]


def flash(request: Request, message: LocalizedValue, level: str = "success") -> None:
    request.session.setdefault("flash", []).append([level, to_json(message)])


def render(
    request: Request,
    template: str,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    **context: Any,
) -> Response:
    templates: Jinja2Templates = request.app.state.templates
    user: User | None = context.setdefault("user", getattr(request.state, "user", None))
    lang = request_language(request)
    context["lang"] = lang
    context["csrf_token"] = csrf_token(request)
    context["csrf_field"] = CSRF_FORM_FIELD
    context["flashes"] = [
        (level, localize(from_json(message), lang))
        for level, message in request.session.pop("flash", [])
    ]
    context["email_unverified"] = user is not None and not user.email_verified
    context.setdefault("membership", getattr(request.state, "membership", None))
    context["current_path"] = request.url.path
    return templates.TemplateResponse(
        request, template, context, status_code=status_code, headers=headers
    )


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def safe_next(value: str | None) -> str:
    if value and value.startswith("/") and not value.startswith(("//", "/\\")):
        return value
    return "/dashboard"


def start_session(request: Request, user: User) -> None:
    lang = request.session.get("lang")
    request.session.clear()  # new session on login: no fixation, fresh CSRF token
    request.session["uid"] = user.id
    request.session["sv"] = user.session_version
    if isinstance(lang, str):
        request.session["lang"] = lang


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def owned_domain(
    request: Request, db: Session, user: User, domain_id: int
) -> tuple[Domain, Membership]:
    found = services.get_domain(db, user, domain_id)
    if found is None:
        raise HTTPException(status_code=404, detail=N_("Alan adı bulunamadı."))
    domain, membership = found
    request.session["org"] = membership.organization_id  # follow the link into its workspace
    request.state.membership = membership
    return domain, membership


def owned_scan(request: Request, db: Session, user: User, scan_id: int) -> tuple[Scan, Membership]:
    found = services.get_scan(db, user, scan_id)
    if found is None:
        raise HTTPException(status_code=404, detail=N_("Tarama bulunamadı."))
    scan, membership = found
    request.session["org"] = membership.organization_id
    request.state.membership = membership
    return scan, membership


def service_error(request: Request, exc: services.ServiceError) -> str:
    return localize(exc.text, request_language(request))
