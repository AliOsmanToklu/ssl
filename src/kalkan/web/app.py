"""FastAPI application factory (``uvicorn --factory kalkan.web.app:create_app``)."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import logging
import secrets
from collections.abc import AsyncIterator
from pathlib import Path

import jinja2
from fastapi import FastAPI, HTTPException, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from kalkan import __version__
from kalkan.i18n import N_, localize
from kalkan.report.render import register_helpers
from kalkan.scanner import scan
from kalkan.web import account, api, routes, team
from kalkan.web.config import Settings
from kalkan.web.db import make_engine, make_session_factory
from kalkan.web.deps import LoginRequired, render, request_language
from kalkan.web.mail import Mailer, make_mailer
from kalkan.web.migrate import ensure_current, upgrade_database
from kalkan.web.observability import ObservabilityMiddleware
from kalkan.web.security import SecurityHeadersMiddleware, SlidingWindowLimiter
from kalkan.web.tokens import Signer
from kalkan.web.verification import verify_ownership
from kalkan.web.worker import Scanner, ScanWorker, Verifier

log = logging.getLogger(__name__)
WEB_DIR = Path(__file__).parent

API_DESCRIPTION = """
Use Kalkan from your own systems: add domains, prove ownership, start scans and fetch
reports as JSON or PDF.

**Authentication:** create a token under *Account > API tokens* and send
`Authorization: Bearer klk_...` with every request. A token acts in the workspace
(organization) it was created in, with its creator's role.

**Plans:** the API is available on the Pro and Agency plans. Domains, scans per day and
automatic scan intervals follow the workspace's plan (see `GET /api/v1/me`).

**Rate limit:** 60 requests per minute per user.

**Language:** error messages use the token user's language setting, then
`Accept-Language` (`tr` or `en`).
"""
# Swagger UI is served from a CDN and boots with an inline script: allow exactly that,
# on this page only. Every other page keeps the strict default policy.
DOCS_CSP = (
    "default-src 'none'; script-src https://cdn.jsdelivr.net 'unsafe-inline'; "
    "style-src https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data: "
    "https://fastapi.tiangolo.com; connect-src 'self'; frame-ancestors 'none'"
)


def _templates() -> Jinja2Templates:
    env = jinja2.Environment(
        loader=jinja2.ChoiceLoader(
            [
                jinja2.PackageLoader("kalkan.web", "templates"),
                jinja2.PackageLoader("kalkan.report", "templates"),
            ]
        ),
        autoescape=jinja2.select_autoescape(("html", "htm", "xml")),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    register_helpers(env)
    env.globals["app_version"] = __version__
    return Jinja2Templates(env=env)


def create_app(
    settings: Settings | None = None,
    *,
    scanner: Scanner | None = None,
    mailer: Mailer | None = None,
    verifier: Verifier | None = None,
) -> FastAPI:
    settings = settings or Settings()
    if not settings.secret_key:
        log.warning("KALKAN_SECRET_KEY is not set: using a random key, sessions end on restart")
    if settings.skip_verification or settings.allow_private_targets:
        log.warning("development-only options are enabled; never use them in production")
    secret = settings.secret_key or secrets.token_urlsafe(48)

    engine = make_engine(settings.database_url)
    if settings.auto_migrate:
        upgrade_database(engine)
    else:
        ensure_current(engine)
    session_factory = make_session_factory(engine)
    mailer = mailer or make_mailer(settings)
    worker = ScanWorker(
        session_factory,
        settings,
        scanner=scanner or scan,
        mailer=mailer,
        verifier=verifier or verify_ownership,
    )

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        stop = asyncio.Event()
        task = asyncio.create_task(worker.run_forever(stop)) if settings.embedded_worker else None
        try:
            yield
        finally:
            stop.set()
            if task is not None:
                try:
                    await asyncio.wait_for(task, timeout=10)
                except TimeoutError:
                    task.cancel()
            engine.dispose()

    app = FastAPI(
        title="Kalkan API",
        version=__version__,
        description=API_DESCRIPTION,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.settings = settings
    app.state.session_factory = session_factory
    app.state.worker = worker
    app.state.mailer = mailer
    app.state.signer = Signer(secret)
    app.state.templates = _templates()
    app.state.login_limiter = SlidingWindowLimiter(settings.login_attempts_per_15_min, 15 * 60)
    app.state.forgot_limiter = SlidingWindowLimiter(5, 15 * 60)
    app.state.resend_limiter = SlidingWindowLimiter(3, 60 * 60)
    app.state.api_limiter = SlidingWindowLimiter(settings.api_requests_per_minute, 60)

    app.add_middleware(
        SessionMiddleware,
        secret_key=secret,
        session_cookie="kalkan_session",
        max_age=14 * 24 * 3600,
        same_site="lax",
        https_only=settings.https_only,
    )
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.https_only)
    app.add_middleware(ObservabilityMiddleware)  # outermost: sees every request
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")
    app.include_router(routes.router)
    app.include_router(account.router)
    app.include_router(team.router)
    app.include_router(api.router)

    @app.get("/api/docs", include_in_schema=False)
    def api_docs() -> Response:
        page = get_swagger_ui_html(openapi_url="/api/openapi.json", title="Kalkan API")
        page.headers["Content-Security-Policy"] = DOCS_CSP
        return page

    @app.get("/metrics", include_in_schema=False)
    def metrics(request: Request) -> Response:
        if not settings.metrics_token:
            raise HTTPException(status_code=404)
        expected = f"Bearer {settings.metrics_token}"
        if not hmac.compare_digest(request.headers.get("authorization", ""), expected):
            raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Bearer"})
        worker.queue_depth()
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, _exc: Exception) -> Response:
        return RedirectResponse(f"/login?next={request.url.path}", status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: Exception) -> Response:
        if not isinstance(exc, StarletteHTTPException):  # pragma: no cover - registered type
            raise exc
        lang = request_language(request)
        detail = localize(exc.detail, lang)  # messages are raised in every language
        if request.url.path.startswith(("/api/", "/metrics")):
            return JSONResponse(
                {"detail": detail}, status_code=exc.status_code, headers=exc.headers
            )
        if exc.status_code == 404:
            detail = localize(N_("Aradığınız sayfa bulunamadı."), lang)
        return render(
            request,
            "error.html",
            status_code=exc.status_code,
            status=exc.status_code,
            message=detail,
            # The request's database session is already closed here: nothing may lazy-load.
            membership=None,
        )

    return app
