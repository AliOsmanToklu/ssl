"""Server-rendered pages: sign-up/sign-in, language, domains, scans and reports."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from kalkan.i18n import LANGUAGES, N_, T, from_json
from kalkan.report import compare_reports, render_html, render_pdf
from kalkan.scanner.scoring import GRADE_SUMMARIES
from kalkan.web import sample, services
from kalkan.web.charts import score_chart
from kalkan.web.config import Settings
from kalkan.web.deps import (
    CSRF,
    DB,
    AppMailer,
    AppSettings,
    AppSigner,
    CurrentMembership,
    CurrentUser,
    OptionalUser,
    flash,
    owned_domain,
    owned_scan,
    redirect,
    render,
    request_language,
    require_session_api_user,
    safe_next,
    start_session,
)
from kalkan.web.emails import verification_email
from kalkan.web.mail import deliver
from kalkan.web.models import PLANS, SCAN_INTERVALS, Plan, Role, Scan, User
from kalkan.web.security import CONTENT_SECURITY_POLICY, SlidingWindowLimiter
from kalkan.web.verification import FILE_PATH, txt_names, txt_value

router = APIRouter(include_in_schema=False)


# --- public pages -----------------------------------------------------------


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/report.css")
def report_css() -> Response:
    css = resources.files("kalkan.report").joinpath("templates/report.css").read_text("utf-8")
    return Response(css, media_type="text/css", headers={"Cache-Control": "public, max-age=3600"})


@router.get("/lang/{code}")
def set_language(
    request: Request, db: DB, user: OptionalUser, code: str, next: str | None = None
) -> Response:
    if code in LANGUAGES:
        request.session["lang"] = code
        if user is not None:
            services.set_locale(db, user, code)
    return redirect(safe_next(next) if next else "/")


@dataclass(frozen=True, slots=True)
class SelfCheckRow:
    label: str
    header: str
    value: str | None


def self_check_rows(request: Request, settings: Settings) -> list[SelfCheckRow]:
    """What the landing page's own response carries (the page's script re-reads it live)."""
    https = request.url.scheme == "https"
    return [
        SelfCheckRow(N_("Şifreli bağlantı (HTTPS)"), "", "https" if https else None),
        SelfCheckRow(
            N_("HTTPS zorlama (HSTS)"),
            "strict-transport-security",
            "max-age=31536000" if settings.https_only else None,
        ),
        SelfCheckRow(
            N_("İçerik güvenlik politikası (CSP)"),
            "content-security-policy",
            CONTENT_SECURITY_POLICY,
        ),
        SelfCheckRow(N_("Çerçeveleme koruması"), "x-frame-options", "DENY"),
        SelfCheckRow(N_("Dosya türü koruması"), "x-content-type-options", "nosniff"),
        SelfCheckRow(
            N_("Yönlendiren bilgisi politikası"),
            "referrer-policy",
            "strict-origin-when-cross-origin",
        ),
    ]


@router.get("/", response_class=HTMLResponse)
def landing(request: Request, user: OptionalUser, settings: AppSettings) -> Response:
    if user is not None:
        return redirect("/dashboard")
    score, grade = sample.sample_grade()
    return render(
        request,
        "landing.html",
        self_check=self_check_rows(request, settings),
        checks=sample.CHECKS,
        findings=sample.SAMPLE_FINDINGS,
        fixes=sample.SAMPLE_FIXES,
        remote_desktop=sample.REMOTE_DESKTOP,
        sample_domain=sample.SAMPLE_DOMAIN,
        token=sample.VERIFICATION_TOKEN,
        score=score,
        grade=grade,
        grade_summary_text=GRADE_SUMMARIES[grade],
        grade_summaries=GRADE_SUMMARIES,
        rules=json.dumps(sample.scoring_rules()),
        plans=PLANS,
        free_plan=Plan.FREE,
    )


@router.get("/register", response_class=HTMLResponse)
def register_form(
    request: Request, user: OptionalUser, email: str = "", next: str | None = None
) -> Response:
    if user is not None:
        return redirect(safe_next(next))
    return render(request, "auth.html", mode="register", email=email[:320], next=safe_next(next))


@router.post("/register", dependencies=CSRF)
def register(
    request: Request,
    db: DB,
    settings: AppSettings,
    signer: AppSigner,
    mailer: AppMailer,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    password_confirm: Annotated[str, Form()],
    consent: Annotated[str | None, Form()] = None,
    next: Annotated[str | None, Form()] = None,
) -> Response:
    lang = request_language(request)

    def fail(message: Any) -> Response:
        return render(
            request,
            "auth.html",
            status_code=400,
            mode="register",
            email=email,
            next=safe_next(next),
            error=message,
        )

    if password != password_confirm:
        return fail(T("Şifreler birbiriyle aynı değil."))
    if consent != "yes":
        return fail(
            T("Yalnızca size ait veya taramak için izniniz olan siteleri tarayacağınızı onaylayın.")
        )
    try:
        user = services.register_user(
            db, email, password, locale=lang, plan=Plan(settings.default_plan)
        )
    except services.ServiceError as exc:
        return fail(exc.text)
    link = settings.link(f"/verify-email/{signer.email_token(user)}")
    deliver(mailer, verification_email(user.email, link, lang))
    start_session(request, user)
    flash(
        request,
        T(
            "Hesabınız oluşturuldu. E-posta adresinize gönderdiğimiz bağlantıyla hesabınızı "
            "doğrulayın; ardından ilk alan adınızı ekleyebilirsiniz."
        ),
    )
    return redirect(safe_next(next))


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, user: OptionalUser, next: str | None = None) -> Response:
    if user is not None:
        return redirect(safe_next(next))
    return render(request, "auth.html", mode="login", email="", next=safe_next(next))


@router.post("/login", dependencies=CSRF)
def login(
    request: Request,
    db: DB,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    next: Annotated[str | None, Form()] = None,
) -> Response:
    limiter: SlidingWindowLimiter = request.app.state.login_limiter
    client = request.client.host if request.client else "unknown"
    key = f"{client}|{email.strip().lower()}"

    def fail(status: int, message: Any) -> Response:
        return render(
            request,
            "auth.html",
            status_code=status,
            mode="login",
            email=email,
            next=safe_next(next),
            error=message,
        )

    if not limiter.hit(key):
        return fail(
            429, T("Çok fazla hatalı deneme yapıldı. Lütfen 15 dakika sonra tekrar deneyin.")
        )
    user = services.authenticate(db, email, password)
    if user is None:
        return fail(400, T("E-posta adresi veya şifre hatalı."))
    limiter.reset(key)
    start_session(request, user)
    return redirect(safe_next(next))


@router.post("/logout", dependencies=CSRF)
def logout(request: Request) -> Response:
    lang = request.session.get("lang")
    request.session.clear()
    if isinstance(lang, str):
        request.session["lang"] = lang
    return redirect("/")


# --- owner pages ------------------------------------------------------------


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, membership: CurrentMembership) -> Response:
    return render(
        request,
        "dashboard.html",
        organization=membership.organization,
        domains=membership.organization.domains,
        usage=services.plan_usage(membership.organization),
        can_manage=membership.role.at_least(Role.ADMIN),
    )


@router.post("/domains", dependencies=CSRF)
def create_domain(
    request: Request,
    db: DB,
    membership: CurrentMembership,
    hostname: Annotated[str, Form()],
) -> Response:
    try:
        domain = services.add_domain(db, membership, hostname)
    except services.ServiceError as exc:
        flash(request, exc.text, "error")
        return redirect("/dashboard")
    flash(
        request,
        T("{domain} eklendi. Şimdi size ait olduğunu doğrulayın.", domain=domain.display_name),
    )
    return redirect(f"/domains/{domain.id}")


@router.get("/domains/{domain_id}", response_class=HTMLResponse)
def domain_detail(
    request: Request, db: DB, settings: AppSettings, user: CurrentUser, domain_id: int
) -> Response:
    domain, membership = owned_domain(request, db, user, domain_id)
    return render(
        request,
        "domain.html",
        domain=domain,
        txt_names=txt_names(domain.hostname),
        txt_value=txt_value(domain.verification_token),
        file_path=FILE_PATH,
        can_scan=domain.is_verified or settings.skip_verification,
        can_manage=membership.role.at_least(Role.ADMIN),
        intervals=SCAN_INTERVALS,
        allowed_intervals=membership.organization.limits.intervals,
        chart=score_chart(domain.scans),
    )


@router.post("/domains/{domain_id}/verify", dependencies=CSRF)
async def verify_domain(
    request: Request, db: DB, settings: AppSettings, user: CurrentUser, domain_id: int
) -> Response:
    domain, membership = owned_domain(request, db, user, domain_id)
    try:
        result = await services.verify_domain(db, membership, domain, settings)
    except services.ServiceError as exc:
        flash(request, exc.text, "error")
        return redirect(f"/domains/{domain.id}")
    if result.ok:
        flash(
            request,
            T("{domain} doğrulandı. Artık tarama başlatabilirsiniz.", domain=domain.display_name),
        )
    else:
        flash(request, result.message, "error")
    return redirect(f"/domains/{domain.id}")


@router.post("/domains/{domain_id}/settings", dependencies=CSRF)
def domain_settings(
    request: Request,
    db: DB,
    user: CurrentUser,
    domain_id: int,
    interval_days: Annotated[int, Form()],
    notify_email: Annotated[str | None, Form()] = None,
) -> Response:
    domain, membership = owned_domain(request, db, user, domain_id)
    try:
        services.update_domain_settings(
            db, membership, domain, interval_days=interval_days, notify_email=notify_email == "yes"
        )
    except services.ServiceError as exc:
        flash(request, exc.text, "error")
    else:
        flash(request, T("Otomatik tarama ayarları kaydedildi."))
    return redirect(f"/domains/{domain.id}")


@router.post("/domains/{domain_id}/scans", dependencies=CSRF)
def start_scan(
    request: Request, db: DB, settings: AppSettings, user: CurrentUser, domain_id: int
) -> Response:
    domain, membership = owned_domain(request, db, user, domain_id)
    try:
        scan = services.request_scan(db, membership, domain, settings)
    except services.ServiceError as exc:
        flash(request, exc.text, "error")
        return redirect(f"/domains/{domain.id}")
    return redirect(f"/scans/{scan.id}")


@router.post("/domains/{domain_id}/delete", dependencies=CSRF)
def remove_domain(request: Request, db: DB, user: CurrentUser, domain_id: int) -> Response:
    domain, membership = owned_domain(request, db, user, domain_id)
    name = domain.display_name
    try:
        services.delete_domain(db, membership, domain)
    except services.ServiceError as exc:
        flash(request, exc.text, "error")
        return redirect(f"/domains/{domain_id}")
    flash(request, T("{domain} ve tüm tarama geçmişi silindi.", domain=name))
    return redirect("/dashboard")


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(request: Request, db: DB, user: CurrentUser, scan_id: int) -> Response:
    scan, _membership = owned_scan(request, db, user, scan_id)
    report = scan.report
    previous = services.previous_scan(db, scan)
    comparison = (
        compare_reports(previous.report, report)
        if report is not None and previous is not None and previous.report is not None
        else None
    )
    return render(
        request,
        "scan.html",
        scan=scan,
        domain=scan.domain,
        report=report,
        comparison=comparison,
        previous=previous,
        scan_error=from_json(scan.error_text) if scan.error_text else None,
    )


@router.get("/scans/{scan_id}/report.html")
def scan_report_html(request: Request, db: DB, user: CurrentUser, scan_id: int) -> Response:
    report = owned_scan(request, db, user, scan_id)[0].report
    if report is None:
        raise HTTPException(status_code=404)
    filename = f"kalkan-rapor-{report.target}-{report.finished_at:%Y%m%d}.html"
    return HTMLResponse(
        render_html(report, request_language(request)),
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            # the standalone report carries its own inline stylesheet
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
        },
    )


@router.get("/scans/{scan_id}/report.pdf")
def scan_report_pdf(request: Request, db: DB, user: CurrentUser, scan_id: int) -> Response:
    return pdf_response(owned_scan(request, db, user, scan_id)[0], request_language(request))


def pdf_response(scan: Scan, lang: str) -> Response:
    report = scan.report
    if report is None:
        raise HTTPException(status_code=404, detail=N_("Rapor henüz hazır değil."))
    filename = f"kalkan-rapor-{report.target}-{report.finished_at:%Y%m%d}.pdf"
    return Response(
        render_pdf(report, lang),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/scans/{scan_id}/report.json")
def scan_report_json(request: Request, db: DB, user: CurrentUser, scan_id: int) -> Response:
    scan = owned_scan(request, db, user, scan_id)[0]
    if scan.report_data is None:
        raise HTTPException(status_code=404)
    return JSONResponse(scan.report_data)


@router.get("/api/scans/{scan_id}")
def scan_status(
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_session_api_user)],
    scan_id: int,
) -> dict[str, Any]:
    """Polled by the scan page; the documented API lives under /api/v1."""
    scan = owned_scan(request, db, user, scan_id)[0]
    return {
        "id": scan.id,
        "status": scan.status.value,
        "grade": scan.grade,
        "score": scan.score,
        "error": scan.error,
    }
