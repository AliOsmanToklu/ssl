"""Public REST API (``/api/v1``), authenticated with personal access tokens.

Only ``Authorization: Bearer klk_...`` is accepted. Deliberately no cookie auth:
a cookie-authenticated JSON API would need CSRF protection of its own.

A token acts as its creator *within one organization*: it sees that organization's
domains and scans, with the creator's role. Error messages follow the creator's
language setting, then ``Accept-Language``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from kalkan.i18n import N_, localize
from kalkan.web import services
from kalkan.web.deps import DB, AppSettings, request_language
from kalkan.web.models import Domain, Membership, Scan, ScanTrigger
from kalkan.web.routes import pdf_response
from kalkan.web.security import SlidingWindowLimiter
from kalkan.web.verification import FILE_PATH, txt_names, txt_value

router = APIRouter(prefix="/api/v1", tags=["Kalkan API"])
bearer = HTTPBearer(
    auto_error=False,
    scheme_name="API token",
    description="A `klk_...` token created under Account > API tokens.",
)


# --- schemas ----------------------------------------------------------------


class ErrorOut(BaseModel):
    detail: str


class PlanOut(BaseModel):
    name: str = Field(examples=["free", "pro", "agency"])
    domains: int = Field(description="Maximum number of domains")
    scans_per_domain_per_day: int
    scan_intervals: list[int] = Field(description="Allowed automatic scan intervals (days)")
    members: int


class OrganizationOut(BaseModel):
    id: int
    name: str
    role: str = Field(examples=["owner", "admin", "member"], description="The token's role")
    plan: PlanOut


class MeOut(BaseModel):
    email: str
    email_verified: bool
    language: str | None
    created_at: datetime
    organization: OrganizationOut


class VerificationInstructions(BaseModel):
    txt_record_name: str
    txt_record_value: str
    file_url: str
    file_content: str


class DomainOut(BaseModel):
    id: int
    hostname: str = Field(description="ASCII (punycode) hostname")
    display_name: str = Field(description="Unicode hostname, e.g. örnek.com.tr")
    verified: bool
    verified_at: datetime | None
    scan_interval_days: int = Field(description="0 = automatic scans off")
    next_scan_at: datetime | None
    notify_email: bool
    created_at: datetime
    verification: VerificationInstructions | None = Field(
        description="How to prove ownership; present until the domain is verified"
    )


class DomainCreate(BaseModel):
    hostname: str = Field(max_length=253, examples=["firmaniz.com.tr"])


class DomainUpdate(BaseModel):
    scan_interval_days: int | None = Field(default=None, examples=[7])
    notify_email: bool | None = None


class VerificationOut(BaseModel):
    verified: bool
    method: str | None
    message: str


class ScanOut(BaseModel):
    id: int
    domain_id: int
    hostname: str
    status: str = Field(examples=["queued", "running", "done", "failed"])
    trigger: str = Field(examples=["manual", "scheduled", "api"])
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    grade: str | None
    score: int | None
    error: str | None


# --- helpers ----------------------------------------------------------------

_ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorOut, "description": "Token missing or invalid"},
    403: {"model": ErrorOut, "description": "Not allowed by the plan or the token's role"},
    404: {"model": ErrorOut, "description": "Not found (or not in this organization)"},
    429: {"model": ErrorOut, "description": "Rate limited"},
}


def api_membership(
    request: Request,
    db: DB,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Membership:
    membership = (
        services.membership_for_api_token(db, credentials.credentials) if credentials else None
    )
    if membership is None:
        raise HTTPException(
            status_code=401,
            detail=N_("Geçerli bir API tokeni gerekiyor."),
            headers={"WWW-Authenticate": "Bearer"},
        )
    request.state.user = membership.user  # error messages in the user's language
    if not membership.organization.limits.api:  # the plan was downgraded
        raise HTTPException(
            status_code=403, detail=N_("API erişimi Pro ve Ajans planlarında kullanılabilir.")
        )
    limiter: SlidingWindowLimiter = request.app.state.api_limiter
    if not limiter.hit(f"user:{membership.user_id}"):
        raise HTTPException(
            status_code=429,
            detail=N_("Dakika başına istek sınırı aşıldı."),
            headers={"Retry-After": "60"},
        )
    return membership


ApiMembership = Annotated[Membership, Depends(api_membership)]


def _service_error(exc: services.ServiceError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.text)


def _domain(db: DB, membership: Membership, domain_id: int) -> Domain:
    domain = services.organization_domain(db, membership, domain_id)
    if domain is None:
        raise HTTPException(status_code=404, detail=N_("Alan adı bulunamadı."))
    return domain


def _scan(db: DB, membership: Membership, scan_id: int) -> Scan:
    scan = services.organization_scan(db, membership, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=N_("Tarama bulunamadı."))
    return scan


def _finished(scan: Scan) -> None:
    if scan.report_data is None:
        raise HTTPException(status_code=409, detail=N_("Tarama henüz tamamlanmadı."))


def domain_out(domain: Domain) -> DomainOut:
    instructions = None
    if not domain.is_verified:
        instructions = VerificationInstructions(
            txt_record_name=txt_names(domain.hostname)[-1],
            txt_record_value=txt_value(domain.verification_token),
            file_url=f"https://{domain.hostname}{FILE_PATH}",
            file_content=domain.verification_token,
        )
    return DomainOut(
        id=domain.id,
        hostname=domain.hostname,
        display_name=domain.display_name,
        verified=domain.is_verified,
        verified_at=domain.verified_at,
        scan_interval_days=domain.scan_interval_days,
        next_scan_at=domain.next_scan_at,
        notify_email=domain.notify_email,
        created_at=domain.created_at,
        verification=instructions,
    )


def scan_out(scan: Scan, lang: str) -> ScanOut:
    error = scan.error_text
    return ScanOut(
        id=scan.id,
        domain_id=scan.domain_id,
        hostname=scan.domain.hostname,
        status=scan.status.value,
        trigger=scan.trigger.value,
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        grade=scan.grade,
        score=scan.score,
        error=localize(error, lang) if error is not None else None,
    )


# --- endpoints --------------------------------------------------------------


@router.get("/me", responses=_ERRORS, summary="The token's user, organization and plan")
def me(membership: ApiMembership) -> MeOut:
    user, organization = membership.user, membership.organization
    limits = organization.limits
    return MeOut(
        email=user.email,
        email_verified=user.email_verified,
        language=user.locale,
        created_at=user.created_at,
        organization=OrganizationOut(
            id=organization.id,
            name=organization.name,
            role=membership.role.value,
            plan=PlanOut(
                name=organization.plan.value,
                domains=limits.domains,
                scans_per_domain_per_day=limits.scans_per_domain_per_day,
                scan_intervals=list(limits.intervals),
                members=limits.members,
            ),
        ),
    )


@router.get("/domains", responses=_ERRORS, summary="List the organization's domains")
def list_domains(membership: ApiMembership) -> list[DomainOut]:
    return [domain_out(d) for d in membership.organization.domains]


@router.post(
    "/domains",
    status_code=201,
    responses={**_ERRORS, 409: {"model": ErrorOut}, 422: {"model": ErrorOut}},
    summary="Add a domain (admin)",
)
def create_domain(
    body: DomainCreate, response: Response, db: DB, membership: ApiMembership
) -> DomainOut:
    try:
        domain = services.add_domain(db, membership, body.hostname)
    except services.ServiceError as exc:
        raise _service_error(exc) from exc
    response.headers["Location"] = f"/api/v1/domains/{domain.id}"
    return domain_out(domain)


@router.get("/domains/{domain_id}", responses=_ERRORS, summary="Domain details")
def get_domain(domain_id: int, db: DB, membership: ApiMembership) -> DomainOut:
    return domain_out(_domain(db, membership, domain_id))


@router.patch(
    "/domains/{domain_id}",
    responses={**_ERRORS, 422: {"model": ErrorOut}},
    summary="Automatic scan and notification settings (admin)",
)
def update_domain(
    domain_id: int, body: DomainUpdate, db: DB, membership: ApiMembership
) -> DomainOut:
    domain = _domain(db, membership, domain_id)
    try:
        services.update_domain_settings(
            db,
            membership,
            domain,
            interval_days=(
                domain.scan_interval_days
                if body.scan_interval_days is None
                else body.scan_interval_days
            ),
            notify_email=domain.notify_email if body.notify_email is None else body.notify_email,
        )
    except services.ServiceError as exc:
        raise _service_error(exc) from exc
    return domain_out(domain)


@router.delete(
    "/domains/{domain_id}", status_code=204, responses=_ERRORS, summary="Delete a domain (admin)"
)
def delete_domain(domain_id: int, db: DB, membership: ApiMembership) -> Response:
    domain = _domain(db, membership, domain_id)
    try:
        services.delete_domain(db, membership, domain)
    except services.ServiceError as exc:
        raise _service_error(exc) from exc
    return Response(status_code=204)


@router.post(
    "/domains/{domain_id}/verify",
    responses=_ERRORS,
    summary="Check ownership (DNS TXT record or file) (admin)",
)
async def verify_domain(
    request: Request, domain_id: int, db: DB, settings: AppSettings, membership: ApiMembership
) -> VerificationOut:
    domain = _domain(db, membership, domain_id)
    try:
        result = await services.verify_domain(db, membership, domain, settings)
    except services.ServiceError as exc:
        raise _service_error(exc) from exc
    return VerificationOut(
        verified=result.ok,
        method=result.method,
        message=localize(result.message, request_language(request)),
    )


@router.get("/domains/{domain_id}/scans", responses=_ERRORS, summary="Scan history")
def list_scans(
    request: Request,
    domain_id: int,
    db: DB,
    membership: ApiMembership,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[ScanOut]:
    domain = _domain(db, membership, domain_id)
    lang = request_language(request)
    return [scan_out(s, lang) for s in services.list_scans(db, domain, limit)]


@router.post(
    "/domains/{domain_id}/scans",
    status_code=202,
    responses={**_ERRORS, 409: {"model": ErrorOut}},
    summary="Start a scan (queued)",
)
def start_scan(
    request: Request,
    domain_id: int,
    response: Response,
    db: DB,
    settings: AppSettings,
    membership: ApiMembership,
) -> ScanOut:
    domain = _domain(db, membership, domain_id)
    try:
        scan = services.request_scan(db, membership, domain, settings, trigger=ScanTrigger.API)
    except services.ServiceError as exc:
        raise _service_error(exc) from exc
    response.headers["Location"] = f"/api/v1/scans/{scan.id}"
    return scan_out(scan, request_language(request))


@router.get("/scans/{scan_id}", responses=_ERRORS, summary="Scan status")
def get_scan(request: Request, scan_id: int, db: DB, membership: ApiMembership) -> ScanOut:
    return scan_out(_scan(db, membership, scan_id), request_language(request))


@router.get(
    "/scans/{scan_id}/report",
    responses={**_ERRORS, 409: {"model": ErrorOut, "description": "Scan not finished"}},
    summary="Full report (findings, software, open ports)",
    description=(
        "Texts (titles, descriptions, recommendations) are objects with one string per "
        'language, e.g. `{"tr": "...", "en": "..."}`.'
    ),
)
def get_report(scan_id: int, db: DB, membership: ApiMembership) -> dict[str, Any]:
    scan = _scan(db, membership, scan_id)
    _finished(scan)
    assert scan.report_data is not None  # noqa: S101 - checked by _finished
    return scan.report_data


@router.get(
    "/scans/{scan_id}/report.pdf",
    responses={**_ERRORS, 200: {"content": {"application/pdf": {}}, "description": "PDF report"}},
    response_class=Response,
    summary="Download the report as PDF",
    description="In the token user's language; `?lang=en` or `?lang=tr` overrides it.",
)
def get_report_pdf(
    request: Request,
    scan_id: int,
    db: DB,
    membership: ApiMembership,
    lang: Annotated[str | None, Query(pattern="^(tr|en)$")] = None,
) -> Response:
    scan = _scan(db, membership, scan_id)
    _finished(scan)
    return pdf_response(scan, lang or request_language(request))
