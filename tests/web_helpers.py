"""Helpers for driving the web app through ``TestClient`` like a browser would."""

from __future__ import annotations

import asyncio
import re

import httpx
from conftest import make_report
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kalkan.scanner import ScanOptions, ScanReport, TargetError
from kalkan.web.config import Settings
from kalkan.web.mail import Email, MemoryMailer

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
LINK_RE = re.compile(r"https?://[^\s]+(/[a-z-]+/[A-Za-z0-9._-]+)")
PASSWORD = "cok-gizli-sifre-42"


async def fake_scanner(hostname: str, options: ScanOptions) -> ScanReport:
    if hostname == "broken.example.com":
        raise TargetError("'broken.example.com' alan adı çözümlenemedi (DNS kaydı yok).")
    return make_report(target=hostname, display_name=hostname)


def settings_for(database_url: str, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "database_url": database_url,
        "secret_key": "test-secret-key",
        "embedded_worker": False,
        "login_attempts_per_15_min": 3,
        # Pro: 5 domains, 5 scans/day, weekly schedules, API. tests/test_teams.py covers plans.
        "default_plan": "pro",
        # Phase 0 tests focus on domains/scans; tests/test_accounts.py covers this rule.
        "require_email_verification": False,
        "public_url": "https://kalkan.test",
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def csrf(client: TestClient, path: str = "/register") -> str:
    match = CSRF_RE.search(client.get(path).text)
    assert match, f"no CSRF token on {path}"
    return match.group(1)


def register(
    client: TestClient, email: str = "sahip@example.com", **overrides: str
) -> httpx.Response:
    data = {
        "email": email,
        "password": PASSWORD,
        "password_confirm": PASSWORD,
        "consent": "yes",
        "csrf_token": csrf(client, "/register"),
    }
    data.update(overrides)
    response: httpx.Response = client.post("/register", data=data, follow_redirects=False)
    return response


def login(
    client: TestClient, email: str = "sahip@example.com", password: str = PASSWORD
) -> httpx.Response:
    data = {"email": email, "password": password, "csrf_token": csrf(client, "/login")}
    response: httpx.Response = client.post("/login", data=data, follow_redirects=False)
    return response


def post(client: TestClient, path: str, data: dict[str, str] | None = None) -> httpx.Response:
    payload = {"csrf_token": csrf(client, "/dashboard"), **(data or {})}
    response: httpx.Response = client.post(path, data=payload, follow_redirects=False)
    return response


def add_domain(client: TestClient, hostname: str = "example.com") -> int:
    response = post(client, "/domains", {"hostname": hostname})
    assert response.status_code == 303, response.text
    match = re.fullmatch(r"/domains/(\d+)", response.headers["location"])
    assert match, response.headers["location"]
    return int(match.group(1))


def run_worker(app: FastAPI) -> bool:
    processed: bool = asyncio.run(app.state.worker.run_once())
    return processed


def last_email(mailer: MemoryMailer, kind: str) -> Email:
    matching = [e for e in mailer.outbox if e.kind == kind]
    assert matching, f"no {kind!r} e-mail in {[e.kind for e in mailer.outbox]}"
    return matching[-1]


def link_path(email: Email) -> str:
    """The path of the first kalkan link in an e-mail, e.g. /verify-email/<token>."""
    match = LINK_RE.search(email.body)
    assert match, email.body
    return match.group(1)
