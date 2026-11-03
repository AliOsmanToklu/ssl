from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from typing import Any, ClassVar

import pytest

from kalkan.scanner.models import Category, Finding, Severity
from kalkan.web import emails
from kalkan.web.config import Settings
from kalkan.web.mail import ConsoleMailer, Email, MemoryMailer, SmtpMailer, deliver, make_mailer

MESSAGE = Email("sahip@example.com", "Konu", "Gövde: şifre sıfırlama", "reset")


class FakeSMTP:
    instances: ClassVar[list[FakeSMTP]] = []

    def __init__(self, host: str, port: int, **kwargs: Any) -> None:
        self.host, self.port, self.kwargs = host, port, kwargs
        self.calls: list[str] = []
        self.sent: list[EmailMessage] = []
        FakeSMTP.instances.append(self)

    def __enter__(self) -> FakeSMTP:
        return self

    def __exit__(self, *args: object) -> None:
        self.calls.append("quit")

    def starttls(self, context: object) -> None:
        self.calls.append("starttls")

    def login(self, user: str, password: str) -> None:
        self.calls.append(f"login:{user}")

    def send_message(self, message: EmailMessage) -> None:
        self.sent.append(message)


@pytest.fixture(autouse=True)
def fake_smtp(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeSMTP.instances = []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)


def test_smtp_with_starttls_and_login() -> None:
    settings = Settings(
        mail_backend="smtp",
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_username="kalkan",
        smtp_password="gizli",
        mail_from="Kalkan <no-reply@example.com>",
    )
    mailer = make_mailer(settings)
    assert isinstance(mailer, SmtpMailer)
    assert deliver(mailer, MESSAGE) is True
    smtp = FakeSMTP.instances[0]
    assert (smtp.host, smtp.port) == ("smtp.example.com", 587)
    assert smtp.calls == ["starttls", "login:kalkan", "quit"]
    sent = smtp.sent[0]
    assert sent["To"] == "sahip@example.com"
    assert sent["From"] == "Kalkan <no-reply@example.com>"
    assert sent["Subject"] == "Konu"
    assert "şifre sıfırlama" in sent.get_content()


def test_smtp_over_implicit_tls_without_login() -> None:
    mailer = SmtpMailer(Settings(smtp_ssl=True, smtp_port=465))
    mailer.send(MESSAGE)
    smtp = FakeSMTP.instances[0]
    assert smtp.port == 465 and "context" in smtp.kwargs
    assert smtp.calls == ["quit"]  # no STARTTLS on an already encrypted connection


def test_console_backend_logs(caplog: pytest.LogCaptureFixture) -> None:
    assert isinstance(make_mailer(Settings()), ConsoleMailer)
    with caplog.at_level(logging.INFO, logger="kalkan.web.mail"):
        ConsoleMailer().send(MESSAGE)
    assert "sahip@example.com" in caplog.text and "Konu" in caplog.text


def test_deliver_swallows_failures(caplog: pytest.LogCaptureFixture) -> None:
    class Broken(MemoryMailer):
        def send(self, email: Email) -> None:
            raise OSError("bağlantı reddedildi")

    with caplog.at_level(logging.ERROR):
        assert deliver(Broken(), MESSAGE) is False
    assert "could not send reset e-mail" in caplog.text


def test_alert_email_texts() -> None:
    finding = Finding(
        "ports.open_3389", Category.PORTS, Severity.HIGH, "RDP açık", recommendation="Kapatın."
    )
    with_findings = emails.scan_alert_email("a@b.com", "örnek.com.tr", [finding], ("B", "D"), "L")
    assert with_findings.subject == "Kalkan: örnek.com.tr için 1 yeni önemli sorun"
    assert "Güvenlik notu B → D oldu." in with_findings.body
    assert "Ne yapmalı: Kapatın." in with_findings.body
    grade_only = emails.scan_alert_email("a@b.com", "örnek.com.tr", [], ("A", "C"), "L")
    assert grade_only.subject == "Kalkan: örnek.com.tr güvenlik notu düştü"
