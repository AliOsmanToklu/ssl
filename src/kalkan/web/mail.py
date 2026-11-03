"""Outgoing e-mail: a tiny interface with console, SMTP and in-memory backends."""

from __future__ import annotations

import logging
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Protocol

from kalkan.web.config import Settings
from kalkan.web.metrics import EMAILS

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Email:
    to: str
    subject: str
    body: str
    kind: str  # "verify", "reset", "alert", ... (metrics label)


class Mailer(Protocol):
    def send(self, email: Email) -> None: ...


class ConsoleMailer:
    """Development backend: writes the message to the log instead of sending it."""

    def send(self, email: Email) -> None:
        log.info("e-mail to %s: %s\n%s", email.to, email.subject, email.body)


class MemoryMailer:
    """Test backend: keeps messages in ``outbox``."""

    def __init__(self) -> None:
        self.outbox: list[Email] = []

    def send(self, email: Email) -> None:
        self.outbox.append(email)


class SmtpMailer:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _message(self, email: Email) -> EmailMessage:
        message = EmailMessage()
        message["From"] = self.settings.mail_from
        message["To"] = email.to
        message["Subject"] = email.subject
        message["Date"] = formatdate(localtime=False)
        message["Message-ID"] = make_msgid(domain="kalkan")
        message.set_content(email.body)
        return message

    def send(self, email: Email) -> None:
        s = self.settings
        context = ssl.create_default_context()
        smtp: smtplib.SMTP
        if s.smtp_ssl:
            smtp = smtplib.SMTP_SSL(s.smtp_host, s.smtp_port, timeout=20, context=context)
        else:
            smtp = smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=20)
        with smtp:
            if s.smtp_starttls and not s.smtp_ssl:
                smtp.starttls(context=context)
            if s.smtp_username:
                smtp.login(s.smtp_username, s.smtp_password)
            smtp.send_message(self._message(email))


def make_mailer(settings: Settings) -> Mailer:
    if settings.mail_backend == "smtp":
        return SmtpMailer(settings)
    return ConsoleMailer()


def deliver(mailer: Mailer, email: Email) -> bool:
    """Send without letting a mail outage break the request or the worker."""
    try:
        mailer.send(email)
    except Exception:
        log.exception("could not send %s e-mail to %s", email.kind, email.to)
        EMAILS.labels(email.kind, "error").inc()
        return False
    EMAILS.labels(email.kind, "sent").inc()
    return True
