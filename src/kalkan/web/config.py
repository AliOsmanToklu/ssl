"""Runtime configuration, read from ``KALKAN_*`` environment variables or ``.env``."""

from __future__ import annotations

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KALKAN_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./kalkan.db"
    # Apply pending migrations when the web app starts. Turn off when a separate
    # `kalkan migrate` step runs before deployment (see docker-compose.yml).
    auto_migrate: bool = True
    # Signs session cookies and e-mail links. Must be set (and kept stable) in production.
    secret_key: str = ""
    # Behind HTTPS: mark cookies Secure and send HSTS.
    https_only: bool = False
    # Base URL used in e-mail links.
    public_url: str = "http://127.0.0.1:8000"

    # Run the scan worker inside the web process (fine for one instance / development).
    embedded_worker: bool = True
    worker_concurrency: int = 2
    worker_poll_interval: float = 2.0
    stale_scan_minutes: int = 15
    scheduler_interval: float = 60.0
    # Ownership is re-checked before scanning when the last proof is older than this.
    reverify_after_days: int = 30

    # Plan of the personal workspace created at sign-up. Plans are changed with
    # `kalkan admin set-plan`; a self-hosted install can give everyone "agency".
    default_plan: Literal["free", "pro", "agency"] = "free"
    login_attempts_per_15_min: int = 10
    scan_timeout: float = 10.0
    require_email_verification: bool = True

    # E-mail: "console" logs messages (development), "smtp" sends them.
    mail_backend: Literal["console", "smtp"] = "console"
    mail_from: str = "Kalkan <no-reply@kalkan.local>"
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_starttls: bool = True
    smtp_ssl: bool = False

    # REST API
    api_requests_per_minute: int = 60
    max_api_tokens_per_user: int = 5

    # Observability
    log_format: Literal["text", "json"] = "text"
    log_level: str = "INFO"
    # /metrics is served only when a token is set (Authorization: Bearer <token>).
    metrics_token: str = ""
    # `kalkan worker` exposes its own metrics on this port when non-zero.
    worker_metrics_port: int = 0

    # Development only. Never enable these on a public deployment.
    allow_private_targets: bool = False
    skip_verification: bool = False

    def link(self, path: str) -> str:
        return self.public_url.rstrip("/") + path
