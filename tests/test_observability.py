from __future__ import annotations

import json
import logging
import re
import sys
from collections.abc import Iterator

import pytest
from conftest import AppFactory
from fastapi.testclient import TestClient
from web_helpers import register

from kalkan.web.config import Settings
from kalkan.web.observability import (
    JsonFormatter,
    RequestIdFilter,
    configure_logging,
    request_id_var,
)


def test_request_id_is_generated_and_returned(client: TestClient) -> None:
    response = client.get("/healthz")
    assert re.fullmatch(r"[0-9a-f]{32}", response.headers["x-request-id"])
    assert client.get("/healthz").headers["x-request-id"] != response.headers["x-request-id"]


def test_incoming_request_id_is_kept_when_safe(client: TestClient) -> None:
    kept = client.get("/healthz", headers={"X-Request-ID": "lb-abc.123_X"})
    assert kept.headers["x-request-id"] == "lb-abc.123_X"
    for hostile in ("a" * 65, "id with spaces", "x\x01y"):
        replaced = client.get("/healthz", headers={"X-Request-ID": hostile})
        assert replaced.headers["x-request-id"] != hostile


def test_access_log_line(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="kalkan.access"):
        client.get("/healthz")
    record = next(r for r in caplog.records if r.name == "kalkan.access")
    assert record.method == "GET"  # type: ignore[attr-defined]
    assert record.path == "/healthz"  # type: ignore[attr-defined]
    assert record.status == 200  # type: ignore[attr-defined]
    assert record.duration_ms >= 0  # type: ignore[attr-defined]


def test_json_formatter() -> None:
    record = logging.LogRecord(
        "kalkan.test", logging.WARNING, __file__, 1, "merhaba %s", ("dünya",), None
    )
    record.domain = "örnek.com.tr"
    token = request_id_var.set("req-1")
    try:
        RequestIdFilter().filter(record)
    finally:
        request_id_var.reset(token)
    try:
        raise ValueError("boom")
    except ValueError:
        record.exc_info = sys.exc_info()
    data = json.loads(JsonFormatter().format(record))
    assert data["level"] == "WARNING"
    assert data["message"] == "merhaba dünya"
    assert data["request_id"] == "req-1"
    assert data["domain"] == "örnek.com.tr"
    assert "ValueError: boom" in data["exception"]
    assert data["ts"].endswith("+00:00")


@pytest.fixture
def restore_root_logger() -> Iterator[None]:
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    root.handlers, root.level = handlers, level


@pytest.mark.usefixtures("restore_root_logger")
@pytest.mark.parametrize(
    ("fmt", "formatter"), [("json", JsonFormatter), ("text", logging.Formatter)]
)
def test_configure_logging(fmt: str, formatter: type[logging.Formatter]) -> None:
    configure_logging(Settings(log_format=fmt, log_level="debug"))
    root = logging.getLogger()
    assert len(root.handlers) == 1
    assert type(root.handlers[0].formatter) is formatter
    assert root.level == logging.DEBUG
    assert logging.getLogger("httpx").level == logging.WARNING


def test_metrics_endpoint_is_off_without_a_token(client: TestClient) -> None:
    assert client.get("/metrics").status_code == 404


def test_metrics_endpoint(make_app: AppFactory) -> None:
    with TestClient(make_app(metrics_token="izleme-tokeni")) as client:
        register(client)
        client.get("/scans/12345")
        assert client.get("/metrics").status_code == 401
        assert client.get("/metrics", headers={"Authorization": "Bearer yanlis"}).status_code == 401
        response = client.get("/metrics", headers={"Authorization": "Bearer izleme-tokeni"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    body = response.text
    # route templates, not raw paths: label cardinality stays bounded
    assert 'route="/scans/{scan_id}"' in body
    assert "/scans/12345" not in body
    assert 'kalkan_scan_queue{status="queued"} 0.0' in body
    assert "kalkan_http_request_duration_seconds_bucket" in body
