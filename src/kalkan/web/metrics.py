"""Prometheus metrics shared by the web app and the worker."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

HTTP_REQUESTS = Counter(
    "kalkan_http_requests_total", "HTTP requests handled", ["method", "route", "status"]
)
HTTP_DURATION = Histogram("kalkan_http_request_duration_seconds", "HTTP request latency", ["route"])
SCANS = Counter("kalkan_scans_total", "Finished scans", ["result", "trigger"])
SCAN_DURATION = Histogram(
    "kalkan_scan_duration_seconds",
    "Time spent scanning one domain",
    buckets=(1, 2, 5, 10, 20, 30, 60, 120, 300),
)
SCAN_QUEUE = Gauge("kalkan_scan_queue", "Scans waiting or running", ["status"])
SCHEDULED_SCANS = Counter("kalkan_scheduled_scans_total", "Scans queued by the scheduler")
EMAILS = Counter("kalkan_emails_total", "E-mails handed to the mail backend", ["kind", "result"])
OWNERSHIP_CHECKS = Counter(
    "kalkan_ownership_rechecks_total", "Periodic domain ownership re-checks", ["result"]
)
