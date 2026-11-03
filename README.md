# Kalkan

**Plain-language website security scanner for small businesses.** Kalkan checks a
website's SSL/TLS certificate, internet-facing ports, outdated software and WordPress
plugins, exposed files, e-mail and DNS security, then explains every problem in plain
Turkish together with what to do about it.

It ships as a **command-line tool** and as a **multi-user web app (SaaS)** with domain
ownership verification, a background scan queue, scheduled re-scans with e-mail alerts,
a token-authenticated REST API, score history and HTML/PDF/JSON reports.

[Türkçe README](README.tr.md)

```text
$ kalkan scan example.com
Kalkan güvenlik raporu: example.com
Not:  B   Puan: 82/100  (03.11.2026 00:59)
Siteniz iyi durumda; birkaç küçük iyileştirme yapılabilir. Taramada 2 orta, 2 düşük öncelikli sorun bulundu.

SORUNLAR
  [Orta] Eski ve güvensiz şifreleme sürümleri açık (TLS 1.0, TLS 1.1)
      Ne yapmalı: Sunucu veya hosting ayarlarından yalnızca TLS 1.2 ve TLS 1.3'e izin verin.
  [Orta] Siteniz ziyaretçileri şifreli bağlantıya yönlendirmiyor
  ...
BAŞARILI KONTROLLER
  ✓ SSL sertifikası geçerli (53 gün kaldı)
  ✓ DMARC sahte e-postaları engelliyor (p=reject)
```

## What it checks

| Area | Checks | Example finding |
|---|---|---|
| **SSL/TLS** | HTTPS available, expiry, hostname match, self-signed / incomplete chain, key size, SHA-1, TLS 1.0/1.1 enabled, TLS 1.3 support | *"Sertifika zinciri eksik (ara sertifika yüklenmemiş)"* |
| **Web server** | HTTP→HTTPS redirect, HSTS, CSP / X-Frame-Options / nosniff / Referrer-Policy, cookie flags, version disclosure, mixed content and forms posting over `http://`, `security.txt`, CDN detection | *"Sayfadaki bir form bilgileri şifresiz gönderiyor"* |
| **Exposed files** | `.env`, `.git/`, `wp-config.php` backups, SQL dumps, `phpinfo()`, `server-status`, directory listing | *"Gizli ayar dosyası (.env) herkese açık"* |
| **Open ports** | ~35 ports that matter to small businesses: RDP, SMB, databases, Redis/MongoDB/Elasticsearch, FTP, Telnet, Docker API, admin panels | *"Uzak Masaüstü (RDP) internete açık"* |
| **Software versions** | Fingerprints from headers, HTML, asset URLs and service banners (Apache, nginx, IIS, PHP, OpenSSL, WordPress, Drupal, Joomla, OpenSSH, MySQL/MariaDB, ProFTPD, Exim, jQuery, Bootstrap, AngularJS, Vue…) judged against end-of-life and minimum-safe versions | *"PHP 7.4 artık güvenlik güncellemesi almıyor"* |
| **WordPress** | Plugins and themes found on the page; installed version from their `readme.txt` / `style.css` compared with WordPress.org: outdated, abandoned (2+ years) or pulled from the directory (e.g. for a security issue) | *"'X' eklentisi güvenlik sorunu nedeniyle WordPress.org'dan kaldırılmış"* |
| **E-mail** | SPF, DMARC and DKIM (common selectors, key length) of the organisation's zone; STARTTLS and certificate of the MX servers | *"E-posta sunucunuz şifreli bağlantıyı (STARTTLS) desteklemiyor"* |
| **DNS** | DNSSEC, CAA (certificate authority restriction) | *"DNSSEC etkin değil"* |

Each finding has a severity (critical → low), a plain explanation ("what does it
mean?"), a concrete fix ("what should you do?") and collapsible technical details.
The report opens with the three most urgent actions and an **A–F grade**, and is
available as a web page, a single-file HTML document, a PDF (fonts bundled, so Turkish
characters render everywhere) and JSON.

## The web app

- **Accounts:** sign-up with e-mail verification, password reset by e-mail, password
  change (signs out every other session), data export as JSON and account deletion
  (KVKK/GDPR).
- **Domains:** a domain is scanned only after its owner proves control with a DNS TXT
  record or a file under `/.well-known/`. Ownership is re-checked before scanning once
  the proof is older than 30 days.
- **Scheduled scans and alerts:** weekly or monthly re-scans; an e-mail goes out only
  when something *new* and important appears (critical/high finding, certificate about
  to expire, grade dropping to C or worse), so an unfixed issue does not send the same
  e-mail every week.
- **Progress over time:** a score-history chart per domain (pure SVG with pointer and
  keyboard tooltips, no JavaScript) and, on every report, what changed since the previous
  scan: score delta, resolved problems, new or worse problems.
- **REST API** with personal access tokens and interactive docs at `/api/docs`.

## Quick start

### Command line

```bash
pip install -e .
kalkan scan firmaniz.com.tr                        # coloured terminal report
kalkan scan firmaniz.com.tr -f html -o rapor.html  # self-contained HTML report
kalkan scan firmaniz.com.tr -f pdf -o rapor.pdf    # PDF report
kalkan scan firmaniz.com.tr -f json                # machine-readable
kalkan scan firmaniz.com.tr --fail-on high         # exit code 1 for CI pipelines
```

Only scan systems you own or are authorised to test.

### Web app

```bash
pip install -e ".[web]"
kalkan serve      # http://127.0.0.1:8000 (SQLite, migrations + worker in-process,
                  # e-mails printed to the log)
```

Production-like stack: PostgreSQL, a one-shot migration job, the web app, a separate
worker and [Mailpit](https://mailpit.axllent.org/) to read the e-mails it sends:

```bash
cp .env.example .env    # set KALKAN_SECRET_KEY
docker compose up --build
# app: http://127.0.0.1:8000   e-mails: http://127.0.0.1:8025
```

### REST API

Create a token under *Hesabım → API tokenleri*, then:

```bash
export KALKAN_TOKEN=klk_...
curl -H "Authorization: Bearer $KALKAN_TOKEN" -d '{"hostname":"firmaniz.com.tr"}' \
     -H "Content-Type: application/json" http://127.0.0.1:8000/api/v1/domains
curl -X POST -H "Authorization: Bearer $KALKAN_TOKEN" \
     http://127.0.0.1:8000/api/v1/domains/1/verify
curl -X POST -H "Authorization: Bearer $KALKAN_TOKEN" \
     http://127.0.0.1:8000/api/v1/domains/1/scans            # 202 + Location: /api/v1/scans/7
curl -H "Authorization: Bearer $KALKAN_TOKEN" http://127.0.0.1:8000/api/v1/scans/7/report
```

| Method | Path | |
|---|---|---|
| `GET` | `/api/v1/me` | token owner |
| `GET` `POST` | `/api/v1/domains` | list / add |
| `GET` `PATCH` `DELETE` | `/api/v1/domains/{id}` | details (incl. verification instructions) / schedule settings / delete |
| `POST` | `/api/v1/domains/{id}/verify` | check the DNS record or file |
| `GET` `POST` | `/api/v1/domains/{id}/scans` | history / start a scan (`202`) |
| `GET` | `/api/v1/scans/{id}`, `/report`, `/report.pdf` | status / full JSON report / PDF |

Errors are `{"detail": "..."}` with meaningful status codes (`401`, `403` not verified,
`404` not found or not yours, `409` conflict, `422` invalid input, `429` limits).

## Architecture

```mermaid
flowchart LR
    B[Browser] -->|forms + CSRF| W[FastAPI web app]
    C[API client] -->|Bearer token| W
    W --> S[services layer]
    S --> DB[(PostgreSQL / SQLite)]
    K[kalkan worker] -->|claim queued scan| DB
    K -->|scheduler: due domains| DB
    K --> E[scanner engine]
    K -->|alerts| M[SMTP]
    W -->|verification / reset links| M
    E -->|stage 1| T1[TLS · HTTP · E-mail · MX STARTTLS · DNS]
    E -->|stage 2| T2[Ports · Exposed files · WordPress]
    E -->|stage 3| T3[Software versions]
```

- **`kalkan.scanner`**: an async engine with no web dependencies. Checks run concurrently in
  stages; later stages reuse facts from earlier ones (the homepage, CDN, open ports and
  detected software). A failing or slow check becomes a "could not complete" note instead
  of failing the scan.
- **`kalkan.report`**: text, JSON, a single-file HTML report (inline CSS, safe to
  e-mail) and a PDF built with fpdf2 (pure Python: no browser or system libraries), plus
  the comparison between two scans.
- **`kalkan.web`**: FastAPI + Jinja2 pages, a REST API, SQLAlchemy 2 models with Alembic
  migrations, and a worker that uses the `scans` table as its queue. Jobs are claimed with
  a conditional `UPDATE … WHERE status = 'queued'`, and the scheduler claims due domains
  the same way on `next_scan_at`, so any number of workers can run side by side without
  Redis or row locks. Scans left `running` by a crashed worker are re-queued. Business
  rules live in one `services` module shared by the pages and the API.
- **Software database**: `scripts/update_software_db.py` regenerates
  `scanner/data/software.json` from [endoflife.date](https://endoflife.date) and the
  OpenSSH release notes, so scans need no network access for version data. WordPress
  plugin and theme data comes from the WordPress.org API at scan time (cached per
  process; when it is unreachable, components are listed but not judged).

## Security design

A scanner offered as a service can easily become an attack tool, and it handles hostile
input (the sites it scans) by definition. The main safeguards:

- **Ownership verification.** A domain can only be scanned after its owner proves control
  with a DNS TXT record or a file under `/.well-known/`, and the proof is renewed every 30
  days. Redirects are only followed within the same site, so an open redirect on someone
  else's site cannot "verify" it.
- **SSRF protection.** Every connection goes to an address that was resolved and checked
  to be public (private, loopback, link-local, CGNAT, multicast, IPv4-mapped and 6to4
  wrapped addresses are refused). The HTTP client then connects to *that IP* with the
  original `Host` header and TLS SNI, which closes the DNS rebinding gap, and every
  redirect hop is validated again.
- **Non-intrusive scanning.** TCP connect checks on a short port list, a handful of GET
  requests with content validation, a greeting/EHLO/STARTTLS exchange with the domain's
  own mail servers (no mail is sent), no exploit attempts, and per-domain daily limits.
  MX hosts go through the same SSRF guard as everything else.
- **Accounts.** Argon2id hashing with constant-time behaviour for unknown accounts; no
  account enumeration on sign-in or password reset; signed, expiring e-mail links; reset
  links are single-use (they embed a fingerprint of the current password hash); changing
  the password invalidates every other session (a session version stored with the user).
- **API.** Bearer tokens only (no cookie auth, so no CSRF surface), stored as SHA-256
  digests and shown once, per-token rate limits, ownership enforced in every query.
- **Pages.** CSRF tokens on every form, session rotation on login, login throttling,
  autoescaped templates for scanned content, no `Server` header, and the same strict
  security headers the scanner recommends (`CSP`, `X-Frame-Options`, `nosniff`,
  `Referrer-Policy`, HSTS behind HTTPS). Only `/api/docs` gets a relaxed CSP for Swagger UI.
- **Few false positives.** Ports are not reported for sites behind a CDN, software from
  distribution packages (Ubuntu, Debian, RHEL…) is downgraded because fixes are backported
  without changing version numbers, browser-side libraries are one level milder (impact
  depends on how the site uses them), file probes validate content so "soft 404" pages
  are ignored, and "no DKIM key at a common selector" or "port 25 blocked from the
  scanner's network" become notes, not problems.

## Operations

- **Migrations:** `kalkan migrate` (Alembic). The web app migrates on start-up unless
  `KALKAN_AUTO_MIGRATE=false`; the worker never migrates and refuses to start on an
  outdated schema. Databases created by v0.1 are adopted automatically.
- **Logs:** `KALKAN_LOG_FORMAT=json` writes one JSON object per line. Every request gets
  an `X-Request-ID` (an incoming one from a load balancer is kept) that appears in the
  response and in every log line written while handling it.
- **Metrics:** Prometheus at `/metrics` when `KALKAN_METRICS_TOKEN` is set (bearer token);
  the worker serves its own on `KALKAN_WORKER_METRICS_PORT`. Request counts and latency
  (labelled by route template), scans by result and trigger, scan duration, queue depth,
  e-mails sent, ownership re-checks.

## Scoring

Starting from 100: critical −35, high −15, medium −7, low −2. Any critical finding caps the
score at 49 (grade F), any high finding at 79 (grade C).
Grades: A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, F < 50.

## Configuration

All settings are environment variables (or `.env`); see [.env.example](.env.example)
for the full list.

| Variable | Default | Purpose |
|---|---|---|
| `KALKAN_SECRET_KEY` | random per process | Signs sessions and e-mail links; required in production |
| `KALKAN_DATABASE_URL` | `sqlite:///./kalkan.db` | e.g. `postgresql+psycopg://…` |
| `KALKAN_PUBLIC_URL` | `http://127.0.0.1:8000` | Base URL for links in e-mails |
| `KALKAN_MAIL_BACKEND` | `console` | `smtp` to send real e-mail (`KALKAN_SMTP_*`) |
| `KALKAN_EMBEDDED_WORKER` | `true` | Run scans inside the web process |
| `KALKAN_REVERIFY_AFTER_DAYS` | `30` | Renew ownership proof before scanning |
| `KALKAN_LOG_FORMAT` | `text` | `json` for log shippers |
| `KALKAN_METRICS_TOKEN` | *(empty: off)* | Enables `/metrics` |
| `KALKAN_SKIP_VERIFICATION` | `false` | Development only |

## Development

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
pytest --cov          # ~400 tests, including real local TLS and SMTP servers
ruff format --check . && ruff check . && mypy   # mypy runs in strict mode
python scripts/update_software_db.py            # refresh release/EOL data
alembic revision --autogenerate -m "..."        # after changing a model

# run the database tests against PostgreSQL instead of SQLite
docker run -d -p 55432:5432 -e POSTGRES_USER=kalkan -e POSTGRES_PASSWORD=test \
  -e POSTGRES_DB=kalkan_test postgres:17-alpine
KALKAN_TEST_DATABASE_URL=postgresql+psycopg://kalkan:test@127.0.0.1:55432/kalkan_test pytest
```

The tests never touch the internet: DNS, HTTP sites and TLS servers are simulated
(certificates are generated on the fly with `cryptography`). A test fails if the models
and the migrations drift apart. CI runs the suite on Linux and Windows, and again against
a PostgreSQL service.

## Roadmap

- Multiple languages (English UI and reports)
- Known-vulnerability (CVE) data for WordPress plugins
- Teams (several users per company), plans and billing
- Deployment guide (container platform + managed PostgreSQL + HTTPS)

## License

[MIT](LICENSE)
