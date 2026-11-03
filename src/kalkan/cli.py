"""Command line interface: ``kalkan scan``, ``serve``, ``worker``, ``migrate`` and ``admin``."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from kalkan import __version__
from kalkan.i18n import DEFAULT_LANGUAGE, LANGUAGES, normalize_language, translate
from kalkan.report import render_html, render_json, render_pdf, render_text
from kalkan.scanner import ScanOptions, Severity, TargetError, scan
from kalkan.scanner.checks import CHECK_NAMES

EXIT_OK = 0
EXIT_FINDINGS = 1  # --fail-on threshold reached
EXIT_USAGE = 2


def _checks(value: str) -> frozenset[str]:
    names = frozenset(n.strip() for n in value.split(",") if n.strip())
    unknown = names - set(CHECK_NAMES)
    if unknown:
        raise argparse.ArgumentTypeError(
            f"bilinmeyen kontrol: {', '.join(sorted(unknown))} "
            f"(seçenekler: {', '.join(CHECK_NAMES)})"
        )
    return names


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kalkan",
        description="KOBİ'ler için sade web sitesi güvenlik tarayıcısı.",
    )
    parser.add_argument("--version", action="version", version=f"kalkan {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser(
        "scan",
        help="bir web sitesini tara",
        description=(
            "Bir alan adını tarar. Yalnızca sahibi olduğunuz veya taramak için yazılı izniniz "
            "olan sistemleri tarayın."
        ),
    )
    p_scan.add_argument("target", help="alan adı veya adres, ör. firmaniz.com.tr")
    p_scan.add_argument(
        "-f",
        "--format",
        choices=("text", "json", "html", "pdf"),
        default="text",
        help="çıktı biçimi",
    )
    p_scan.add_argument("-o", "--output", type=Path, help="raporu bu dosyaya yaz")
    p_scan.add_argument(
        "--checks", type=_checks, help=f"yalnızca bu kontroller ({','.join(CHECK_NAMES)})"
    )
    p_scan.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity if s.is_problem],
        help="bu önem derecesinde veya üstünde sorun varsa 1 koduyla çık (CI için)",
    )
    p_scan.add_argument(
        "--allow-private",
        action="store_true",
        help="özel/iç ağ adreslerinin taranmasına izin ver (yalnızca yerel test için)",
    )
    p_scan.add_argument("--timeout", type=float, default=10.0, help="ağ zaman aşımı (saniye)")
    p_scan.add_argument("--no-color", action="store_true", help="renksiz çıktı")
    p_scan.add_argument(
        "--lang",
        choices=tuple(LANGUAGES),
        default=normalize_language(os.environ.get("KALKAN_LANG", DEFAULT_LANGUAGE)),
        help="rapor dili (varsayılan: KALKAN_LANG veya tr)",
    )

    p_serve = sub.add_parser("serve", help="web uygulamasını başlat")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument(
        "--reload", action="store_true", help="geliştirme için otomatik yeniden yükleme"
    )

    sub.add_parser("worker", help="tarama kuyruğunu işleyen arka plan işçisini başlat")
    p_migrate = sub.add_parser("migrate", help="veritabanı şemasını güncelle (Alembic)")
    p_migrate.add_argument("--revision", default="head", help="hedef sürüm (varsayılan: en güncel)")

    p_admin = sub.add_parser("admin", help="yönetici işlemleri (çalışma alanları ve planlar)")
    admin = p_admin.add_subparsers(dest="admin_command", required=True)
    admin.add_parser("orgs", help="çalışma alanlarını planları ve kullanımlarıyla listele")
    p_plan = admin.add_parser(
        "set-plan",
        help="bir çalışma alanının planını değiştir",
        description=(
            "Ödeme entegrasyonu olmadığı için planlar elle değiştirilir. Yeni planın izin "
            "vermediği otomatik taramalar kapatılır."
        ),
    )
    p_plan.add_argument("organization", help="çalışma alanı numarası veya sahibinin e-postası")
    p_plan.add_argument("plan", choices=("free", "pro", "agency"))
    return parser


def _use_utf8_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def cmd_scan(args: argparse.Namespace) -> int:
    options = ScanOptions(
        checks=args.checks, allow_private=args.allow_private, timeout=args.timeout
    )
    try:
        report = asyncio.run(scan(args.target, options))
    except TargetError as exc:
        print(f"kalkan: {exc}", file=sys.stderr)
        return EXIT_USAGE

    output: str | bytes
    if args.format == "json":
        output = render_json(report) + "\n"
    elif args.format == "html":
        output = render_html(report)
    elif args.format == "pdf":
        output = render_pdf(report)
    else:
        color = (
            args.output is None
            and not args.no_color
            and sys.stdout.isatty()
            and "NO_COLOR" not in os.environ
        )
        output = render_text(report, color=color, lang=args.lang)

    if args.output:
        if isinstance(output, bytes):
            args.output.write_bytes(output)
        else:
            args.output.write_text(output, encoding="utf-8")
        message = translate(
            "Rapor yazıldı: {path} (not: {grade}, puan: {score})",
            args.lang,
            path=args.output,
            grade=report.grade,
            score=report.score,
        )
        print(message)
    else:
        sys.stdout.write(output if isinstance(output, str) else output.decode("latin-1"))

    if args.fail_on:
        threshold = Severity(args.fail_on).rank
        if any(f.severity.rank <= threshold for f in report.findings):
            return EXIT_FINDINGS
    return EXIT_OK


_WEB_MISSING = "kalkan: web bileşenleri kurulu değil: pip install 'kalkan[web]'"


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn

        from kalkan.web.config import Settings
        from kalkan.web.observability import configure_logging
    except ImportError:
        print(_WEB_MISSING, file=sys.stderr)
        return EXIT_USAGE
    configure_logging(Settings())
    uvicorn.run(
        "kalkan.web.app:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        reload=args.reload,
        server_header=False,
        proxy_headers=True,
        log_config=None,  # keep our logging setup (JSON / request IDs)
        access_log=False,  # ObservabilityMiddleware writes the access log
    )
    return EXIT_OK


def cmd_worker(_args: argparse.Namespace) -> int:
    try:
        from kalkan.web.migrate import SchemaOutdatedError
        from kalkan.web.worker import run_standalone
    except ImportError:
        print(_WEB_MISSING, file=sys.stderr)
        return EXIT_USAGE
    try:
        run_standalone()
    except SchemaOutdatedError as exc:
        print(f"kalkan: {exc}", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_OK


def cmd_migrate(args: argparse.Namespace) -> int:
    try:
        from kalkan.web.config import Settings
        from kalkan.web.db import make_engine
        from kalkan.web.migrate import current_revision, upgrade_database
    except ImportError:
        print(_WEB_MISSING, file=sys.stderr)
        return EXIT_USAGE
    engine = make_engine(Settings().database_url)
    try:
        before = current_revision(engine)
        upgrade_database(engine, args.revision)
        after = current_revision(engine)
    finally:
        engine.dispose()
    print(f"Veritabanı şeması: {before or 'sürümsüz'} → {after}")
    return EXIT_OK


def cmd_admin(args: argparse.Namespace) -> int:
    try:
        from kalkan.web import services
        from kalkan.web.config import Settings
        from kalkan.web.db import make_engine, make_session_factory
        from kalkan.web.migrate import SchemaOutdatedError, ensure_current
        from kalkan.web.models import Organization, Plan, Role
    except ImportError:
        print(_WEB_MISSING, file=sys.stderr)
        return EXIT_USAGE
    from sqlalchemy import select

    engine = make_engine(Settings().database_url)
    try:
        ensure_current(engine)
        with make_session_factory(engine)() as db:
            if args.admin_command == "orgs":
                organizations = db.scalars(select(Organization).order_by(Organization.id)).all()
                print(f"{'no':>4}  {'plan':<7} {'alan adı':>9} {'üye':>4}  ad / sahipler")
                for org in organizations:
                    owners = ", ".join(
                        m.user.email for m in org.memberships if m.role is Role.OWNER
                    )
                    print(
                        f"{org.id:>4}  {org.plan.value:<7} "
                        f"{len(org.domains):>4}/{org.limits.domains:<4} "
                        f"{len(org.memberships):>2}/{org.limits.members:<2} "
                        f"{org.name} ({owners or '-'})"
                    )
                return EXIT_OK
            organization = services.find_organization(db, args.organization)
            if organization is None:
                print(f"kalkan: çalışma alanı bulunamadı: {args.organization}", file=sys.stderr)
                return EXIT_USAGE
            before = organization.plan
            services.set_plan(db, organization, Plan(args.plan))
            print(f"{organization.name} (#{organization.id}): {before.value} → {args.plan}")
            return EXIT_OK
    except SchemaOutdatedError as exc:
        print(f"kalkan: {exc}", file=sys.stderr)
        return EXIT_USAGE
    finally:
        engine.dispose()


def main(argv: Sequence[str] | None = None) -> int:
    _use_utf8_stdout()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan" and args.format == "pdf" and args.output is None:
        parser.error("PDF çıktısı için bir dosya adı verin: -o rapor.pdf")
    handlers = {
        "scan": cmd_scan,
        "serve": cmd_serve,
        "worker": cmd_worker,
        "migrate": cmd_migrate,
        "admin": cmd_admin,
    }
    return handlers[args.command](args)
