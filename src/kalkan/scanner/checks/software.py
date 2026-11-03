"""Judge fingerprinted software versions against the release/EOL database.

Runs after the HTTP and port checks, which fill ``ctx.software``.
"""

from __future__ import annotations

from datetime import date

from kalkan.i18n import N_, T
from kalkan.scanner.context import ScanContext
from kalkan.scanner.models import Category, DetectedSoftware, Finding, Severity
from kalkan.scanner.softwaredb import Evaluation, Status

NAME = "software"

_UPGRADE_HINTS = {
    "php": (
        T(
            "Hosting panelinizden (cPanel: 'MultiPHP Manager' / 'Select PHP Version', "
            "Plesk: 'PHP Ayarları') sürümü değiştirebilirsiniz. Önce sitenizin "
            "yedeğini alın ve yeni sürümle çalıştığını kontrol edin."
        )
    ),
    "wordpress": (
        T(
            "WordPress yönetim panelinde Başlangıç > Güncellemeler sayfasından "
            "güncelleyin; eklenti ve temaları da güncel tutun ve otomatik "
            "güncellemeleri açın."
        )
    ),
    "joomla": T("Joomla yönetim panelindeki 'Joomla Güncelle' bileşeniyle güncelleyin."),
    "drupal": T("Web geliştiricinizden Drupal'ı desteklenen bir sürüme yükseltmesini isteyin."),
    "jquery": (
        T(
            "Web geliştiricinizden sitedeki jQuery dosyasını güncellemesini isteyin. "
            "WordPress kullanıyorsanız WordPress'i ve temanızı güncellemek genellikle "
            "yeterlidir."
        )
    ),
    "bootstrap": T(
        "Web geliştiricinizden temadaki Bootstrap kütüphanesini güncellemesini isteyin."
    ),
    "angularjs": (
        T(
            "AngularJS'in desteği 2021 sonunda tamamen bitti; uygulamanın güncel bir "
            "çatıya (Angular, Vue, React) taşınması gerekir. Web geliştiricinizle "
            "planlayın."
        )
    ),
    "vue": T("Web geliştiricinizden uygulamayı desteklenen Vue.js sürümüne taşımasını isteyin."),
}
# Libraries that run in the visitor's browser: how exploitable an old version is
# depends on how the site uses it, so findings are one level less severe.
CLIENT_SIDE = frozenset({"jquery", "bootstrap", "angularjs", "vue"})
_DEFAULT_HINT = T("Sunucu yöneticinizden veya hosting firmanızdan güncelleme isteyin.")

_DOWNGRADE = {
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
}


async def run(ctx: ScanContext) -> list[Finding]:
    today = ctx.options.current_date()
    findings: list[Finding] = []
    for item in ctx.software:
        evaluation = ctx.software_db.evaluate(item.product, item.version, today)
        if evaluation is None or evaluation.status is Status.UNKNOWN:
            continue
        findings.append(_finding(item, evaluation, today))
    return findings


def _supported_list(evaluation: Evaluation, today: date) -> str:
    cycles = [c.cycle for c in evaluation.product.supported_cycles(today) if c.cycle][:3]
    return ", ".join(cycles)


def _finding(item: DetectedSoftware, evaluation: Evaluation, today: date) -> Finding:
    name = item.name
    version = str(evaluation.version)
    hint = _UPGRADE_HINTS.get(item.product, _DEFAULT_HINT)
    details = {N_("Tespit edilen"): f"{name} {item.version}", N_("Kaynak"): item.source}
    if item.distro:
        details[N_("Dağıtım")] = item.distro

    if evaluation.status is Status.CURRENT:
        return Finding(
            id=f"software.current.{item.product}",
            category=Category.SOFTWARE,
            severity=Severity.PASS,
            title=T("{name} {version} güncel", name=name, version=version),
            details=details,
        )

    if evaluation.status is Status.EOL:
        cycle = evaluation.cycle.cycle if evaluation.cycle else version
        eol = evaluation.eol_date
        supported = _supported_list(evaluation, today)
        target = T(" Desteklenen sürümler: {supported}.", supported=supported) if supported else ""
        severity = Severity.HIGH
        finding = Finding(
            id=f"software.eol.{item.product}",
            category=Category.SOFTWARE,
            severity=severity,
            title=T("{name} {cycle} artık güvenlik güncellemesi almıyor", name=name, cycle=cycle),
            description=(
                T(
                    "Bu sürüm {date} tarihinden beri desteklenmiyor. Yeni bulunan açıklar "
                    "kapatılmıyor ve saldırganlar eski sürümleri otomatik araçlarla tarayıp "
                    "hedefliyor.",
                    date=f"{eol:%m.%Y}",
                )
                if eol
                else T(
                    "Bu sürüm artık desteklenmiyor. Yeni bulunan açıklar kapatılmıyor ve "
                    "saldırganlar eski sürümleri otomatik araçlarla tarayıp hedefliyor."
                )
            ),
            recommendation=T(
                "Desteklenen bir sürüme yükseltin.{target} {hint}", target=target, hint=hint
            ),
            details=details,
        )
    elif evaluation.status is Status.VULNERABLE:
        reason = evaluation.product.minimum_safe_reason or T("bilinen güvenlik açıkları")
        finding = Finding(
            id=f"software.vulnerable.{item.product}",
            category=Category.SOFTWARE,
            severity=Severity.HIGH,
            title=T(
                "{name} {version} bilinen güvenlik açıkları içeriyor", name=name, version=version
            ),
            description=T("Bu sürüm {reason} nedeniyle risklidir.", reason=reason),
            recommendation=(
                T(
                    "{name} yazılımını en az {minimum_safe} sürümüne güncelleyin. ",
                    name=name,
                    minimum_safe=evaluation.product.minimum_safe,
                )
                + hint
            ),
            details=details,
        )
    else:  # OUTDATED
        latest = evaluation.latest_in_cycle or "?"
        details[N_("Bu serinin son sürümü")] = latest
        finding = Finding(
            id=f"software.outdated.{item.product}",
            category=Category.SOFTWARE,
            severity=Severity.MEDIUM,
            title=T(
                "{name} güncel değil ({version} → {latest})",
                name=name,
                version=version,
                latest=latest,
            ),
            description=(
                T(
                    "Kullandığınız sürüm hâlâ destekleniyor ancak sonradan yayınlanan "
                    "güvenlik düzeltmeleri yüklenmemiş."
                )
            ),
            recommendation=T(
                "{name} yazılımını {latest} sürümüne güncelleyin. {hint}",
                name=name,
                latest=latest,
                hint=hint,
            ),
            details=details,
        )

    if item.product in CLIENT_SIDE:
        finding.severity = _DOWNGRADE.get(finding.severity, finding.severity)
        finding.description += T(
            "Bu kütüphane ziyaretçinin tarayıcısında çalışır; açıkların etkisi "
            "sitenin onu nasıl kullandığına bağlıdır."
        )
    if item.distro:
        finding.severity = _DOWNGRADE.get(finding.severity, finding.severity)
        finding.description += T(
            (
                "Not: Sunucunuz {distro} paketlerini kullanıyor; {distro} güvenlik "
                "yamalarını sürüm numarasını değiştirmeden yayınlayabilir. Sistem "
                "güncellemeleri düzenli yapılıyorsa gerçek risk daha düşük olabilir."
            ),
            distro=item.distro,
        )
    return finding
