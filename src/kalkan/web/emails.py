"""E-mail texts, written in the recipient's language. Plain text keeps them readable in
every mail client."""

from __future__ import annotations

from typing import Any

from kalkan.i18n import DEFAULT_LANGUAGE, LANGUAGES, N_, localize, translate
from kalkan.scanner.models import Finding, ScanReport
from kalkan.web.mail import Email


def _lang(value: str | None) -> str:
    return value if value in LANGUAGES else DEFAULT_LANGUAGE


def _email(to: str, kind: str, lang: str | None, subject: str, body: str, **params: Any) -> Email:
    language = _lang(lang)
    signature = translate("Kalkan\nBu e-posta otomatik olarak gönderildi.", language)
    return Email(
        to=to,
        subject=translate(subject, language, **params),
        body=translate(body, language, **params) + "\n\n" + signature,
        kind=kind,
    )


def verification_email(to: str, link: str, lang: str | None = None) -> Email:
    return _email(
        to,
        "verify",
        lang,
        N_("Kalkan: e-posta adresinizi doğrulayın"),
        N_(
            "Merhaba,\n\nKalkan hesabınızı etkinleştirmek için aşağıdaki bağlantıyı açın "
            "(3 gün geçerli):\n\n{link}\n\n"
            "Bu hesabı siz oluşturmadıysanız bu e-postayı yok sayabilirsiniz."
        ),
        link=link,
    )


def reset_email(to: str, link: str, lang: str | None = None) -> Email:
    return _email(
        to,
        "reset",
        lang,
        N_("Kalkan: şifre sıfırlama"),
        N_(
            "Merhaba,\n\nŞifrenizi sıfırlamak için aşağıdaki bağlantıyı açın (1 saat geçerli, "
            "yalnızca bir kez kullanılabilir):\n\n{link}\n\n"
            "Bu isteği siz yapmadıysanız bu e-postayı yok sayın; şifreniz değişmez."
        ),
        link=link,
    )


def password_changed_email(to: str, lang: str | None = None) -> Email:
    return _email(
        to,
        "password-changed",
        lang,
        N_("Kalkan: şifreniz değiştirildi"),
        N_(
            "Merhaba,\n\nKalkan hesabınızın şifresi az önce değiştirildi ve diğer tüm oturumlar "
            "kapatıldı.\n\nBu değişikliği siz yapmadıysanız hemen 'Şifremi unuttum' sayfasından "
            "yeni bir şifre belirleyin."
        ),
    )


def invitation_email(
    to: str, inviter: str, organization: str, link: str, lang: str | None = None
) -> Email:
    return _email(
        to,
        "invitation",
        lang,
        N_("Kalkan: {organization} çalışma alanına davet edildiniz"),
        N_(
            "Merhaba,\n\n{inviter}, sizi Kalkan'daki {organization} çalışma alanına davet etti. "
            "Kalkan, web sitelerinin güvenliğini düzenli olarak kontrol eder.\n\n"
            "Daveti kabul etmek için (7 gün geçerli):\n{link}"
        ),
        inviter=inviter,
        organization=organization,
        link=link,
    )


def welcome_email(to: str, link: str, lang: str | None = None) -> Email:
    return _email(
        to,
        "welcome",
        lang,
        N_("Kalkan'a hoş geldiniz"),
        N_(
            "Merhaba,\n\nE-posta adresiniz doğrulandı. Sitenizin güvenlik raporuna üç adımda "
            "ulaşırsınız:\n\n"
            "1. Alan adınızı ekleyin.\n"
            "2. Size ait olduğunu doğrulayın: DNS'e bir TXT kaydı ekleyin veya sitenize küçük bir "
            "dosya yükleyin.\n"
            "3. Taramayı başlatın; rapor genellikle bir dakikadan kısa sürede hazır olur.\n\n"
            "Başlamak için: {link}"
        ),
        link=link,
    )


def onboarding_reminder_email(to: str, link: str, lang: str | None = None) -> Email:
    return _email(
        to,
        "onboarding",
        lang,
        N_("Kalkan: sitenizi taramaya bir adım kaldı"),
        N_(
            "Merhaba,\n\nKalkan hesabınızı oluşturdunuz ancak henüz doğrulanmış bir alan adınız "
            "yok. Alan adınızı ekleyip doğruladığınızda ilk güvenlik raporunuz birkaç dakika "
            "içinde hazır olur.\n\nDNS kaydı veya dosya yükleme konusunda yardıma ihtiyacınız "
            "varsa bu e-postayı web sitenizi yöneten kişiye iletebilirsiniz.\n\n{link}"
        ),
        link=link,
    )


def first_report_email(to: str, report: ScanReport, link: str, lang: str | None = None) -> Email:
    language = _lang(lang)
    actions = [f for f in report.findings if f.severity.is_problem][:3]
    lines = [
        f"  • [{f.severity.label_in(language)}] {localize(f.title, language)}" for f in actions
    ]
    summary = (
        translate("Öncelikli işler:", language) + "\n" + "\n".join(lines)
        if lines
        else translate("Taramada öncelikli bir sorun bulunmadı.", language)
    )
    return _email(
        to,
        "first-report",
        lang,
        N_("Kalkan: {domain} için ilk raporunuz hazır ({grade})"),
        N_(
            "Merhaba,\n\n{domain} için ilk güvenlik taramanız tamamlandı. Not: {grade} "
            "({score}/100).\n\n{summary}\n\nRaporun tamamı ve ne yapmanız gerektiği: {link}\n\n"
            "İpucu: alan adı sayfasından otomatik taramayı açarsanız yeni bir sorun çıktığında "
            "size haber veririz."
        ),
        domain=report.display_name,
        grade=report.grade,
        score=report.score,
        summary=summary,
        link=link,
    )


def scan_alert_email(
    to: str,
    domain: str,
    findings: list[Finding],
    grade_change: tuple[str, str] | None,
    link: str,
    lang: str | None = None,
) -> Email:
    language = _lang(lang)
    lines: list[str] = []
    if grade_change:
        lines.append(
            translate(
                "Güvenlik notu {before} → {after} oldu.",
                language,
                before=grade_change[0],
                after=grade_change[1],
            )
            + "\n"
        )
    if findings:
        lines.append(translate("Yeni bulunan önemli sorunlar:", language))
        for finding in findings:
            lines.append(
                f"  • [{finding.severity.label_in(language)}] {localize(finding.title, language)}"
            )
            if finding.recommendation:
                lines.append(
                    "    "
                    + translate(
                        "Ne yapmalı: {text}",
                        language,
                        text=localize(finding.recommendation, language),
                    )
                )
    subject = (
        N_("Kalkan: {domain} için {n} yeni önemli sorun")
        if findings
        else N_("Kalkan: {domain} güvenlik notu düştü")
    )
    return _email(
        to,
        "alert",
        lang,
        subject,
        N_(
            "Merhaba,\n\n{domain} için yapılan otomatik taramada değişiklik var.\n\n{changes}\n\n"
            "Raporun tamamı: {link}\n\nBu bildirimleri alan adı sayfasından kapatabilirsiniz."
        ),
        domain=domain,
        n=len(findings),
        changes="\n".join(lines),
        link=link,
    )


def ownership_lost_email(to: str, domain: str, link: str, lang: str | None = None) -> Email:
    return _email(
        to,
        "ownership-lost",
        lang,
        N_("Kalkan: {domain} doğrulaması geçersiz oldu"),
        N_(
            "Merhaba,\n\n{domain} alan adının size ait olduğunu gösteren DNS kaydı veya doğrulama "
            "dosyası artık bulunamıyor. Bu nedenle alan adınızı tarayamadık.\n\n"
            "Taramalara devam etmek için alan adını yeniden doğrulayın:\n{link}"
        ),
        domain=domain,
        link=link,
    )
