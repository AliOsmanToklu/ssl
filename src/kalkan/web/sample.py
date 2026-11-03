"""The sample site shown on the landing page.

Its findings use the scanner's own messages, severities and advice, and its grade comes
from the real scoring rules, so the page demonstrates the product rather than a mock-up:
fixing the issues from the top re-grades it F → D → C → B → A.
"""

from __future__ import annotations

from dataclasses import dataclass

from kalkan.i18n import T, Text
from kalkan.scanner.models import Category, Finding, Severity
from kalkan.scanner.scoring import CAPS, GRADES, PENALTIES, compute_score

SAMPLE_DOMAIN = "ornekfirma.com.tr"
VERIFICATION_TOKEN = "4f9c2a7e1b6d03c58e2f7a91d4b6c0e3"  # noqa: S105 - shown as an example


@dataclass(frozen=True, slots=True)
class SampleCheck:
    """One module of the landing page: a check, the finding it produced, and why it matters."""

    heading: Text
    finding: Finding


ENV_FILE = Finding(
    "exposure.env",
    Category.EXPOSURE,
    Severity.CRITICAL,
    T("Gizli ayar dosyası (.env) herkese açık"),
    T(
        "Bu dosya genellikle veritabanı şifreleri, e-posta şifreleri ve API anahtarları "
        "içerir. Otomatik botlar bu dosyayı her gün binlerce sitede arıyor."
    ),
    T(
        "Dosyayı sunucudan hemen kaldırın veya web erişimini engelleyin. İçindeki tüm şifre "
        "ve anahtarları (veritabanı, e-posta, API) DEĞİŞTİRİN; çünkü zaten kopyalanmış "
        "olabilirler."
    ),
)
REMOTE_DESKTOP = Finding(
    "ports.open_3389",
    Category.PORTS,
    Severity.HIGH,
    T("{service} internete açık (port {port})", service=T("Uzak Masaüstü (RDP)"), port=3389),
    T(
        "İnternete açık Uzak Masaüstü, KOBİ'lere yönelik fidye yazılımı saldırılarında en sık "
        "kullanılan giriş kapısıdır."
    ),
    T(
        "RDP'yi internete kapatın ve yalnızca VPN üzerinden erişin. Mümkün değilse Ağ Düzeyinde "
        "Kimlik Doğrulama (NLA), güçlü şifre ve hesap kilitleme kullanın."
    ),
)
OLD_PHP = Finding(
    "software.eol.php",
    Category.SOFTWARE,
    Severity.HIGH,
    T("{name} {cycle} artık güvenlik güncellemesi almıyor", name="PHP", cycle="7.4"),
    T(
        "Bu sürüm {date} tarihinden beri desteklenmiyor. Yeni bulunan açıklar kapatılmıyor ve "
        "saldırganlar eski sürümleri otomatik araçlarla tarayıp hedefliyor.",
        date="11.2022",
    ),
    T(
        "Hosting panelinizden (cPanel: 'MultiPHP Manager' / 'Select PHP Version', Plesk: "
        "'PHP Ayarları') sürümü değiştirebilirsiniz. Önce sitenizin yedeğini alın ve yeni "
        "sürümle çalıştığını kontrol edin."
    ),
)
NO_SPF = Finding(
    "email.spf_missing",
    Category.EMAIL,
    Severity.MEDIUM,
    T("Sahte e-posta koruması (SPF kaydı) yok"),
    T(
        "Dolandırıcılar firmanızın adresinden (ör. muhasebe@firmaniz.com) sahte fatura veya "
        "ödeme talebi gönderebilir ve bu e-postalar alıcıya gerçekmiş gibi ulaşır."
    ),
    T(
        "'{domain}' için DNS'e bir SPF kaydı ekleyin. E-posta sağlayıcınız bu kaydı verir; "
        "örneğin Google Workspace için: 'v=spf1 include:_spf.google.com ~all'. Alan adınızdan "
        "hiç e-posta gönderilmiyorsa: 'v=spf1 -all'.",
        domain=SAMPLE_DOMAIN,
    ),
)
CERT_EXPIRING = Finding(
    "tls.cert_expiring",
    Category.TLS,
    Severity.MEDIUM,
    T("SSL sertifikanızın süresi {days_left} gün içinde doluyor", days_left=12),
    T(
        "Sertifika süresi dolduğunda ziyaretçileriniz güvenlik uyarısı görecek. Otomatik "
        "yenileme çalışıyorsa bu süre genellikle daha uzun olur."
    ),
    T("Sertifikanın otomatik yenilendiğinden emin olun; değilse hemen yenileyin."),
)
MISSING_HEADERS = Finding(
    "http.security_headers_missing",
    Category.HTTP,
    Severity.LOW,
    T("{n} tarayıcı güvenlik başlığı eksik", n=3),
    T(
        "Güvenlik başlıkları, ziyaretçilerin tarayıcısına sitenizi nasıl koruyacağını söyler. "
        "Tek başına acil değildir ancak saldırıları zorlaştıran ücretsiz bir önlemdir."
    ),
)

# Worst first, as the report orders them, each with the fix that closes it.
SAMPLE_FIXES: list[tuple[Finding, Text]] = [
    (ENV_FILE, T(".env dosyasını kaldır, şifreleri değiştir")),
    (REMOTE_DESKTOP, T("Uzak Masaüstünü internete kapat")),
    (OLD_PHP, T("PHP'yi desteklenen bir sürüme yükselt")),
    (NO_SPF, T("SPF kaydı ekle")),
    (CERT_EXPIRING, T("Sertifikanın otomatik yenilenmesini aç")),
    (MISSING_HEADERS, T("Güvenlik başlıklarını ekle")),
]
SAMPLE_FINDINGS = [finding for finding, _fix in SAMPLE_FIXES]

CHECKS = [
    SampleCheck(T("SSL/TLS sertifikası ve protokoller"), CERT_EXPIRING),
    SampleCheck(T("Açık portlar"), REMOTE_DESKTOP),
    SampleCheck(T("Yazılım sürümleri"), OLD_PHP),
    SampleCheck(T("E-posta sahteciliği koruması (SPF/DMARC/DKIM)"), NO_SPF),
    SampleCheck(T("Açıkta kalan hassas dosyalar"), ENV_FILE),
]


def scoring_rules() -> dict[str, object]:
    """The rules the page's re-grading script applies (rendered as data attributes)."""
    return {
        "penalties": {s.value: p for s, p in PENALTIES.items()},
        "caps": {s.value: c for s, c in CAPS.items()},
        "grades": [[threshold, grade] for threshold, grade in GRADES],
    }


def sample_grade() -> tuple[int, str]:
    return compute_score(SAMPLE_FINDINGS)
