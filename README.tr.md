# Kalkan

**KOBİ'ler için sade web sitesi güvenlik tarayıcısı.** Kalkan bir web sitesinin SSL/TLS
sertifikasını, internete açık portlarını, eski yazılımlarını, açıkta kalan dosyalarını ve
e-posta sahteciliği korumasını kontrol eder. Bulduğu her sorunu teknik bilgi gerektirmeyen
bir dille, **ne yapılması gerektiğiyle birlikte** raporlar.

Hem **komut satırı aracı** hem de **çok kullanıcılı bir web uygulaması (SaaS)** olarak
çalışır: alan adı sahipliği doğrulaması, arka planda tarama kuyruğu, e-posta uyarılı
otomatik taramalar, token ile çalışan REST API ve indirilebilir raporlar.

[English README](README.md)

## Neleri kontrol eder?

| Alan | Kontroller |
|---|---|
| **SSL/TLS** | HTTPS var mı, sertifika süresi, alan adı uyumu, kendinden imzalı / eksik zincir, zayıf anahtar, TLS 1.0/1.1 açık mı, TLS 1.3 desteği |
| **Web sunucusu** | HTTP→HTTPS yönlendirme, HSTS, güvenlik başlıkları, çerez ayarları, sürüm ifşası, şifresiz (http://) yüklenen içerik ve formlar, security.txt, CDN tespiti |
| **Açıkta kalan dosyalar** | `.env`, `.git/`, `wp-config.php` yedekleri, SQL yedekleri, `phpinfo()`, `server-status`, klasör listeleme |
| **Açık portlar** | RDP, SMB, veritabanları, Redis/MongoDB/Elasticsearch, FTP, Telnet, Docker API, yönetim panelleri (~35 port) |
| **Yazılım sürümleri** | Apache, nginx, IIS, PHP, OpenSSL, WordPress, Drupal, Joomla, OpenSSH, MySQL/MariaDB, jQuery, Bootstrap… destek süresi bitmiş mi, güncel mi? |
| **WordPress** | Eklenti ve temalar: güncel mi, 2 yıldır güncellenmiyor mu, WordPress.org'dan (ör. güvenlik nedeniyle) kaldırılmış mı? |
| **E-posta** | SPF, DMARC, DKIM (anahtar uzunluğu dahil) ve e-posta sunucularında şifreli bağlantı (STARTTLS) |
| **DNS** | DNSSEC ve CAA (sertifika verebilecek kuruluş kısıtlaması) |

Rapor A–F arası bir notla ve "önce bunları yapın" listesiyle başlar. Her bulguda
"Ne anlama geliyor?", "Ne yapmalısınız?" ve açılır teknik ayrıntılar bulunur. Rapor web
sayfası, tek dosyalık HTML, PDF ve JSON olarak alınabilir. Web uygulamasında her alan adı
için puan geçmişi grafiği ve "önceki taramaya göre" karşılaştırması (çözülen ve yeni
sorunlar) vardır.

## Web uygulaması

- **Hesaplar:** e-posta doğrulamalı kayıt, e-postayla şifre sıfırlama, şifre değiştirme
  (diğer tüm oturumları kapatır), verileri JSON olarak indirme ve hesap silme (KVKK).
- **Alan adları:** Bir site yalnızca sahibi DNS TXT kaydı veya `/.well-known/` altındaki bir
  dosyayla sahipliğini kanıtladıktan sonra taranır; kanıt 30 günde bir yenilenir.
- **Otomatik tarama ve uyarılar:** haftalık veya aylık tarama; yalnızca *yeni* ve önemli bir
  sorun çıktığında (kritik/yüksek bulgu, süresi dolmak üzere olan sertifika, notun C veya
  altına düşmesi) e-posta gönderilir. Düzeltilmemiş bir sorun her hafta tekrar bildirilmez.
- **REST API:** kişisel erişim tokenleri ve `/api/docs` adresinde etkileşimli belgeler.

## Hızlı başlangıç

```bash
pip install -e .
kalkan scan firmaniz.com.tr
kalkan scan firmaniz.com.tr -f html -o rapor.html
kalkan scan firmaniz.com.tr -f pdf -o rapor.pdf
```

Web uygulaması:

```bash
pip install -e ".[web]"
kalkan serve            # http://127.0.0.1:8000
```

PostgreSQL, migration adımı, ayrı tarama işçisi ve gönderilen e-postaları görmek için
Mailpit ile:

```bash
cp .env.example .env    # KALKAN_SECRET_KEY değerini girin
docker compose up --build
# uygulama: http://127.0.0.1:8000   e-postalar: http://127.0.0.1:8025
```

REST API (Hesabım → API tokenleri sayfasından token oluşturun):

```bash
curl -H "Authorization: Bearer klk_..." http://127.0.0.1:8000/api/v1/domains
```

> Yalnızca size ait olan veya taramak için yazılı izniniz bulunan sistemleri tarayın.

## Güvenlik tasarımı

- **Alan adı sahipliği doğrulaması:** Bir site ancak sahibi DNS TXT kaydı veya
  `/.well-known/` altındaki bir dosyayla sahipliğini kanıtladıktan sonra taranabilir.
- **SSRF koruması:** Tarayıcı yalnızca doğrulanmış, internete açık IP adreslerine bağlanır;
  iç ağa (127.0.0.1, 10.x, 169.254.169.254…) yönlendirmeler engellenir. IP sabitleme
  (Host + SNI) ile DNS rebinding saldırıları da kapatılır.
- **Zarar vermeyen tarama:** Saldırı denemesi yapılmaz; kısa bir port listesi ve birkaç
  GET isteğiyle yalnızca dışarıdan görünen bilgiler kontrol edilir.
- **Hesap güvenliği:** Argon2id; giriş ve şifre sıfırlamada hesap numaralandırma yok;
  imzalı, süreli e-posta bağlantıları; tek kullanımlık sıfırlama bağlantıları; şifre
  değişince diğer tüm oturumlar geçersiz olur.
- **API güvenliği:** yalnızca Bearer token (çerez yok, dolayısıyla CSRF yüzeyi yok),
  tokenler SHA-256 özetiyle saklanır ve bir kez gösterilir, token başına istek sınırı.
- **Uygulama güvenliği:** CSRF koruması, giriş denemesi sınırı, her sorguda sahiplik
  kontrolü (IDOR yok) ve Kalkan'ın kullanıcılarına önerdiği güvenlik başlıklarının aynısı.
- **Az yanlış alarm:** CDN arkasındaki sitelerde port sonuçları bastırılır; Ubuntu/Debian
  gibi dağıtımların geriye taşınmış yamaları dikkate alınır; "sahte 404" sayfaları ayıklanır.

## İşletim

- **Migration:** `kalkan migrate` (Alembic). İşçi asla kendi başına migration yapmaz ve
  şema eskiyse başlamayı reddeder. v0.1 ile oluşturulmuş veritabanları otomatik devralınır.
- **Log:** `KALKAN_LOG_FORMAT=json` ile satır başına bir JSON; her istek bir `X-Request-ID`
  alır ve o isteğin tüm log satırlarında görünür.
- **Metrikler:** `KALKAN_METRICS_TOKEN` ayarlıysa `/metrics` (Prometheus); işçi kendi
  metriklerini `KALKAN_WORKER_METRICS_PORT` üzerinden sunar.

## Geliştirme

```bash
pip install -e ".[dev]"
pytest --cov
ruff format --check . && ruff check . && mypy
python scripts/update_software_db.py   # sürüm/EOL verisini güncelle
alembic revision --autogenerate -m "..."  # model değişikliğinden sonra

# veritabanı testlerini PostgreSQL'e karşı çalıştırmak için
KALKAN_TEST_DATABASE_URL=postgresql+psycopg://kalkan:test@127.0.0.1:55432/kalkan_test pytest
```

## Lisans

[MIT](LICENSE)
