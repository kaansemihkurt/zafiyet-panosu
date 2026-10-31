# Tehdit modeli: STRIDE (DFD: `docs/architecture.png`)

**Risk puanı** = Olasılık (1–5) × Etki (1–5). Kalan risk, önlem sonrası yeniden puanlanmıştır.
**Kartın öncelikli tehdidi:** T1, yani kurum içi panoya yetkisiz erişim (izleme listeleri ve öncelikler dışarıdan görülebilir).

| # | STRIDE | Varlık / akış | Tehdit | O×E | Risk | Önlem | Kalan |
|---|---|---|---|---|---|---|---|
| **T1** | **Information disclosure** + Elevation | Akış 1→4/5 · `/panel/*`, `/api/watchlist` | **Yetkisiz kişi panoyu açıp izleme listesini ve öncelikleri görür** | 5×5 | **25** | Zero Trust: her istek kimlik doğrulamalı (Entra ID + MFA); `/panel/*` yalnız `viewer`/`analyst`; `/api/*` oturum zorunlu ve rol API'de yeniden denetlenir; rolsüz hesap 403; roller yalnızca davetle; GitHub sağlayıcısı kapalı; her karar loglanır; 5 dk'da 5'ten fazla başarısız istekte alarm | 1×5 = **5** |
| T2 | Elevation of privilege | Akış 5 · `POST/DELETE /api/watchlist` | İzleyici, arayüzü atlayıp API'ye doğrudan yazma isteği gönderir | 4×4 | 16 | Yazma yalnızca `analyst`; kontrol sunucu tarafında; arayüzde düğmeleri gizlemek sadece kullanılabilirlik içindir; birim testleri (izleyici POST/DELETE → 403, depoya çağrı yok) | 1×4 = 4 |
| T3 | Spoofing | Akış 2–3 | Parola avı ile çalınan hesapla giriş | 3×5 | 15 | MFA zorunlu hesaplar; davet yalnızca bilinen kişilere; davet süreli; şüpheli girişte rol hemen kaldırılır | 2×4 = 8 |
| T4 | Spoofing / Tampering | Akış 5 | Saldırgan `x-ms-client-principal` başlığını sahteleyerek analist gibi görünür | 2×5 | 10 | SWA, dışarıdan gelen bu başlığı siler ve kendisi üretir; API'ye yalnızca SWA üzerinden erişilir (yönetilen fonksiyonun kendi URL'si yok) | 1×5 = 5 |
| T5 | Information disclosure | Depo / CI / istemci | Tablo SAS'ı, dağıtım belirteci veya NVD API anahtarı depoya, istemciye ya da loga sızar | 3×5 | 15 | SAS Bicep ile doğrudan uygulama ayarına yazılır, insan görmez; dağıtım belirteci ve `NVD_API_KEY` yalnızca GitHub Secrets'ta (NVD anahtarı yalnızca veri iş akışında kullanılır, istemciye gitmez, testle doğrulandı); gitleaks + GitHub secret scanning ve push protection; SAS içeren URL loglanmaz (test edildi); runbook | 1×4 = 4 |
| T6 | Tampering | Akış 6 · Table Storage | Sızan SAS ile izleme listesi değiştirilir | 2×4 | 8 | SAS yalnız Table + nesne + r/a/u/d + HTTPS + süreli; anahtar döndürülünce tüm SAS'lar geçersizleşir (runbook) | 1×4 = 4 |
| T7 | Tampering (XSS) | Akış 4 · not alanı | Analist notuna betik gömülür, izleyicinin tarayıcısında çalışır | 3×4 | 12 | Sıkı CSP (`script-src 'self'`, satır içi kod yok); veriler `textContent` ile yazılır; not 280 karakter, kontrol karakterleri temizlenir | 1×3 = 3 |
| T8 | Tampering (enjeksiyon) | Akış 6 · OData anahtarı | CVE alanına OData ifadesi enjekte edilir | 2×4 | 8 | CVE `^CVE-\d{4}-\d{4,7}$` ile doğrulanır; öncelik beyaz listede (P1–P4); test edildi | 1×2 = 2 |
| T9 | Repudiation | Akış 8 | Analist bir önceliği değiştirdiğini inkâr eder | 2×3 | 6 | Her ALLOW/DENY kararı takma adlı kullanıcı, rol, yöntem, yol ve CVE ile App Insights'ta; kayıtta `updatedBy` ve `updatedAt` | 1×3 = 3 |
| T10 | Denial of service | Akış 7 · KEV vekili | Çok sayıda istekle veri sağlayıcıya yük bindirilir ya da maliyet artar | 3×3 | 9 | KEV yanıtı 6 saat bellekte önbellekli; API oturum zorunlu; Free katman sabit ücretsiz; günlük log tavanı 100 MB; bütçe alarmı | 2×2 = 4 |
| T11 | Information disclosure | Akış 8 · loglar | Loglarda kişisel veri (e-posta, IP) birikir | 3×3 | 9 | Kullanıcı kimliği tuzlu SHA-256 özetiyle loglanır, e-posta loglanmaz; App Insights IP maskeleme açık; saklama 30 gün | 1×2 = 2 |
| T12 | Tampering (tedarik zinciri) | CI/CD | Kötü amaçlı bağımlılık ya da Action sürümü | 2×5 | 10 | API'de sıfır npm bağımlılığı; Dependabot; npm audit; CodeQL; workflow'larda `permissions: contents: read`; main dalı korumalı | 1×4 = 4 |

## T1'in ayrıntılı analizi (kartın tehdidi)
- **Saldırı yolları:**
  1. Kimlik doğrulamasız doğrudan URL (`/panel/`, `/api/watchlist`).
  2. Herhangi bir Microsoft veya GitHub hesabıyla giriş yapıp rol olmadan erişim.
  3. Önizleme veya staging ortamından erişim.
  4. Önbellekteki sayfa ya da yanıtın başkasına sunulması.
  5. Arama motoru indeksleme.
- **Önlemler (yollara göre):**
  1. 401 durumunda girişe yönlendirme; oturumsuz API isteği reddedilir.
  2. Rol yalnızca davetle verilir; rolsüz kullanıcı `/panel/*` için SWA'dan, `/api/*` için fonksiyondan 403 alır.
  3. `stagingEnvironmentPolicy: Disabled`.
  4. Pano ve API yanıtlarında `Cache-Control: no-store`; KEV yanıtı yalnızca `private`.
  5. `robots.txt Disallow: /` ve `noindex`.
- **Doğrulama:**
  - Yetkisiz hesapla `/panel/` → 403 sayfası.
  - Aynı hesapla `/api/watchlist` → 403 JSON.
  - İzleyiciyle `POST /api/watchlist` → 403.
  - App Insights'ta `decision == "DENY"` kayıtları.
  - Metrik alarmı e-postası.
- **Kalan risk:**
  - Rolü olan bir hesabın ele geçirilmesi (MFA ile düşürüldü).
  - Free planda özel Entra kiracısı kısıtı ve Koşullu Erişim kullanılamıyor, bu yüzden MFA kimlik sağlayıcının hesap ayarına dayanıyor.
  - İyileştirme: Standard plan + özel Entra kayıt + Koşullu Erişim (MFA zorunlu) + Key Vault referansları.
