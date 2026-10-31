# Kurulum ve kanıt toplama: adım adım (~60–90 dk)

> Ekran görüntülerinde **tarih ve saat görünmeli** (görev çubuğundaki saat ekrana girsin). Her adımın kanıtını `report/kanitlar/` klasörüne koy.
> `⟦…⟧` işaretli yerleri gerçek değerlerle değiştir. Hiçbir anahtarı sohbete, rapora ya da ekran görüntüsüne koyma.

## A. GitHub deposu (5 dk)
1. github.com'da **public** ve boş bir `zafiyet-panosu` deposu aç.
2. PowerShell:
   ```powershell
   cd C:\Users\archf\OneDrive\Desktop\CBU\repositories\zafiyet-panosu
   Rename-Item _github .github   # iş akışları güvenlik nedeniyle _github adıyla yazıldı; adını düzelt
   git init; git add .; git commit -m "Zafiyet İstihbarat Panosu: Zero Trust erişim"
   git branch -M main
   git remote add origin https://github.com/kaansemihkurt/zafiyet-panosu.git
   git push -u origin main
   ```
   İlk `deploy` çalışması belirteç olmadığı için başarısız olur, bu normal.

## B. Azure altyapısı (Cloud Shell, kurulum gerektirmez) (15 dk)
1. portal.azure.com adresine Azure for Students hesabınla gir, sağ üstten **Cloud Shell → Bash** aç.
2. Şunları çalıştır:
   ```bash
   git clone https://github.com/kaansemihkurt/zafiyet-panosu && cd zafiyet-panosu
   az group create -n rg-zafiyet-panosu -l westeurope
   az deployment group create -g rg-zafiyet-panosu -f infra/main.bicep -p alertEmail=⟦e-postan⟧ --query properties.outputs
   ```
   Çıktıdaki `url` değeri ürün adresin (ör. `https://xxx.azurestaticapps.net`).
3. **Bütçe alarmı:**
   ```bash
   az deployment group create -g rg-zafiyet-panosu -f infra/budget.bicep -p alertEmail=⟦e-postan⟧ startDate=2026-10-01
   ```
   Hata verirse portalda **Cost Management → Budgets → + Add** ile oluştur: 1 USD, aylık, %50 ve %100 e-posta.
   📸 Bütçe ekranının görüntüsünü al.
4. **Dağıtım belirteci:** belirteci kopyalayıp hiçbir yere kaydetmeden doğrudan C1 adımına geç.
   ```bash
   az staticwebapp secrets list -n zafiyetpano-swa -g rg-zafiyet-panosu --query properties.apiKey -o tsv
   ```

## C. CI/CD ve "önce" sürümü (10 dk)
1. GitHub → *Settings → Secrets and variables → Actions → New repository secret* ekranında adı `AZURE_STATIC_WEB_APPS_API_TOKEN` yap, değer olarak B4'teki belirteci yapıştır.
2. **NVD API anahtarı (önerilir):** nvd.nist.gov/developers/request-an-api-key adresinden e-postayla ücretsiz al. GitHub Secrets'a `NVD_API_KEY` adıyla ekle. Anahtarı başka hiçbir yere yazma; anahtarsız da çalışır, yalnızca daha yavaş.
3. **İlk veri çekimi:** *Actions → data → Run workflow*. Bu iş akışı `data` dalını oluşturur, NVD + KEV verisini çeker ve ürünü yayınlar (~2–4 dk). Ürün adresini aç; "Son güncelleme" saatini gör. Bu iş akışı her sabah 07:15'te kendiliğinden çalışır.
4. *Actions → deploy → Run workflow → config: **baseline*** ile güvenlik başlıksız sürümü yayınla (yalnızca karşılaştırma için).
5. **Önce taramaları:**
   - *Actions → zap-baseline → Run workflow*: target = ürün adresin, label = `once`. İş bitince *Artifacts* altından `zap_once` raporunu indir.
   - developer.mozilla.org/observatory ve securityheaders.com adreslerinde ürün adresini tara. 📸 İki sonucun ekran görüntüsünü al.
6. *Actions → deploy → Run workflow → config: **hardened*** ile asıl sürümü yayınla.
7. **Sonra taramaları:** aynı üç taramayı `label = sonra` ile tekrarla. 📸 Hedef: Observatory ≥ B+, securityheaders ≥ A.

## D. Roller ve MFA (10 dk)
1. Portal → `zafiyetpano-swa` → **Role management → Invite** ekranında:
   - Sağlayıcı **Azure Active Directory**, kendi hesabın, rol `analyst` → davet bağlantısını aç ve kabul et.
   - İkinci bir Microsoft hesabı (ör. okul hesabın) → rol `viewer` → kabul et.
   - Üçüncü bir hesaba (ör. gmail ile açılmış Microsoft hesabı) **davet gönderme**. Bu hesap "yetkisiz" test hesabın.
2. **MFA:** iki rollü hesapta da iki adımlı doğrulama açık olmalı (account.microsoft.com → Güvenlik). Okul hesabın büyük ihtimalle zaten MFA istiyor.
   📸 Girişte MFA onay ekranını çek. 📸 Role management listesini çek.

## E. Kart doğrulama testi (15 dk), raporun en önemli kanıtları
1. **Yetkisiz hesap → 403:** gizli pencerede üçüncü hesapla giriş yap ve `/panel/` aç.
   📸 403 sayfasını çek. F12 → Network açıkken `/api/watchlist` adresine git ve 📸 403 yanıtını çek.
2. **İzleyici düzenleyemez:** viewer hesabıyla panoyu aç; ekleme formu görünmemeli. F12 → Console'a yaz:
   ```js
   fetch('/api/watchlist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cve:'CVE-2024-3400',priority:'P1'})}).then(r=>console.log('durum',r.status))
   ```
   📸 `durum 403` çıktısını çek. Analist hesabıyla aynı komut `201` vermeli, onu da 📸 çek.
3. **Erişim logları:** Portal → `zafiyetpano-appi` → **Logs** ekranında çalıştır:
   ```kusto
   traces
   | where message has "zt_access"
   | extend d = parse_json(message)
   | project timestamp, decision = tostring(d.decision), status = toint(d.status), user = tostring(d.user),
             roles = tostring(d.roles), method = tostring(d.method), path = tostring(d.path)
   | order by timestamp desc
   ```
   📸 ALLOW ve DENY satırlarının birlikte göründüğü sonucu çek (loglar 2–5 dk gecikebilir).
4. **Alarm:** viewer hesabıyla 2. adımdaki komutu 1 dakika içinde 8 kez çalıştır (veya `for(let i=0;i<8;i++) fetch(...)`).
   5–10 dk içinde e-posta gelir. 📸 E-postayı ve *Monitor → Alerts* ekranını çek.

## F. GitHub güvenlik ayarları (5 dk)
1. *Settings → Code security* altında aç: Dependabot alerts, Dependabot security updates, Secret scanning, **Push protection**, Private vulnerability reporting.
2. *Settings → Branches → Add branch ruleset* (veya classic rule), hedef `main`:
   - Require a pull request
   - Require status checks: `test`, `gitleaks`, `dependencies`
   - Block force pushes
   - Do not allow bypassing
3. 📸 Kural ekranını çek. 📸 Actions'ta yeşil `security` ve `deploy` çalışmalarını çek.
4. Bu adımdan sonra değişiklikler PR ile yapılır: `git switch -c duzeltme` → push → PR aç → kontroller geçince birleştir.

## G. Rapor ve portföy (15 dk)
1. `report/guvenlik_raporu.docx` dosyasını aç. `⟦DOLDUR⟧` işaretli yerlere ZAP sayılarını, notları ve ekran görüntülerini koy. *Dosya → PDF olarak kaydet*.
2. Portföyde `app/(site)/projeler/zafiyet-panosu/page.js` dosyasının en üstündeki `SONUCLAR` nesnesine ürün adresini ve ZAP/Observatory sonuçlarını yaz, sonra commit ve push yap.
3. README'deki CV cümlesinde `⟦X⟧ → ⟦Y⟧` değerlerini ZAP sonuçlarınla değiştir.

## H. Arayüz dersi kanıtları (30–45 dk)
1. **Lighthouse (mobil):** pagespeed.web.dev adresinde ürün adresini **Mobil** sekmesinde tara. 📸 Hedef: Erişilebilirlik ≥ 90, Performans ≥ 80. Altta sorun çıkarsa ekran görüntüsünü bana at.
2. **Kullanıcı testi:** `docs/KULLANICI-TESTI.md` dosyasındaki 3 görevi 2 kişiyle yap ve tabloyu doldur. Testte görülen bir sorunu düzelt. Önce/sonra ekran görüntülerini `docs/test/once.png` ve `docs/test/sonra.png` olarak kaydet.
3. **Hata durumu provası:**
   - Ürün adresinin sonuna `?veri=/bozuk/` ekle; pano kırmızı bantla son veriyle açılmalı.
   - DevTools → Network → Offline seçeneğiyle de dene.
4. **Demo videosu:** `docs/DEMO-VIDEO.md` dosyasındaki komutlarla otomatik kaydet (`node scripts/demo-video.mjs <adres>`). Çıkan `demo/zafiyet-panosu-demo.webm` ve `.vtt` dosyalarını portföyde `public/video/` klasörüne koy.
5. **Portföy:** `app/(site)/projeler/zafiyet-panosu/page.js` dosyasının üstündeki `SONUCLAR`, `EKRANLAR` ve `TEST` alanlarını doldur. `projeler/page.js` içindeki `ZAFIYET_URL` değerini ürün adresinle değiştir.
6. **Commit geçmişi:** ödev "4 farklı güne yayılmış 15+ commit" istiyor. Commit tarihlerini geriye alma (sahte tarih = akademik dürüstlük ihlali). Bugünden itibaren her anlamlı değişikliği ayrı commit'le; gerekirse eksik kalan puanı kabul et.

## LMS'e teslim
- **Arayüz dersi:**
  - ürün linki
  - depo linki
  - vaka sayfası (`/projeler/zafiyet-panosu`)
  - video linki
  - Lighthouse mobil ekran görüntüsü
  - README'deki CV cümlesi
  - kullanıcı testi önce/sonra görselleri
- **Bulut dersi:** aşağıdaki liste.

- Ürün linki
- Depo linki
- `guvenlik_raporu.pdf`
- Portföy güvenlik bölümü linki (`/projeler/zafiyet-panosu#guvenlik`)
