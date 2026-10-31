# Demo videosu (60–90 sn): senaryo

Kayıt iki yolla yapılabilir:
1. **Otomatik (önerilen):** `scripts/demo-video.mjs` canlı adresine gider, aşağıdaki senaryoyu altyazılı olarak oynatır ve `demo/zafiyet-panosu-demo.webm` + `.vtt` altyazı dosyasını üretir.
   ```powershell
   cd C:\Users\archf\OneDrive\Desktop\CBU\repositories\zafiyet-panosu
   npm init -y; npm i -D playwright; npx playwright install chromium
   node scripts/demo-video.mjs https://⟦senin-adresin⟧.azurestaticapps.net
   ```
2. **Elle:** Windows + Alt + R (Xbox Game Bar) ile kaydet; aşağıdaki altyazıları Clipchamp'te ekle.

| Süre | Ekranda | Altyazı / anlatım |
|---|---|---|
| 0–8 sn | Pano açılır | "Zafiyet İstihbarat Panosu: üniversite güvenlik ekibinin sabah vardiyası için CVE önceliklendirme." |
| 8–16 | Üst çubuk | "Veri NVD CVE API ve CISA KEV'den GitHub Actions ile her gün otomatik çekiliyor; son güncelleme ve kaynak hep görünür." |
| 16–26 | KPI kartları | "Filtrelenen CVE, kritikler, aktif istismar edilen (KEV) ve izleme listesi eşleşmeleri tek bakışta." |
| 26–38 | İzleme listesine `fortinet` eklenir | "Analist kurumundaki ürünleri izleme listesine ekler; liste yalnızca tarayıcıda saklanır." |
| 38–48 | `K` tuşu, öncelik listesi | "Klavye kısayollarıyla KEV'e odaklanır; öncelik puanı CVSS, KEV, fidye ve izleme listesinden hesaplanır." |
| 48–58 | Trend grafiği + "tablo olarak gör" | "Her grafiğin otomatik özeti ve tablo alternatifi var; renk tek başına anlam taşımıyor." |
| 58–68 | EN düğmesi, mobil görünüm | "Türkçe/İngilizce, koyu SOC teması ve mobil özet görünüm." |
| 68–80 | `?veri=/bozuk/` ile hata | "Veri kaynağı çökerse pano son başarılı veriyle açılır ve bunu açıkça söyler." |
