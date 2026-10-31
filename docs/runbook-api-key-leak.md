# Olay müdahale runbook'u: "API anahtarım sızdı"

**Kapsam:** Tablo SAS'ı (`TABLE_SAS`), depolama hesabı anahtarı, SWA dağıtım belirteci (`AZURE_STATIC_WEB_APPS_API_TOKEN`) ya da Application Insights bağlantı dizesi depoya, loga, ekran görüntüsüne veya sohbete düştü.
**Hedef süre:** tespitten iptale 15 dakika.

## 1. Tespit (0–5 dk)
- Sinyal kaynakları:
  - GitHub secret scanning veya push protection uyarısı
  - gitleaks iş akışının başarısız olması
  - Bütçe alarmı
  - Depolama metriklerinde beklenmeyen işlem
  - App Insights'ta tanımadığın `updatedBy` değerleri
  - Dışarıdan bildirim (security.txt)
- Kaydet: ne sızdı, nerede göründü, ilk görülme zamanı (ekran görüntüsü, saat bilgisi görünür).

## 2. İptal (5–15 dk), önce anahtarı geçersiz kıl, sonra temizle
| Sızan | İptal |
|---|---|
| Tablo SAS veya depolama anahtarı | Portal → Depolama hesabı → *Access keys* → **key1'i yeniden oluştur** (hesap SAS'ları key1 ile imzalanır, hepsi anında geçersizleşir). CLI: `az storage account keys renew -g rg-zafiyet-panosu -n <hesap> --key primary` |
| SWA dağıtım belirteci | Portal → Static Web App → *Overview* → **Manage deployment token → Reset**. CLI: `az staticwebapp secrets reset-api-key -n zafiyetpano-swa -g rg-zafiyet-panosu` |
| NVD API anahtarı (`NVD_API_KEY`) | nvd.nist.gov üzerinden yeni anahtar iste (eskisi kullanım dışı kalır); GitHub Secrets'ta güncelle; `data` iş akışını çalıştır |
| App Insights bağlantı dizesi (yalnızca telemetri yazar) | Düşük risk. Gerekirse kaynağı yeniden oluştur. |

## 3. Yenileme (15–30 dk)
1. Altyapıyı yeniden dağıt: `az deployment group create -g rg-zafiyet-panosu -f infra/main.bicep -p alertEmail=<e-posta>`. Bicep yeni anahtarla yeni SAS üretir ve uygulama ayarına yazar.
2. Yeni dağıtım belirtecini GitHub → *Settings → Secrets → Actions* → `AZURE_STATIC_WEB_APPS_API_TOKEN` alanına yaz; `deploy` iş akışını çalıştır.
3. Panoyu analist hesabıyla aç: liste okunuyor ve kayıt eklenebiliyor mu kontrol et.

## 4. İnceleme (30–90 dk)
- Sızan değeri depodan çıkar.
  - Geçmişte kaldıysa yalnızca silmek yetmez, anahtar zaten iptal edildi.
  - İstenirse `git filter-repo` ile geçmiş temizlenir.
- Kötüye kullanımı ara:
  - App Insights → Logs: `traces | where message has "zt_access" | where timestamp > ago(7d)`
  - Depolama metrikleri: Transactions (API adına göre)
- İzleme listesini son yedekle ya da bilinen durumla karşılaştır. Şüpheli kayıtları analist düzeltir.
- Kök nedeni yaz (ör. yerel `.env` dosyası commit'lendi), bir önleyici adım ekle (pre-commit gitleaks, push protection).

## 5. Bildirim
- Ekip ve ders sorumlusu: ne sızdı, ne zaman iptal edildi, kötüye kullanım bulgusu var mı.
- Kişisel veri etkilendiyse KVKK md. 12/5 kapsamında değerlendir (bu sistemde loglar takma adlı, izleme listesi kişisel veri içermez).
- Güvenlik raporunun "olaylar" bölümüne ve README'ye kısa not.

## Kontrol listesi
- [ ] Sızan değer ve ilk görülme zamanı kaydedildi
- [ ] Anahtar veya belirteç iptal edildi (saat: ____)
- [ ] Yeni değerler kasaya yazıldı, yeniden dağıtım başarılı
- [ ] Loglar incelendi, kötüye kullanım: var / yok
- [ ] Kök neden ve önleyici adım yazıldı
- [ ] Bildirimler yapıldı
