# Kullanıcı testi: protokol ve bulgular

**Amaç:** Sabah vardiyasında öncelik belirleyen güvenlik analistine benzeyen kişilerin panoyla 3 temel görevi yapıp yapamadığını görmek.
**Katılımcı profili (en az 2):** siber güvenlik / sistem yönetimi ilgisi olan kişiler (ör. bölümden bir arkadaş, bilgi işlemde çalışan bir tanıdık). Kişisel veri toplanmaz; katılımcılar K1, K2 diye anılır.
**Süre:** kişi başı ~10 dk. Kronometre tut, ekranı izle, düşüncelerini sesli söylemelerini iste ("sesli düşünme").

## Görevler (yönergeyi aynen oku, ipucu verme)
| # | Görev | Başarı ölçütü |
|---|---|---|
| G1 | "Kurumunuzda Fortinet ürünleri var. Bunu panoya bildirin ve Fortinet ile ilgili en yüksek öncelikli CVE'yi bulun." | İzleme listesine `fortinet` eklendi ve doğru CVE söylendi |
| G2 | "Şu an aktif olarak istismar edilen (KEV) ve fidye yazılımlarında kullanılan kritik bir zafiyet söyleyin; neden öncelikli olduğunu açıklayın." | KEV filtresi/etiketi kullanıldı, öncelik puanının gerekçesi söylendi |
| G3 | "Son haftalarda yeni CVE sayısı artıyor mu? Veriyi tablo olarak da görün." | Trend grafiği yorumlandı, "Veriyi tablo olarak gör" açıldı |

## Sonuç tablosu (doldur)
| Katılımcı | Görev | Başarılı mı? | Süre (sn) | Nerede takıldı / yorum |
|---|---|---|---|---|
| K1 | G1 | ⟦evet/hayır⟧ | ⟦ ⟧ | ⟦ ⟧ |
| K1 | G2 | | | |
| K1 | G3 | | | |
| K2 | G1 | | | |
| K2 | G2 | | | |
| K2 | G3 | | | |

## Bulgular → değişiklik
- **Bulgu:** ⟦ör. iki katılımcı da izleme listesi kutusunu sol altta geç fark etti⟧
- **Değişiklik:** ⟦ör. KPI kartındaki "İzleme listesi boş" metnini tıklanabilir yapıp kutuya odaklama⟧
- **Önce / sonra:** `docs/test/once.png` ve `docs/test/sonra.png` (aynı ekran, değişiklikten önce ve sonra)

> Olası değişiklik adayları (testte gerçekten görülen sorunu seç, uydurma):
> - izleme listesi KPI'ından forma kısayol
> - öncelik puanı formülünü tablodaki puana `title` ipucu olarak eklemek
> - mobilde filtrelerin daha üstte olması
> - "Yalnızca KEV" düğmesinin KPI kartından da açılabilmesi
