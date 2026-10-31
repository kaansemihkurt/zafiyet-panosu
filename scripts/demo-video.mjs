// Altyazılı demo videosunu canlı üründen otomatik kaydeder (Playwright).
// Kullanım: node scripts/demo-video.mjs https://<adres>.azurestaticapps.net
import { chromium } from 'playwright';
import { mkdirSync, renameSync, writeFileSync } from 'node:fs';

const BASE = (process.argv[2] || '').replace(/\/$/, '');
if (!/^https:\/\//.test(BASE) && !process.env.ALLOW_HTTP) { console.error('Kullanım: node scripts/demo-video.mjs https://<adres>'); process.exit(1); }
mkdirSync('demo', { recursive: true });

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 }, recordVideo: { dir: 'demo', size: { width: 1600, height: 900 } }, bypassCSP: true, locale: 'tr-TR' });
const page = await ctx.newPage();
const cues = []; const t0 = Date.now();
const wait = (ms) => page.waitForTimeout(ms);
async function say(text, ms) {
  const start = (Date.now() - t0) / 1000;
  await page.evaluate((tx) => {
    let d = document.getElementById('__cap');
    if (!d) { d = document.createElement('div'); d.id = '__cap'; Object.assign(d.style, { position: 'fixed', left: '50%', bottom: '28px', transform: 'translateX(-50%)', maxWidth: '1100px', background: 'rgba(2,6,18,.88)', color: '#fff', font: '600 22px system-ui', padding: '12px 20px', borderRadius: '12px', zIndex: 9999, textAlign: 'center', border: '1px solid #34508f' }); document.body.append(d); }
    d.textContent = tx;
  }, text);
  await wait(ms);
  cues.push([start, (Date.now() - t0) / 1000, text]);
}

await page.goto(`${BASE}/?lang=tr`); await wait(2500);
await say('Zafiyet İstihbarat Panosu: üniversite güvenlik ekibinin sabah vardiyası için CVE önceliklendirme.', 7000);
await say('Veri NVD CVE API ve CISA KEV\'den GitHub Actions ile her gün otomatik çekiliyor; son güncelleme ve kaynak hep görünür.', 8000);
await say('Filtrelenen CVE, kritikler, aktif istismar edilen (KEV) ve izleme listesi eşleşmeleri tek bakışta.', 8000);
await page.fill('#wIn', 'fortinet'); await page.press('#wIn', 'Enter');
await say('Analist kurumundaki ürünleri izleme listesine ekler; liste yalnızca tarayıcıda saklanır.', 8000);
await page.locator('body').click({ position: { x: 5, y: 700 } }); await page.keyboard.press('k');
await say('K kısayoluyla KEV\'e odaklanır; öncelik puanı CVSS, KEV, fidye ve izleme listesinden hesaplanır.', 9000);
await page.keyboard.press('k');
await page.click('[data-table=tTrend]');
await say('Her grafiğin otomatik bir özet cümlesi ve tablo alternatifi var; renk tek başına anlam taşımıyor.', 9000);
await page.click('[data-lang=en]'); await wait(1500);
await page.setViewportSize({ width: 420, height: 900 });
await say('TR/EN iki dil, koyu SOC teması ve mobil özet görünüm.', 8000);
await page.setViewportSize({ width: 1600, height: 900 });
await page.goto(`${BASE}/?veri=/bozuk/&lang=tr`); await wait(2000);
await say('Veri kaynağı çökerse pano son başarılı veriyle açılır ve bunu kullanıcıya açıkça söyler.', 9000);
await page.goto(`${BASE}/?lang=tr`); await wait(1500);
await say('Kod: github.com/kaansemihkurt/zafiyet-panosu', 4000);

const video = page.video(); await ctx.close(); await browser.close();
const path = await video.path(); renameSync(path, 'demo/zafiyet-panosu-demo.webm');
const ts = (s) => new Date(s * 1000).toISOString().slice(11, 23);
writeFileSync('demo/zafiyet-panosu-demo.vtt', 'WEBVTT\n\n' + cues.map(([a, b, x], i) => `${i + 1}\n${ts(a)} --> ${ts(b)}\n${x}\n`).join('\n'));
console.log(`Hazır: demo/zafiyet-panosu-demo.webm (${Math.round((Date.now() - t0) / 1000)} sn) + .vtt`);
