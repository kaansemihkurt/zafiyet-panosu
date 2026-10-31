/* Zafiyet İstihbarat Panosu — service worker (PWA, çevrimdışı dayanıklılık)
 * - Uygulama kabuğu önbelleğe alınır.
 * - /data/* önce ağdan; ağ yoksa son kaydedilen veri "x-zp-offline: 1" başlığıyla döner (arayüz uyarı gösterir).
 * - Kimlik gerektiren yollar (/panel, /api, /.auth, /login) ASLA önbelleğe alınmaz.
 */
const VERSION = 'zp-v1';
const SHELL = ['/', '/assets/app.css', '/assets/app.js', '/assets/vendor/echarts.simple.min.js', '/manifest.webmanifest', '/icons/icon-192.png', '/icons/icon-512.png'];
const PRIVATE = /^\/(panel|api|\.auth|login|logout)(\/|$)/;

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(VERSION).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== VERSION).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});

async function networkFirst(req) {
  const cache = await caches.open(VERSION);
  try {
    const res = await fetch(req);
    if (res.ok) cache.put(req, res.clone());
    return res;
  } catch (err) {
    const hit = await cache.match(req, { ignoreSearch: true });
    if (!hit) throw err;
    const h = new Headers(hit.headers); h.set('x-zp-offline', '1');
    return new Response(await hit.blob(), { status: 200, headers: h });
  }
}

async function staleWhileRevalidate(req) {
  const cache = await caches.open(VERSION);
  const hit = await cache.match(req);
  const net = fetch(req).then((res) => { if (res.ok) cache.put(req, res.clone()); return res; }).catch(() => hit);
  return hit || net;
}

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin || PRIVATE.test(url.pathname)) return;
  if (url.pathname.startsWith('/data/') || e.request.mode === 'navigate') { e.respondWith(networkFirst(e.request)); return; }
  e.respondWith(staleWhileRevalidate(e.request));
});
