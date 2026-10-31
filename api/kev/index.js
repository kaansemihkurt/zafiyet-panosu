'use strict';
/**
 * CISA Known Exploited Vulnerabilities (KEV) kataloğu için vekil (proxy) fonksiyon.
 * - İstemci veri kaynağına doğrudan bağlanmaz.
 * - Yanıt 6 saat bellekte önbelleklenir: veri sağlayıcıya yük bindirilmez, yük testleri önbelleğe gider.
 * - Kaynak anahtar gerektirmez (herkese açık JSON).
 */
const { authorize, audit, json } = require('../shared/auth');

const SOURCE = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const TTL_MS = 6 * 60 * 60 * 1000;
let cache = { at: 0, payload: null };

function trim(raw) {
  const list = Array.isArray(raw.vulnerabilities) ? raw.vulnerabilities : [];
  const items = list
      .map((v) => ({
        cve: String(v.cveID || ''),
        vendor: String(v.vendorProject || ''),
        product: String(v.product || ''),
        name: String(v.vulnerabilityName || ''),
        added: String(v.dateAdded || ''),
        due: String(v.dueDate || ''),
        ransomware: String(v.knownRansomwareCampaignUse || '') === 'Known',
      }))
      .filter((v) => /^CVE-\d{4}-\d{4,7}$/.test(v.cve))
      .sort((a, b) => (a.added < b.added ? 1 : a.added > b.added ? -1 : 0));
  return { catalogVersion: raw.catalogVersion || null, dateReleased: raw.dateReleased || null, count: items.length, items };
}

async function load(now = Date.now()) {
  if (cache.payload && now - cache.at < TTL_MS) return { payload: cache.payload, cached: true };
  const res = await fetch(SOURCE, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(10000) });
  if (!res.ok) throw new Error(`KEV kaynağı ${res.status}`);
  const payload = trim(await res.json());
  cache = { at: now, payload };
  return { payload, cached: false };
}

module.exports = async function (context, req) {
  const auth = authorize(context, req, ['viewer', 'analyst']);
  if (!auth.ok) { context.res = auth.res; return; }
  try {
    const { payload, cached } = await load();
    audit(context, req, auth.principal, 'ALLOW', 200, { cached });
    context.res = json(200, payload, { 'Cache-Control': 'private, max-age=600' });
  } catch (err) {
    context.log.error(`KEV yüklenemedi: ${err.message}`);
    if (cache.payload) { context.res = json(200, { ...cache.payload, stale: true }); return; }
    context.res = json(502, { error: 'upstream', message: 'Zafiyet kataloğu şu an alınamıyor.' });
  }
};

module.exports._test = { trim, reset: () => { cache = { at: 0, payload: null }; } };
