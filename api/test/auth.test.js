'use strict';
const test = require('node:test');
const assert = require('node:assert');
const watchlist = require('../watchlist/index.js');
const kev = require('../kev/index.js');

const principal = (roles, id = 'u1') => Buffer.from(JSON.stringify({
  identityProvider: 'aad', userId: id, userDetails: `${id}@ornek.edu.tr`, userRoles: ['anonymous', 'authenticated', ...roles],
})).toString('base64');

function ctx(cve) {
  const logs = [];
  const log = (m) => logs.push(['info', m]);
  log.warn = (m) => logs.push(['warn', m]);
  log.error = (m) => logs.push(['error', m]);
  return { log, logs, bindingData: cve ? { cve } : {} };
}
const req = (method, roles, body) => ({
  method, url: 'https://ornek.azurestaticapps.net/api/watchlist', body,
  headers: roles === null ? {} : { 'x-ms-client-principal': principal(roles) },
});

process.env.TABLE_ENDPOINT = 'https://st.table.core.windows.net';
process.env.TABLE_SAS = '?sv=x&sig=GIZLI';
const calls = [];
global.fetch = async (url, init = {}) => {
  calls.push({ url: String(url), method: init.method || 'GET' });
  if (String(url).includes('cisa.gov')) {
    return { ok: true, status: 200, json: async () => ({ catalogVersion: '1', vulnerabilities: [
      { cveID: 'CVE-2024-0001', vendorProject: 'A', product: 'B', vulnerabilityName: 'x', dateAdded: '2024-01-02', knownRansomwareCampaignUse: 'Known' },
      { cveID: 'kotu<script>', dateAdded: '2025-01-01' }] }) };
  }
  if ((init.method || 'GET') === 'GET') return { ok: true, status: 200, json: async () => ({ value: [{ RowKey: 'CVE-2024-0001', priority: 'P1', note: 'n' }] }) };
  return { ok: true, status: 204, json: async () => ({}) };
};

test('rolsüz (yetkisiz) hesap izleme listesini okuyamaz: 403 + DENY logu', async () => {
  const c = ctx(); await watchlist(c, req('GET', []));
  assert.strictEqual(c.res.status, 403);
  const deny = c.logs.find(([lvl, m]) => lvl === 'warn' && m.includes('"decision":"DENY"'));
  assert.ok(deny, 'DENY logu yazılmalı');
  assert.ok(!deny[1].includes('u1@ornek.edu.tr'), 'logda e-posta olmamalı');
});

test('oturumsuz istek 403', async () => {
  const c = ctx(); await watchlist(c, req('GET', null));
  assert.strictEqual(c.res.status, 403);
});

test('izleyici okuyabilir', async () => {
  const c = ctx(); await watchlist(c, req('GET', ['viewer']));
  assert.strictEqual(c.res.status, 200);
  assert.strictEqual(JSON.parse(c.res.body).items[0].cve, 'CVE-2024-0001');
});

test('izleyici düzenleyemez: POST 403, depoya yazma çağrısı yapılmaz', async () => {
  calls.length = 0;
  const c = ctx(); await watchlist(c, req('POST', ['viewer'], { cve: 'CVE-2024-0001', priority: 'P1' }));
  assert.strictEqual(c.res.status, 403);
  assert.strictEqual(calls.filter((x) => x.method === 'PUT').length, 0);
});

test('izleyici silemez: DELETE 403', async () => {
  const c = ctx('CVE-2024-0001'); await watchlist(c, req('DELETE', ['viewer']));
  assert.strictEqual(c.res.status, 403);
});

test('analist ekleyebilir ve silebilir', async () => {
  const c1 = ctx(); await watchlist(c1, req('POST', ['analyst'], { cve: 'cve-2024-0001', priority: 'p2', note: 'yama bekleniyor' }));
  assert.strictEqual(c1.res.status, 201);
  assert.strictEqual(JSON.parse(c1.res.body).item.cve, 'CVE-2024-0001');
  const c2 = ctx('CVE-2024-0001'); await watchlist(c2, req('DELETE', ['analyst']));
  assert.strictEqual(c2.res.status, 204);
});

test('analist bile geçersiz girdi gönderemez (OData anahtar enjeksiyonu engeli)', async () => {
  const c = ctx(); await watchlist(c, req('POST', ['analyst'], { cve: "CVE-2024-1') or 1 eq 1", priority: 'P1' }));
  assert.strictEqual(c.res.status, 400);
});

test('SAS anahtarı hiçbir log satırına yazılmaz', async () => {
  const c = ctx(); await watchlist(c, req('GET', ['analyst']));
  assert.ok(c.logs.every(([, m]) => !String(m).includes('GIZLI')));
});

test('KEV vekili: rolsüz 403, izleyici 200 ve geçersiz kayıtlar ayıklanır', async () => {
  kev._test.reset();
  const c0 = ctx(); await kev(c0, { ...req('GET', []), url: 'https://x/api/kev' });
  assert.strictEqual(c0.res.status, 403);
  const c1 = ctx(); await kev(c1, { ...req('GET', ['viewer']), url: 'https://x/api/kev' });
  const body = JSON.parse(c1.res.body);
  assert.strictEqual(c1.res.status, 200);
  assert.strictEqual(body.count, 1);
  assert.strictEqual(body.items[0].ransomware, true);
});

test('KEV önbelleği: ikinci istek kaynağa gitmez', async () => {
  calls.length = 0;
  const c = ctx(); await kev(c, { ...req('GET', ['viewer']), url: 'https://x/api/kev' });
  assert.strictEqual(calls.filter((x) => x.url.includes('cisa.gov')).length, 0);
});
