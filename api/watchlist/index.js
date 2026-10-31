'use strict';
/**
 * Kurum içi izleme listesi ve öncelikler — kartımızdaki korunacak varlık.
 *   GET    /api/watchlist          izleyici + analist
 *   POST   /api/watchlist          yalnızca analist  (ekle / güncelle)
 *   DELETE /api/watchlist/{cve}    yalnızca analist
 * Rota kuralı da yazma isteklerini analist dışına kapatır; burada ikinci kez kontrol edilir.
 */
const { authorize, audit, json, pseudonym } = require('../shared/auth');
const { normalizeCve, parseItem } = require('../shared/validate');
const store = require('../shared/table');

const ORDER = { P1: 1, P2: 2, P3: 3, P4: 4 };

module.exports = async function (context, req) {
  const method = String(req.method || 'GET').toUpperCase();
  const needed = method === 'GET' ? ['viewer', 'analyst'] : ['analyst'];
  const auth = authorize(context, req, needed);
  if (!auth.ok) { context.res = auth.res; return; }

  try {
    if (method === 'GET') {
      const items = (await store.listItems()).sort((a, b) => (ORDER[a.priority] || 9) - (ORDER[b.priority] || 9) || a.cve.localeCompare(b.cve));
      audit(context, req, auth.principal, 'ALLOW', 200, { items: items.length });
      context.res = json(200, { items });
      return;
    }
    if (method === 'POST') {
      const { item, error } = parseItem(req.body);
      if (error) { audit(context, req, auth.principal, 'REJECT', 400, { reason: error }); context.res = json(400, { error: 'validation', message: error }); return; }
      const record = { ...item, updatedAt: new Date().toISOString(), updatedBy: pseudonym(auth.principal) };
      await store.upsertItem(record);
      audit(context, req, auth.principal, 'ALLOW', 201, { cve: record.cve, priority: record.priority });
      context.res = json(201, { item: record });
      return;
    }
    if (method === 'DELETE') {
      const cve = normalizeCve(context.bindingData && context.bindingData.cve);
      if (!cve) { context.res = json(400, { error: 'validation', message: 'Geçersiz CVE.' }); return; }
      await store.deleteItem(cve);
      audit(context, req, auth.principal, 'ALLOW', 204, { cve });
      context.res = { status: 204, headers: { 'Cache-Control': 'no-store' }, body: '' };
      return;
    }
    context.res = json(405, { error: 'method_not_allowed' });
  } catch (err) {
    context.log.error(`İzleme listesi hatası: ${err.message}`);
    context.res = json(502, { error: 'storage', message: 'İzleme listesine şu an ulaşılamıyor.' });
  }
};
