'use strict';
/**
 * Azure Table Storage — izleme listesi deposu.
 * SDK yerine doğrudan REST (bağımlılık yok = tedarik zinciri riski yok).
 * Kimlik: yalnızca Table servisine, yalnızca nesne düzeyinde, yalnızca r/a/u/d yetkili
 * ve süresi sınırlı bir SAS. SAS, Bicep tarafından doğrudan SWA uygulama ayarına yazılır;
 * depoda, istemcide veya logda yer almaz.
 */
const PARTITION = 'wl';
const HEADERS = {
  Accept: 'application/json;odata=nometadata',
  'x-ms-version': '2019-02-02',
  DataServiceVersion: '3.0;NetFx',
};

function cfg() {
  const endpoint = process.env.TABLE_ENDPOINT;
  const table = process.env.TABLE_NAME || 'watchlist';
  const sas = (process.env.TABLE_SAS || '').replace(/^\?/, '');
  if (!endpoint || !sas) throw new Error('Tablo yapılandırması eksik (TABLE_ENDPOINT / TABLE_SAS).');
  return { base: `${endpoint.replace(/\/$/, '')}/${table}`, sas };
}

async function call(url, init) {
  const res = await fetch(url, { ...init, signal: AbortSignal.timeout(8000) });
  if (!res.ok && !(init.method === 'DELETE' && res.status === 404)) {
    throw new Error(`Tablo isteği başarısız: ${res.status}`); // SAS'ı içeren URL loglanmaz
  }
  return res;
}

async function listItems() {
  const { base, sas } = cfg();
  const filter = encodeURIComponent(`PartitionKey eq '${PARTITION}'`);
  const res = await call(`${base}()?${sas}&$filter=${filter}`, { method: 'GET', headers: HEADERS });
  const data = await res.json();
  return (data.value || []).map((e) => ({
    cve: e.RowKey, priority: e.priority, note: e.note || '', updatedAt: e.updatedAt, updatedBy: e.updatedBy,
  }));
}

/** cve önceden doğrulanmış olmalı (CVE-YYYY-NNNN), bu yüzden anahtar içine güvenle yazılabilir. */
async function upsertItem(item) {
  const { base, sas } = cfg();
  const url = `${base}(PartitionKey='${PARTITION}',RowKey='${item.cve}')?${sas}`;
  const body = { PartitionKey: PARTITION, RowKey: item.cve, priority: item.priority, note: item.note, updatedAt: item.updatedAt, updatedBy: item.updatedBy };
  await call(url, { method: 'PUT', headers: { ...HEADERS, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}

async function deleteItem(cve) {
  const { base, sas } = cfg();
  await call(`${base}(PartitionKey='${PARTITION}',RowKey='${cve}')?${sas}`, { method: 'DELETE', headers: { ...HEADERS, 'If-Match': '*' } });
}

module.exports = { listItems, upsertItem, deleteItem };
