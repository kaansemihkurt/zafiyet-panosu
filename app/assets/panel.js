'use strict';
/* Satır içi script yok (CSP: script-src 'self'). Sunucudan gelen tüm metinler textContent ile yazılır (XSS'e karşı). */
(() => {
  const $ = (id) => document.getElementById(id);
  let isAnalyst = false;
  let kevItems = [];
  const MAX_ROWS = 200;

  async function api(path, init = {}) {
    const res = await fetch(path, { credentials: 'same-origin', headers: { Accept: 'application/json', ...(init.headers || {}) }, ...init });
    let data = null;
    try { data = res.status === 204 ? null : await res.json(); } catch { data = null; }
    return { status: res.status, data };
  }

  function cell(tr, text, cls) {
    const td = document.createElement('td');
    td.textContent = text == null ? '' : String(text);
    if (cls) td.className = cls;
    tr.appendChild(td);
    return td;
  }

  function msg(text, kind = '') { const m = $('wlMsg'); m.textContent = text; m.className = `msg ${kind}`; }

  async function loadMe() {
    const { data } = await api('/api/me');
    const roles = (data && data.roles) || [];
    isAnalyst = roles.includes('analyst');
    $('user').textContent = (data && data.user) || '';
    $('role').textContent = isAnalyst ? 'analist' : roles.includes('viewer') ? 'izleyici' : 'rol yok';
    $('role').className = `badge ${isAnalyst ? 'analyst' : 'viewer'}`;
    $('wlForm').classList.toggle('hidden', !isAnalyst);
  }

  async function loadWatchlist() {
    const { status, data } = await api('/api/watchlist');
    const body = $('wlBody'); body.replaceChildren();
    if (status !== 200) { msg(status === 403 ? 'İzleme listesini görme yetkiniz yok (403).' : 'İzleme listesi alınamadı.', 'err'); return; }
    const items = data.items || [];
    $('wlCount').textContent = `${items.length} kayıt`;
    for (const it of items) {
      const tr = document.createElement('tr');
      cell(tr, it.priority, `pri ${String(it.priority).toLowerCase()}`);
      cell(tr, it.cve, 'mono');
      cell(tr, it.note);
      cell(tr, it.updatedAt ? it.updatedAt.slice(0, 16).replace('T', ' ') : '', 'muted');
      const td = cell(tr, '', 'act');
      if (isAnalyst) {
        const b = document.createElement('button'); b.className = 'btn small ghost'; b.textContent = 'Sil';
        b.addEventListener('click', () => removeItem(it.cve)); td.appendChild(b);
      }
      body.appendChild(tr);
    }
  }

  async function saveItem(cve, priority, note) {
    const { status, data } = await api('/api/watchlist', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ cve, priority, note }) });
    if (status === 201) { msg(`${data.item.cve} kaydedildi.`, 'ok'); await loadWatchlist(); }
    else if (status === 403) msg('Düzenleme yetkiniz yok (403): yalnızca analist rolü değiştirebilir.', 'err');
    else msg((data && data.message) || 'Kaydedilemedi.', 'err');
  }

  async function removeItem(cve) {
    const { status } = await api(`/api/watchlist/${encodeURIComponent(cve)}`, { method: 'DELETE' });
    if (status === 204) { msg(`${cve} silindi.`, 'ok'); await loadWatchlist(); }
    else msg(status === 403 ? 'Silme yetkiniz yok (403).' : 'Silinemedi.', 'err');
  }

  function renderKev() {
    const q = $('q').value.trim().toLowerCase();
    const rows = q ? kevItems.filter((v) => `${v.cve} ${v.vendor} ${v.product} ${v.name}`.toLowerCase().includes(q)) : kevItems;
    const body = $('kevBody'); body.replaceChildren();
    for (const v of rows.slice(0, MAX_ROWS)) {
      const tr = document.createElement('tr');
      cell(tr, v.cve, 'mono'); cell(tr, `${v.vendor} · ${v.product}`); cell(tr, v.name);
      cell(tr, v.added, 'muted'); cell(tr, v.due, 'muted'); cell(tr, v.ransomware ? 'Evet' : '', v.ransomware ? 'warn' : '');
      const td = cell(tr, '', 'act');
      if (isAnalyst) {
        const b = document.createElement('button'); b.className = 'btn small'; b.textContent = '+ İzle';
        b.addEventListener('click', () => saveItem(v.cve, v.ransomware ? 'P1' : 'P2', v.name.slice(0, 120))); td.appendChild(b);
      }
      body.appendChild(tr);
    }
    $('kevMore').textContent = rows.length > MAX_ROWS ? `${rows.length} sonuçtan ilk ${MAX_ROWS} gösteriliyor; aramayı daraltın.` : `${rows.length} sonuç`;
  }

  async function loadKev() {
    const { status, data } = await api('/api/kev');
    if (status !== 200) { $('kevMore').textContent = 'Katalog alınamadı.'; return; }
    kevItems = data.items || [];
    $('kevMeta').textContent = `· KEV ${data.catalogVersion || ''} · ${data.count} zafiyet`;
    renderKev();
  }

  document.addEventListener('DOMContentLoaded', async () => {
    $('q').addEventListener('input', renderKev);
    $('wlForm').addEventListener('submit', (e) => { e.preventDefault(); saveItem($('fCve').value, $('fPri').value, $('fNote').value); });
    await loadMe();
    await Promise.all([loadWatchlist(), loadKev()]);
  });
})();
