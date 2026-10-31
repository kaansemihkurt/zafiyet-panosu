'use strict';
/*
 * Zafiyet İstihbarat Panosu — istemci.
 * - Veri: /data/{meta,cves,trend}.json (GitHub Actions günde 1 kez üretir; API anahtarı istemcide yok).
 * - Dayanıklılık: veri alınamazsa tarayıcıda saklanan son başarılı veriyle açılır ve bunu söyler.
 * - Satır içi betik/stil yok (CSP: script-src 'self'); sunucudan gelen metin yalnızca textContent ile yazılır.
 * - Demo/test: ?veri=/bozuk/ ile veri adresi bozulabilir (hata durumunu göstermek için).
 */
(() => {
  const $ = (id) => document.getElementById(id);
  const params = new URLSearchParams(location.search);
  const BASE = (params.get('veri') || '/data/').replace(/[^a-zA-Z0-9/_.-]/g, '');
  const CACHE_KEY = 'zp-cache-v1', WATCH_KEY = 'zp-watch', LANG_KEY = 'zp-lang';
  const PAGE = 50;
  const SEVS = ['critical', 'high', 'medium', 'low', 'none'];
  const SUGGEST = ['microsoft', 'cisco', 'fortinet', 'vmware', 'apache', 'wordpress', 'moodle'];

  // ---------- dil ----------
  const T = {
    tr: {
      skip: 'Tabloya geç', title: 'Zafiyet İstihbarat Panosu', subtitle: 'Sabah vardiyası önceliklendirme · CVE + KEV', lastUpdate: 'Son güncelleme', source: 'Kaynak',
      shortcuts: 'Kısayollar', team: '🔒 Ekip panosu', filters: 'Filtreler', search: 'Ara (CVE, üretici, ürün, açıklama)', scope: 'Kapsam',
      scopeRecent: 'Son 10 günde yayımlananlar', scopeKev: 'KEV kataloğundakiler', scopeAll: 'Hepsi', severity: 'CVSS önem derecesi',
      critical: 'Kritik', high: 'Yüksek', medium: 'Orta', low: 'Düşük', none: 'Puan yok', onlyKev: "Yalnızca KEV'de olanlar", onlyWatch: 'Yalnızca izleme listem',
      reset: 'Filtreleri sıfırla', watchlist: 'İzleme listem', watchHint: 'Kurumunuzdaki ürün/üretici anahtar kelimeleri. Yalnızca bu tarayıcıda saklanır, sunucuya gönderilmez.',
      watchAdd: 'Anahtar kelime ekle', add: 'Ekle', suggest: 'Öneri:', kVisible: 'Filtrelenen CVE', kCritical: 'Kritik (CVSS ≥ 9)', kKev: "KEV'de (aktif istismar)",
      kWatch: 'İzleme listesi eşleşmesi', cTrend: 'Haftalık yeni CVE ve KEV eklemeleri', cCvss: 'CVSS dağılımı (filtrelenmiş)', asTable: 'Veriyi tablo olarak gör',
      hideTable: 'Tabloyu gizle', table: 'Ayrıntı tablosu', tableCap: 'Filtrelenmiş CVE listesi; sütun başlıklarıyla sıralanabilir', thPrio: 'Öncelik', thPub: 'Yayın',
      thVp: 'Üretici / ürün', thDesc: 'Açıklama (NVD, İngilizce)', emptyT: 'Bu filtrelerle sonuç yok.',
      emptyD: 'Kapsamı "Hepsi" yapmayı, önem derecelerini açmayı veya aramayı kısaltmayı deneyin.', prev: '← Önceki', next: 'Sonraki →',
      priority: 'Bugünün önceliği', priorityD: 'Filtrelenen kayıtlar arasında öncelik puanı en yüksek 10 CVE.', formula: 'Öncelik puanı nasıl hesaplanır?',
      fKev: 'KEV kataloğunda (aktif istismar ediliyor)', fRw: 'fidye yazılımı kampanyasında kullanılıyor', fWatch: 'izleme listenizle eşleşiyor',
      fNote: 'Puan bir karar destek ölçüsüdür; nihai öncelik ekibin değerlendirmesiyle belirlenir.', errT: 'Veri yüklenemedi.',
      errD: 'Veri sunucusuna ulaşılamadı ve bu tarayıcıda kayıtlı önceki veri yok. Bağlantınızı kontrol edip yeniden deneyin.', retry: 'Yeniden dene',
      disclaimer: 'Kurgusal bir müşteri (üniversite bilgi işlem güvenlik ekibi) için hazırlanmış ders projesidir; resmî bir kurum aracı değildir. Bilgilendirme amaçlıdır. Veriler: NIST NVD ve CISA KEV (ABD kamu malı).',
      kSearch: 'Aramaya odaklan', kK: 'Yalnızca KEV aç/kapa', kW: 'Yalnızca izleme listem aç/kapa', kSev: 'Kritik / Yüksek / Orta / Düşük aç/kapa', kR: 'Filtreleri sıfırla',
      kPage: 'Önceki / sonraki tablo sayfası', kT: 'Tabloya git', kL: 'Dili değiştir (TR/EN)', kEsc: 'Pencereyi kapat / aramadan çık', close: 'Kapat',
      // dinamik
      ofTotal: (n) => `toplam ${n} kayıt içinden`, pct: (p) => `filtrelenenlerin %${p}'i`, rw: (n) => `${n} tanesi fidye kampanyalarında`,
      kevDelta: (d) => (d === null ? 'snapshot geçmişi birikiyor' : `KEV kataloğu dünden beri ${d >= 0 ? '+' : ''}${d}`),
      watchNone: 'İzleme listesi boş: soldan ekleyin', watchN: (n) => `${n} anahtar kelime`,
      rows: (a, b, n) => `${a}–${b} / ${n} kayıt · öncelik puanına göre`, page: (p, n) => `Sayfa ${p} / ${n}`,
      trendSum: (avg, maxW, maxN, kev, last) => `Son 12 haftada her hafta ortalama ${avg} yeni CVE yayımlandı; en yoğun hafta ${maxW} (${maxN} CVE). Aynı dönemde KEV'e ${kev} zafiyet eklendi${last}.`,
      trendLast: (n) => `; içinde bulunduğumuz hafta şimdiye kadar ${n} CVE`,
      cvssSum: (n, c, h, top) => `Filtrelenen ${n} CVE'nin %${c}'i kritik, %${h}'i yüksek önemde; en kalabalık grup "${top}".`,
      noData: 'Gösterilecek veri yok.', week: 'Hafta', newCve: 'Yeni CVE', kevAdd: 'KEV eklemesi', partial: '(sürüyor)', group: 'Önem', count: 'CVE sayısı', share: 'Pay',
      kevTag: 'KEV', rwTag: 'fidye', watchTag: 'izleme', why: { kev: 'KEV', rw: 'fidye', watch: 'izleme listesi' }, unknownVp: '—',
      staleClient: (t) => `Veri sunucusuna ulaşılamadı. Bu tarayıcıda kayıtlı son başarılı veriyle açıldı (veri tarihi: ${t}).`,
      offline: (t) => `Çevrimdışısınız. Son kaydedilen veri gösteriliyor (veri tarihi: ${t}).`,
      staleSource: (s, t, e) => `${s} kaynağına son çekimde ulaşılamadı (${e}). ${s} verileri ${t} tarihli son başarılı çekimden gösteriliyor.`,
      oldData: (h) => `Veri ${h} saattir güncellenmedi; otomatik çekim gecikmiş olabilir.`, kevCount: (n) => `KEV kataloğunda ${n} zafiyet`,
      noScore: 'puan yok', remove: (w) => `${w} anahtar kelimesini kaldır`, sortBy: 'Sırala',
    },
    en: {
      skip: 'Skip to table', title: 'Vulnerability Intelligence Dashboard', subtitle: 'Morning-shift prioritisation · CVE + KEV', lastUpdate: 'Last update', source: 'Source',
      shortcuts: 'Shortcuts', team: '🔒 Team panel', filters: 'Filters', search: 'Search (CVE, vendor, product, description)', scope: 'Scope',
      scopeRecent: 'Published in the last 10 days', scopeKev: 'In the KEV catalogue', scopeAll: 'All', severity: 'CVSS severity',
      critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'No score', onlyKev: 'Only KEV-listed', onlyWatch: 'Only my watchlist',
      reset: 'Reset filters', watchlist: 'My watchlist', watchHint: "Product/vendor keywords from your organisation. Stored only in this browser, never sent to a server.",
      watchAdd: 'Add keyword', add: 'Add', suggest: 'Suggestions:', kVisible: 'Filtered CVEs', kCritical: 'Critical (CVSS ≥ 9)', kKev: 'In KEV (actively exploited)',
      kWatch: 'Watchlist matches', cTrend: 'Weekly new CVEs and KEV additions', cCvss: 'CVSS distribution (filtered)', asTable: 'Show data as table',
      hideTable: 'Hide table', table: 'Detail table', tableCap: 'Filtered CVE list; sortable by column headers', thPrio: 'Priority', thPub: 'Published',
      thVp: 'Vendor / product', thDesc: 'Description (NVD)', emptyT: 'No results for these filters.',
      emptyD: 'Try setting the scope to "All", enabling more severities or shortening the search.', prev: '← Previous', next: 'Next →',
      priority: "Today's priority", priorityD: 'The 10 filtered CVEs with the highest priority score.', formula: 'How is the priority score calculated?',
      fKev: 'in the KEV catalogue (actively exploited)', fRw: 'used in ransomware campaigns', fWatch: 'matches your watchlist',
      fNote: 'The score supports decisions; the final priority is set by the team.', errT: 'Data could not be loaded.',
      errD: 'The data server could not be reached and no earlier data is stored in this browser. Check your connection and try again.', retry: 'Try again',
      disclaimer: 'Course project built for a fictional client (a university IT security team); not an official tool of any organisation. For information only. Data: NIST NVD and CISA KEV (US public domain).',
      kSearch: 'Focus search', kK: 'Toggle KEV only', kW: 'Toggle watchlist only', kSev: 'Toggle Critical / High / Medium / Low', kR: 'Reset filters',
      kPage: 'Previous / next table page', kT: 'Go to table', kL: 'Switch language (TR/EN)', kEsc: 'Close dialog / leave search', close: 'Close',
      ofTotal: (n) => `out of ${n} records`, pct: (p) => `${p}% of filtered`, rw: (n) => `${n} used by ransomware`,
      kevDelta: (d) => (d === null ? 'snapshot history is building up' : `KEV catalogue ${d >= 0 ? '+' : ''}${d} since yesterday`),
      watchNone: 'Watchlist empty: add keywords on the left', watchN: (n) => `${n} keywords`,
      rows: (a, b, n) => `${a}–${b} of ${n} records · by priority score`, page: (p, n) => `Page ${p} / ${n}`,
      trendSum: (avg, maxW, maxN, kev, last) => `Over the last 12 weeks an average of ${avg} new CVEs were published per week; the busiest week was ${maxW} (${maxN} CVEs). ${kev} vulnerabilities were added to KEV in the same period${last}.`,
      trendLast: (n) => `; the current week has ${n} CVEs so far`,
      cvssSum: (n, c, h, top) => `Of the ${n} filtered CVEs, ${c}% are critical and ${h}% high; the largest group is "${top}".`,
      noData: 'No data to show.', week: 'Week', newCve: 'New CVEs', kevAdd: 'KEV additions', partial: '(in progress)', group: 'Severity', count: 'CVE count', share: 'Share',
      kevTag: 'KEV', rwTag: 'ransomware', watchTag: 'watch', why: { kev: 'KEV', rw: 'ransomware', watch: 'watchlist' }, unknownVp: '—',
      staleClient: (t) => `The data server could not be reached. Opened with the last successful data stored in this browser (data from ${t}).`,
      offline: (t) => `You are offline. Showing the last saved data (data from ${t}).`,
      staleSource: (s, t, e) => `${s} could not be reached in the last fetch (${e}). ${s} data shown from the last successful fetch on ${t}.`,
      oldData: (h) => `Data has not been updated for ${h} hours; the scheduled fetch may be delayed.`, kevCount: (n) => `${n} vulnerabilities in KEV`,
      noScore: 'no score', remove: (w) => `Remove keyword ${w}`, sortBy: 'Sort',
    },
  };
  let LANG = (() => { try { return params.get('lang') || localStorage.getItem(LANG_KEY) || 'tr'; } catch { return 'tr'; } })();
  if (!T[LANG]) LANG = 'tr';
  const t = (k, ...a) => { const v = T[LANG][k]; return typeof v === 'function' ? v(...a) : v; };

  // ---------- durum ----------
  const S = { meta: null, items: [], trend: null, filtered: [], sort: { key: 'prio', dir: -1 }, page: 0, watch: [], source: 'network', charts: {} };
  try { S.watch = JSON.parse(localStorage.getItem(WATCH_KEY) || '[]').filter((x) => typeof x === 'string').slice(0, 50); } catch { S.watch = []; }

  const fmtDate = (iso) => {
    if (!iso) return '—';
    const d = new Date(iso);
    return isNaN(d) ? iso : d.toLocaleString(LANG === 'tr' ? 'tr-TR' : 'en-GB', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  };
  const fmtDay = (s) => { const d = new Date(`${s}T00:00:00Z`); return isNaN(d) ? s : d.toLocaleDateString(LANG === 'tr' ? 'tr-TR' : 'en-GB', { day: '2-digit', month: 'short', timeZone: 'UTC' }); };
  const nf = (n) => Number(n || 0).toLocaleString(LANG === 'tr' ? 'tr-TR' : 'en-GB');
  const el = (tag, attrs = {}, ...kids) => {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) { if (v == null) continue; if (k === 'class') e.className = v; else if (k === 'text') e.textContent = v; else e.setAttribute(k, v); }
    for (const c of kids) if (c != null) e.append(c);
    return e;
  };

  // ---------- veri ----------
  async function getJSON(name) {
    const res = await fetch(`${BASE}${name}`, { cache: 'no-cache' });
    if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
    return { data: await res.json(), offline: res.headers.get('x-zp-offline') === '1' };
  }

  async function load() {
    $('fatal').hidden = true;
    try {
      const [m, c, tr] = await Promise.all([getJSON('meta.json'), getJSON('cves.json'), getJSON('trend.json')]);
      if (!Array.isArray(c.data.items)) throw new Error('cves.json biçimi geçersiz');
      S.meta = { ...m.data, windowDays: c.data.windowDays }; S.items = c.data.items; S.trend = tr.data;
      S.source = (m.offline || c.offline) ? 'sw-cache' : 'network';
      if (S.source === 'network') {
        try { localStorage.setItem(CACHE_KEY, JSON.stringify({ meta: S.meta, cves: c.data, trend: S.trend })); } catch { /* kota dolu olabilir */ }
      }
    } catch (err) {
      let cached = null;
      try { cached = JSON.parse(localStorage.getItem(CACHE_KEY) || 'null'); } catch { cached = null; }
      if (!cached) { showFatal(); return; }
      S.meta = { ...cached.meta, windowDays: cached.cves.windowDays }; S.items = cached.cves.items; S.trend = cached.trend; S.source = 'local-cache';
      console.warn('Veri alınamadı, yerel önbellek kullanılıyor:', err.message);
    }
    prepare(); render(); banner(); loadCharts();
  }

  function showFatal() {
    document.querySelector('.layout').hidden = true;
    $('fatal').hidden = false;
    $('updatedAt').textContent = '—';
  }

  // ---------- puanlama ----------
  function prepare() {
    const kw = S.watch.map((w) => w.toLowerCase());
    for (const it of S.items) {
      it._hay = it._hay || `${it.id} ${(it.vp || []).join(' ')} ${it.desc || ''}`.toLowerCase();
      it._watch = kw.filter((w) => it._hay.includes(w));
      const s = typeof it.score === 'number' ? it.score : 0;
      it._prio = Math.round(50 * (s / 10) + (it.kev ? 30 : 0) + (it.kev && it.kev.rw ? 10 : 0) + (it._watch.length ? 10 : 0));
    }
  }

  function readFilters() {
    return {
      q: $('q').value.trim().toLowerCase(),
      scope: $('scope').value,
      sevs: new Set([...document.querySelectorAll('input[name=sev]:checked')].map((i) => i.value)),
      onlyKev: $('onlyKev').checked,
      onlyWatch: $('onlyWatch').checked,
    };
  }

  function applyFilters() {
    const f = readFilters();
    const cut = recentCut();
    S.filtered = S.items.filter((it) => {
      if (f.scope === 'recent' && it.pub < cut) return false;
      if (f.scope === 'kev' && !it.kev) return false;
      if (!f.sevs.has(it.sev || 'none')) return false;
      if (f.onlyKev && !it.kev) return false;
      if (f.onlyWatch && !it._watch.length) return false;
      if (f.q && !it._hay.includes(f.q)) return false;
      return true;
    });
    const { key, dir } = S.sort;
    const val = { prio: (x) => x._prio, id: (x) => x.id, score: (x) => (typeof x.score === 'number' ? x.score : -1), pub: (x) => x.pub, kev: (x) => (x.kev ? x.kev.added : '') };
    S.filtered.sort((a, b) => { const A = val[key](a), B = val[key](b); return (A < B ? -1 : A > B ? 1 : 0) * dir || (b._prio - a._prio) || (a.id < b.id ? 1 : -1); });
  }

  function recentCut() {
    const days = (S.meta && S.meta.windowDays) || 10;
    const base = S.meta && S.meta.generatedAt ? new Date(S.meta.generatedAt) : new Date();
    return new Date(base.getTime() - days * 864e5).toISOString().slice(0, 10);
  }

  // ---------- çizim ----------
  function render() {
    applyFilters();
    $('updatedAt').textContent = fmtDate(S.meta && S.meta.generatedAt);
    renderKpis(); renderTable(); renderTop(); renderWatch(); renderCharts();
  }

  function renderKpis() {
    const F = S.filtered, n = F.length || 1;
    const crit = F.filter((x) => x.sev === 'critical').length;
    const kev = F.filter((x) => x.kev).length, rw = F.filter((x) => x.kev && x.kev.rw).length;
    const watch = F.filter((x) => x._watch.length).length;
    const hist = (S.trend && S.trend.history) || [];
    const delta = hist.length > 1 ? hist[hist.length - 1].kev - hist[hist.length - 2].kev : null;
    $('kVisible').textContent = nf(F.length); $('kVisibleD').textContent = t('ofTotal', nf(S.items.length));
    $('kCritical').textContent = nf(crit); $('kCriticalD').textContent = t('pct', Math.round((100 * crit) / n));
    $('kKev').textContent = nf(kev); $('kKevD').textContent = `${t('rw', nf(rw))} · ${t('kevDelta', delta)}`;
    $('kWatch').textContent = S.watch.length ? nf(watch) : '—'; $('kWatchD').textContent = S.watch.length ? t('watchN', S.watch.length) : t('watchNone');
    document.querySelectorAll('.kpi.sk').forEach((k) => k.classList.remove('sk'));
  }

  function sevCell(it) {
    const icon = { critical: '▲▲', high: '▲', medium: '■', low: '▼', none: '○' }[it.sev || 'none'];
    const txt = typeof it.score === 'number' ? `${it.score.toFixed(1)} ${t(it.sev)}` : t('noScore');
    return el('span', { class: `sv ${it.sev || 'none'}`, text: `${icon} ${txt}` });
  }

  function renderTable() {
    const F = S.filtered, pages = Math.max(1, Math.ceil(F.length / PAGE));
    S.page = Math.min(S.page, pages - 1);
    const slice = F.slice(S.page * PAGE, S.page * PAGE + PAGE);
    const body = $('rows'); body.replaceChildren();
    const L = { prio: t('thPrio'), score: 'CVSS', pub: t('thPub'), kev: 'KEV', vp: t('thVp'), desc: t('thDesc') };
    for (const it of slice) {
      const tags = el('span', {});
      if (it.kev) tags.append(el('span', { class: 'tag kev', text: `✔ ${t('kevTag')}`, title: `${it.kev.added} → ${it.kev.due}` }), ' ');
      if (it.kev && it.kev.rw) tags.append(el('span', { class: 'tag rw', text: `🔥 ${t('rwTag')}` }), ' ');
      if (it._watch.length) tags.append(el('span', { class: 'tag watch', text: `★ ${it._watch.join(', ')}` }));
      body.append(el('tr', {},
        el('td', { class: 'num prio', 'data-l': L.prio, text: String(it._prio) }),
        el('td', { class: 'mono' }, el('a', { href: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(it.id)}`, rel: 'noopener', target: '_blank', text: it.id })),
        el('td', { 'data-l': L.score }, sevCell(it)),
        el('td', { class: 'mono', 'data-l': L.pub, text: it.pub }),
        el('td', { 'data-l': L.kev }, tags),
        el('td', { 'data-l': L.vp, text: (it.vp && it.vp.length ? it.vp.slice(0, 2).join(', ') : t('unknownVp')) }),
        el('td', { class: 'desc', 'data-l': L.desc, text: it.desc || '' })));
    }
    const empty = F.length === 0;
    $('empty').hidden = !empty;
    document.querySelector('.main-tbl').hidden = empty;
    document.querySelector('.pager').hidden = empty;
    $('tInfo').textContent = empty ? '' : t('rows', nf(S.page * PAGE + 1), nf(S.page * PAGE + slice.length), nf(F.length));
    $('page').textContent = t('page', S.page + 1, pages);
    $('prev').disabled = S.page === 0; $('next').disabled = S.page >= pages - 1;
    document.querySelectorAll('#grid th[aria-sort]').forEach((th) => {
      const k = th.querySelector('button').dataset.sort;
      th.setAttribute('aria-sort', k === S.sort.key ? (S.sort.dir > 0 ? 'ascending' : 'descending') : 'none');
    });
  }

  function renderTop() {
    const top = [...S.filtered].sort((a, b) => b._prio - a._prio || (a.pub < b.pub ? 1 : -1)).slice(0, 10);
    const ol = $('top'); ol.replaceChildren();
    for (const it of top) {
      const why = [];
      if (typeof it.score === 'number') why.push(`CVSS ${it.score.toFixed(1)}`);
      if (it.kev) why.push(t('why').kev);
      if (it.kev && it.kev.rw) why.push(t('why').rw);
      if (it._watch.length) why.push(`${t('why').watch}: ${it._watch.join(', ')}`);
      ol.append(el('li', {},
        el('div', {}, el('a', { class: 'mono', href: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(it.id)}`, rel: 'noopener', target: '_blank', text: it.id }),
          el('p', { class: 'why', text: `${why.join(' · ')} — ${(it.vp && it.vp[0]) || ''}` })),
        el('span', { class: 'score', title: t('thPrio'), text: String(it._prio) })));
    }
    if (!top.length) ol.append(el('li', { class: 'hint', text: t('noData') }));
  }

  function renderWatch() {
    const ul = $('wList'); ul.replaceChildren();
    for (const w of S.watch) {
      const b = el('button', { type: 'button', 'aria-label': t('remove', w), text: '×' });
      b.addEventListener('click', () => { S.watch = S.watch.filter((x) => x !== w); saveWatch(); });
      ul.append(el('li', {}, w, b));
    }
    const sg = $('wSuggest'); sg.replaceChildren(el('span', { text: `${t('suggest')} ` }));
    for (const w of SUGGEST.filter((x) => !S.watch.includes(x)).slice(0, 5)) {
      const b = el('button', { type: 'button', class: 'sugg', text: `+ ${w}` });
      b.addEventListener('click', () => addWatch(w)); sg.append(b);
    }
  }

  function addWatch(raw) {
    const w = String(raw || '').trim().toLowerCase().replace(/\s+/g, ' ').slice(0, 40);
    if (w.length < 2 || S.watch.includes(w)) return;
    S.watch.push(w); saveWatch();
  }
  function saveWatch() { try { localStorage.setItem(WATCH_KEY, JSON.stringify(S.watch)); } catch { /* yok say */ } prepare(); render(); }

  // ---------- grafikler (ECharts, yerel dosyadan, ilk boyamadan sonra) ----------
  function loadCharts() {
    if (window.echarts) { renderCharts(); return; }
    const s = document.createElement('script');
    s.src = '/assets/vendor/echarts.simple.min.js';
    s.onload = () => renderCharts();
    s.onerror = () => { ['chTrend', 'chCvss'].forEach((id) => { $(id).classList.remove('sk'); $(id).hidden = true; }); ['tTrend', 'tCvss'].forEach((id) => { $(id).hidden = false; }); };
    document.head.append(s);
  }

  const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  function baseOpt() {
    return {
      backgroundColor: 'transparent', textStyle: { color: css('--ink'), fontFamily: css('--sans') },
      aria: { enabled: true, decal: { show: true } }, // desen: renk tek başına anlam taşımaz
      grid: { left: 44, right: 44, top: 34, bottom: 30 }, tooltip: { trigger: 'axis' },
      legend: { textStyle: { color: css('--mut') }, top: 0 }, animationDuration: 300,
    };
  }

  function renderCharts() {
    const tr = (S.trend && S.trend.weeks) || [];
    const kevW = new Map(((S.trend && S.trend.kevWeekly) || []).map((w) => [w.start, w.count]));
    const labels = tr.map((w) => `${fmtDay(w.start)}${w.partial ? ` ${t('partial')}` : ''}`);
    // özet cümlesi (grafikten bağımsız; grafik yüklenmese de görünür)
    if (tr.length) {
      const full = tr.filter((w) => !w.partial);
      const avg = Math.round(full.reduce((s, w) => s + w.total, 0) / Math.max(1, full.length));
      const mx = full.reduce((a, b) => (b.total > a.total ? b : a), full[0] || tr[0]);
      const kevSum = tr.reduce((s, w) => s + (kevW.get(w.start) || 0), 0);
      const last = tr[tr.length - 1];
      $('sTrend').textContent = t('trendSum', nf(avg), fmtDay(mx.start), nf(mx.total), nf(kevSum), last.partial ? t('trendLast', nf(last.total)) : '');
    } else $('sTrend').textContent = t('noData');
    tableOf('tTrend', [t('week'), t('newCve'), t('kevAdd')], tr.map((w, i) => [labels[i], nf(w.total), nf(kevW.get(w.start) || 0)]));

    const groups = SEVS.map((s) => ({ s, n: S.filtered.filter((x) => (x.sev || 'none') === s).length }));
    const total = S.filtered.length;
    if (total) {
      const top = groups.reduce((a, b) => (b.n > a.n ? b : a));
      $('sCvss').textContent = t('cvssSum', nf(total), Math.round((100 * groups[0].n) / total), Math.round((100 * groups[1].n) / total), t(top.s));
    } else $('sCvss').textContent = t('noData');
    tableOf('tCvss', [t('group'), t('count'), t('share')], groups.map((g) => [t(g.s), nf(g.n), `%${total ? Math.round((100 * g.n) / total) : 0}`]));

    if (!window.echarts) return;
    ['chTrend', 'chCvss'].forEach((id) => $(id).classList.remove('sk'));
    const c1 = S.charts.trend || (S.charts.trend = echarts.init($('chTrend'), null, { renderer: 'canvas' }));
    c1.setOption({
      ...baseOpt(),
      xAxis: { type: 'category', data: labels, axisLabel: { color: css('--mut'), fontSize: 11 }, axisLine: { lineStyle: { color: css('--line2') } } },
      yAxis: [
        { type: 'value', name: t('newCve'), nameTextStyle: { color: css('--mut') }, axisLabel: { color: css('--mut') }, splitLine: { lineStyle: { color: css('--line') } } },
        { type: 'value', name: t('kevAdd'), nameTextStyle: { color: css('--mut') }, axisLabel: { color: css('--mut') }, splitLine: { show: false } },
      ],
      series: [
        { name: t('newCve'), type: 'bar', data: tr.map((w) => ({ value: w.total, itemStyle: { opacity: w.partial ? 0.55 : 1 } })), itemStyle: { color: css('--accent'), borderRadius: [4, 4, 0, 0] } },
        { name: t('kevAdd'), type: 'line', yAxisIndex: 1, data: tr.map((w) => kevW.get(w.start) || 0), symbol: 'triangle', symbolSize: 8, lineStyle: { width: 2, color: css('--kev') }, itemStyle: { color: css('--kev') } },
      ],
    }, true);
    const sevColor = { critical: css('--crit'), high: css('--high'), medium: css('--med'), low: css('--low'), none: css('--none') };
    const c2 = S.charts.cvss || (S.charts.cvss = echarts.init($('chCvss'), null, { renderer: 'canvas' }));
    c2.setOption({
      ...baseOpt(), legend: { show: false }, grid: { left: 44, right: 16, top: 20, bottom: 30 },
      xAxis: { type: 'category', data: groups.map((g) => t(g.s)), axisLabel: { color: css('--mut'), interval: 0, fontSize: 11 }, axisLine: { lineStyle: { color: css('--line2') } } },
      yAxis: { type: 'value', axisLabel: { color: css('--mut') }, splitLine: { lineStyle: { color: css('--line') } } },
      series: [{ type: 'bar', name: t('count'), data: groups.map((g) => ({ value: g.n, itemStyle: { color: sevColor[g.s], borderRadius: [4, 4, 0, 0] } })), label: { show: true, position: 'top', color: css('--ink') } }],
    }, true);
  }

  function tableOf(id, head, rows) {
    const tbl = el('table', {}, el('thead', {}, el('tr', {}, ...head.map((h) => el('th', { scope: 'col', text: h })))),
      el('tbody', {}, ...rows.map((r) => el('tr', {}, ...r.map((c, i) => el('td', { class: i ? 'num' : '', text: c }))))));
    $(id).replaceChildren(tbl);
  }

  // ---------- uyarı bandı ----------
  function banner() {
    const b = $('banner'), msgs = []; let err = false;
    const m = S.meta || {}, src = m.sources || {}, ls = m.lastSuccess || {};
    if (S.source === 'local-cache') { msgs.push(t('staleClient', fmtDate(m.generatedAt))); err = true; }
    if (S.source === 'sw-cache') { msgs.push(t('offline', fmtDate(m.generatedAt))); err = true; }
    if (src.nvd && src.nvd.ok === false) msgs.push(t('staleSource', 'NVD', fmtDate(ls.nvd), src.nvd.error || 'hata'));
    if (src.kev && src.kev.ok === false) msgs.push(t('staleSource', 'CISA KEV', fmtDate(ls.kev), src.kev.error || 'hata'));
    const age = m.generatedAt ? (Date.now() - new Date(m.generatedAt)) / 36e5 : 0;
    if (age > 36) msgs.push(t('oldData', Math.round(age)));
    b.replaceChildren();
    if (!msgs.length) { b.hidden = true; return; }
    b.className = `banner${err ? ' err' : ''}`;
    b.append(`⚠ ${msgs.join(' ')}`);
    if (S.source !== 'network') { const r = el('button', { type: 'button', class: 'btn small', text: t('retry') }); r.addEventListener('click', () => location.reload()); b.append(r); }
    b.hidden = false;
  }

  // ---------- dil uygula ----------
  function applyLang() {
    document.documentElement.lang = LANG;
    document.querySelectorAll('[data-i18n]').forEach((e) => { const v = T[LANG][e.dataset.i18n]; if (typeof v === 'string') e.textContent = v; });
    document.querySelectorAll('[data-i18n-title]').forEach((e) => { e.title = T[LANG][e.dataset.i18nTitle]; });
    document.querySelectorAll('[data-lang]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.lang === LANG)));
    document.querySelectorAll('[data-table]').forEach((b) => { b.textContent = $(b.dataset.table).hidden ? t('asTable') : t('hideTable'); });
    document.title = `${t('title')} · CVE/KEV`;
    if (S.meta) { render(); banner(); }
  }
  function setLang(l) { LANG = l; try { localStorage.setItem(LANG_KEY, l); } catch { /* */ } applyLang(); }

  // ---------- olaylar ----------
  let deb;
  const refilter = () => { S.page = 0; clearTimeout(deb); deb = setTimeout(render, 120); };
  function resetFilters() {
    $('q').value = ''; $('scope').value = 'recent'; $('onlyKev').checked = false; $('onlyWatch').checked = false;
    document.querySelectorAll('input[name=sev]').forEach((i) => { i.checked = true; });
    S.sort = { key: 'prio', dir: -1 }; refilter();
  }

  function bind() {
    $('q').addEventListener('input', refilter);
    ['scope', 'onlyKev', 'onlyWatch'].forEach((id) => $(id).addEventListener('change', refilter));
    document.querySelectorAll('input[name=sev]').forEach((i) => i.addEventListener('change', refilter));
    $('reset').addEventListener('click', resetFilters); $('emptyReset').addEventListener('click', resetFilters);
    $('retry').addEventListener('click', () => location.reload());
    $('prev').addEventListener('click', () => { S.page = Math.max(0, S.page - 1); renderTable(); });
    $('next').addEventListener('click', () => { S.page += 1; renderTable(); });
    document.querySelectorAll('#grid th button').forEach((b) => b.addEventListener('click', () => {
      const k = b.dataset.sort;
      S.sort = S.sort.key === k ? { key: k, dir: -S.sort.dir } : { key: k, dir: k === 'id' ? 1 : -1 };
      S.page = 0; render();
    }));
    $('wForm').addEventListener('submit', (e) => { e.preventDefault(); addWatch($('wIn').value); $('wIn').value = ''; });
    document.querySelectorAll('[data-lang]').forEach((b) => b.addEventListener('click', () => setLang(b.dataset.lang)));
    document.querySelectorAll('[data-table]').forEach((b) => b.addEventListener('click', () => {
      const box = $(b.dataset.table); box.hidden = !box.hidden;
      b.setAttribute('aria-expanded', String(!box.hidden)); b.textContent = box.hidden ? t('asTable') : t('hideTable');
    }));
    const help = $('help');
    $('helpBtn').addEventListener('click', () => help.showModal());
    window.addEventListener('resize', () => Object.values(S.charts).forEach((c) => c.resize()));

    document.addEventListener('keydown', (e) => {
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      const typing = /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName) && document.activeElement.type !== 'checkbox';
      if (e.key === 'Escape' && typing) { document.activeElement.blur(); return; }
      if (typing || help.open) return;
      const k = e.key.toLowerCase();
      const toggle = (id) => { $(id).checked = !$(id).checked; refilter(); };
      if (e.key === '/') { e.preventDefault(); $('q').focus(); }
      else if (e.key === '?') { e.preventDefault(); help.showModal(); }
      else if (k === 'k') toggle('onlyKev');
      else if (k === 'w') toggle('onlyWatch');
      else if (k === 'r') resetFilters();
      else if (k === 'l') setLang(LANG === 'tr' ? 'en' : 'tr');
      else if (k === 't') { $('tablo').focus(); $('tablo').scrollIntoView({ block: 'start' }); }
      else if (e.key === '[') $('prev').click();
      else if (e.key === ']') $('next').click();
      else if (/^[1-4]$/.test(e.key)) { const box = document.querySelectorAll('input[name=sev]')[Number(e.key) - 1]; box.checked = !box.checked; refilter(); }
    });
  }

  function skeletonRows() {
    const body = $('rows');
    for (let i = 0; i < 8; i++) body.append(el('tr', { class: 'skrow sk', 'aria-hidden': 'true' }, ...Array.from({ length: 7 }, () => el('td'))));
  }

  document.addEventListener('DOMContentLoaded', () => {
    bind(); skeletonRows(); applyLang(); load();
    if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('/sw.js').catch(() => {});
  });
})();
