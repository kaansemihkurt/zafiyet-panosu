'use strict';
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
const PRIORITIES = ['P1', 'P2', 'P3', 'P4'];

function normalizeCve(v) {
  const s = String(v || '').trim().toUpperCase();
  return CVE_RE.test(s) ? s : null;
}

/** Analistin gönderdiği kaydı doğrular; hatalıysa {error} döner. */
function parseItem(body) {
  if (!body || typeof body !== 'object') return { error: 'Geçersiz gövde.' };
  const cve = normalizeCve(body.cve);
  if (!cve) return { error: 'CVE biçimi CVE-YYYY-NNNN olmalı.' };
  const priority = String(body.priority || '').toUpperCase();
  if (!PRIORITIES.includes(priority)) return { error: 'Öncelik P1, P2, P3 veya P4 olmalı.' };
  // Kontrol karakterlerini at, 280 karakterle sınırla (depolanan XSS'e karşı istemci zaten textContent kullanır)
  const note = String(body.note || '').replace(/[\u0000-\u001F\u007F]/g, ' ').trim().slice(0, 280);
  return { item: { cve, priority, note } };
}

module.exports = { CVE_RE, PRIORITIES, normalizeCve, parseItem };
