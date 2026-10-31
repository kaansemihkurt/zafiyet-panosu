'use strict';
/**
 * Zero Trust yetkilendirme yardımcıları.
 *
 * Azure Static Web Apps, oturum açmış kullanıcının kimliğini API'ye
 * `x-ms-client-principal` başlığında (base64 JSON) iletir. Bu başlığı istemci
 * taklit edemez: SWA dış istekte gelen aynı adlı başlığı siler ve kendisi yazar.
 *
 * Kural: rota kuralları (staticwebapp.config.json) ilk savunma hattıdır; API yine de
 * her istekte rolü kendisi kontrol eder (derinlemesine savunma) ve kararı loglar.
 */
const crypto = require('node:crypto');

const APP_ROLES = ['viewer', 'analyst'];

function getPrincipal(req) {
  const header = req.headers && (req.headers['x-ms-client-principal'] || req.headers['X-MS-CLIENT-PRINCIPAL']);
  if (!header) return null;
  try {
    const p = JSON.parse(Buffer.from(header, 'base64').toString('utf8'));
    return p && typeof p === 'object' ? p : null;
  } catch {
    return null;
  }
}

function appRoles(principal) {
  if (!principal || !Array.isArray(principal.userRoles)) return [];
  return principal.userRoles.filter((r) => APP_ROLES.includes(r));
}

/** Loglarda kişisel veri tutmamak için kullanıcı kimliğinin tuzlu özeti. */
function pseudonym(principal) {
  if (!principal || !principal.userId) return 'anonim';
  return crypto.createHash('sha256').update(`${process.env.AUDIT_SALT || ''}:${principal.userId}`).digest('hex').slice(0, 12);
}

function pathOf(req) {
  try { return new URL(req.url).pathname; } catch { return req.url || ''; }
}

/** Erişim logu: Application Insights'a "traces" olarak düşer. */
function audit(context, req, principal, decision, status, extra = {}) {
  const entry = {
    event: 'zt_access',
    decision,
    status,
    user: pseudonym(principal),
    idp: principal ? principal.identityProvider : null,
    roles: appRoles(principal),
    method: req.method,
    path: pathOf(req),
    ...extra,
  };
  const line = JSON.stringify(entry);
  if (decision === 'DENY' && context.log && context.log.warn) context.log.warn(line);
  else context.log(line);
  return entry;
}

function json(status, body, headers = {}) {
  return {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers },
    body: body === undefined ? '' : JSON.stringify(body),
  };
}

/**
 * İsteğin rolünü kontrol eder. İzin yoksa 403 yanıtı ve DENY logu üretir.
 * @returns {{ok: true, principal: object, roles: string[]} | {ok: false, res: object}}
 */
function authorize(context, req, allowedRoles) {
  const principal = getPrincipal(req);
  const roles = appRoles(principal);
  if (!roles.some((r) => allowedRoles.includes(r))) {
    audit(context, req, principal, 'DENY', 403, { required: allowedRoles });
    return { ok: false, res: json(403, { error: 'forbidden', message: 'Bu işlem için yetkiniz yok.' }) };
  }
  return { ok: true, principal, roles };
}

module.exports = { APP_ROLES, getPrincipal, appRoles, pseudonym, audit, authorize, json };
