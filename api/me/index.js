'use strict';
const { getPrincipal, appRoles, json } = require('../shared/auth');

/** Oturumdaki kullanıcıya kendi adını ve rolünü gösterir (arayüz düğmeleri için). */
module.exports = async function (context, req) {
  const p = getPrincipal(req);
  context.res = json(200, {
    authenticated: Boolean(p),
    user: p ? p.userDetails : null,
    provider: p ? p.identityProvider : null,
    roles: appRoles(p),
  });
};
