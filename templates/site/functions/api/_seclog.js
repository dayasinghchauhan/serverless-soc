/**
 * Security event log: the app's half of the SOC.
 *
 * The app writes one row per security-relevant event; the sentinel's 5-minute SOC run reads
 * new rows (by id cursor), turns them into cases and alerts, and takes the automatic actions.
 * Writing is cheap and never throws, so it can sit on hot paths.
 *
 *   import { secLog } from './_seclog.js';
 *   await secLog(context, 'admin_ok',   { actor: user.name });           // an admin request was allowed
 *   await secLog(context, 'admin_fail');                                 // wrong admin key / password
 *   await secLog(context, 'webhook_bad_sig', { meta: { source: 'payments' } });
 *   await secLog(context, 'otp_sent',   { meta: { to: last4 } });        // never the full number
 *   await secLog(context, 'attack',     { meta: { pattern: 'sqli' } });  // input that looks like injection
 *   await secLog(context, 'probe',      { meta: { status: 404 } });      // request for a never-public path
 *   await secLog(context, 'server_error', { message: e.message });
 *   await secLog(context, 'tfa_off',    { actor });                      // two-step login turned off
 *   await secLog(context, 'secret_replaced', { actor, meta: { name: 'PAYMENT_KEY' } });
 *   await secLog(context, 'csp',        { meta: report });               // from your CSP report endpoint
 *
 * Known kinds and what the SOC does with them: references/soc-rules.md.
 * Never put customer personal data in `meta` (it ends up in alerts).
 */

export const SECLOG_SQL = `CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT DEFAULT (datetime('now')),
  kind TEXT NOT NULL, severity TEXT, actor TEXT, message TEXT,
  ip TEXT, country TEXT, asn_org TEXT, ua TEXT, path TEXT, meta TEXT)`;

const ready = new WeakSet();   // per database binding
export async function ensureSecLog(db) {
  if (ready.has(db)) return;
  await db.prepare(SECLOG_SQL).run();
  await db.prepare('CREATE INDEX IF NOT EXISTS security_events_kind ON security_events (kind, created_at)').run();
  ready.add(db);
}

/** Where a request came from, as Cloudflare tells it. */
export function originOf(request) {
  if (!request) return {};
  const cf = request.cf || {};
  let path = '';
  try { path = new URL(request.url).pathname; } catch { /* no url */ }
  return {
    method: request.method, path,
    ip: request.headers.get('CF-Connecting-IP') || '',
    country: request.headers.get('CF-IPCountry') || cf.country || '',
    asnOrg: String(cf.asOrganization || '').slice(0, 80),
    ua: String(request.headers.get('User-Agent') || '').slice(0, 200),
  };
}

/** Write one event. `context` = Pages/Workers context ({ env, request, waitUntil? }) or { env } + `where`. */
export async function secLog(context, kind, { actor = '', message = '', severity = '', meta = null, where = null } = {}) {
  const env = context.env || context;
  const w = where || originOf(context.request);
  const job = (async () => {
    await ensureSecLog(env.DB);
    await env.DB.prepare(`INSERT INTO security_events (kind, severity, actor, message, ip, country, asn_org, ua, path, meta, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(kind, severity || null, String(actor || '').slice(0, 80), String(message || '').slice(0, 500),
      w.ip || '', w.country || '', w.asnOrg || '', String(w.ua || '').slice(0, 200), String(w.path || '').slice(0, 200),
      meta ? JSON.stringify(meta).slice(0, 2000) : null, new Date(context.now || Date.now()).toISOString().replace('T', ' ').slice(0, 19)).run();
  })().catch(() => {});
  if (context.waitUntil) { context.waitUntil(job); return; }
  await job;
}
