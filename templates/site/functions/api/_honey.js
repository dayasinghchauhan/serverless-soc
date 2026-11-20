/**
 * Honeytokens for a serverless app (Cloudflare Pages / Workers + D1).
 *
 * Decoy values that sit ONLY where someone who is already inside would find
 * them: a row in your database (and so in every backup and export of it).
 * Nothing on the site links to them and none of them opens anything:
 *
 *   admin-key      x-admin-key header         → refused exactly like a wrong key
 *   admin-session  session header / cookie    → refused exactly like an unknown session
 *   phone          login code / order lookup  → answered like a normal number; nothing is ever sent
 *   email          order lookup / mailbox     → answered like a normal address; mail is dropped
 *
 * A use therefore means your database, a backup, or an admin screen has left
 * your hands. There are no false positives from scanners: nobody can guess them.
 *
 * Only SHA-256 hashes live in code/config (env HONEY_HASHES), so this file
 * and your repo never hold a working-looking value someone could paste by
 * mistake. The plaintext lives only in the database you are protecting.
 *
 * env:
 *   DB              D1
 *   HONEY_HASHES    JSON {"<sha256 hex>": "admin-key" | "admin-session" | "phone" | "email", ...}
 *                   (scripts/make-decoys.mjs prints it)
 *   HONEY_PHONE_DIGITS  digits kept when normalising a phone (default 10)
 *   DISCORD_WEBHOOK / SLACK_WEBHOOK / NTFY_URL   alert roads
 *   APP_NAME
 */

import { ensureSecLog } from './_seclog.js';

export const HONEY = {
  ROWS_PER_HOUR: 20,          // a script looping on a stolen value must not fill the table
  ALERT_COOLDOWN_MIN: 60,     // one page per kind per hour; every hit is still logged
};

const enc = new TextEncoder();
export async function sha256Hex(s) {
  const d = await crypto.subtle.digest('SHA-256', enc.encode(String(s)));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export const normPhone = (p, digits = 10) => String(p || '').replace(/\D/g, '').slice(-digits);
export const normEmail = (e) => String(e || '').trim().toLowerCase();

function hashes(env) {
  if (env.__honeyHashes) return env.__honeyHashes;
  let h = {};
  try { h = JSON.parse(env.HONEY_HASHES || '{}') || {}; } catch { h = {}; }
  Object.defineProperty(env, '__honeyHashes', { value: h, enumerable: false });
  return h;
}

// Same security_events table as _seclog.js: the sentinel's SOC turns each hit into a CRITICAL
// case and runs the automatic response (sign everyone out, block the address).
async function ensure(db) {
  await ensureSecLog(db);
  await db.prepare(`CREATE TABLE IF NOT EXISTS honey_state (kind TEXT PRIMARY KEY, window_start INTEGER, hits INTEGER, last_alert INTEGER)`).run();
}

const WHAT = { 'admin-key': 'decoy admin key', 'admin-session': 'decoy admin session', phone: 'decoy customer phone', email: 'decoy customer email' };

async function alert(env, title, text) {
  const msg = ('**' + title + '**\n' + text).slice(0, 1900);
  const name = env.APP_NAME || 'App';
  const jobs = [];
  if (env.DISCORD_WEBHOOK) jobs.push(fetch(env.DISCORD_WEBHOOK, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: name + ' Security', allowed_mentions: { parse: [] }, content: msg }) }));
  if (env.SLACK_WEBHOOK) jobs.push(fetch(env.SLACK_WEBHOOK, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: msg.replace(/\*\*/g, '*') }) }));
  if (env.NTFY_URL) jobs.push(fetch(env.NTFY_URL, { method: 'POST', headers: { Title: (name + ' CRITICAL: honeytoken used').slice(0, 200), Priority: '5', Tags: 'rotating_light' }, body: text }));
  await Promise.allSettled(jobs);
}

/**
 * Log + (rate-limited) alert. `where` = { method, path, ip, country, asnOrg, ua }.
 * `onHit` (optional) = your automatic response, e.g. sign out every admin session.
 */
export async function recordHit(env, kind, where = {}, { now = Date.now(), onHit } = {}) {
  const db = env.DB;
  await ensure(db);
  const row = await db.prepare('SELECT window_start, hits, last_alert FROM honey_state WHERE kind = ?').bind(kind).first();
  let ws = row ? row.window_start : now, hits = row ? row.hits : 0, last = row ? row.last_alert : 0;
  if (now - ws >= 3_600_000) { ws = now; hits = 0; }
  hits++;
  const logIt = hits <= HONEY.ROWS_PER_HOUR;
  const page = !last || now - last >= HONEY.ALERT_COOLDOWN_MIN * 60_000;
  if (page) last = now;
  await db.prepare(`INSERT INTO honey_state (kind, window_start, hits, last_alert) VALUES (?, ?, ?, ?)
    ON CONFLICT(kind) DO UPDATE SET window_start = excluded.window_start, hits = excluded.hits, last_alert = excluded.last_alert`).bind(kind, ws, hits, last).run();

  const what = WHAT[kind] || 'decoy value';
  const msg = 'Honeytoken used: ' + kind + (where.path ? ' on ' + (where.method || 'GET') + ' ' + where.path : '');
  if (logIt) {
    // meta.paged tells the SOC this hit already rang a phone: it opens the case and acts, without a second message.
    await db.prepare(`INSERT INTO security_events (severity, kind, message, ip, country, asn_org, ua, path, meta, created_at) VALUES ('CRITICAL', ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind('honeytoken:' + kind, msg, where.ip || '', where.country || '', where.asnOrg || '', String(where.ua || '').slice(0, 160), where.path || '',
        JSON.stringify({ hitsThisHour: hits, paged: page }), new Date(now).toISOString().replace('T', ' ').slice(0, 19)).run();
  }
  if (page) {
    await alert(env, '🚨 CRITICAL: the ' + what + ' was used',
      [
        'A decoy that exists only inside your database (and its backups) was just used. Nothing was opened.',
        where.path ? 'Where: ' + (where.method || 'GET') + ' ' + where.path : '',
        where.ip ? 'From: ' + where.ip + (where.country ? ' (' + where.country + ')' : '') + (where.asnOrg ? ', ' + where.asnOrg : '') : '',
        'Means: someone has a copy of your database, a backup, or admin access.',
        'Do now: rotate the admin key + all staff passwords · check backup bucket is private · review Cloudflare members + API tokens · read security_events for this IP.',
      ].filter(Boolean).join('\n'));
  }
  if (onHit) { try { await onHit({ kind, where, hits }); } catch { /* the alert above already went */ } }
  return { kind, logged: logIt, paged: page, hits };
}

function whereOf(request) {
  const u = new URL(request.url);
  const cf = request.cf || {};
  return { method: request.method, path: u.pathname, ip: request.headers.get('CF-Connecting-IP') || '', country: request.headers.get('CF-IPCountry') || cf.country || '',
    asnOrg: String(cf.asOrganization || '').slice(0, 80), ua: request.headers.get('User-Agent') || '' };
}

function background(context, p) {
  // With waitUntil the caller answers at once (no timing tell); without it (tests, plain Node) we wait.
  const job = p.catch(() => {});
  if (context.waitUntil) { context.waitUntil(job); return null; }
  return job;
}

/**
 * Call FIRST in your admin-key / session check, before any lockout or compare.
 * Returns true for a decoy: then refuse EXACTLY like a wrong key (same status, body, timing).
 */
export async function honeyKey(context, value, opts = {}) {
  if (!value || String(value).length < 16) return false;
  const kind = hashes(context.env)[await sha256Hex(value)];
  if (kind !== 'admin-key' && kind !== 'admin-session') return false;
  const job = background(context, recordHit(context.env, kind, whereOf(context.request), opts));
  if (job) await job;
  return true;
}

/** Call in customer lookups (login code request, order tracking). true → answer like normal, send nothing. */
export async function honeyContact(context, { phone, email } = {}, opts = {}) {
  const h = hashes(context.env);
  const digits = Number(context.env.HONEY_PHONE_DIGITS || 10);
  const p = normPhone(phone, digits), e = normEmail(email);
  let kind = '';
  if (p.length === digits && h[await sha256Hex(p)] === 'phone') kind = 'phone';
  else if (e && h[await sha256Hex(e)] === 'email') kind = 'email';
  if (!kind) return false;
  const job = background(context, recordHit(context.env, kind, whereOf(context.request), opts));
  if (job) await job;
  return true;
}
