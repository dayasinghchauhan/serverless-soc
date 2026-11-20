/**
 * Storage watchdog for a Cloudflare Pages / Workers app.
 *
 * GET /api/watchdog   header  x-watchdog-key: <WATCHDOG_KEY>
 *   200  D1, every R2 bucket and the newest backup are healthy
 *   503  something is wrong: the alert has been sent, AND the 503 makes the
 *        external pinger (cron-job.org, UptimeRobot, ...) send its own failure
 *        email - the one road that still works when the whole app is down.
 *
 * Why this exists: Cloudflare can switch R2 or D1 off (billing, plan limits,
 * an incident) while every binding still EXISTS. A health check that only
 * asks "is env.BUCKET defined?" stays green while photos 403 and backups fail.
 * This file does real work instead: a D1 read AND write, an R2 list per
 * bucket, and the age of the newest dated backup object.
 *
 * Rules that keep it quiet and trustworthy:
 *  - two failed checks in a row (45 s - 10 min apart) before the first alert,
 *    so one "D1 overloaded" blip does not send DOWN + FIXED together;
 *  - one alert per problem, a reminder every REMIND_HOURS, a "fixed" note
 *    with the outage length when it clears;
 *  - the memory of what was already sent lives in D1 AND in R2, read from
 *    whichever answers (newer copy wins), and is written only when it changes;
 *  - with neither store answering ("blind") it alerts only on the half hour,
 *    instead of every minute.
 *
 * Bindings / vars (wrangler.toml or Pages settings):
 *   DB                     D1 database
 *   WATCHDOG_BUCKETS       "IMAGES,BACKUPS"  R2 binding names to probe
 *   WATCHDOG_STATE_BUCKET  "BACKUPS"         private bucket for the state copy
 *   BACKUP_BUCKET          "BACKUPS"         where dated backups land (optional)
 *   BACKUP_PREFIX          "db/backup-"      keys look like db/backup-2026-11-20T03-00-00.json
 *   WATCHDOG_KEY           secret            shared with the pinger + sentinel
 *   DISCORD_WEBHOOK / SLACK_WEBHOOK / NTFY_URL   any of them (secrets)
 *   APP_NAME               shown in alerts
 */

export const CONFIG = {
  BACKUP_LATE_HOURS: 26,        // a daily backup + 2 h of slack
  BACKUP_LOOKBACK_DAYS: 3,      // list today's prefix and the 2 days before, never the whole bucket
  REMIND_HOURS: 6,
  CONFIRM_MIN_MS: 45_000,       // the 2nd failure must be a separate run
  CONFIRM_MAX_MS: 10 * 60_000,  // an older 1st failure is forgotten
  STATE_KEY: 'watchdog_state',
  STATE_OBJECT: 'ops/watchdog-state.json',
};

const errText = (e) => String((e && e.message) || e).slice(0, 160);
const list = (s) => String(s || '').split(',').map((x) => x.trim()).filter(Boolean);

const KV_SQL = `CREATE TABLE IF NOT EXISTS watchdog_kv (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT)`;
const UPSERT = `INSERT INTO watchdog_kv (key, value, updated_at) VALUES (?, ?, datetime('now'))
  ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`;

async function d1Upsert(db, key, value) {
  try { await db.prepare(UPSERT).bind(key, value).run(); }
  catch (e) {
    if (!/no such table/i.test(String(e && e.message))) throw e;
    await db.prepare(KV_SQL).run();
    await db.prepare(UPSERT).bind(key, value).run();
  }
}

/** Live probe. Never throws. */
export async function probe(env, now = Date.now()) {
  const out = {
    d1: { ok: true, error: '' },
    r2: { ok: true, error: '' },
    backup: { ok: true, ageHours: null, last: null, error: '' },
  };

  // D1: a read and a write. A database that reads but refuses writes
  // (plan limit, read-only incident) still loses every new order.
  if (!env.DB) out.d1 = { ok: false, error: 'DB not bound' };
  else {
    try {
      await d1Upsert(env.DB, 'heartbeat', new Date(now).toISOString());
      await env.DB.prepare('SELECT value FROM watchdog_kv WHERE key = ?').bind('heartbeat').first();
    } catch (e) { out.d1 = { ok: false, error: errText(e) }; }
  }

  const fails = [];
  for (const name of list(env.WATCHDOG_BUCKETS)) {
    const b = env[name];
    if (!b) { fails.push(name + ' not bound'); continue; }
    try { await b.list({ limit: 1 }); } catch (e) { fails.push(name + ': ' + errText(e)); }
  }
  if (fails.length) out.r2 = { ok: false, error: fails.join(' · ') };

  const bk = env.BACKUP_BUCKET && env[env.BACKUP_BUCKET];
  if (!env.BACKUP_BUCKET) out.backup = { ok: true, ageHours: null, last: null, error: 'not watched' };
  else if (!bk) out.backup = { ok: false, ageHours: null, last: null, error: env.BACKUP_BUCKET + ' not bound' };
  else if (!out.r2.ok && list(env.WATCHDOG_BUCKETS).includes(env.BACKUP_BUCKET)) {
    out.backup = { ok: false, ageHours: null, last: null, error: 'R2 unreachable, backups cannot be written' };
  } else {
    try {
      const prefix = env.BACKUP_PREFIX || 'db/backup-';
      let newest = null;
      for (let d = 0; d < CONFIG.BACKUP_LOOKBACK_DAYS && !newest; d++) {
        const day = new Date(now - d * 86_400_000).toISOString().slice(0, 10);
        let cursor;
        do {
          const page = await bk.list({ prefix: prefix + day, limit: 1000, cursor });
          for (const o of page.objects || []) if (!newest || o.key > newest.key) newest = o;
          cursor = page.truncated ? page.cursor : undefined;
        } while (cursor);
      }
      const age = newest ? (now - new Date(newest.uploaded).getTime()) / 3_600_000 : Infinity;
      out.backup = {
        ok: age < CONFIG.BACKUP_LATE_HOURS,
        ageHours: Number.isFinite(age) ? Math.round(age * 10) / 10 : null,
        last: newest ? newest.key : null,
        error: newest ? '' : 'no backup in the last ' + CONFIG.BACKUP_LOOKBACK_DAYS + ' days',
      };
    } catch (e) { out.backup = { ok: false, ageHours: null, last: null, error: errText(e) }; }
  }
  return out;
}

// ------------------------------------------------------------------ memory

const body = (s) => { const { savedAt, ...rest } = s || {}; return JSON.stringify(rest); };
const parse = (s) => { try { return s ? JSON.parse(s) || null : null; } catch { return null; } };

async function loadState(env, p) {
  let d1Raw = null, r2Raw = null;
  const sb = env.WATCHDOG_STATE_BUCKET && env[env.WATCHDOG_STATE_BUCKET];
  if (p.d1.ok) {
    try { const r = await env.DB.prepare('SELECT value FROM watchdog_kv WHERE key = ?').bind(CONFIG.STATE_KEY).first(); d1Raw = r ? r.value : null; } catch { /* R2 copy */ }
  }
  const r2Up = !!sb && !String(p.r2.error).includes(env.WATCHDOG_STATE_BUCKET);
  if (r2Up) {
    try { const o = await sb.get(CONFIG.STATE_OBJECT); r2Raw = o ? await o.text() : null; } catch { /* D1 copy */ }
  }
  const a = parse(d1Raw), b = parse(r2Raw);
  const useR2 = b && (!a || (b.savedAt || 0) > (a.savedAt || 0));
  const state = (useR2 ? b : a) || {};
  const from = useR2 ? 'r2' : a ? 'd1' : (p.d1.ok || r2Up) ? 'empty' : 'none';
  return { state, loadedBody: body(state), savedAt: state.savedAt || 0, d1Raw, r2Raw, r2Up, from };
}

async function saveState(env, p, state, mem, now) {
  // savedAt moves only when the content does: a quiet minute writes nothing,
  // and a store that missed a change while it was down is caught up once.
  state.savedAt = body(state) === mem.loadedBody && mem.savedAt ? mem.savedAt : now;
  const raw = JSON.stringify(state);
  if (p.d1.ok && raw !== mem.d1Raw) { try { await d1Upsert(env.DB, CONFIG.STATE_KEY, raw); } catch { /* R2 copy */ } }
  const sb = env.WATCHDOG_STATE_BUCKET && env[env.WATCHDOG_STATE_BUCKET];
  if (mem.r2Up && sb && raw !== mem.r2Raw) {
    try { await sb.put(CONFIG.STATE_OBJECT, raw, { httpMetadata: { contentType: 'application/json', cacheControl: 'no-store' } }); } catch { /* D1 copy */ }
  }
}

// ----------------------------------------------------------------- alerting

/** Every configured road; one failing never stops the others. */
export async function notify(env, title, text) {
  const name = env.APP_NAME || 'App';
  const msg = ('**' + title + '**\n' + text).slice(0, 1900);
  const jobs = [];
  if (env.DISCORD_WEBHOOK) jobs.push(['discord', fetch(env.DISCORD_WEBHOOK, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: name + ' Watchdog', allowed_mentions: { parse: [] }, content: msg }) })]);
  if (env.SLACK_WEBHOOK) jobs.push(['slack', fetch(env.SLACK_WEBHOOK, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: msg.replace(/\*\*/g, '*') }) })]);
  if (env.NTFY_URL) jobs.push(['ntfy', fetch(env.NTFY_URL, { method: 'POST',
    headers: { Title: (name + ': ' + title).replace(/[^\x20-\x7e]/g, '').slice(0, 200) || name, Priority: title.startsWith('✅') ? '3' : '5' }, body: text })]);
  const res = {};
  await Promise.all(jobs.map(async ([k, j]) => { try { res[k] = (await j).ok; } catch { res[k] = false; } }));
  return res;
}

const LABEL = { d1: 'D1 database', r2: 'R2 storage', backup: 'database backups' };
const duration = (ms) => { const m = Math.max(1, Math.round(ms / 60000)); return m < 60 ? m + ' min' : Math.round(m / 6) / 10 + ' h'; };
const utc = (t) => new Date(t).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';

function problemsOf(p) {
  const out = {};
  if (!p.d1.ok) out.d1 = { title: '🔴 D1 database is DOWN', body: 'Nothing can be read or saved (orders, sign-in, admin).\n' + p.d1.error + '\nCheck: Cloudflare dashboard → D1, and Billing → Subscriptions.' };
  if (!p.r2.ok) out.r2 = { title: '🔴 R2 storage is DOWN', body: 'Files stop loading as the cache empties, and backups fail.\n' + p.r2.error + '\nCheck: Cloudflare dashboard → R2 is enabled, and Billing → Subscriptions.' };
  if (!p.backup.ok && p.r2.ok) out.backup = { title: '🟠 Database backup is late', body: 'Newest backup: ' + (p.backup.last || 'none') + (p.backup.ageHours != null ? ' (' + p.backup.ageHours + ' h old)' : '') + '. ' + (p.backup.error || '') + '\nCheck the backup job (GitHub Actions / cron).' };
  return out;
}

/** One watchdog run. `send` is injectable for tests. */
export async function runWatchdog(env, { now = Date.now(), send = notify } = {}) {
  const p = await probe(env, now);
  const problems = problemsOf(p);
  const mem = await loadState(env, p);
  const state = { alerts: {}, ...mem.state };
  if (!state.alerts || typeof state.alerts !== 'object') state.alerts = {};
  const pending = state.pending && typeof state.pending === 'object' ? state.pending : {};
  const blind = mem.from === 'none';
  const sent = [], held = [];

  for (const [id, pr] of Object.entries(problems)) {
    const s = state.alerts[id];
    if (!s && !blind) {                         // first sighting: wait for a second, separate run
      const first = pending[id];
      const stale = !first || now - first.at > CONFIG.CONFIRM_MAX_MS;
      if (stale) pending[id] = { at: now, error: String(p[id].error || '').slice(0, 160) };
      if (stale || now - first.at < CONFIG.CONFIRM_MIN_MS) { held.push(id); continue; }
    }
    const due = blind ? new Date(now).getUTCMinutes() % 30 === 0 : (!s || now - s.lastSent >= CONFIG.REMIND_HOURS * 3_600_000);
    if (!due) continue;
    const r = await send(env, pr.title, pr.body + (s ? '\n(broken since ' + utc(s.since) + ')' : ''));
    state.alerts[id] = { since: s ? s.since : (pending[id] ? pending[id].at : now), lastSent: now };
    delete pending[id];
    sent.push({ id, ...r });
  }
  for (const id of Object.keys(pending)) if (!problems[id]) delete pending[id];   // one blip that cleared: no alert
  if (Object.keys(pending).length) state.pending = pending; else delete state.pending;

  for (const id of Object.keys(state.alerts)) {
    if (problems[id]) continue;
    const r = await send(env, '✅ Fixed: ' + (LABEL[id] || id) + ' working again', 'Was broken for about ' + duration(now - state.alerts[id].since) + '.');
    sent.push({ id, recovered: true, ...r });
    delete state.alerts[id];
  }
  await saveState(env, p, state, mem, now);
  return { ok: !Object.keys(problems).length, d1: p.d1.ok, r2: p.r2.ok, backupAgeHours: p.backup.ageHours,
    problems: Object.keys(problems), held, memory: mem.from, sent };
}

// ---------------------------------------------------------------- endpoint

/** Constant-time compare. Not a D1-backed lockout on purpose: this must answer while D1 is down. */
export function sameKey(a, b) {
  a = String(a || ''); b = String(b || '');
  let d = !a || !b ? 1 : a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return d === 0;
}

export async function onRequest({ request, env }) {
  const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
  if (!sameKey(request.headers.get('x-watchdog-key'), env.WATCHDOG_KEY)) return json({ error: 'Unauthorized' }, 401);
  try {
    const r = await runWatchdog(env);
    return json(r, r.ok ? 200 : 503);
  } catch (e) {
    return json({ ok: false, error: errText(e) }, 503);
  }
}
