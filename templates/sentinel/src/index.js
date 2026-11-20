/**
 * Sentinel: a separate Cloudflare Worker that watches the site from OUTSIDE.
 * It also runs the SOC (src/soc/run.js, own 5-minute cron) and the decoy mailbox (email handler).
 *
 * The site's own /api/watchdog can only alert while the site's code runs. If
 * Pages / the Worker itself is down, or the account is suspended, nothing
 * inside can speak. This Worker is a different deployment, so it still runs.
 *
 * Two clocks: the native cron (every minute) and an external pinger calling
 * GET /run every minute. The external call stands down when the native cron
 * ran in the last 150 s, so normally one runs; if either dies the other goes on.
 *
 * A third road for when Cloudflare itself stops: every run pings a dead-man
 * switch (Healthchecks.io HC_PING_URL). When the pings stop, it alerts.
 *
 * Alerting: one message per run (everything newly down together), a reminder
 * every REMIND_HOURS, one "Fixed" message with the outage length. Weekly
 * uptime report. Domain expiry via RDAP once a day.
 *
 * Bindings: STATE (KV).  Secrets: WATCHDOG_KEY (same as the site),
 * RUN_KEY (for GET /run; may equal WATCHDOG_KEY), DISCORD_WEBHOOK / SLACK_WEBHOOK /
 * NTFY_URL, REPORT_WEBHOOK (optional, Discord channel for the weekly report),
 * HC_PING_URL (optional).
 * Vars: STATE_FLUSH_MIN (0 = write KV every run, needs Workers Paid; 15 on the
 * Free plan, which allows 1,000 KV writes a day).
 */
import { CHECKS, SITE, DOMAINS, NAME } from './checks.js';
import { notify } from './notify.js';
import { runSoc } from './soc/run.js';
import { closeIncident, undoAction, ensureSoc } from './soc/respond.js';
import { sha256Hex, iso } from './soc/util.js';

const SOC_CRON = '*/5 * * * *';   // must match wrangler.toml

export const CONFIG = {
  REMIND_HOURS: 6,
  SLOW_MS: 4000,
  SLOW_RUNS: 5,
  FULL_EVERY_MS: 5 * 60_000 - 15_000,   // 'full' checks every ~5 min (load on your own site matters)
  STANDDOWN_MS: 150_000,
  EXPIRY_WARN_DAYS: 14,
  REPORT_UTC_DAY: 1,                    // Monday
  REPORT_UTC_MIN: 3 * 60 + 30,          // 03:30 UTC
  RETRY_MS: 3000,
};
const UA = 'Sentinel/1.0 (+uptime)';
const BY_ID = Object.fromEntries(CHECKS.map((c) => [c.id, c]));
const EXTRA = {
  slow: { label: 'Website is very SLOW', short: 'Speed' },
  expiry: { label: 'Domain name expiring soon', short: 'Domain dates' },
};
const meta = (id) => BY_ID[id] || EXTRA[id] || { label: id, short: id };

// ------------------------------------------------------------------ helpers

export async function get(url, opts = {}, ms = 10000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  const t0 = Date.now();
  try {
    const r = await fetch(url, { redirect: 'manual', ...opts, signal: ctl.signal, headers: { 'User-Agent': UA, ...(opts.headers || {}) } });
    r.ms = Date.now() - t0;
    return r;
  } finally { clearTimeout(t); }
}
const bust = (u) => u + (u.includes('?') ? '&' : '?') + 'sentinel=' + Date.now();
const reachable = (url) => async () => { const r = await get(url); return r.status < 500 ? '' : url.replace(/^https:\/\//, '') + ' HTTP ' + r.status; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const utc = (t) => new Date(t).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';

export function sameKey(a, b) {
  a = String(a || ''); b = String(b || '');
  let d = !a || !b ? 1 : a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return d === 0;
}

export { notify };

// ------------------------------------------------------------------- checks

export async function runChecks(env, ids, { wait = sleep } = {}) {
  const ctx = {};
  const h = { env, ctx, get, bust, reachable };
  const failed = {};
  await Promise.all(CHECKS.filter((c) => ids.includes(c.id)).map(async (c) => {
    const once = async () => { try { return await c.run(h); } catch (e) { return String((e && e.message) || e).slice(0, 120) || 'no answer'; } };
    let why = await once();
    if (why) { await wait(CONFIG.RETRY_MS); why = await once(); }   // one retry: a single dropped packet never pages
    if (why) failed[c.id] = why;
  }));
  return { failed, ctx };
}

export async function expiryProblems(domains = DOMAINS, now = Date.now()) {
  const out = [];
  for (const d of domains) {
    try {
      const r = await get('https://rdap.org/domain/' + d, { redirect: 'follow', headers: { Accept: 'application/rdap+json' } });
      const j = await r.json();
      const ev = (j.events || []).find((e) => e.eventAction === 'expiration');
      if (ev && new Date(ev.eventDate).getTime() - now < CONFIG.EXPIRY_WARN_DAYS * 86_400_000) out.push('domain ' + d + ' expires ' + ev.eventDate.slice(0, 10));
    } catch { /* lookup failed: try tomorrow, never a false alarm */ }
  }
  return out.join(' · ');
}

// ------------------------------------------------------------ stats + report

const dayKey = (t) => new Date(t).toISOString().slice(0, 10);
function record(state, now, failing, homeMs) {
  const s = (state.stats[dayKey(now)] ||= { runs: 0, down: {}, ms: 0, msN: 0, maxMs: 0 });
  s.runs++;
  for (const id of failing) s.down[id] = (s.down[id] || 0) + 1;
  if (homeMs) { s.ms += homeMs; s.msN++; s.maxMs = Math.max(s.maxMs, homeMs); }
  for (const d of Object.keys(state.stats)) if (now - new Date(d).getTime() > 9 * 86_400_000) delete state.stats[d];
}

export function weeklyReport(state, now) {
  const days = Object.keys(state.stats).filter((d) => now - new Date(d).getTime() <= 7 * 86_400_000).sort();
  let runs = 0, ms = 0, msN = 0, maxMs = 0; const down = {};
  for (const d of days) {
    const s = state.stats[d]; runs += s.runs; ms += s.ms; msN += s.msN; maxMs = Math.max(maxMs, s.maxMs);
    for (const [id, n] of Object.entries(s.down)) down[id] = (down[id] || 0) + n;
  }
  if (!runs) return null;
  const pct = (n) => (Math.round((1 - n / runs) * 10000) / 100).toFixed(2) + '%';
  const coreDown = Math.max(0, ...CHECKS.filter((c) => c.core).map((c) => down[c.id] || 0));
  const lines = [
    'Checks run: ' + runs + ' · ' + days[0] + ' to ' + days[days.length - 1],
    'Site up: **' + pct(coreDown) + '**' + (coreDown ? ' (about ' + coreDown + ' failed runs)' : ' - no downtime'),
    'Homepage: average ' + (msN ? Math.round(ms / msN) : '?') + ' ms, slowest ' + maxMs + ' ms',
  ];
  const other = Object.entries(down).filter(([, n]) => n).map(([id, n]) => '• ' + meta(id).short + ': ' + n + ' failed runs');
  if (other.length) lines.push('Problems this week:\n' + other.join('\n'));
  const inc = (state.incidents || []).filter((i) => now - i.start <= 7 * 86_400_000);
  if (inc.length) lines.push('Outages:\n' + inc.slice(-10).map((i) => '• ' + utc(i.start) + ', ' + Math.max(1, Math.round((i.end - i.start) / 60000)) + ' min: ' + i.ids.join(', ')).join('\n'));
  return lines.join('\n');
}

// --------------------------------------------------------------------- tick

const MATERIAL = (s) => JSON.stringify({ a: s.alerts, k: s.streak, w: s.why, i: s.incidents.length, r: s.reportDay, e: s.expiryAt, sl: s.slowRuns });

export async function tick(env, { source = 'cron', force = {}, now = Date.now(), send = notify, wait } = {}) {
  let state = {};
  try { state = JSON.parse((await env.STATE.get('state')) || '{}') || {}; } catch { state = {}; }
  if (source === 'cronjob' && state.lastRun && now - state.lastRun < CONFIG.STANDDOWN_MS) {
    return { skipped: 'native cron ran ' + Math.round((now - state.lastRun) / 1000) + ' s ago' };
  }
  state.alerts ||= {}; state.streak ||= {}; state.stats ||= {}; state.incidents ||= []; state.why ||= {};
  const before = MATERIAL(state);
  state.lastRun = now;

  const watching = Object.keys(state.streak).concat(Object.keys(state.alerts)).some((id) => BY_ID[id] && BY_ID[id].every !== 'min');
  const full = source === 'manual' || watching || !state.lastFullAt || now - state.lastFullAt >= CONFIG.FULL_EVERY_MS;
  const ran = new Set(CHECKS.filter((c) => full || c.every === 'min').map((c) => c.id));
  if (full) state.lastFullAt = now;

  const { failed, ctx } = await runChecks(env, [...ran], { wait });
  for (const id of ran) { if (failed[id]) state.why[id] = failed[id]; else delete state.why[id]; }
  // A check skipped this run keeps its last result: never a false "Fixed".
  for (const c of CHECKS) if (!ran.has(c.id) && state.alerts[c.id] && state.why[c.id]) failed[c.id] = state.why[c.id];

  state.slowRuns = ctx.homeMs && ctx.homeMs > CONFIG.SLOW_MS ? (state.slowRuns || 0) + 1 : 0;
  if (state.slowRuns >= CONFIG.SLOW_RUNS && !failed.site) failed.slow = 'homepage took ' + (ctx.homeMs / 1000).toFixed(1) + ' s (' + state.slowRuns + ' runs in a row over ' + CONFIG.SLOW_MS / 1000 + ' s)';

  if (force.expiry || !state.expiryAt || now - state.expiryAt >= 86_400_000) {
    state.expiryWhy = await expiryProblems(DOMAINS, now).catch(() => state.expiryWhy || '');
    state.expiryAt = now;
  }
  if (state.expiryWhy) failed.expiry = state.expiryWhy;

  // Alert only after `need` failing runs in a row (or while already alerting).
  const fails = {};
  for (const id of new Set([...Object.keys(BY_ID), ...Object.keys(EXTRA)])) {
    const judged = !BY_ID[id] || ran.has(id);
    if (judged) { if (failed[id]) state.streak[id] = (state.streak[id] || 0) + 1; else delete state.streak[id]; }
    const need = BY_ID[id] ? BY_ID[id].need || 1 : 1;
    if (failed[id] && (state.streak[id] >= need || state.alerts[id])) fails[id] = failed[id];
  }

  const sent = [];
  const due = Object.keys(fails).filter((id) => { const s = state.alerts[id]; return !s || now - s.lastSent >= CONFIG.REMIND_HOURS * 3_600_000; });
  if (due.length) {
    const core = due.some((id) => BY_ID[id] && BY_ID[id].core);
    const since = Math.min(...due.map((id) => (state.alerts[id] ? state.alerts[id].since : now)));
    const r = await send(env, (core ? '🔴 ' : '🟠 ') + due.map((id) => meta(id).label).join(' · '),
      due.map((id) => '• ' + fails[id]).join('\n') + '\nChecked from outside the site.' + (since < now ? '\n(broken since ' + utc(since) + ')' : ''));
    for (const id of due) state.alerts[id] = { since: state.alerts[id] ? state.alerts[id].since : now, lastSent: now };
    sent.push({ ids: due, ...r });
  }
  const back = Object.keys(state.alerts).filter((id) => !fails[id]);
  if (back.length) {
    const start = Math.min(...back.map((id) => state.alerts[id].since));
    const min = Math.max(1, Math.round((now - start) / 60000));
    sent.push({ ids: back, recovered: true, ...(await send(env, '✅ Fixed: ' + back.map((id) => meta(id).short).join(' · ') + ' - OK again', 'Was broken for about ' + (min < 60 ? min + ' min' : Math.round(min / 6) / 10 + ' h') + '.')) });
    state.incidents.push({ start, end: now, ids: back });
    state.incidents = state.incidents.slice(-50);
    for (const id of back) delete state.alerts[id];
  }

  record(state, now, Object.keys(failed), ctx.homeMs);

  const d = new Date(now);
  if (force.report || (d.getUTCDay() === CONFIG.REPORT_UTC_DAY && d.getUTCHours() * 60 + d.getUTCMinutes() >= CONFIG.REPORT_UTC_MIN && state.reportDay !== dayKey(now))) {
    const text = weeklyReport(state, now);
    if (text) { await send(env, '📊 Weekly uptime report', text, { level: 'report' }); state.reportDay = dayKey(now); }
  }

  // KV: every run on Workers Paid; on Free only on change or every STATE_FLUSH_MIN.
  const flushMin = Number(env.STATE_FLUSH_MIN || 0);
  const changed = MATERIAL(state) !== before;
  if (!flushMin || changed || !state.flushedAt || now - state.flushedAt >= flushMin * 60_000) {
    state.flushedAt = now;
    await env.STATE.put('state', JSON.stringify(state));
  }

  const inner = ctx.inner && Array.isArray(ctx.inner.problems) ? ctx.inner.problems : [];
  const ok = !Object.keys(fails).length && !inner.length;
  // Healthchecks is a pure heartbeat ("the sentinel ran"). We already alerted on what we found,
  // so we never send /fail: Healthchecks speaks only when the pings STOP.
  let hc = 'skipped';
  if (env.HC_PING_URL) { const r = await fetch(env.HC_PING_URL, { method: 'POST', body: ok ? 'ok' : 'alerted: ' + Object.keys(fails).join(',') }).catch(() => null); hc = r ? r.status : 'error'; }
  console.log(JSON.stringify({ run: source, ok, homeMs: ctx.homeMs, failed: Object.keys(failed), alerting: Object.keys(fails), inner, hc }));
  return { ok, source, homeMs: ctx.homeMs, failed, fails, inner, expiry: state.expiryWhy || 'ok', sent, hc };
}

/**
 * Decoy mailbox (Email Routing → this Worker). The decoy address exists only in your database
 * and its backups, so mail to it means a copy of the customer list is in use. Logged as a
 * honeytoken event (the SOC opens a CRITICAL case and acts), paged at once, and DROPPED:
 * never forwarded, never answered. Any other address is rejected.
 */
export async function honeyMail(message, env, now = Date.now()) {
  const to = String(message.to || '').trim().toLowerCase();
  let kinds = {};
  try { kinds = JSON.parse(env.HONEY_HASHES || '{}') || {}; } catch { kinds = {}; }
  if (kinds[await sha256Hex(to)] !== 'email') { message.setReject('Unknown address'); return { rejected: true }; }
  const subject = String((message.headers && message.headers.get('subject')) || '').slice(0, 120);
  const from = String(message.from || '').slice(0, 120);
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS security_events (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT DEFAULT (datetime('now')),
    kind TEXT NOT NULL, severity TEXT, actor TEXT, message TEXT, ip TEXT, country TEXT, asn_org TEXT, ua TEXT, path TEXT, meta TEXT)`).run();
  await env.DB.prepare("INSERT INTO security_events (kind, severity, message, ua, path, meta, created_at) VALUES ('honeytoken:email', 'CRITICAL', ?, ?, 'mailbox', ?, ?)")
    .bind('Mail received at the decoy address', ('from ' + from + (subject ? ' · ' + subject : '')).slice(0, 200), JSON.stringify({ paged: true }), iso(now)).run();
  await notify(env, '🛡️ [CRITICAL] Decoy mailbox received mail: your customer list has leaked',
    'What happened: mail arrived at the decoy customer address, which exists only in your database and its backups.\nFrom: ' + from + (subject ? '\nSubject: ' + subject : '') +
    '\nWhat to do: 1. Rotate the admin key + staff passwords. 2. Check the backups bucket is private. 3. Review Cloudflare members + API tokens.', { level: 'page' });
  return { logged: true };
}

export default {
  async email(message, env) { await honeyMail(message, env); },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(event.cron === SOC_CRON ? runSoc(env) : tick(env, { source: 'cron' }));
  },
  // All routes need header x-run-key.
  //   GET  /run                 external pinger (202) · ?wait=1 run now · ?test=1 test alert · ?report=1 · ?expiry=1
  //   GET  /soc/run             one SOC run now · &posture=1 &integrity=1 &selftest=1 &prune=1 &summary=1 force that part
  //   GET  /soc/cases           open cases          POST /soc/case?id=&verdict=mine|handled|false_alarm
  //   GET  /soc/actions         automatic actions   POST /soc/undo?id=      POST /soc/allow?value=&note=
  async fetch(request, env, ctx) {
    const u = new URL(request.url);
    if (!sameKey(request.headers.get('x-run-key'), env.RUN_KEY || env.WATCHDOG_KEY)) return new Response('Not found', { status: 404 });
    const q = (k) => !!u.searchParams.get(k);
    const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
    const post = request.method === 'POST';
    if (u.pathname.startsWith('/soc/')) {
      await ensureSoc(env.DB);
      const p = u.pathname.slice(5), v = (k) => u.searchParams.get(k) || '';
      if (p === 'run') return json(await runSoc(env, { force: { posture: q('posture'), integrity: q('integrity'), selftest: q('selftest'), prune: q('prune'), summary: q('summary') } }));
      if (p === 'cases') return json((await env.DB.prepare("SELECT * FROM soc_incidents WHERE status = ? ORDER BY last_at DESC LIMIT 100").bind(v('status') || 'open').all()).results);
      if (p === 'actions') return json((await env.DB.prepare('SELECT * FROM soc_actions ORDER BY id DESC LIMIT 100').all()).results);
      if (p === 'case' && post) return json({ ok: await closeIncident(env.DB, Number(v('id')), v('verdict') || 'handled', 'owner') });
      if (p === 'undo' && post) return json(await undoAction(env, env.DB, Number(v('id')), 'owner'));
      if (p === 'allow' && post && v('value')) {
        await env.DB.prepare('INSERT OR REPLACE INTO soc_allow (value, note, at) VALUES (?, ?, ?)').bind(v('value').toLowerCase(), v('note'), iso(Date.now())).run();
        return json({ ok: true });
      }
      return json({ error: 'unknown route' }, 404);
    }
    if (u.pathname !== '/run') return new Response('Not found', { status: 404 });
    if (q('test')) return json(await notify(env, '🧪 Sentinel test', 'Alerts reach you here. Nothing is broken.'));
    const force = { report: q('report'), expiry: q('expiry') };
    if (q('wait') || force.report || force.expiry) return json(await tick(env, { source: 'manual', force }));
    ctx.waitUntil(tick(env, { source: 'cronjob' }));
    return new Response('started', { status: 202 });
  },
};
