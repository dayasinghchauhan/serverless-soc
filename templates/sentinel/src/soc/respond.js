/**
 * Cases, blocks and automatic actions (all in the app's D1, so your admin can show them).
 *
 *   soc_incidents  one case per rule + subject; every alert joins its open case
 *   soc_blocks     Cloudflare IP Access Rules we created, with expiry
 *   soc_actions    every automatic action, with how to undo it
 *   soc_allow      never-block list (exact IP, or a prefix ending in '.' or ':')
 */
import { SOC } from './config.js';
import { iso, parse, ipKind, isPrivateIp, isCfWorkerIp, netType, cfApi, H, DAY } from './util.js';

const SQL = [
  `CREATE TABLE IF NOT EXISTS soc_incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, rule TEXT NOT NULL, subject TEXT NOT NULL DEFAULT '',
    sev TEXT NOT NULL, title TEXT, status TEXT NOT NULL DEFAULT 'open', first_at TEXT, last_at TEXT, hits INTEGER NOT NULL DEFAULT 1,
    ip TEXT, country TEXT, asn_org TEXT, who TEXT, actions TEXT, verdict TEXT, closed_by TEXT, closed_at TEXT, close_reason TEXT)`,
  'CREATE INDEX IF NOT EXISTS soc_incidents_open ON soc_incidents (status, rule, subject)',
  `CREATE TABLE IF NOT EXISTS soc_blocks (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, reason TEXT, incident_id INTEGER,
    created_at TEXT, expires_at TEXT, cf_rule_id TEXT, status TEXT NOT NULL DEFAULT 'active', removed_at TEXT, removed_by TEXT, country TEXT, asn_org TEXT)`,
  'CREATE INDEX IF NOT EXISTS soc_blocks_ip ON soc_blocks (ip, status)',
  `CREATE TABLE IF NOT EXISTS soc_actions (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, action TEXT NOT NULL, target TEXT, auto INTEGER NOT NULL DEFAULT 1,
    incident_id INTEGER, result TEXT, undo TEXT, undone_at TEXT, undone_by TEXT)`,
  'CREATE TABLE IF NOT EXISTS soc_allow (value TEXT PRIMARY KEY, note TEXT, at TEXT)',
];
const ready = new WeakSet();   // per database binding
export async function ensureSoc(db) {
  if (ready.has(db)) return;
  for (const s of SQL) await db.prepare(s).run();
  ready.add(db);
}

const RANK = { CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0 };

/** Join the open case for rule + subject, or open one. Returns the case id. */
export async function upsertIncident(db, { rule, subject = '', sev, title, ip = '', country = '', asnOrg = '', who = '' }, now = Date.now()) {
  await ensureSoc(db);
  subject = String(subject).slice(0, 120);
  const open = await db.prepare("SELECT id, sev FROM soc_incidents WHERE rule = ? AND subject = ? AND status <> 'closed' ORDER BY id DESC LIMIT 1").bind(rule, subject).first();
  if (open) {
    const s = (RANK[sev] || 0) > (RANK[open.sev] || 0) ? sev : open.sev;
    await db.prepare("UPDATE soc_incidents SET hits = hits + 1, last_at = ?, sev = ?, ip = COALESCE(NULLIF(ip, ''), ?), country = COALESCE(NULLIF(country, ''), ?), asn_org = COALESCE(NULLIF(asn_org, ''), ?), who = COALESCE(NULLIF(?, ''), who) WHERE id = ?")
      .bind(iso(now), s, ip, country, asnOrg, who, open.id).run();
    return open.id;
  }
  const r = await db.prepare('INSERT INTO soc_incidents (rule, subject, sev, title, first_at, last_at, ip, country, asn_org, who) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(rule, subject, sev, String(title).slice(0, 200), iso(now), iso(now), ip, country, asnOrg, who).run();
  return r.meta.last_row_id;
}

/** Quiet cases close themselves: MEDIUM after 3 days, HIGH after 14. CRITICAL only by a person. */
export async function autoClose(db, now = Date.now()) {
  await ensureSoc(db);
  await db.prepare(`UPDATE soc_incidents SET status = 'closed', closed_by = 'auto', closed_at = ?, close_reason = 'quiet'
    WHERE status <> 'closed' AND ((sev = 'MEDIUM' AND last_at < ?) OR (sev = 'HIGH' AND last_at < ?))`).bind(iso(now), iso(now - 3 * DAY), iso(now - 14 * DAY)).run();
}

/** A person's verdict on a case: 'mine' (it was me), 'handled', 'false_alarm'. Closes it. */
export async function closeIncident(db, id, verdict, by = 'owner', now = Date.now()) {
  await ensureSoc(db);
  const r = await db.prepare("UPDATE soc_incidents SET status = 'closed', verdict = ?, closed_by = ?, closed_at = ?, close_reason = ? WHERE id = ? AND status <> 'closed'")
    .bind(verdict, by, iso(now), verdict, id).run();
  return !!r.meta.changes;
}

export async function recordAction(db, { action, target = '', incident = null, result = '', undo = null, auto = true }, now = Date.now()) {
  await ensureSoc(db);
  const r = await db.prepare('INSERT INTO soc_actions (at, action, target, auto, incident_id, result, undo) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(iso(now), action, String(target).slice(0, 200), auto ? 1 : 0, incident, String(result).slice(0, 300), undo ? JSON.stringify(undo) : null).run();
  if (incident) {
    const row = await db.prepare('SELECT actions FROM soc_incidents WHERE id = ?').bind(incident).first();
    if (row) {
      const list = parse(row.actions, []);
      list.push({ action, target, result, at: iso(now) });
      await db.prepare('UPDATE soc_incidents SET actions = ? WHERE id = ?').bind(JSON.stringify(list.slice(-20)), incident).run();
    }
  }
  return r.meta.last_row_id;
}

/** Why this IP must never be blocked automatically ('' = may be blocked). */
export async function protectedWhy(db, ip, now = Date.now()) {
  if (!ipKind(ip)) return 'not an IP';
  if (isPrivateIp(ip)) return 'private address';
  if (isCfWorkerIp(ip)) return 'Cloudflare Workers network (may be your own Worker)';
  await ensureSoc(db);
  const allow = ((await db.prepare('SELECT value FROM soc_allow').all()).results || []).map((a) => a.value);
  if (allow.some((v) => (/[.:]$/.test(v) ? ip.startsWith(v) : ip === v))) return 'never-block list';
  const admin = await db.prepare("SELECT 1 FROM security_events WHERE kind = 'admin_ok' AND ip = ? AND created_at >= ? LIMIT 1").bind(ip, iso(now - DAY)).first().catch(() => null);
  if (admin) return 'an admin used it in the last 24 h';
  return '';
}

/**
 * Block an IP at Cloudflare (IP Access Rule on SOC.BLOCK_ZONE). Escalates: 24 h, then 7 days,
 * then 30 days for repeats within 30 days. Only hosting networks / abroad, never home residential.
 */
export async function blockIp(env, db, { ip, reason = '', incident = null, country = '', asnOrg = '' }, now = Date.now()) {
  await ensureSoc(db);
  ip = String(ip || '').trim().toLowerCase();
  if (!SOC.AUTO.blockHostingOrAbroad || !SOC.BLOCK_ZONE) return { ok: false, skipped: 'automatic blocking is off' };
  const type = netType(country, asnOrg);
  if (type === 'home') return { ok: false, skipped: 'home-country residential address (may be shared by real customers)' };
  const why = await protectedWhy(db, ip, now);
  if (why) return { ok: false, skipped: why };
  const active = await db.prepare("SELECT id, expires_at FROM soc_blocks WHERE ip = ? AND status = 'active' LIMIT 1").bind(ip).first();
  const prior = await db.prepare('SELECT COUNT(*) n FROM soc_blocks WHERE ip = ? AND created_at >= ?').bind(ip, iso(now - 30 * DAY)).first('n');
  const hours = SOC.BLOCK_HOURS[Math.min(prior, SOC.BLOCK_HOURS.length - 1)];
  const until = iso(now + hours * H);
  if (active) {
    if (active.expires_at < until) await db.prepare('UPDATE soc_blocks SET expires_at = ? WHERE id = ?').bind(until, active.id).run();
    return { ok: true, already: true };
  }
  let cfId = null, status = 'active', note;
  if (!env.CF_TOKEN) { status = 'pending_token'; note = 'Recorded only: CF_TOKEN is not set.'; }
  else {
    try {
      const zone = await zoneId(env, SOC.BLOCK_ZONE);
      const j = await cfApi(env, '/zones/' + zone + '/firewall/access_rules/rules', { method: 'POST', body: JSON.stringify({
        mode: 'block', configuration: { target: ipKind(ip) === 6 ? 'ip6' : 'ip', value: ip }, notes: ('soc auto until ' + until + ' UTC: ' + reason).slice(0, 500) }) });
      cfId = j.result && j.result.id;
      note = 'Blocked for ' + (hours >= 48 ? hours / 24 + ' days' : hours + ' h') + ' (' + type + ').';
    } catch (e) {
      if (!/duplicate|already exists/i.test(String(e.message))) return { ok: false, error: String(e.message).slice(0, 200) };
      note = 'Cloudflare already had a block for it.';
    }
  }
  const r = await db.prepare('INSERT INTO soc_blocks (ip, reason, incident_id, created_at, expires_at, cf_rule_id, status, country, asn_org) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(ip, String(reason).slice(0, 200), incident, iso(now), until, cfId, status, country, asnOrg).run();
  await recordAction(db, { action: 'block_ip', target: ip, incident, result: note, undo: { action: 'unblock', id: r.meta.last_row_id } }, now);
  return { ok: true, status, hours, note };
}

const zones = new Map();
async function zoneId(env, name) {
  if (zones.has(name)) return zones.get(name);
  const j = await cfApi(env, '/zones?name=' + encodeURIComponent(name));
  const id = j.result && j.result[0] && j.result[0].id;
  if (!id) throw new Error('zone not found: ' + name);
  zones.set(name, id);
  return id;
}

async function unblockRow(env, db, b, by, now) {
  if (b.cf_rule_id && env.CF_TOKEN) {
    try { await cfApi(env, '/zones/' + (await zoneId(env, SOC.BLOCK_ZONE)) + '/firewall/access_rules/rules/' + b.cf_rule_id, { method: 'DELETE' }); }
    catch (e) { if (!/not.?found|10001|404/i.test(String(e.message))) return false; }
  }
  await db.prepare("UPDATE soc_blocks SET status = 'removed', removed_at = ?, removed_by = ? WHERE id = ?").bind(iso(now), by, b.id).run();
  return true;
}

/** Expired blocks come off Cloudflare (run every SOC cycle). */
export async function expireBlocks(env, db, now = Date.now()) {
  await ensureSoc(db);
  const rows = (await db.prepare("SELECT id, ip, cf_rule_id FROM soc_blocks WHERE status IN ('active', 'pending_token') AND expires_at < ? LIMIT 25").bind(iso(now)).all()).results || [];
  let n = 0;
  for (const b of rows) if (await unblockRow(env, db, b, 'expired', now)) n++;
  return n;
}

/** Undo one automatic action by its id (unblock; a sign-out cannot be undone, sessions are re-created by signing in). */
export async function undoAction(env, db, actionId, by = 'owner', now = Date.now()) {
  await ensureSoc(db);
  const a = await db.prepare('SELECT * FROM soc_actions WHERE id = ?').bind(actionId).first();
  if (!a) return { ok: false, error: 'no such action' };
  if (a.undone_at) return { ok: true, already: true };
  const u = parse(a.undo, null);
  if (!u) return { ok: false, error: 'this action cannot be undone' };
  if (u.action === 'unblock') {
    const b = await db.prepare('SELECT * FROM soc_blocks WHERE id = ?').bind(u.id).first();
    if (b && b.status !== 'removed' && !(await unblockRow(env, db, b, by, now))) return { ok: false, error: 'Cloudflare refused the unblock' };
  }
  await db.prepare('UPDATE soc_actions SET undone_at = ?, undone_by = ? WHERE id = ?').bind(iso(now), by, actionId).run();
  return { ok: true };
}

export async function signOutAll(env, db, { incident = null, reason = '' } = {}, now = Date.now()) {
  if (!SOC.SIGN_OUT_ALL_SQL) return { ok: false, skipped: 'SIGN_OUT_ALL_SQL not set' };
  try {
    const r = await db.prepare(SOC.SIGN_OUT_ALL_SQL).run();
    await recordAction(db, { action: 'sign_out_all', target: 'admin sessions', incident, result: (r.meta.changes || 0) + ' sessions ended. ' + reason }, now);
    return { ok: true, ended: r.meta.changes || 0 };
  } catch (e) { return { ok: false, error: String(e.message || e).slice(0, 160) }; }
}

export async function holdOrder(env, db, orderId, { incident = null } = {}, now = Date.now()) {
  if (!SOC.AUTO.holdUnderpricedOrders || !SOC.HOLD_ORDER_SQL) return { ok: false, skipped: 'off' };
  const r = await db.prepare(SOC.HOLD_ORDER_SQL).bind(orderId).run();
  if (r.meta.changes) await recordAction(db, { action: 'hold_order', target: orderId, incident, result: 'held before courier booking' }, now);
  return { ok: !!r.meta.changes };
}
