/**
 * Tamper (every 5 min): snapshots of sensitive app data compared with the last run.
 * Snapshots live in KV ('soc_tamper'); a query that fails keeps its old snapshot,
 * so one error can never read as "everything changed".
 */
import { SOC } from './config.js';

export async function tamper(ctx, raise) {
  const { env, now } = ctx;
  const db = env.DB;
  let snap = {};
  try { snap = JSON.parse((await env.STATE.get('soc_tamper')) || '{}') || {}; } catch { snap = {}; }
  const next = { ...snap };

  for (const t of SOC.TAMPER) {
    let rows;
    try { rows = (await db.prepare(t.sql).all()).results || []; }
    catch (e) { ctx.errors.push('tamper ' + t.id + ': ' + String(e.message || e).slice(0, 120)); continue; }
    const map = Object.fromEntries(rows.map((r) => [String(r.k), String(r.v)]));
    const before = snap[t.id];
    next[t.id] = map;
    if (!before) continue;                               // first sight: learn only

    if (t.mode === 'price_drop') {
      const drops = Object.keys(map).filter((k) => k in before && Number(before[k]) > 0 && Number(map[k]) < Number(before[k]) * (1 - t.dropPct / 100));
      if (drops.length) await raise(t.sev || 'HIGH', 'price_drop', drops.length + ' product price(s) dropped more than ' + t.dropPct + '%',
        { facts: drops.slice(0, 8).map((k) => k + ': ' + before[k] + ' → ' + map[k]).join('\n'), cooldownH: 1 });
      continue;
    }
    const added = Object.keys(map).filter((k) => !(k in before));
    const removed = Object.keys(before).filter((k) => !(k in map));
    const changed = Object.keys(map).filter((k) => k in before && before[k] !== map[k]);
    const on = new Set(t.on || ['added', 'removed', 'changed']);
    const lines = [
      ...(on.has('added') ? added.map((k) => 'added ' + k + (map[k] ? ' (' + map[k] + ')' : '')) : []),
      ...(on.has('removed') ? removed.map((k) => 'removed ' + k) : []),
      ...(on.has('changed') ? changed.map((k) => k + ': ' + before[k] + ' → ' + map[k]) : []),
    ];
    if (lines.length) await raise(t.sev || 'HIGH', 'tamper:' + t.id, t.label + ' changed', { facts: lines.slice(0, 10).join('\n'), cooldownH: 1 });
  }

  // Tables that only grow: a lower count means rows were deleted.
  next.counts = { ...(snap.counts || {}) };
  for (const table of SOC.NO_DELETE_TABLES) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) continue;
    let n;
    try { n = await db.prepare('SELECT COUNT(*) n FROM ' + table).first('n'); }
    catch (e) { ctx.errors.push('count ' + table + ': ' + String(e.message || e).slice(0, 120)); continue; }
    const was = snap.counts && snap.counts[table];
    if (was != null && n < was) await raise('HIGH', 'rows_deleted:' + table, (was - n) + ' row(s) deleted from ' + table, { facts: table + ': ' + was + ' → ' + n, cooldownH: 1 });
    next.counts[table] = n;
  }
  if (JSON.stringify(next) !== JSON.stringify(snap)) await env.STATE.put('soc_tamper', JSON.stringify(next));
  return { tables: SOC.TAMPER.length };
}
