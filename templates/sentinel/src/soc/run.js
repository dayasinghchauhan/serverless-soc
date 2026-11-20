/**
 * The SOC run (every 5 minutes, on the sentinel's own cron).
 *
 *   every run   detect (app security events) · tamper (DB snapshots) · expire blocks
 *   hourly      posture (Cloudflare account) · integrity (page scripts, public repos)
 *   daily       self-test · prune old deployments · close quiet cases · remind open CRITICAL cases
 *   09:00       daily summary of everything that did not ring (own changes, blocked attacks, notes)
 *
 * The first run only LEARNS (networks, snapshots, script inventory): it never alerts on what
 * already existed. State: KV 'soc_state' (small) + 'soc_tamper' (snapshots).
 */
import { SOC } from './config.js';
import { makeRaise } from './raise.js';
import { detect } from './detect.js';
import { tamper } from './tamper.js';
import { posture } from './posture.js';
import { integrity } from './integrity.js';
import { selftest, pruneDeployments } from './selftest.js';
import { ensureSoc, expireBlocks, autoClose } from './respond.js';
import { notify } from '../notify.js';
import { iso, dayKey, H, DAY } from './util.js';

const SLOTS = { posture: H, integrity: H, selftest: DAY, prune: DAY, close: DAY };

export async function runSoc(env, { now = Date.now(), force = {}, send = notify } = {}) {
  let state = {};
  try { state = JSON.parse((await env.STATE.get('soc_state')) || '{}') || {}; } catch { state = {}; }
  state.cooldown ||= {}; state.counts ||= {}; state.slots ||= {}; state.notes ||= []; state.digest ||= { blocked: 0, attacks: 0, probes: 0 };
  const ctx = {
    env, state, now, send, learning: !state.learned, raised: [], errors: [], digest: state.digest,
    note: (t) => { state.notes.push(new Date(now).toISOString().slice(11, 16) + ' ' + String(t).slice(0, 200)); state.notes = state.notes.slice(-60); },
  };
  const raise = makeRaise(ctx);
  const due = (k) => force[k] || !state.slots[k] || now - state.slots[k] >= SLOTS[k] - 60_000;
  const step = async (name, fn) => { try { return await fn(); } catch (e) { ctx.errors.push(name + ': ' + String(e.message || e).slice(0, 160)); return null; } };
  const out = {};

  await ensureSoc(env.DB);
  out.detect = await step('detect', () => detect(ctx, raise));
  out.tamper = await step('tamper', () => tamper(ctx, raise));
  out.expired = await step('expire', () => expireBlocks(env, env.DB, now));
  if (due('posture')) { out.posture = await step('posture', () => posture(ctx, raise)); state.slots.posture = now; }
  if (due('integrity')) { out.integrity = await step('integrity', () => integrity(ctx, raise)); state.slots.integrity = now; }
  if (!ctx.learning && due('selftest')) {
    const failed = await step('selftest', () => selftest(ctx));
    if (failed && failed.length) await raise('HIGH', 'selftest_failed', 'A security protection stopped working', { facts: failed.join('\n'), cooldownH: 20 });
    out.selftest = failed; state.slots.selftest = now;
  }
  if (due('prune')) { out.prune = await step('prune', () => pruneDeployments(ctx)); state.slots.prune = now; }
  if (due('close')) {
    await step('close', () => autoClose(env.DB, now));
    // An open CRITICAL case nobody answered for a day rings again once a day.
    const stale = (await env.DB.prepare("SELECT id, title FROM soc_incidents WHERE sev = 'CRITICAL' AND status = 'open' AND first_at < ?").bind(iso(now - DAY)).all()).results || [];
    if (stale.length && !ctx.learning) await send(env, '🛡️ [CRITICAL] still open', stale.map((c) => '#' + c.id + ' ' + c.title).join('\n') + '\nClose each case when handled (POST /soc/case).', { level: 'page' });
    state.slots.close = now;
  }

  // Daily summary: everything that was noted instead of ringing.
  const d = new Date(now), today = dayKey(now);
  if (force.summary || (!ctx.learning && state.summaryDay !== today && d.getUTCHours() * 60 + d.getUTCMinutes() >= SOC.SUMMARY_UTC_MIN)) {
    const open = await env.DB.prepare("SELECT sev, COUNT(*) n FROM soc_incidents WHERE status = 'open' GROUP BY sev").all();
    const lines = [
      'Open cases: ' + ((open.results || []).map((r) => r.sev + ' ' + r.n).join(', ') || 'none'),
      'Blocked automatically: ' + state.digest.blocked + ' · attacks refused: ' + state.digest.attacks + ' · private-file probes refused: ' + state.digest.probes,
      ...(Object.keys(state.counts).length ? ['Rules that fired: ' + Object.entries(state.counts).map(([k, n]) => k + ' ' + n).join(', ')] : []),
      ...(state.notes.length ? ['Noted (no alert):', ...state.notes.map((t) => '• ' + t)] : ['Nothing else noted.']),
    ];
    await send(env, '🛡️ Daily security summary', lines.join('\n'), { level: 'report' });
    state.summaryDay = today; state.notes = []; state.counts = {}; state.digest = { blocked: 0, attacks: 0, probes: 0 };
  }

  // The monitor watching itself.
  state.failRuns = ctx.errors.length ? (state.failRuns || 0) + 1 : 0;
  if (state.failRuns >= 3 && !ctx.learning) await raise('MEDIUM', 'soc_failing', 'Security monitor is failing', { facts: state.failRuns + ' runs in a row:\n' + ctx.errors.join('\n'), cooldownH: 24 });
  for (const [k, t] of Object.entries(state.cooldown)) if (now - t > 30 * DAY) delete state.cooldown[k];
  if (ctx.learning) { state.learned = now; state.summaryDay = today; }   // first summary: tomorrow, not minutes after install
  await env.STATE.put('soc_state', JSON.stringify(state));
  console.log(JSON.stringify({ run: 'soc', learning: ctx.learning, raised: ctx.raised.map((r) => r.sev + ' ' + r.key), errors: ctx.errors }));
  return { learning: ctx.learning, raised: ctx.raised, errors: ctx.errors, ...out };
}
