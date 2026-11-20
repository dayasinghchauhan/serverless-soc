/**
 * Who made a change? Every Cloudflare change alert asks the account audit log first.
 * A change by one of YOUR logins, or by one of your tokens doing its job, is "own":
 * it goes to the daily summary with the name, not to your phone. Anything else rings, with the name.
 *
 * Audit-log field names differ between Cloudflare's audit log versions; this reads
 * actor.token_name / actor.email / actor.type and action.type / resource.type defensively.
 */
import { SOC } from './config.js';
import { cfApi, H } from './util.js';

export async function auditLog(ctx, hours = 2) {
  const { env, now } = ctx;
  ctx.cache ||= {};
  const key = 'audit' + hours;
  if (ctx.cache[key]) return ctx.cache[key];
  try {
    const since = new Date(now - hours * H).toISOString();
    const j = await cfApi(env, '/accounts/' + env.CF_ACCOUNT + '/audit_logs?per_page=100&direction=desc&since=' + encodeURIComponent(since));
    ctx.cache[key] = { events: j.result || [] };
  } catch (e) { ctx.cache[key] = { events: [], failed: String(e.message || e) }; }
  return ctx.cache[key];
}

const lc = (s) => String(s || '').toLowerCase();
export const actorName = (e) => (e.actor && (e.actor.token_name || e.actor.email || e.actor.type)) || 'unknown';
const what = (e) => [e.action && e.action.type, e.resource && e.resource.type].filter(Boolean).join(' ');

export function isOwn(e) {
  const a = e.actor || {};
  if (a.token_name) {
    const job = SOC.OWN_TOKENS[a.token_name];
    return !!job && job.test(what(e));          // your token, but doing something it does not exist for = not own
  }
  return SOC.OWN_EMAILS.map(lc).includes(lc(a.email));
}

/** Attribute recent changes matching `filter` (event → bool). */
export async function attribute(ctx, filter, hours = 2) {
  const a = await auditLog(ctx, hours);
  const hits = a.events.filter(filter);
  const who = [...new Set(hits.map(actorName))];
  const strangers = [...new Set(hits.filter((e) => !isOwn(e)).map(actorName))];
  return { found: hits.length > 0, own: hits.length > 0 && strangers.length === 0, who, strangers, failed: a.failed };
}

export const describe = (events) => events.slice(0, 8).map((e) => actorName(e) + ': ' + what(e) + (e.when ? ' at ' + String(e.when).slice(0, 16) : ''));
