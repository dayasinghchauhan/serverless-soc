/**
 * Posture (hourly): the Cloudflare account itself. API tokens, members + two-factor,
 * DNS and security settings of your zones, private buckets that gained a public address,
 * and changes by anyone who is not on your own list. Snapshot-diffed; a failed step keeps
 * its old snapshot (an API hiccup is never a "change").
 */
import { SOC } from './config.js';
import { cfApi, diffMaps } from './util.js';
import { attribute, auditLog, isOwn, describe } from './who.js';

export async function posture(ctx, raise) {
  const { env, state } = ctx;
  if (!env.CF_TOKEN || !env.CF_ACCOUNT) return { skipped: 'CF_TOKEN / CF_ACCOUNT not set' };
  const acc = '/accounts/' + env.CF_ACCOUNT;
  const snap = state.posture || {};
  const next = {};
  const errors = [];
  const step = async (name, fn) => { try { await fn(); } catch (e) { errors.push(name + ': ' + String(e.message || e).slice(0, 160)); } };
  const ownOrRaise = async (sev, key, title, facts, filter) => {
    const w = await attribute(ctx, filter);
    if (w.found && w.own) { ctx.note(title + ' (by ' + w.who.join(', ') + ')'); return; }
    await raise(sev, key, title, { facts, who: (w.strangers.length ? w.strangers : w.who).join(', ') || 'nobody named in the audit log',
      why: w.found ? 'not one of your logins / tokens' : 'no matching entry in the Cloudflare audit log', cooldownH: 1 });
  };

  await step('tokens', async () => {
    next.tokens = Object.fromEntries((await cfApi(env, acc + '/tokens?per_page=100')).result.map((t) => [t.id, t.name + '|' + t.status]));
    if (!snap.tokens) return;
    const d = diffMaps(snap.tokens, next.tokens);
    if (d.added.length) await ownOrRaise('HIGH', 'cf_token_added:' + d.added[0], 'New Cloudflare API token created', d.added.map((k) => next.tokens[k].split('|')[0]).join(', '), (e) => /token/i.test(JSON.stringify(e.resource || {}) + JSON.stringify(e.action || {})));
  });

  await step('members', async () => {
    const m = (await cfApi(env, acc + '/members?per_page=100')).result;
    next.members = Object.fromEntries(m.map((x) => [lc(x.user ? x.user.email : x.id), String(!!(x.user && x.user.two_factor_authentication_enabled))]));
    if (!snap.members) return;
    const d = diffMaps(snap.members, next.members);
    if (d.added.length) {
      const allOwn = d.added.every((k) => SOC.OWN_EMAILS.map(lc).includes(k));
      // Locked rule: a new member always rings at least HIGH, CRITICAL unless it is your own other login.
      const w = await attribute(ctx, (e) => /member/i.test(JSON.stringify(e.resource || {}) + JSON.stringify(e.action || {})), 48);
      await raise(allOwn && w.own ? 'HIGH' : 'CRITICAL', 'cf_member_added:' + d.added[0], 'New member on the Cloudflare account', { facts: d.added.join(', '), who: w.who.join(', '), cooldownH: 1 });
    }
    const off = d.changed.filter((k) => next.members[k] === 'false');
    if (off.length) await raise('CRITICAL', 'cf_2fa_off', 'Two-factor login turned OFF on Cloudflare', { facts: off.join(', '), cooldownH: 1 });
  });

  await step('zones', async () => {
    next.dns = {}; next.settings = {};
    for (const name of SOC.ZONES) {
      const z = (await cfApi(env, '/zones?name=' + encodeURIComponent(name))).result[0];
      if (!z) throw new Error('zone not found: ' + name);
      for (const r of (await cfApi(env, '/zones/' + z.id + '/dns_records?per_page=500')).result) {
        if (/_acme-challenge|_cf-custom-hostname/.test(r.name)) continue;   // certificate renewals churn these by themselves
        next.dns[r.type + ' ' + r.name + ' ' + String(r.content).slice(0, 120)] = String(r.proxied);
      }
      for (const s of (await cfApi(env, '/zones/' + z.id + '/settings')).result) if (SOC.ZONE_SETTINGS.includes(s.id)) next.settings[name + ' ' + s.id] = String(s.value);
    }
    if (snap.dns) {
      const d = diffMaps(snap.dns, next.dns);
      const lines = [...d.added.map((k) => 'added ' + k), ...d.removed.map((k) => 'removed ' + k), ...d.changed.map((k) => 'proxy changed ' + k)];
      if (lines.length) await ownOrRaise('HIGH', 'dns_changed', 'DNS records changed', lines.slice(0, 10).join('\n'), (e) => /dns/i.test(JSON.stringify(e.resource || {}) + JSON.stringify(e.action || {})));
    }
    if (snap.settings) {
      const d = diffMaps(snap.settings, next.settings);
      if (d.changed.length) await ownOrRaise('HIGH', 'zone_settings_changed', 'Site security settings changed', d.changed.map((k) => k + ': ' + snap.settings[k] + ' → ' + next.settings[k]).join('\n'),
        (e) => /setting|zone/i.test(JSON.stringify(e.resource || {}) + JSON.stringify(e.action || {})));
    }
  });

  await step('private buckets', async () => {
    for (const b of SOC.PRIVATE_BUCKETS) {
      const dev = (await cfApi(env, acc + '/r2/buckets/' + b + '/domains/managed')).result;
      const custom = (await cfApi(env, acc + '/r2/buckets/' + b + '/domains/custom')).result;
      const urls = [dev && dev.enabled && (dev.domain || 'r2.dev URL'), ...((custom && custom.domains) || []).map((d) => d.domain)].filter(Boolean);
      if (urls.length) await raise('CRITICAL', 'backups_public:' + b, 'Private bucket "' + b + '" is PUBLIC', { facts: 'Public address: ' + urls.join(', '), cooldownH: 1 });
    }
  });

  await step('audit log', async () => {
    const a = await auditLog(ctx, 2);
    if (a.failed) throw new Error(a.failed);
    const seen = new Set(state.auditSeen || []);
    const fresh = a.events.filter((e) => e.id && !seen.has(e.id));
    state.auditSeen = a.events.map((e) => e.id).filter(Boolean).slice(0, 300);
    const own = fresh.filter(isOwn), strangers = fresh.filter((e) => !isOwn(e));
    if (own.length) ctx.note('Cloudflare changes by you: ' + describe(own).join('; '));
    if (strangers.length && snap.tokens) await raise('HIGH', 'cf_change_by_stranger:' + (strangers[0].actor && (strangers[0].actor.email || strangers[0].actor.token_name) || 'unknown'),
      'Cloudflare change by someone not on your list', { facts: describe(strangers).join('\n'), cooldownH: 6 });
  });

  state.posture = { ...snap, ...next };
  if (errors.length) await raise('MEDIUM', 'soc_blind', 'Security monitor cannot read part of Cloudflare', { facts: errors.join('\n'), cooldownH: 24 });
  return { errors };
}
const lc = (s) => String(s || '').toLowerCase();
