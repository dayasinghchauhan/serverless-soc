/**
 * Self-test (daily): re-run the attacks your app must keep refusing. A protection that
 * silently regressed (a refactor removed an auth check, a deploy shipped .env) is an incident.
 * Requests carry SOC.SELFTEST_UA so detect() does not count them as attacks.
 */
import { SOC, SITE } from './config.js';
import { cfApi } from './util.js';
import { recordAction } from './respond.js';

const SECRET = /-----BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|\bsk_live_[0-9a-zA-Z]{10,}|\bxox[abp]-[0-9A-Za-z-]{10,}|\bgh[pousr]_[0-9A-Za-z]{20,}|\b(api[_-]?key|secret|password|token)\s*[=:]\s*\S{8,}/i;

export async function selftest(ctx) {
  const failed = [];
  for (const t of SOC.SELFTEST) {
    try {
      const r = await fetch(SITE + t.path, { method: t.method || 'GET', redirect: 'manual', headers: { 'User-Agent': SOC.SELFTEST_UA, ...(t.headers || {}) } });
      const body = await r.text().catch(() => '');
      if (t.expect && !t.expect.includes(r.status)) failed.push(t.name + ': HTTP ' + r.status + ' (expected ' + t.expect.join('/') + ')');
      if (t.expectNot && t.expectNot.includes(r.status)) {
        // Many static hosts answer every path with the app's index.html (200): that is not a leak.
        const spaFallback = /^\s*<!doctype html|<html[\s>]/i.test(body) && !SECRET.test(body);
        if (!spaFallback) failed.push(t.name + ': ' + t.path + ' answered ' + r.status + (SECRET.test(body) ? ' WITH SECRET-LOOKING CONTENT' : ''));
      }
    } catch (e) { ctx.errors.push('selftest ' + t.name + ': ' + String(e.message || e).slice(0, 100)); }
  }
  return failed;
}

/** Old Pages deployments keep serving their OLD code against the LIVE database: prune them. */
export async function pruneDeployments(ctx) {
  const { env, now } = ctx;
  if (!SOC.PAGES_PROJECT || !(SOC.PRUNE_KEEP_PRODUCTION > 0) || !env.CF_TOKEN || !env.CF_ACCOUNT) return { skipped: true };
  const base = '/accounts/' + env.CF_ACCOUNT + '/pages/projects/' + SOC.PAGES_PROJECT + '/deployments';
  let removed = 0;
  for (const [envName, keep] of [['production', SOC.PRUNE_KEEP_PRODUCTION], ['preview', SOC.PRUNE_KEEP_PREVIEW || SOC.PRUNE_KEEP_PRODUCTION]]) {
    const list = (await cfApi(env, base + '?env=' + envName + '&per_page=25')).result || [];
    for (const d of list.slice(keep)) {
      try { await cfApi(env, base + '/' + d.id + '?force=true', { method: 'DELETE' }); removed++; } catch (e) { ctx.errors.push('prune ' + d.id + ': ' + String(e.message).slice(0, 80)); }
    }
  }
  if (removed) await recordAction(env.DB, { action: 'prune_deployments', target: SOC.PAGES_PROJECT, result: removed + ' old deployments deleted' }, now);
  return { removed };
}
