/**
 * raise(): the one door every security finding goes through.
 *
 *   CRITICAL / HIGH  → channel + phone push        MEDIUM → channel only
 *   LOW / own change → the 9 AM daily summary       first run ("learning") → nothing
 *
 * A repeat of the same key inside its cooldown only counts on the open case.
 * Rule overrides (env SOC_RULES JSON): { "<rule>": { "off": true, "sev": "MEDIUM", "cooldownH": 24, "ignore": ["word"] } };
 * LOCKED_RULES can never be switched off or downgraded.
 */
import { LOCKED_RULES } from './config.js';
import { upsertIncident } from './respond.js';
import { fourParts } from './guide.js';
import { parse } from './util.js';

export const COOLDOWN_H = 6;

export function makeRaise(ctx) {
  const rules = parse(ctx.env.SOC_RULES, {}) || {};
  return async function raise(sev, key, title, { facts = '', from = null, who = '', why = '', cooldownH = COOLDOWN_H, quiet = false } = {}) {
    const { state, now } = ctx;
    const rule = key.split(':')[0], subject = key.slice(rule.length + 1);
    if (ctx.learning) return null;
    if (sev === 'LOW') { ctx.note(title + (facts ? ': ' + facts.split('\n')[0] : '')); return null; }
    const o = rules[rule] || {};
    if (!LOCKED_RULES.has(rule)) {
      if (o.off) { ctx.note('Rule off, not sent: ' + title); return null; }
      const hay = (title + ' ' + facts + ' ' + JSON.stringify(from || {})).toLowerCase();
      const word = (o.ignore || []).find((w) => w && hay.includes(String(w).toLowerCase()));
      if (word) { ctx.note('Ignored by rule ("' + word + '"): ' + title); return null; }
      if (o.sev) sev = o.sev;
    }
    if (o.cooldownH > 0) cooldownH = o.cooldownH;
    const f = from || {};
    const caseId = await upsertIncident(ctx.env.DB, { rule, subject, sev, title, ip: f.ip || '', country: f.country || '', asnOrg: f.asnOrg || '', who }, now);
    state.counts[rule] = (state.counts[rule] || 0) + 1;
    if (state.cooldown[key] && now - state.cooldown[key] < cooldownH * 3_600_000) return caseId;
    state.cooldown[key] = now;
    if (!quiet) {
      const head = '🛡️ [' + sev + '] ' + title;
      await ctx.send(ctx.env, head, fourParts(rule, { facts, from, who, why }) + '\nCase #' + caseId, { level: sev === 'MEDIUM' ? 'channel' : 'page' });
    }
    ctx.raised.push({ sev, key, title, caseId });
    return caseId;
  };
}
