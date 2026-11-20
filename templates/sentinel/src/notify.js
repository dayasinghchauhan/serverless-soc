// Alert roads shared by uptime and the SOC. Any one failing never stops the others.
import { NAME } from './checks.js';

/**
 * level: 'page' (phone push + channel) | 'channel' (channel only, no push) | 'report' (REPORT_WEBHOOK if set)
 */
export async function notify(env, title, text, { level = 'page', webhook } = {}) {
  const msg = ('**' + title + '**\n' + text).slice(0, 1900);
  const roads = [];
  const discord = webhook || (level === 'report' && env.REPORT_WEBHOOK) || env.DISCORD_WEBHOOK;
  if (discord) roads.push(['discord', () => fetch(discord, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: NAME + ' Sentinel', allowed_mentions: { parse: [] }, content: msg }) })]);
  if (level !== 'report' && env.SLACK_WEBHOOK) roads.push(['slack', () => fetch(env.SLACK_WEBHOOK, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: msg.replace(/\*\*/g, '*') }) })]);
  if (level === 'page' && env.NTFY_URL) roads.push(['ntfy', () => fetch(env.NTFY_URL, { method: 'POST',
    headers: { Title: (NAME + ': ' + title).replace(/[^\x20-\x7e]/g, '').slice(0, 200) || NAME, Priority: title.startsWith('✅') ? '3' : '5' }, body: text })]);
  const res = {};
  await Promise.all(roads.map(async ([k, f]) => { try { res[k] = (await f()).ok; } catch { res[k] = false; } }));
  return res;
}
