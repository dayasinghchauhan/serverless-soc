/**
 * Integrity (hourly): the serverless version of file-integrity monitoring.
 *
 *  Page scripts   every <script> on the configured pages (home, product, checkout…).
 *                 A script from a NEW outside host, or one of your own scripts changing while
 *                 no new version was deployed, is how card-skimming (Magecart) code shows up.
 *                 PCI DSS 4.0 req. 6.4.3 / 11.6.1 ask for exactly this inventory + change alert.
 *  Public code    repositories that turn public by mistake expose code and their whole history.
 *
 * Inline scripts are hashed as a "skeleton" (strings and numbers blanked), so a nonce, a
 * timestamp or a price inside a script is not a change; new CODE is.
 */
import { SOC, SITE } from './config.js';
import { sha256Hex, cfApi } from './util.js';

const SCRIPT = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
const attr = (attrs, name) => { const m = new RegExp('\\b' + name + '\\s*=\\s*(["\'])(.*?)\\1', 'i').exec(attrs) || new RegExp('\\b' + name + '\\s*=\\s*([^\\s>]+)', 'i').exec(attrs); return m ? (m[2] ?? m[1]) : ''; };
const DATA_TYPES = /json|template|text\/html|text\/x-|importmap|speculationrules/i;

export const skeleton = (code) => String(code)
  .replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:\\])\/\/[^\n]*/g, '$1')
  .replace(/(["'`])(?:\\.|(?!\1)[^\\])*\1/g, '""').replace(/\b\d+(\.\d+)?\b/g, '0').replace(/\s+/g, ' ').trim();

/** Inventory one page: outside hosts, own script URL → hash, inline skeleton hashes. */
export async function inventory(html, pageUrl, fetchText) {
  const base = new URL(pageUrl);
  const hosts = new Set(), own = {}, inline = new Set();
  for (const m of String(html).matchAll(SCRIPT)) {
    const attrs = m[1] || '', body = m[2] || '';
    if (DATA_TYPES.test(attr(attrs, 'type'))) continue;
    const src = attr(attrs, 'src');
    if (src) {
      let u; try { u = new URL(src, base); } catch { continue; }
      if (u.hostname !== base.hostname) { hosts.add(u.hostname); continue; }
      const key = u.pathname;                                  // query strings (?v=123) are cache-busters
      const text = await fetchText(u.href).catch(() => null);
      if (text != null) own[key] = await sha256Hex(text);
    } else if (body.trim()) inline.add(await sha256Hex(skeleton(body)));
  }
  return { hosts: [...hosts].sort(), own, inline: [...inline].sort() };
}

async function deployMarker(env) {
  if (SOC.VERSION_URL) { const r = await fetch(SOC.VERSION_URL, { cf: { cacheTtl: 0 } }); return r.ok ? (await r.text()).trim().slice(0, 80) : null; }
  if (SOC.PAGES_PROJECT && env.CF_TOKEN && env.CF_ACCOUNT) {
    const j = await cfApi(env, '/accounts/' + env.CF_ACCOUNT + '/pages/projects/' + SOC.PAGES_PROJECT + '/deployments?env=production&per_page=1');
    const d = j.result && j.result[0];
    return d ? d.id + (d.deployment_trigger && d.deployment_trigger.metadata ? ' ' + String(d.deployment_trigger.metadata.commit_hash || '').slice(0, 7) : '') : null;
  }
  return null;
}

export async function integrity(ctx, raise) {
  const { env, state } = ctx;
  state.integrity ||= {};
  const prev = state.integrity;
  let marker = null;
  try { marker = await deployMarker(env); } catch (e) { ctx.errors.push('deploy marker: ' + String(e.message || e).slice(0, 120)); }
  const deployed = marker && prev.marker && marker !== prev.marker;
  if (deployed) ctx.note('New version deployed: ' + marker);
  const fetchText = async (u) => { const r = await fetch(u, { headers: { 'User-Agent': SOC.SELFTEST_UA } }); if (!r.ok) throw new Error(u + ' ' + r.status); return r.text(); };

  const pages = {};
  for (const p of SOC.PAGES) {
    let inv;
    try {
      const r = await fetch(SITE + p.path, { headers: { 'User-Agent': SOC.SELFTEST_UA }, redirect: 'follow' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      inv = await inventory(await r.text(), SITE + p.path, fetchText);
    } catch (e) { ctx.errors.push('integrity ' + p.name + ': ' + String(e.message || e).slice(0, 120)); if (prev.pages && prev.pages[p.name]) pages[p.name] = prev.pages[p.name]; continue; }
    pages[p.name] = inv;
    const was = prev.pages && prev.pages[p.name];
    if (!was) continue;                                          // first sight: learn

    const newHosts = inv.hosts.filter((h) => !was.hosts.includes(h) && !SOC.SCRIPT_HOSTS.includes(h));
    if (newHosts.length) {
      await raise(p.payment ? 'CRITICAL' : 'HIGH', (p.payment ? 'payment_script_added:' : 'script_added:') + newHosts[0], (p.payment ? 'Payment page' : 'Page "' + p.name + '"') + ' loads a script from a new host',
        { facts: newHosts.join(', ') + ' on ' + p.path + (deployed ? ' (a new version was deployed: check it is yours)' : ''), cooldownH: 1 });
    }
    const changedOwn = Object.keys(inv.own).filter((k) => was.own[k] && was.own[k] !== inv.own[k]);
    const addedOwn = Object.keys(inv.own).filter((k) => !was.own[k]);
    const newInline = inv.inline.filter((h) => !was.inline.includes(h));
    const lines = [...changedOwn.map((k) => 'changed ' + k), ...addedOwn.map((k) => 'new ' + k), ...(newInline.length ? [newInline.length + ' new inline script(s)'] : [])];
    if (!lines.length) continue;
    if (deployed) ctx.note('Scripts changed with the deploy on ' + p.name + ': ' + lines.join(', '));
    else if (marker) await raise('HIGH', 'script_changed_no_deploy:' + p.name, 'Your scripts changed with no new deploy (' + p.name + ')', { facts: lines.slice(0, 8).join('\n'), cooldownH: 1 });
    else ctx.note('Scripts changed on ' + p.name + ' (no deploy marker configured, cannot tell if expected): ' + lines.join(', '));
  }

  // Public repositories.
  const repos = { ...(prev.repos || {}) };
  for (const user of SOC.GITHUB_USERS) {
    try {
      const r = await fetch('https://api.github.com/users/' + encodeURIComponent(user) + '/repos?type=public&per_page=100', { headers: { 'User-Agent': 'serverless-soc', Accept: 'application/vnd.github+json' } });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const names = (await r.json()).map((x) => x.full_name).sort();
      const was = prev.repos && prev.repos[user];
      if (was) {
        const fresh = names.filter((n) => !was.includes(n) && !SOC.PUBLIC_REPOS_OK.includes(n));
        if (fresh.length) await raise('HIGH', 'repo_public:' + fresh[0], 'A repository is now public', { facts: fresh.join(', '), cooldownH: 24 });
      }
      repos[user] = names;
    } catch (e) { ctx.errors.push('github ' + user + ': ' + String(e.message || e).slice(0, 100)); }
  }
  state.integrity = { marker: marker || prev.marker || null, pages, repos };
  return { pages: Object.keys(pages).length };
}
