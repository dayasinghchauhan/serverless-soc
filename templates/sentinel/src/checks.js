/**
 * What the sentinel watches. Edit this file; src/index.js stays generic.
 *
 * Each check:   id, label (alert text), short (report text),
 *               need   = failing runs in a row before it alerts (1 = at once;
 *                        3 for outside APIs that blip),
 *               every  = 'min' (every run) or 'full' (every FULL_EVERY_MS, and
 *                        every minute again while it is failing),
 *               core   = true makes the alert 🔴 and counts toward "shop up %",
 *               run(h) → '' when fine, otherwise a short reason.
 *
 * h = { env, ctx, get, bust, reachable }   (see src/index.js)
 */

export const SITE = 'https://example.com';           // ← your site
export const DOMAINS = ['example.com'];              // RDAP expiry, 14 days' warning
export const NAME = 'Example Shop';

export const CHECKS = [
  {
    id: 'site', label: 'Website is DOWN', short: 'Website', core: true, need: 1, every: 'min',
    run: async (h) => {
      const r = await h.get(h.bust(SITE + '/'), { redirect: 'follow' });
      const t = await r.text();
      h.ctx.homeMs = r.ms;
      return r.status === 200 && /<\/html>/i.test(t) ? '' : 'homepage HTTP ' + r.status;
    },
  },
  {
    // Any cheap JSON endpoint that touches the database.
    id: 'api', label: 'Website API is DOWN', short: 'API', core: true, need: 1, every: 'full',
    run: async (h) => {
      const r = await h.get(h.bust(SITE + '/api/health'));
      if (r.status !== 200) return '/api/health HTTP ' + r.status;
      return (await r.json().catch(() => null)) ? '' : '/api/health answered non-JSON';
    },
  },
  {
    // The site's own storage watchdog. 503 WITH a JSON `problems` list means the
    // site found a D1/R2/backup problem and already alerted - not our alarm.
    id: 'inner', label: 'Site watchdog is unreachable', short: 'Site watchdog', core: true, need: 1, every: 'full',
    run: async (h) => {
      if (!h.env.WATCHDOG_KEY) return '';
      const r = await h.get(SITE + '/api/watchdog', { headers: { 'x-watchdog-key': h.env.WATCHDOG_KEY } }, 15000);
      const j = await r.json().catch(() => null);
      h.ctx.inner = j;
      return r.status === 200 || (r.status === 503 && j && Array.isArray(j.problems)) ? '' : '/api/watchdog HTTP ' + r.status;
    },
  },
  {
    id: 'sitemap', label: 'Sitemap is broken', short: 'Sitemap', need: 2, every: 'full',
    run: async (h) => {
      const r = await h.get(SITE + '/sitemap.xml', { redirect: 'follow' });
      const t = await r.text();
      return r.status === 200 && /<urlset|<sitemapindex/.test(t) ? '' : 'sitemap.xml HTTP ' + r.status;
    },
  },
  // Outside APIs you depend on: "reachable" = any answer below 500 (401/404 are fine).
  // { id: 'payments', label: 'Payment API unreachable', short: 'Payments', need: 3, every: 'full', run: (h) => h.reachable('https://api.example-payments.com/')() },
  // { id: 'whatsapp', label: 'WhatsApp / Meta API unreachable', short: 'WhatsApp', need: 3, every: 'full', run: (h) => h.reachable('https://graph.facebook.com/')() },
];
