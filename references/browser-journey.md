# Optional: real-browser checkout test (every 30 min)

HTTP checks prove that pages *answer*. They do not prove a shopper can buy:
a JS error, a broken bag/cart script or a missing payment script all return
200. A headless Chrome run catches those.

Needs **Workers Paid** (Browser Rendering). Add to the sentinel's `wrangler.toml`:

```toml
[browser]
binding = "BROWSER"

[triggers]
crons = ["* * * * *", "*/30 * * * *"]   # run the journey on its own cron so it never overlaps the minute checks
```

```bash
npm i @cloudflare/puppeteer@1.4.0
```
Pin 1.4.0 or newer. Older 1.0.x builds hang with "Websocket error" on current
Browser Rendering.

```js
// src/journey.js
import puppeteer from '@cloudflare/puppeteer';
import { SITE } from './checks.js';

const PRODUCT_PATH = '/product/EXAMPLE-SKU';     // a product that is always in stock
const ADD_BUTTON = '#add-to-cart';
const CHECKOUT_PATH = '/checkout';
const TOTAL = '#checkout-total';

export async function journey(env) {
  const browser = await puppeteer.launch(env.BROWSER);
  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 412, height: 915, isMobile: true });
    await page.setRequestInterception(true);
    const own = new URL(SITE).hostname;
    page.on('request', (req) => {
      if (req.url().startsWith('data:')) return req.continue();
      let host = '', path = '';
      try { const u = new URL(req.url()); host = u.hostname; path = u.pathname; } catch {}
      // GET only, own host only (plus fonts / payment script). Block analytics, ad
      // pixels and your own tracking/order endpoints, so the robot never creates an
      // ad event, an abandoned-cart row or a WhatsApp message.
      const allowed3p = /(^|\.)fonts\.(googleapis|gstatic)\.com$/.test(host) || host === 'checkout.example-payments.com';
      const tracking = host.endsWith(own) && /^\/api\/(metrics|events|orders|checkout|abandon)/.test(path);
      if (req.method() !== 'GET' || (!host.endsWith(own) && !allowed3p) || tracking) return req.abort();
      req.continue();
    });

    const r = await page.goto(SITE + PRODUCT_PATH, { waitUntil: 'domcontentloaded', timeout: 25000 });
    if (!r || r.status() !== 200) return 'product page HTTP ' + (r ? r.status() : 'no answer');
    await page.waitForSelector(ADD_BUTTON, { visible: true, timeout: 15000 }).catch(() => null);
    if (!(await page.$(ADD_BUTTON))) return 'Add to cart button missing';
    await page.$eval(ADD_BUTTON, (b) => b.click());   // JS click: a cookie bar can't swallow it
    await new Promise((res) => setTimeout(res, 1500));

    const c = await page.goto(SITE + CHECKOUT_PATH, { waitUntil: 'domcontentloaded', timeout: 25000 });
    if (!c || c.status() !== 200) return 'checkout HTTP ' + (c ? c.status() : 'no answer');
    await page.waitForFunction((sel) => /\d/.test((document.querySelector(sel) || {}).textContent || ''), { timeout: 10000 }, TOTAL).catch(() => null);
    const total = await page.$eval(TOTAL, (el) => el.textContent).catch(() => '');
    return /\d/.test(total) ? '' : 'checkout shows no total: the cart did not keep the item';
  } finally { await browser.close().catch(() => {}); }
}

// Two attempts, 75 s cap each; store the result for the minute tick to read.
export async function runJourney(env) {
  const attempt = () => Promise.race([
    journey(env).catch((e) => 'browser test crashed: ' + String(e && e.message || e).slice(0, 120)),
    new Promise((res) => setTimeout(() => res('browser test timed out after 75 s'), 75000)),
  ]);
  let why = await attempt();
  if (why) why = await attempt();
  await env.STATE.put('journey', JSON.stringify({ at: Date.now(), why }));
  return why;
}
```

Wire it in `src/index.js`:
- `scheduled`: `event.cron === '*/30 * * * *' ? runJourney(env) : tick(env)`.
- In `tick`, read `await env.STATE.get('journey', 'json')`. If `why` is set → `failed.journey = why`. If `at` is older than 2 h → the journey cron stopped, which is a failure too.
- Add `journey: { label: 'Real-browser test FAILED (cart / checkout)', short: 'Browser test' }` to `EXTRA`.
