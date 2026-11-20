import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { fakeKV, recorder } from './fakes.mjs';
import { tick, weeklyReport } from '../templates/sentinel/src/index.js';

const T0 = Date.parse('2026-01-06T10:00:00Z');   // a Tuesday
const MIN = 60_000;
let down = new Set();
const HTML = '<html><body>ok</body></html>';

beforeEach(() => {
  down = new Set();
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (u.startsWith('https://rdap.org/')) return Response.json({ events: [{ eventAction: 'expiration', eventDate: '2030-01-01T00:00:00Z' }] });
    if (u.includes('/api/watchdog')) return down.has('inner') ? new Response('x', { status: 502 }) : Response.json({ ok: true, problems: [] });
    if (u.includes('/api/health')) return down.has('api') ? new Response('x', { status: 500 }) : Response.json({ ok: true });
    if (u.includes('/sitemap.xml')) return new Response('<urlset></urlset>');
    return down.has('site') ? new Response('bad', { status: 522 }) : new Response(HTML);
  };
});

const env = () => ({ STATE: fakeKV(), WATCHDOG_KEY: 'k' });
const wait = async () => {};

test('healthy run', async () => {
  const r = recorder();
  const out = await tick(env(), { now: T0, send: r.send, wait });
  assert.equal(out.ok, true);
  assert.equal(r.calls.length, 0);
});

test('site down → one 🔴 alert, then Fixed with incident', async () => {
  const e = env(), r = recorder();
  down.add('site');
  await tick(e, { now: T0, send: r.send, wait });
  assert.equal(r.calls.length, 1);
  assert.match(r.calls[0].title, /^🔴 Website is DOWN/);
  for (let i = 1; i < 10; i++) await tick(e, { now: T0 + i * MIN, send: r.send, wait });
  assert.equal(r.calls.length, 1);
  down.clear();
  await tick(e, { now: T0 + 10 * MIN, send: r.send, wait });
  assert.match(r.calls[1].title, /Fixed: Website/);
  const st = JSON.parse(await e.STATE.get('state'));
  assert.equal(st.incidents.length, 1);
});

test('external clock stands down while native cron is running', async () => {
  const e = env(), r = recorder();
  await tick(e, { now: T0, send: r.send, wait });
  const out = await tick(e, { source: 'cronjob', now: T0 + 30_000, send: r.send, wait });
  assert.match(out.skipped, /native cron ran/);
  const out2 = await tick(e, { source: 'cronjob', now: T0 + 200_000, send: r.send, wait });
  assert.equal(out2.ok, true);
});

test('need=2 check (sitemap) waits for two failing full runs', async () => {
  const e = env(), r = recorder();
  globalThis.fetch = (orig => async (url, o) => String(url).includes('sitemap') ? new Response('no', { status: 500 }) : orig(url, o))(globalThis.fetch);
  await tick(e, { now: T0, send: r.send, wait });
  assert.equal(r.calls.length, 0);
  await tick(e, { now: T0 + MIN, send: r.send, wait });   // failing → full checks every minute
  assert.equal(r.calls.length, 1);
  assert.match(r.calls[0].title, /^🟠 Sitemap/);
});

test('site 503 with problems list = site already alerted, not a sentinel alarm', async () => {
  const e = env(), r = recorder();
  globalThis.fetch = (orig => async (url, o) => String(url).includes('/api/watchdog') ? Response.json({ ok: false, problems: ['r2'] }, { status: 503 }) : orig(url, o))(globalThis.fetch);
  const out = await tick(e, { now: T0, send: r.send, wait });
  assert.equal(r.calls.length, 0);
  assert.deepEqual(out.inner, ['r2']);
  assert.equal(out.ok, false);
});

test('free-plan flush: quiet runs do not write KV every minute', async () => {
  const e = { ...env(), STATE_FLUSH_MIN: '15' }, r = recorder();
  for (let i = 0; i < 10; i++) await tick(e, { now: T0 + i * MIN, send: r.send, wait });
  assert.ok(e.STATE.puts <= 2, 'puts=' + e.STATE.puts);
});

test('weekly report', () => {
  const state = { stats: { '2026-01-05': { runs: 1440, down: { site: 3 }, ms: 1440 * 300, msN: 1440, maxMs: 900 } }, incidents: [] };
  const text = weeklyReport(state, T0);
  assert.match(text, /Site up: \*\*99\.79%\*\*/);
});
