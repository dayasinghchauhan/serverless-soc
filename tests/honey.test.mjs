import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fakeD1 } from './fakes.mjs';
import { honeyKey, honeyContact, recordHit, sha256Hex, HONEY } from '../templates/site/functions/api/_honey.js';
import { honeyMail } from '../templates/sentinel/src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const KEY = 'a'.repeat(48), SESSION = 'b'.repeat(64), PHONE = '9000000001', EMAIL = 'decoy.person@example.test';
let posts;

async function env() {
  return {
    DB: fakeD1(), DISCORD_WEBHOOK: 'https://discord.example/webhook',
    HONEY_HASHES: JSON.stringify({ [await sha256Hex(KEY)]: 'admin-key', [await sha256Hex(SESSION)]: 'admin-session', [await sha256Hex(PHONE)]: 'phone', [await sha256Hex(EMAIL)]: 'email' }),
  };
}
const ctx = (e, path = '/api/admin/orders') => ({ env: e, request: new Request('https://shop.example' + path, { headers: { 'CF-Connecting-IP': '203.0.113.9', 'CF-IPCountry': 'NL', 'User-Agent': 'curl/8' } }) });

beforeEach(() => { posts = []; globalThis.fetch = async (url, o) => { posts.push({ url: String(url), body: o && o.body }); return new Response('ok'); }; });

test('real or wrong keys are not decoys and log nothing', async () => {
  const e = await env();
  assert.equal(await honeyKey(ctx(e), 'c'.repeat(48)), false);
  assert.equal(await honeyKey(ctx(e), ''), false);
  assert.equal(await honeyContact(ctx(e), { phone: '9000000002' }), false);
  assert.equal(posts.length, 0);
});

test('decoy admin key → true, CRITICAL row with ip/country/path, one page', async () => {
  const e = await env();
  assert.equal(await honeyKey(ctx(e), KEY), true);
  const row = await e.DB.prepare('SELECT * FROM security_events').first();
  assert.equal(row.kind, 'honeytoken:admin-key');
  assert.equal(row.ip, '203.0.113.9');
  assert.equal(row.country, 'NL');
  assert.equal(row.path, '/api/admin/orders');
  assert.equal(posts.length, 1);
  assert.match(JSON.parse(posts[0].body).content, /CRITICAL: the decoy admin key was used/);
});

test('phone is normalised (+91 / spaces) and email is case-insensitive', async () => {
  const e = await env();
  assert.equal(await honeyContact(ctx(e, '/api/login/code'), { phone: '+91 90000 00001' }), true);
  assert.equal(await honeyContact(ctx(e, '/api/track'), { email: '  Decoy.Person@Example.TEST ' }), true);
});

test('cooldown: one page per kind per hour, rows capped at ROWS_PER_HOUR', async () => {
  const e = await env();
  const t0 = Date.parse('2026-01-01T00:00:00Z');
  for (let i = 0; i < 30; i++) await recordHit(e, 'admin-key', { path: '/x' }, { now: t0 + i * 1000 });
  assert.equal(posts.length, 1);
  const n = await e.DB.prepare("SELECT COUNT(*) n FROM security_events").first('n');
  assert.equal(n, HONEY.ROWS_PER_HOUR);
  await recordHit(e, 'admin-key', { path: '/x' }, { now: t0 + 3_600_000 + 5000 });
  assert.equal(posts.length, 2, 'pages again after an hour');
  await recordHit(e, 'phone', { path: '/y' }, { now: t0 + 3_600_000 + 6000 });
  assert.equal(posts.length, 3, 'other kinds page independently');
});

test('onHit hook runs; a failing hook does not lose the alert', async () => {
  const e = await env();
  let seen = null;
  await recordHit(e, 'admin-session', {}, { onHit: (h) => { seen = h.kind; throw new Error('boom'); } });
  assert.equal(seen, 'admin-session');
  assert.equal(posts.length, 1);
});

test('waitUntil: caller is not held up', async () => {
  const e = await env();
  const jobs = [];
  const c = { ...ctx(e), waitUntil: (p) => jobs.push(p) };
  assert.equal(await honeyKey(c, KEY), true);
  assert.equal(jobs.length, 1);
  await Promise.all(jobs);
  assert.equal(posts.length, 1);
});

test('email worker: decoy mailbox logged + dropped, other mail rejected', async () => {
  const e = await env();
  const jobs = [];
  let rejected = null;
  const msg = (to) => ({ to, from: 'spam@bad.example', headers: new Headers({ subject: 'Your account' }), setReject: (r) => { rejected = r; } });
  await honeyMail(msg(EMAIL), e);
  await Promise.all(jobs);
  assert.equal(rejected, null);
  assert.equal(await e.DB.prepare('SELECT kind FROM security_events').first('kind'), 'honeytoken:email');
  await honeyMail(msg('someone@example.test'), e);
  assert.equal(rejected, 'Unknown address');
});

test('make-decoys.mjs: writes plaintext SQL locally, prints only hashes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'decoys-'));
  const out = execFileSync(process.execPath, [join(here, '..', 'scripts', 'make-decoys.mjs'), '--key-format', 'hex48', '--phone', '+91 90000 00001', '--email', EMAIL], { cwd: dir, encoding: 'utf8' });
  assert.ok(existsSync(join(dir, 'decoys.local.sql')));
  const sql = readFileSync(join(dir, 'decoys.local.sql'), 'utf8');
  const key = /'admin_api_key', '([0-9a-f]{48})'/.exec(sql)[1];
  assert.ok(!out.includes(key), 'plaintext key never printed');
  const json = JSON.parse(/echo '(\{.*\})'/.exec(out)[1]);
  assert.equal(Object.values(json).sort().join(','), 'admin-key,admin-session,email,phone');
});
