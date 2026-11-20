import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fakeD1, fakeR2, recorder } from './fakes.mjs';
import { runWatchdog, onRequest, sameKey } from '../templates/site/functions/api/watchdog.js';

const T0 = Date.parse('2026-01-05T10:00:00Z');
const MIN = 60_000;

function setup() {
  const env = {
    DB: fakeD1(), IMAGES: fakeR2(), BACKUPS: fakeR2(),
    WATCHDOG_BUCKETS: 'IMAGES,BACKUPS', WATCHDOG_STATE_BUCKET: 'BACKUPS',
    BACKUP_BUCKET: 'BACKUPS', BACKUP_PREFIX: 'db/backup-', WATCHDOG_KEY: 'k'.repeat(32),
  };
  return env;
}
const backupAt = (env, t) => env.BACKUPS.put('db/backup-' + new Date(t).toISOString().slice(0, 19).replace(/:/g, '-') + '.json', '{}', {}, new Date(t));

test('healthy: ok, no alerts, memory empty→d1', async () => {
  const env = setup(); await backupAt(env, T0 - 2 * 3600_000);
  const r = recorder();
  const out = await runWatchdog(env, { now: T0, send: r.send });
  assert.equal(out.ok, true);
  assert.equal(out.backupAgeHours, 2);
  assert.equal(r.calls.length, 0);
});

test('one blip that clears sends nothing', async () => {
  const env = setup(); await backupAt(env, T0);
  const r = recorder();
  env.IMAGES.down = true;
  let out = await runWatchdog(env, { now: T0, send: r.send });
  assert.deepEqual(out.held, ['r2']);
  env.IMAGES.down = false;
  out = await runWatchdog(env, { now: T0 + MIN, send: r.send });
  assert.equal(out.ok, true);
  assert.equal(r.calls.length, 0);
});

test('two failures in a row → one DOWN, quiet, reminder after 6 h, then Fixed', async () => {
  const env = setup(); await backupAt(env, T0);
  const r = recorder();
  env.IMAGES.down = true;
  await runWatchdog(env, { now: T0, send: r.send });                         // held
  await runWatchdog(env, { now: T0 + 20_000, send: r.send });                // too soon: still held
  assert.equal(r.calls.length, 0);
  await runWatchdog(env, { now: T0 + MIN, send: r.send });                   // confirmed
  assert.equal(r.calls.length, 1);
  assert.match(r.calls[0].title, /R2 storage is DOWN/);
  for (let i = 2; i < 30; i++) await runWatchdog(env, { now: T0 + i * MIN, send: r.send });
  assert.equal(r.calls.length, 1, 'no repeat inside REMIND_HOURS');
  await runWatchdog(env, { now: T0 + 6 * 3600_000 + MIN, send: r.send });
  assert.equal(r.calls.length, 2);
  assert.match(r.calls[1].text, /broken since/);
  env.IMAGES.down = false;
  await runWatchdog(env, { now: T0 + 7 * 3600_000, send: r.send });
  assert.equal(r.calls.length, 3);
  assert.match(r.calls[2].title, /Fixed: R2 storage/);
});

test('D1 down: memory lives in R2, alert is not repeated every minute', async () => {
  const env = setup(); await backupAt(env, T0);
  const r = recorder();
  env.DB.down = true;
  for (let i = 0; i < 10; i++) await runWatchdog(env, { now: T0 + i * MIN, send: r.send });
  assert.equal(r.calls.length, 1);
  assert.match(r.calls[0].title, /D1 database is DOWN/);
  env.DB.down = false;
  const out = await runWatchdog(env, { now: T0 + 11 * MIN, send: r.send });
  assert.equal(out.memory, 'r2', 'newer copy (R2) wins after the outage');
  assert.match(r.calls[1].title, /Fixed: D1/);
});

test('both stores down ("blind"): alerts only on the half hour', async () => {
  const env = setup(); await backupAt(env, T0);
  const r = recorder();
  env.DB.down = true; env.IMAGES.down = true; env.BACKUPS.down = true;
  const start = Date.parse('2026-01-05T10:01:00Z');
  for (let i = 0; i < 29; i++) await runWatchdog(env, { now: start + i * MIN, send: r.send });
  assert.equal(r.calls.length, 0);
  await runWatchdog(env, { now: Date.parse('2026-01-05T10:30:00Z'), send: r.send });
  assert.equal(r.calls.length, 2);   // D1 + R2 (backup is implied by R2)
});

test('late backup alerts; quiet minutes write no state', async () => {
  const env = setup(); await backupAt(env, T0 - 30 * 3600_000);
  const r = recorder();
  await runWatchdog(env, { now: T0, send: r.send });
  await runWatchdog(env, { now: T0 + MIN, send: r.send });
  assert.match(r.calls[0].title, /backup is late/);
  const puts = env.BACKUPS.puts;
  await runWatchdog(env, { now: T0 + 2 * MIN, send: r.send });
  await runWatchdog(env, { now: T0 + 3 * MIN, send: r.send });
  assert.equal(env.BACKUPS.puts, puts, 'state unchanged → no R2 write');
});

test('endpoint: 401 on bad key, 503 on problem, constant-time compare', async () => {
  const env = setup(); await backupAt(env, T0);
  const bad = await onRequest({ request: new Request('https://x/api/watchdog', { headers: { 'x-watchdog-key': 'nope' } }), env });
  assert.equal(bad.status, 401);
  env.DB.down = true;
  const r = await onRequest({ request: new Request('https://x/api/watchdog', { headers: { 'x-watchdog-key': env.WATCHDOG_KEY } }), env: { ...env, DISCORD_WEBHOOK: '' } });
  assert.equal(r.status, 503);
  assert.equal(sameKey('', ''), false);
  assert.equal(sameKey('abc', 'abc'), true);
  assert.equal(sameKey('abc', 'abd'), false);
});
