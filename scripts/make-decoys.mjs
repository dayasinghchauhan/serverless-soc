#!/usr/bin/env node
/**
 * Generate decoy values + their hashes.
 *
 *   node scripts/make-decoys.mjs --key-format hex48 \
 *        --name "Decoy Name" --phone 98xxxxxxxx --email decoy.name@yourdomain.example
 *
 * Writes:
 *   decoys.local.sql   INSERTs that PLANT the decoys in your DB (plaintext!). Run it once, then delete it.
 *   prints             the HONEY_HASHES JSON for `wrangler secret put HONEY_HASHES`
 *
 * --key-format    hex48 | hex64 | b64url43 | prefix:<text>   (match the look of your real admin key)
 * --session-format  same choices (default hex64)
 * --phone         a number YOU control (spare SIM / virtual number) or that cannot be
 *                 assigned. Never a random number that may belong to a real person:
 *                 whoever steals the list may message it.
 * --email         an address on YOUR domain, routed to the email Worker.
 * --digits        phone digits kept when normalising (default 10)
 * --table         decoy credentials table (default ops_credentials)
 * --users-sql     optional INSERT template for your users table, with {name} {phone} {email}
 */
import { createHash, randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const args = Object.fromEntries(process.argv.slice(2).reduce((a, v, i, all) => (v.startsWith('--') ? [...a, [v.slice(2), all[i + 1] && !all[i + 1].startsWith('--') ? all[i + 1] : 'true']] : a), []));
const sha = (s) => createHash('sha256').update(String(s)).digest('hex');
const q = (s) => "'" + String(s).replace(/'/g, "''") + "'";

function make(fmt = 'hex64') {
  if (fmt === 'hex48') return randomBytes(24).toString('hex');
  if (fmt === 'hex64') return randomBytes(32).toString('hex');
  if (fmt === 'b64url43') return randomBytes(32).toString('base64url');
  if (fmt.startsWith('prefix:')) return fmt.slice(7) + randomBytes(24).toString('hex');
  throw new Error('unknown format ' + fmt);
}

const digits = Number(args.digits || 10);
const key = make(args['key-format'] || 'hex64');
const session = make(args['session-format'] || 'hex64');
const table = (args.table || 'ops_credentials').replace(/[^A-Za-z0-9_]/g, '');
const hashes = { [sha(key)]: 'admin-key', [sha(session)]: 'admin-session' };
const sql = [
  `-- PLAINTEXT DECOYS. Run once against the protected DB, then DELETE this file.`,
  `-- wrangler d1 execute <DB_NAME> --remote --file decoys.local.sql`,
  `CREATE TABLE IF NOT EXISTS ${table} (name TEXT PRIMARY KEY, value TEXT, note TEXT, created_at TEXT DEFAULT (datetime('now')));`,
  // Boring, plausible names: an attacker skimming a dump should want to try them.
  `INSERT OR REPLACE INTO ${table} (name, value, note) VALUES ('admin_api_key', ${q(key)}, 'owner key - rotate yearly');`,
  `INSERT OR REPLACE INTO ${table} (name, value, note) VALUES ('admin_session_cron', ${q(session)}, 'session for nightly jobs');`,
];

if (args.phone && args.phone !== 'true') {
  const p = String(args.phone).replace(/\D/g, '').slice(-digits);
  if (p.length !== digits) throw new Error('phone must have ' + digits + ' digits after normalising');
  hashes[sha(p)] = 'phone';
}
if (args.email && args.email !== 'true') hashes[sha(String(args.email).trim().toLowerCase())] = 'email';
if (args['users-sql']) {
  sql.push(args['users-sql'].replace('{name}', q(args.name || 'Customer')).replace('{phone}', q(args.phone || '')).replace('{email}', q(args.email || '')) + ';');
} else if (args.phone || args.email) {
  sql.push(`-- Add the decoy customer to YOUR users table, marked so admin lists can hide it, e.g.:`);
  sql.push(`-- INSERT INTO users (name, phone, email, is_decoy) VALUES (${q(args.name || 'Customer')}, ${q(args.phone || '')}, ${q(args.email || '')}, 1);`);
}

writeFileSync('decoys.local.sql', sql.join('\n') + '\n', { mode: 0o600 });
console.log('Wrote decoys.local.sql (plaintext). Plant it, then delete it:');
console.log('  wrangler d1 execute <DB_NAME> --remote --file decoys.local.sql && rm decoys.local.sql\n');
console.log('Set the hashes as a secret (safe to keep; they open nothing):');
console.log("  echo '" + JSON.stringify(hashes) + "' | wrangler secret put HONEY_HASHES\n");
console.log('Never put the plaintext in code, chat, tickets or notes: every use pages you as CRITICAL.');
