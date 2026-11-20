-- Site tables. Every one also creates itself on first use; this file is for review / up-front setup.
-- npx wrangler d1 execute <DB> --remote --file templates/site/schema.sql

-- Watchdog memory (watchdog.js)
CREATE TABLE IF NOT EXISTS watchdog_kv (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT);

-- Security events written by the app (_seclog.js, _honey.js) and read by the SOC every 5 min
CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT DEFAULT (datetime('now')),
  kind TEXT NOT NULL, severity TEXT, actor TEXT, message TEXT,
  ip TEXT, country TEXT, asn_org TEXT, ua TEXT, path TEXT, meta TEXT
);
CREATE INDEX IF NOT EXISTS security_events_kind ON security_events (kind, created_at);

-- Honeytokens: where decoy credentials are PLANTED (scripts/make-decoys.mjs), and the per-kind rate limit
CREATE TABLE IF NOT EXISTS ops_credentials (name TEXT PRIMARY KEY, value TEXT, note TEXT, created_at TEXT DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS honey_state (kind TEXT PRIMARY KEY, window_start INTEGER, hits INTEGER, last_alert INTEGER);
-- Your users table: ALTER TABLE users ADD COLUMN is_decoy INTEGER DEFAULT 0;

-- SOC (written by the sentinel): cases, blocks, automatic actions, never-block list
CREATE TABLE IF NOT EXISTS soc_incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, rule TEXT NOT NULL, subject TEXT NOT NULL DEFAULT '',
  sev TEXT NOT NULL, title TEXT, status TEXT NOT NULL DEFAULT 'open', first_at TEXT, last_at TEXT, hits INTEGER NOT NULL DEFAULT 1,
  ip TEXT, country TEXT, asn_org TEXT, who TEXT, actions TEXT, verdict TEXT, closed_by TEXT, closed_at TEXT, close_reason TEXT);
CREATE INDEX IF NOT EXISTS soc_incidents_open ON soc_incidents (status, rule, subject);
CREATE TABLE IF NOT EXISTS soc_blocks (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, reason TEXT, incident_id INTEGER,
  created_at TEXT, expires_at TEXT, cf_rule_id TEXT, status TEXT NOT NULL DEFAULT 'active', removed_at TEXT, removed_by TEXT, country TEXT, asn_org TEXT);
CREATE INDEX IF NOT EXISTS soc_blocks_ip ON soc_blocks (ip, status);
CREATE TABLE IF NOT EXISTS soc_actions (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, action TEXT NOT NULL, target TEXT, auto INTEGER NOT NULL DEFAULT 1,
  incident_id INTEGER, result TEXT, undo TEXT, undone_at TEXT, undone_by TEXT);
CREATE TABLE IF NOT EXISTS soc_allow (value TEXT PRIMARY KEY, note TEXT, at TEXT);
