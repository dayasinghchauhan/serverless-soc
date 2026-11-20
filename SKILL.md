---
name: serverless-soc
description: A complete monitoring and security operations setup (a small SOC) for a Cloudflare Pages/Workers + D1 + R2 app, with no servers or paid tools. It installs (1) a storage watchdog with real D1/R2/backup probes, (2) an outside "sentinel" Worker for uptime with a dead-man switch, (3) a 5-minute SOC that turns the app's security events, database snapshots, Cloudflare account changes and page-script inventory into cases with automatic responses (IP blocks, sign-out-all, order hold), each alert explained in four parts, and (4) honeytokens planted in the database. Use it when someone asks for uptime or outage alerts, a security monitor or SOC, intrusion or breach detection, card-skimming or script-integrity monitoring (PCI DSS 6.4.3 / 11.6.1), auto-blocking attackers, "who changed my DNS/Cloudflare", honeytokens or canary tokens, or "how would I know if I was hacked" on Cloudflare. Do not use it for writing secure application code, a WAF rule set, log analytics/APM, or non-Cloudflare infrastructure (the patterns port, the templates don't).
license: MIT
---

# serverless-soc

Four layers. Each one covers the failure of the layer before it:

```
 LAYER                  RUNS                 CATCHES
 1 watchdog (in app)    every minute         D1 off / read-only · R2 off · backup late
 2 sentinel (outside)   every minute         site down · API down · slow · domain expiry · watchdog unreachable
   + Healthchecks.io    pings every run      the sentinel itself or Cloudflare stopped
 3 SOC (in sentinel)    every 5 min / hourly / daily
     detect             app security events  key guessed · admin abroad · brute force · injection · OTP pumping · forged webhooks
     tamper             DB snapshots         new admin/device/coupon · price crash · rows deleted · impossible-price orders
     posture            Cloudflare account   new token/member · 2FA off · DNS/SSL change · private bucket public · stranger changes
     integrity          page scripts, repos  new script host on the payment page (skimming) · own script changed with no deploy · repo turned public
     self-test          daily                a protection that stopped working (admin API open, .env served…)
 4 honeytokens          on use               decoy key/session/phone/email from your DB used = your data has leaked
```

Output: **cases** (`soc_incidents`) with **automatic actions** (`soc_actions`, undoable), **blocks**
(`soc_blocks`, expiring, escalating), and alerts in four parts: *what happened · from where · what it
means · what to do*. CRITICAL/HIGH ring the phone, MEDIUM goes to the channel, everything else (your own
changes, refused attacks) goes to the **09:00 daily summary**. The first run only learns.

## Workflow

Do this in order. Read the user's code and Cloudflare setup before changing anything. Each layer
works on its own, so install only what they ask for and say what's left out.

### 0. Understand the app
- `wrangler.toml` / Pages settings: the D1 and R2 binding names, the zone name(s), Workers plan (Free = 5 cron triggers per account, 1,000 KV writes a day).
- Admin auth: where keys/sessions are checked, the lockout logic, the session table (needed for `SIGN_OUT_ALL_SQL`).
- Sensitive tables to snapshot: admins, devices, coupons, prices, service keys. Tables that must never shrink: orders, users, products.
- Pages that run payments or collect cards or addresses (integrity `payment: true`).
- Alert roads: Discord / Slack webhook, ntfy.sh topic for the phone. At least one is required.

### 1. Watchdog (`templates/site/functions/api/watchdog.js`)
Copy it to `functions/api/watchdog.js`. Set `WATCHDOG_BUCKETS`, `WATCHDOG_STATE_BUCKET` (private), `BACKUP_BUCKET`, `BACKUP_PREFIX` (dated keys), `APP_NAME`, and the secrets `WATCHDOG_KEY` + an alert road. There are no backups yet? Add `templates/backup/d1-backup.yml`. Auth is a constant-time compare. **Never** route it through a D1-backed lockout, because it has to answer while D1 is down.

### 2. Security events in the app (`_seclog.js`)
Copy `_seclog.js` and call `secLog(context, kind, …)` at each point listed in `references/soc-rules.md`:
`admin_ok` (each allowed admin request, with the actor) · `admin_fail` · `webhook_bad_sig` · `otp_sent` · `attack` (input that looks like an injection) · `probe` (requests for never-public paths) · `server_error` · `tfa_off` · `secret_replaced` · `csp` (from a CSP report endpoint). It writes in `waitUntil` and never throws. **No customer personal data in `meta`.**

### 3. Honeytokens (`_honey.js`, `scripts/make-decoys.mjs`)
Generate the decoys, plant them in the DB, and put only the hashes in `HONEY_HASHES`. Call `honeyKey()` **first** in the admin check, before any lockout, and `honeyContact()` in login-code and order lookups. Answer a decoy exactly like a wrong value. Exclude `is_decoy` rows from every customer list and send. Plant only a phone number and email address the user controls. Details: `references/honeytokens.md`.

### 4. Sentinel + SOC (`templates/sentinel/`, a separate Worker)
- Edit `src/checks.js` (uptime: SITE, DOMAINS, checks) and `src/soc/config.js` (`HOME_COUNTRIES`, `OWN_EMAILS`, `OWN_TOKENS`, `ZONES`, `PRIVATE_BUCKETS`, `BLOCK_ZONE`, `TAMPER` queries that match **their** tables, `SIGN_OUT_ALL_SQL`, `UNDERPRICED_SQL` / `HOLD_ORDER_SQL`, `PAGES`, `SCRIPT_HOSTS`, `PAGES_PROJECT`, `SELFTEST`). Every SQL statement must match their real schema. Run each one against their DB before deploying.
- `wrangler.toml`: KV `STATE`, D1 `DB` = **the site's database** (the SOC reads its events and keeps cases there), crons `* * * * *` and `*/5 * * * *`.
- Secrets: `WATCHDOG_KEY`, `RUN_KEY`, alert roads, `HC_PING_URL`, `CF_TOKEN` + `CF_ACCOUNT` (permissions: `references/cloudflare-token.md`), `HONEY_HASHES`.
- Email Routing: the decoy address → **Send to a Worker** → this sentinel (its `email()` handler).
- cron-job.org: `/api/watchdog` (failure email ON) and the sentinel's `/run`, every minute each. Healthchecks.io: period 1 min, grace 3 min.

### 5. Prove it
- `npm test` (Node ≥ 22.13): 39 tests.
- `GET /run?test=1` → a test alert on every road. `GET /soc/run` → the first call returns `learning: true`, the next one `raised: []`.
- On **staging** (separate DB, separate decoys): send a wrong admin key 5 times and then the right one from a new network → expect a `key_guessed` case and sign-out. Use a decoy once → expect a CRITICAL case. Add `<script src="https://example.org/x.js">` to the checkout page → expect a CRITICAL `payment_script_added` within an hour (or `GET /soc/run?integrity=1`).
- **Never** use the production decoys and never run attack tests against production without telling the owner first. Each one is a real page.
- Report what was verified live, what only in tests, and which parts were left off.

## Rules that matter
1. **Probe with real work**: a D1 write, an R2 list. A binding that exists proves nothing.
2. **The sentinel is a separate deploy.** Code inside the site can't report the site being down.
3. **The first run learns.** It never alerts on what already existed (networks, snapshots, scripts).
4. **A failed read keeps the old snapshot.** An API hiccup is never a "change".
5. **Ask "who did it" before ringing.** Your own login or token doing its job goes to the summary, and a stranger rings with their name.
6. **Block only hosting networks or abroad.** Never a home-country residential IP (real customers share them), never your own Workers, never an IP an admin used today. Blocks escalate and expire, and every action can be undone.
7. **One case per rule + subject.** Repeats inside the cooldown count on the case and don't ring again.
8. **Locked rules** (honeytoken, private bucket public, new CF member, CF 2FA off, rows deleted, payment script added, script changed without a deploy) can't be muted.
9. **Every alert says what to do.** Four parts, written to be read on a phone.
10. **No customer personal data in alerts or `meta`.** Discord and Slack are third parties.

## Files
| Path | What |
|---|---|
| `templates/site/functions/api/watchdog.js` | storage watchdog endpoint |
| `templates/site/functions/api/_seclog.js` | `secLog()`: the app's security events |
| `templates/site/functions/api/_honey.js` | honeytoken hooks |
| `templates/site/schema.sql` | every site table (each also creates itself) |
| `templates/sentinel/src/index.js` | uptime tick, SOC cron routing, decoy mailbox, `/run` + `/soc/*` routes |
| `templates/sentinel/src/checks.js` | uptime checks (edit) |
| `templates/sentinel/src/soc/config.js` | SOC settings (edit) |
| `templates/sentinel/src/soc/*.js` | run · raise · guide · detect · tamper · posture · who · integrity · selftest · respond |
| `templates/backup/d1-backup.yml` | nightly D1 → R2 backup |
| `scripts/make-decoys.mjs` | decoy generator |
| `references/soc-rules.md` | every rule: trigger, severity, response |
| `references/cloudflare-token.md` | CF_TOKEN permissions |
| `references/honeytokens.md` | placement, meaning, incident playbook |
| `references/uptime-design.md` | why each uptime rule exists |
| `references/browser-journey.md` | optional real-browser checkout test |
| `tests/` | 39 tests (`npm test`) |
