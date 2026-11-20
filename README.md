# serverless-soc

[![tests](https://github.com/dayasinghchauhan/serverless-soc/actions/workflows/test.yml/badge.svg)](https://github.com/dayasinghchauhan/serverless-soc/actions/workflows/test.yml)
![license](https://img.shields.io/badge/license-MIT-blue)
![deps](https://img.shields.io/badge/dependencies-0-brightgreen)

**A complete monitoring and security operations setup (a small SOC) for a Cloudflare Pages / Workers + D1 + R2 app.
No servers, no paid tools, no dependencies. Packaged as a Claude Code skill.**

Built around the failures a small online shop on Cloudflare can face: storage switched off without anyone
noticing, key-guessing on the admin API, card-skimming scripts on the checkout page. It's what one person needs
to sleep at night without a security team.

| Layer | Runs | Catches |
|---|---|---|
| **Watchdog** (in your app) | every minute | D1 off or read-only · R2 off · nightly backup late |
| **Sentinel** (separate Worker) | every minute | site / API down · slow · domain expiring · the watchdog itself unreachable |
| **Dead-man switch** (Healthchecks.io) | every run | the sentinel, or Cloudflare itself, stopped |
| **SOC: detect** | every 5 min | admin key **guessed** · admin from abroad / a script · brute force · injection on login/checkout · OTP/SMS pumping · forged webhooks · error spikes |
| **SOC: tamper** | every 5 min | new admin / device / coupon · price crash · **rows deleted** · orders at an impossible price (held before courier) |
| **SOC: posture** | hourly | new Cloudflare token or member · **2FA turned off** · DNS / SSL changes · **backup bucket made public** · changes by anyone not on your list |
| **SOC: integrity** | hourly | **new script host on the payment page (Magecart skimming)** · your scripts changed with no deploy · a repo turned public |
| **SOC: self-test** | daily | a protection that stopped working (admin API open, `.env` served) |
| **Honeytokens** | on use | decoy key / session / phone / email from your database used = **your data has leaked** |

---

## What you get when something happens

```
🛡️ [HIGH] Admin key worked after 5 wrong tries
What happened: Actor owner on /api/admin/orders, from a new network.
From where: IP 203.0.113.50 (NL), Example Hosting BV · script · /api/admin/orders
Who: owner
What it means: The admin key WORKED after repeated wrong tries from the same network:
  it was probably guessed or brute-forced. If it was you: Only if you mistyped it many times and then got it right.
What to do:
1. Every admin session was signed out automatically.
2. Rotate the admin key and every staff password; sign everyone out.
3. Make the key longer (32+ random characters).
Case #12
```

The same event also:
- opens or joins **case #12** (`soc_incidents`: rule, subject, severity, hits, IP, who, actions taken, verdict);
- **signs every admin out** and **blocks the address at Cloudflare** for 24 h (7 days on a repeat, then 30),
  because it's a hosting network. Each action is recorded and can be undone;
- is counted, not re-sent, if it happens again inside the cooldown.

Things that need no action (your own DNS change, a new home Wi-Fi, 40 refused scanner hits) don't ring.
They're in the **daily summary** instead:

```
🛡️ Daily security summary
Open cases: HIGH 1
Blocked automatically: 3 · attacks refused: 41 · private-file probes refused: 17
Noted (no alert):
• 06:10 Admin from a new home network (IN, Android Chrome) by owner
• 11:42 DNS records changed (by owner@example.com)
• 14:05 New version deployed: 8f3c2a1
```

## Why it's built this way

| Decision | Reason |
|---|---|
| Probe with **real work** (a D1 write, an R2 list) | A binding still "exists" when the product behind it is switched off, so a shallow health check stays green while storage is down |
| Sentinel is a **separate Worker** | Code inside the site can't report the site being down |
| **First run learns** | Never page about what already existed (networks, snapshots, scripts) |
| **Ask who did it** (Cloudflare audit log) before ringing | "DNS changed" is useless at 2 a.m. "DNS changed by *you*" belongs in the summary, "by *someone else*" rings with the name |
| Block **only hosting networks or abroad** | Mobile carriers put thousands of real customers behind one home-country IP |
| **Inline scripts hashed as a skeleton** (strings and numbers blanked) | A nonce or a price inside a script isn't a change. New code is |
| A script change **with** a deploy is normal | Without the deploy marker every release would page you |
| **Locked rules** | You can mute noisy rules, never "private bucket is public" or "payment page loads a new script" |
| **Four-part alerts** | Someone woken by a CRITICAL needs *what to do*, not a log line |
| Hashes only for honeytokens | The repo never holds a value someone could paste by mistake |

## Install as a Claude Code skill

```bash
git clone https://github.com/dayasinghchauhan/serverless-soc ~/.claude/skills/serverless-soc
```

Then ask, for example:
- *"Set up monitoring and a security SOC for this Cloudflare Pages app."*
- *"Alert me if D1 or R2 goes down or backups stop."*
- *"Watch my checkout page for card-skimming scripts."*
- *"How would I know if my database leaked? Add honeytokens."*
- *"Auto-block whoever is brute-forcing my admin API."*

The skill makes Claude read your bindings, auth and tables first, install only the layers you want, write
the config SQL against **your** schema, and prove each layer (test alert, staging attack drills,
`npm test`) before it says it's done.

## Manual setup

<details>
<summary><b>1. Watchdog (in your app)</b></summary>

`templates/site/functions/api/watchdog.js` → `functions/api/watchdog.js`.

| Var / secret | Example | Meaning |
|---|---|---|
| `WATCHDOG_BUCKETS` | `IMAGES,BACKUPS` | R2 binding names to probe |
| `WATCHDOG_STATE_BUCKET` | `BACKUPS` | private bucket for the second copy of its memory |
| `BACKUP_BUCKET` / `BACKUP_PREFIX` | `BACKUPS` / `db/backup-` | dated backup keys (`db/backup-2026-11-20T03-00-00.sql`) |
| `WATCHDOG_KEY` *(secret)* | `openssl rand -hex 32` | header `x-watchdog-key` |
| `DISCORD_WEBHOOK` / `SLACK_WEBHOOK` / `NTFY_URL` | | at least one |

No backups yet? `templates/backup/d1-backup.yml` (nightly `wrangler d1 export` → R2).
</details>

<details>
<summary><b>2. Security events (in your app)</b></summary>

```js
import { secLog } from './_seclog.js';
await secLog(context, 'admin_ok', { actor: user.name });      // each allowed admin request
await secLog(context, 'admin_fail');                          // wrong key / password
await secLog(context, 'attack', { meta: { pattern: 'sqli' } });
await secLog(context, 'probe', { meta: { status: 404 } });    // /.env, /.git/config, …
await secLog(context, 'otp_sent', { meta: { to: last4 } });   // never the full number
await secLog(context, 'webhook_bad_sig', { meta: { source: 'payments' } });
```
All kinds and what each triggers: [`references/soc-rules.md`](references/soc-rules.md).
</details>

<details>
<summary><b>3. Honeytokens (in your app)</b></summary>

```bash
node scripts/make-decoys.mjs --key-format hex48 --name "Plausible Name" --phone <yours> --email <name>@<your-domain>
npx wrangler d1 execute <DB> --remote --file decoys.local.sql && rm decoys.local.sql
echo '<printed JSON>' | npx wrangler secret put HONEY_HASHES
```
```js
if (await honeyKey(context, request.headers.get('x-admin-key'))) return unauthorized();   // FIRST, before lockout
if (await honeyContact(context, { phone, email })) return json({ ok: true, sent: true });  // looks normal, sends nothing
```
Placement and the incident playbook: [`references/honeytokens.md`](references/honeytokens.md).
</details>

<details>
<summary><b>4. Sentinel + SOC (separate Worker)</b></summary>

```bash
cp -r templates/sentinel ../my-sentinel && cd ../my-sentinel
# edit src/checks.js (uptime) and src/soc/config.js (SOC)
npx wrangler kv namespace create STATE         # id → wrangler.toml
# wrangler.toml: [[d1_databases]] = the SITE's database
npx wrangler secret put WATCHDOG_KEY           # same as the site
npx wrangler secret put DISCORD_WEBHOOK        # and/or SLACK_WEBHOOK, NTFY_URL
npx wrangler secret put CF_TOKEN               # permissions: references/cloudflare-token.md
npx wrangler secret put CF_ACCOUNT
npx wrangler secret put HONEY_HASHES
npx wrangler secret put HC_PING_URL            # optional
npx wrangler deploy
```

Key `src/soc/config.js` settings:

| Setting | Meaning |
|---|---|
| `HOME_COUNTRIES` | where the admin normally works. Outside = HIGH, and blockable |
| `OWN_EMAILS`, `OWN_TOKENS` | your Cloudflare logins, and your token names with the job each exists for |
| `ZONES`, `ZONE_SETTINGS`, `PRIVATE_BUCKETS`, `BLOCK_ZONE` | what posture watches, where blocks go |
| `AUTO.*`, `BLOCK_HOURS` | automatic responses and block durations |
| `SIGN_OUT_ALL_SQL`, `UNDERPRICED_SQL`, `HOLD_ORDER_SQL` | your schema's sign-out and order hold |
| `TAMPER`, `NO_DELETE_TABLES` | snapshot queries (`k`, `v` columns) and tables that only grow |
| `PAGES`, `SCRIPT_HOSTS`, `PAGES_PROJECT` / `VERSION_URL` | script integrity and the deploy marker |
| `GITHUB_USERS`, `PUBLIC_REPOS_OK` | public-repo watch |
| `SELFTEST`, `SELFTEST_UA` | daily attack drills. Their logged requests are skipped only if they carry this UA **and** come from Cloudflare's Workers network **and** arrive within minutes of the self-test run. The UA alone hides nothing |
| thresholds | `KEY_GUESS_FAILS`, `BRUTE_FAILS_10MIN`, `OTP_PER_HOUR`, … |

Decoy mailbox: Email Routing → custom address → **Send to a Worker** → this sentinel.

Clocks: cron-job.org → `GET /api/watchdog` (failure email ON) and `GET /run` on the sentinel, every minute.
Healthchecks.io: period 1 min, grace 3 min.
</details>

<details>
<summary><b>5. Operate it (sentinel routes, header <code>x-run-key</code>)</b></summary>

| Route | What |
|---|---|
| `GET /run?test=1` | test message on every road |
| `GET /run?wait=1` | uptime run now, with the result |
| `GET /soc/run` | SOC run now. `&posture=1 &integrity=1 &selftest=1 &prune=1 &summary=1` force that part |
| `GET /soc/cases` (`?status=closed`) | cases |
| `POST /soc/case?id=12&verdict=mine` | close a case: `mine` / `handled` / `false_alarm` |
| `GET /soc/actions` · `POST /soc/undo?id=7` | automatic actions, and undo (e.g. unblock) |
| `POST /soc/allow?value=198.51.100.&note=office` | never-block an IP or prefix |

Per-rule overrides: `SOC_RULES` var, e.g. `{"admin_new_network":{"sev":"MEDIUM"},"error_spike":{"off":true}}`.
Locked rules ignore it.

The tables (`soc_incidents`, `soc_actions`, `soc_blocks`) live in your app's D1, so your own admin panel
can show a Security tab straight from them.
</details>

---

## Tests

Node ≥ 22.13, no `npm install` (built-in `node:sqlite` as a D1 stand-in; fake KV/R2; mocked Cloudflare,
GitHub and site).

```bash
npm test      # 39 tests
```
**SOC (17):** learn-first · honeytoken → case + sign-out + block without a double page · key guessed ·
new network in a browser vs a script · home residential never blocked · genuine self-test skipped but a **spoofed self-test User-Agent still caught** ·
cooldown counts on the case · OTP pumping + brute force · impossible-price order held · tamper (coupon,
deleted rows, price crash) · posture (stranger token with who, new member, public bucket, own DNS change
quiet) · integrity (skimmer on checkout, script changed with and without a deploy, nonce-insensitive inline
hashing, JSON-LD skipped) · self-test (open admin API vs SPA fallback) · block escalation / expiry / undo /
allow-list · locked rules · daily summary.
**Uptime (14):** watchdog confirm-twice, outage memory in D1/R2, blind mode, backup age, endpoint auth;
sentinel alert/fixed, two-clock stand-down, need-N checks, Free-plan KV flushing, weekly report.
**Honeytokens (8):** hooks, normalisation, cooldown, `waitUntil`, decoy mailbox, generator.

## Repository layout

```
SKILL.md                                  what Claude reads
templates/site/functions/api/
  watchdog.js  _seclog.js  _honey.js      in your app
templates/site/schema.sql
templates/sentinel/
  wrangler.toml
  src/index.js  src/checks.js  src/notify.js
  src/soc/ config.js run.js raise.js guide.js detect.js tamper.js posture.js who.js integrity.js selftest.js respond.js util.js
templates/backup/d1-backup.yml
scripts/make-decoys.mjs
references/ soc-rules.md cloudflare-token.md honeytokens.md uptime-design.md browser-journey.md
tests/
```

## Limits

- Cloudflare-specific templates (bindings, API). The patterns port to other serverless platforms, the code needs adapting.
- Detection is only as good as the events your app writes. Without `secLog` calls, detect has nothing to read.
- It isn't a WAF. Pair it with Cloudflare's WAF/rate-limit rules, and use the cases to decide which ones to add.
- Cloudflare audit-log field names differ between API versions. `who.js` reads them defensively; check that the "Who:" line is filled on your account.
- Script integrity checks the HTML your server sends. Scripts injected later by a tag manager need that tag manager's own change log.

## Related
- [wa-cod-lifecycle](https://github.com/dayasinghchauhan/wa-cod-lifecycle): WhatsApp COD confirmation, order-again and abandoned-cart flows for the same kind of shop.

## License

MIT
