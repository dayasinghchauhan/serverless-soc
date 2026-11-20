# SOC rule catalogue

Every rule: what triggers it, its severity, the automatic response, and where it reads from.
**Severity routing:** CRITICAL / HIGH → channel + phone push · MEDIUM → channel only ·
LOW / own changes / refused attacks → the daily summary. 🔒 = locked (can't be switched off or downgraded).

## Detect: app security events (every 5 min)
The app writes events with `_seclog.js` (`secLog(context, kind, …)`). Rows whose User-Agent contains
`SOC.SELFTEST_UA` are skipped only when they **also** come from Cloudflare's Workers network and arrive
within 10 minutes of the self-test run (the daily attack drill). A spoofed User-Agent alone is counted like any other request.

| Rule | Trigger (event kinds) | Sev | Automatic response |
|---|---|---|---|
| `honeytoken` 🔒 | any `honeytoken:*` (from `_honey.js` or the decoy mailbox) | CRITICAL | sign out all admins · block IP if hosting/abroad. No second message if the site already paged (`meta.paged`) |
| `key_guessed` | `admin_ok` from a **new** network after ≥ `KEY_GUESS_FAILS` `admin_fail` from that network in 60 min | HIGH | sign out all admins · block |
| `admin_abroad` | `admin_ok` from a new network outside `HOME_COUNTRIES` or on a hosting network | HIGH | none (it may be you travelling) |
| `admin_new_network` | `admin_ok` from a new network by a **script** User-Agent (curl, python, …) | HIGH | none |
| *(note)* | `admin_ok` from a new home-country network in a browser | LOW | summary only |
| `brute_force` | ≥ `BRUTE_FAILS_10MIN` `admin_fail` from one IP in 10 min | MEDIUM | block |
| `attack_sensitive` | `attack` on a path matching `SENSITIVE_PATHS` | HIGH | block |
| `attack_scan` | ≥ `ATTACK_SCAN_PER_HOUR` `attack` from one IP in 1 h | HIGH | block |
| *(count)* | `attack` elsewhere, `probe` refused | LOW | summary counts |
| `probe_succeeded` | `probe` with `meta.status = 200` (a never-public path answered) | HIGH | none |
| `otp_abuse` | ≥ `OTP_PER_HOUR` `otp_sent` in 1 h; or ≥ `OTP_PER_IP_HOUR` from one IP | HIGH | block (per-IP case) |
| `error_spike` | ≥ `ERROR_SPIKE_5MIN` `server_error` in 5 min | MEDIUM | none |
| `webhook_forged` | ≥ `WEBHOOK_BAD_SIG_DAY` `webhook_bad_sig` in 24 h | MEDIUM | none |
| `csp_burst` | ≥ `CSP_PER_HOUR` `csp` in 1 h | MEDIUM | none |
| `tfa_off` | `tfa_off` | HIGH | none |
| `secret_replaced` | `secret_replaced` | HIGH | none |
| `order_underpriced` | a row from `UNDERPRICED_SQL` | HIGH | `HOLD_ORDER_SQL` (held before the courier) |

**Blocking rules:** only IPs on a **hosting network** (ASN name looks like AWS, GCP, Hetzner, OVH, "hosting",
"server", …) or **outside `HOME_COUNTRIES`**. A home-country residential IP is never blocked automatically,
because mobile carriers put many real customers behind one address. Never blocked: private ranges,
the Cloudflare Workers range (your own Workers), `soc_allow` entries, and any IP an admin used in the last 24 h.
Durations escalate per IP within 30 days: 24 h → 7 days → 30 days (`BLOCK_HOURS`).

## Tamper: app database snapshots (every 5 min)
| Rule | Trigger | Sev |
|---|---|---|
| `tamper:<id>` | a `SOC.TAMPER` query's rows were added / removed / changed (per its `on`) | per entry (HIGH) |
| `price_drop` | a `mode: 'price_drop'` entry fell more than `dropPct` % | HIGH |
| `rows_deleted:<table>` 🔒 | `COUNT(*)` of a `NO_DELETE_TABLES` table went down | HIGH |

## Posture: Cloudflare account (hourly)
| Rule | Trigger | Sev |
|---|---|---|
| `cf_token_added` | a new account API token | HIGH, or summary if the audit log shows one of your own |
| `cf_member_added` 🔒 | a new account member | CRITICAL (HIGH if it's one of `OWN_EMAILS` and you invited it) |
| `cf_2fa_off` 🔒 | a member's two-factor flag went false | CRITICAL |
| `dns_changed` | DNS records of `ZONES` added / removed / proxy flipped (`_acme-challenge` ignored) | HIGH, or summary if own |
| `zone_settings_changed` | a `ZONE_SETTINGS` value changed | HIGH, or summary if own |
| `backups_public` 🔒 | a `PRIVATE_BUCKETS` bucket has an r2.dev URL or a custom domain | CRITICAL |
| `cf_change_by_stranger` | an audit-log entry by a login or token not in `OWN_EMAILS` / `OWN_TOKENS` | HIGH |
| `soc_blind` | a posture call failed (token permission missing) | MEDIUM |

**"Own" changes:** an audit-log actor whose e-mail is in `OWN_EMAILS`, or a token whose name is in
`OWN_TOKENS` *and* whose action matches that token's job regex. A deploy token creating members is **not** own.

## Integrity: page scripts and public code (hourly)
| Rule | Trigger | Sev |
|---|---|---|
| `payment_script_added` 🔒 | a `payment: true` page loads a script from a host not seen before and not in `SCRIPT_HOSTS` | CRITICAL |
| `script_added` | the same on another page | HIGH |
| `script_changed_no_deploy` 🔒 | an own script's bytes, or an inline script's code skeleton, changed while the deploy marker did not | HIGH |
| *(note)* | scripts changed together with a new deploy | summary |
| `repo_public` | a new public repo on `GITHUB_USERS` not in `PUBLIC_REPOS_OK` | HIGH |

## Daily
| Rule | Trigger | Sev |
|---|---|---|
| `selftest_failed` | a `SOC.SELFTEST` probe got an unexpected answer (a 200 SPA fallback page without secrets isn't a leak) | HIGH |
| *(reminder)* | a CRITICAL case still open after 24 h | page again, daily |
| *(auto-close)* | MEDIUM quiet for 3 days, HIGH quiet for 14 days. CRITICAL only closes by hand | none |
| `soc_failing` | the SOC run itself errored 3 runs in a row | MEDIUM |

## Per-rule overrides
`SOC_RULES` (sentinel var, JSON):
```json
{ "admin_new_network": { "sev": "MEDIUM" }, "error_spike": { "off": true }, "attack_sensitive": { "ignore": ["/api/search"] }, "otp_abuse": { "cooldownH": 24 } }
```
Locked rules ignore `off`, `sev` and `ignore`.
