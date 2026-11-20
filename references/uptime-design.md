# Design notes: why each rule exists

Each rule guards against a failure mode that small apps on Cloudflare Pages + D1 + R2 can hit.

## The failure this is built around
If R2 is disabled at the account level (billing or a plan change):
- files start returning 403 as the CDN cache empties;
- every backup upload fails;
- a health check that only tests `typeof env.IMAGES !== 'undefined'` stays
  **green**. A binding still exists when the product behind it is off.

Without a real probe, nobody finds out until a customer or an unrelated email says so.
Lesson: **probe with real work**.

## Rule by rule

| Rule | What happens without it |
|---|---|
| D1 **write** + read | D1 over a plan limit, or read-only during an incident, still answers `SELECT`. Checkout fails, health stays green. |
| R2 `list({limit:1})` per bucket | Binding exists, product is off (above). |
| Backup age < 26 h from **dated keys** | Backups fail without anyone noticing (expired token, Actions minutes used up, GitHub pausing scheduled workflows in an inactive repo). Dated keys let you list 3 small prefixes instead of a whole bucket. |
| 2 failures, 45 s–10 min apart | A single transient error (a momentary "overloaded") would send DOWN and FIXED within a minute. That noise teaches people to ignore alerts. The 45 s floor matters because two clocks (external pinger + an internal tick) can land in the same second. That isn't a second opinion. |
| Forget a first failure after 10 min | If the checks themselves stopped for an hour, a stale first failure must not count as "confirmed". |
| One alert + remind every 6 h + "Fixed" with the duration | Paging every minute gets the channel muted. Without "Fixed" nobody knows when to stop worrying. |
| State in D1 **and** R2, newer wins | The watchdog's own memory would live in the thing that's down. With one store down, the other remembers what was sent. |
| "Blind" (both down) → only at :00 and :30 | With no memory every run looks like the first one, so without this the alert would repeat every minute. |
| Write state only on change | A per-minute monitor that writes every run is the biggest writer on a small D1/KV, and costs money on R2 Class A operations. |
| 503 on any problem | The external pinger (cron-job.org, UptimeRobot) emails on non-2xx. That road still works when your Worker, Discord and push are all down. |
| Constant-time key compare, no D1 lockout | The usual admin-key check rate-limits through a D1 table. When D1 is down the watchdog would answer 500, and the pinger can't tell "D1 down" from "watchdog broken". |
| Separate sentinel Worker | Code inside the site can't report the site being down. |
| Two clocks + stand-down | The native cron can stop (for example a plan downgrade removes cron slots). The external pinger keeps it alive. The stand-down stops double runs. |
| Healthchecks heartbeat, never `/fail` | The sentinel already alerted on what it saw. Sending `/fail` too means every alert arrives twice. Healthchecks is only there to notice when the sentinel stops. |
| `need: 3` for outside APIs | Payment, courier and Meta APIs blip. Three runs in a row is about 3–15 min, which is quick enough and quiet. |
| One retry after 3 s per check | Removes most single-packet false alarms at almost no cost. |
| Skipped check keeps its last result | Slow checks run every 5 min. Without this, a minute when they didn't run reads as "everything passed", which means a false "Fixed" and then a fresh "DOWN". |
| Site 503 + `problems[]` ≠ sentinel alarm | The site already paged about D1/R2. The sentinel only alarms when the watchdog endpoint itself is unreachable. |
| Load budget | At a 1-minute interval for every check, a monitor can become a **large share of all requests** to a small site. Homepage every minute, everything else every ~5 min (every minute while failing) keeps alerts minute-accurate. |
| No customer data in alerts | Discord and Slack are third-party processors. Under privacy laws (GDPR, India's DPDP Act), keep personal data out. Say *what* broke. |

## Choosing where alerts go
- **Discord / Slack webhook**: easy, shared with a team, but a third party.
- **ntfy.sh**: a free phone push, no account needed. Use a long random topic name, or self-host.
- **Firebase Cloud Messaging**: if you already have your own admin app. Keep a copy of the device tokens in the watchdog state, because the normal push code reads them from D1.
- Keep **at least two roads**. The cron-job.org email is the always-on second one.

## Extending
- More stores (KV, Queues, Durable Objects): add a probe that does real work, plus a `LABEL` and a `problemsOf` entry.
- More outside checks: add an entry to `checks.js`. Pick `need` by how flaky the target is.
- Certificates: Cloudflare renews edge certificates about 30 days early. Watching certificate *settings* changes (audit logs) is more useful than watching expiry.
