# Placement, meaning and response

## Why honeytokens, not a honeypot
A honeypot (T-Pot, Cowrie) is a server that attracts attackers. A serverless app has
no server, so a honeypot would be a new VPS to patch, a new attack surface,
and mostly a feed of internet background noise. It doesn't answer the question that
matters to a small shop: *did my customer data get out?* A honeytoken does,
and it costs one table row.

## Where to plant
| Place | Why an intruder finds it | Notes |
|---|---|---|
| A credentials-looking table (`ops_credentials`, `service_keys`) | Anyone dumping the DB greps for `key`, `token`, `secret` | Give rows boring, believable names and notes ("rotate yearly") |
| A customer row | Anyone exporting or reselling the customer list | Flag `is_decoy = 1`, hide it from every admin read |
| Backups | Same rows, automatically | A backup bucket left public is a classic leak, and this is how you'd find out |
| *(optional)* An env-looking file in a **private** bucket | Someone with R2/S3 access browsing | Hash its decoy key the same way |

**Never** plant decoys anywhere public: in HTML, JS bundles, robots.txt or a public repo.
Scanners would hit them all day and the signal would be gone.

## What a hit means
| Kind | Most likely cause |
|---|---|
| admin-key / admin-session | A DB dump or backup is being tried against your admin API. Could be an insider with DB access, or a compromised backup bucket. |
| phone (login code / tracking) | The customer list is being worked through: phishing prep, OTP abuse, a resold dump. |
| email (lookup or mail received) | Same, through the email channel. Mail received usually means the list was sold or used for spam. |

There is no innocent explanation except **your own test**. Treat every hit as an incident.

## Response playbook (put it in the alert, or link to it)
1. **Rotate**: admin key, every staff password, sessions (sign everyone out), API tokens with DB access.
2. **Close the leak path**: backup bucket public access OFF; check the bucket's public URL / custom domain; review who has Cloudflare account membership and API tokens; audit log for exports.
3. **Trace**: query `security_events` and your request log for that IP / ASN / UA. What else did it touch?
4. **Block**: the IP / ASN at the WAF if it's a hosting network or an unexpected country.
5. **Assess the legal duty**: a confirmed leak of personal data may need a notice to the regulator or to customers (GDPR 72 h; India DPDP Act: the Data Protection Board and the affected people "without delay"). Check with counsel.
6. **Re-plant**: generate fresh decoys after the incident. The old ones are now known.

## Operating notes
- Rate limit: 20 logged rows per hour per kind, one page per hour per kind. A script
  looping on a stolen key can't flood your table or your phone.
- `honey_state` uses read-modify-write. Under heavy parallel hits the counters can
  drift slightly. That's harmless, since the first hit always pages.
- The SOC in this repo turns every hit into a CRITICAL case with automatic sign-out and blocking. The security
  alert can reuse the same roads (Discord/Slack/ntfy).
- Re-check once a year that the decoy rows still exist. A cleanup or migration can
  quietly delete them.
