# The sentinel's Cloudflare API token (`CF_TOKEN`)

Create it at **My Profile → API Tokens → Create Token → Custom token**. Give it only what the
parts you turn on need. Without `CF_TOKEN` the SOC still runs detect, tamper, the self-test and integrity
(without the deploy marker). Blocks are then recorded as `pending_token`.

| Part | Permission (as named in the token editor) | Scope |
|---|---|---|
| Posture: tokens | Account → **Account API Tokens: Read** | your account |
| Posture: members + 2FA | Account → **Account Settings: Read** | your account |
| Posture: who-did-it | Account → **Account Settings: Read** (account audit logs) | your account |
| Posture: private buckets | Account → **Workers R2 Storage: Read** | your account |
| Posture: DNS + settings | Zone → **DNS: Read**, **Zone Settings: Read** | the zones in `SOC.ZONES` |
| Automatic IP blocks | Zone → **Firewall Services: Edit** (IP Access Rules) | `SOC.BLOCK_ZONE` |
| Deploy marker | Account → **Cloudflare Pages: Read** | your account |
| Pruning old deployments | Account → **Cloudflare Pages: Edit** | only if `PRUNE_KEEP_PRODUCTION > 0` |

Cloudflare renames permissions now and then. If one is missing, the next hourly run sends a MEDIUM
`soc_blind` alert naming the API call that was refused, so you know exactly what to add.

Add the token's own NAME to `SOC.OWN_TOKENS` with the job it exists for, so the token's own changes
(for example a block it creates) aren't reported as "a stranger".

Rotate the token if a `honeytoken`, `cf_member_added` or `cf_change_by_stranger` case turns out to be real.
