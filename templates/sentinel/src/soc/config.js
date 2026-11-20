/**
 * SOC settings. This is the only SOC file you edit; everything in src/soc/* reads from here.
 * Each block can be emptied to switch that part off.
 */
import { SITE } from '../checks.js';
export { SITE };

export const SOC = {
  // Countries where the admin normally works (ISO codes). Admin use from elsewhere is HIGH.
  HOME_COUNTRIES: ['IN'],

  // "Own" actors: a change made by one of these goes to the daily summary, not your phone.
  OWN_EMAILS: ['owner@example.com'],                 // your Cloudflare logins
  OWN_TOKENS: {                                      // your Cloudflare API token NAME → what it exists to do (regex on audit action/resource)
    'ci-deploy': /pages|deployment|worker/i,
    'backup-job': /d1|r2/i,
  },

  // Cloudflare (needs CF_TOKEN + CF_ACCOUNT secrets; see references/cloudflare-token.md)
  ZONES: ['example.com'],                            // zone NAMES whose DNS + security settings are watched
  ZONE_SETTINGS: ['ssl', 'always_use_https', 'min_tls_version', 'security_level'],
  PRIVATE_BUCKETS: ['backups'],                      // R2 buckets that must NEVER get a public address
  BLOCK_ZONE: 'example.com',                         // zone where automatic IP blocks are created ('' = never block)

  // Automatic responses (all can be switched off).
  AUTO: {
    blockHostingOrAbroad: true,   // block attacker IPs on hosting networks or outside HOME_COUNTRIES (never home residential: shared by real customers)
    signOutOnKeyGuessed: true,    // a key that worked after repeated wrong tries → every admin session out
    signOutOnHoneytoken: true,
    holdUnderpricedOrders: true,
  },
  BLOCK_HOURS: [24, 24 * 7, 24 * 30],  // 1st, 2nd (within 30 days), 3rd+ block of the same IP

  // SQL run on the app's D1 for the automatic responses ('' = skip). Must be idempotent.
  SIGN_OUT_ALL_SQL: "DELETE FROM admin_sessions",
  // Orders that cannot be right (price tampering, fractional quantities). ? = since timestamp.
  UNDERPRICED_SQL: "SELECT id, total FROM orders WHERE created_at >= ? AND status = 'pending' AND total < 100",
  HOLD_ORDER_SQL: "UPDATE orders SET status = 'on_hold' WHERE id = ? AND status = 'pending'",

  // Detection thresholds.
  KEY_GUESS_FAILS: 5,          // wrong tries from one network in 60 min before a success = "key guessed"
  BRUTE_FAILS_10MIN: 20,       // wrong tries from one IP in 10 min
  ATTACK_SCAN_PER_HOUR: 30,    // injection-looking requests from one IP in 1 h
  OTP_PER_HOUR: 40,            // sign-in codes sent in 1 h (each costs money)
  OTP_PER_IP_HOUR: 10,
  ERROR_SPIKE_5MIN: 10,
  WEBHOOK_BAD_SIG_DAY: 6,
  CSP_PER_HOUR: 25,
  SENSITIVE_PATHS: /\/api\/(admin|auth|login|orders?|checkout|users?|customers?|payment|account|address|otp|cart|coupon)/i,

  // Tamper: snapshots of the app's D1, compared every 5 min. k = row key, v = value to compare.
  // on = which differences ring. The first run only learns.
  TAMPER: [
    { id: 'admin_users', label: 'Admin users', sev: 'HIGH', on: ['added', 'changed'],
      sql: "SELECT username AS k, role AS v FROM admin_users" },
    { id: 'admin_devices', label: 'Admin push devices', sev: 'HIGH', on: ['added'],
      sql: "SELECT substr(token, 1, 16) AS k, COALESCE(name, '') AS v FROM admin_devices" },
    { id: 'coupons', label: 'Coupons', sev: 'HIGH', on: ['added', 'changed'],
      sql: "SELECT code AS k, COALESCE(percent, '') || '|' || COALESCE(active, '') AS v FROM coupons" },
    { id: 'prices', label: 'Product prices', sev: 'HIGH', mode: 'price_drop', dropPct: 40,
      sql: "SELECT sku AS k, price AS v FROM products" },
  ],
  // Row counts that must never fall (rows deleted). Table names only.
  NO_DELETE_TABLES: ['orders', 'users', 'products'],

  // Script integrity (card-skimming / Magecart): pages whose <script>s are inventoried hourly.
  PAGES: [
    { path: '/', name: 'home' },
    { path: '/checkout', name: 'checkout', payment: true },   // payment page: a new outside script is CRITICAL
  ],
  SCRIPT_HOSTS: ['cdnjs.cloudflare.com', 'checkout.example-payments.com', 'www.googletagmanager.com'],
  // How to tell "a new version was deployed" (a script change WITH a deploy is normal).
  // Cloudflare Pages project name (uses CF_TOKEN), or a URL that returns the deployed version.
  PAGES_PROJECT: 'my-shop',
  VERSION_URL: '',

  // Public code: repos that SHOULD be public. Any other public repo on these accounts rings HIGH.
  GITHUB_USERS: [],
  PUBLIC_REPOS_OK: [],

  // Daily self-test: the attacks your app must keep refusing. A regression is HIGH.
  SELFTEST: [
    { name: 'admin API without key', path: '/api/admin/orders', expect: [401, 403] },
    { name: 'admin API with a wrong key', path: '/api/admin/orders', headers: { 'x-admin-key': 'selftest-wrong-key-0000000000' }, expect: [401, 403] },
    { name: 'env file', path: '/.env', expectNot: [200] },
    { name: 'git config', path: '/.git/config', expectNot: [200] },
    { name: 'wrangler config', path: '/wrangler.toml', expectNot: [200] },
    { name: 'database dump', path: '/backup.sql', expectNot: [200] },
  ],
  // The app's logs of the self-test's requests are skipped only with this UA AND a Cloudflare Workers source IP
  // AND inside the self-test run's window: the UA alone is public and hides nothing.
  SELFTEST_UA: 'SOC-SelfTest/1.0',

  // Old deployments keep running their old code against the live database. 0 = do not prune.
  PRUNE_KEEP_PRODUCTION: 0,
  PRUNE_KEEP_PREVIEW: 0,

  // When the daily summary goes (minutes after 00:00 UTC). 210 = 03:30 UTC = 09:00 IST.
  SUMMARY_UTC_MIN: 210,
};

// Rules that can never be switched off or downgraded from the rules setting.
export const LOCKED_RULES = new Set(['honeytoken', 'backups_public', 'cf_member_added', 'cf_2fa_off', 'rows_deleted', 'script_changed_no_deploy', 'payment_script_added']);
