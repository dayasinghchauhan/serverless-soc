/**
 * Every security alert is written in four parts, so it can be acted on from a phone:
 *   What happened  · From where · What it means (+ "if it was you") · What to do, in order
 * Keyed by rule (the part of the alert key before the first ':').
 */
const ROTATE = 'Rotate the admin key and every staff password; sign everyone out.';
const CF_MEMBERS = 'Cloudflare → Manage Account → Members and API Tokens: remove anything you do not recognise.';

export const GUIDE = {
  honeytoken: { means: 'A decoy that exists only inside your database and its backups was used. Someone has a copy of your data or admin access.', mine: 'Only if you were testing the decoys on purpose.',
    todo: [ROTATE, 'Check the backups bucket is private (no r2.dev / custom domain).', CF_MEMBERS, 'Read this case\'s trace: everything this address did.', 'Consider the legal notice duty for a personal-data leak.'] },
  admin_abroad: { means: 'Your admin was used from outside your home countries, from a network it has never used.', mine: 'You or a staff member travelling / on a VPN.',
    todo: ['If not you: ' + ROTATE, 'Block the address (it may already be blocked automatically).'] },
  admin_new_network: { means: 'Your admin was used from a network and device never seen before.', mine: 'A new phone, a new SIM, a new office.',
    todo: ['If not you: ' + ROTATE] },
  key_guessed: { means: 'The admin key WORKED after repeated wrong tries from the same network: it was probably guessed or brute-forced.', mine: 'Only if you mistyped it many times and then got it right.',
    todo: ['Every admin session was signed out automatically.', ROTATE, 'Make the key longer (32+ random characters).'] },
  brute_force: { means: 'Many wrong admin keys/passwords from one address. Nothing worked.', mine: 'A misconfigured script of yours with an old key.',
    todo: ['Nothing urgent; hosting / foreign addresses are blocked automatically.', 'If it continues from home-country addresses, add a WAF rate-limit rule.'] },
  attack_sensitive: { means: 'Injection-looking input reached a sensitive endpoint (login, orders, payment, admin).', mine: 'A security scan you ran yourself.',
    todo: ['Check that endpoint\'s logs for any 200 answers to those requests.', 'Hosting / foreign addresses are blocked automatically.'] },
  attack_scan: { means: 'One address sent many injection-looking requests in an hour: an automated scanner.', mine: 'Your own scanner.',
    todo: ['Usually nothing; it is blocked automatically when on a hosting network or abroad.'] },
  probe_succeeded: { means: 'A request for a file that must never be public got a 200 answer.', mine: '-',
    todo: ['Open that URL yourself. If it serves real content, remove it from the deploy NOW.', 'Rotate any secret that file contained.'] },
  webhook_forged: { means: 'Many webhook calls with a bad signature: someone is forging them, or your secret changed.', mine: 'You rotated the webhook secret on one side only.',
    todo: ['Compare the webhook secret in the provider dashboard and in your app.'] },
  otp_abuse: { means: 'An unusual number of sign-in codes were sent. Each costs money; this is often SMS/WhatsApp pumping fraud.', mine: 'A real sale or campaign spike.',
    todo: ['Check the numbers / countries the codes went to.', 'Lower the per-IP and per-number limits.'] },
  error_spike: { means: 'Server errors are spiking.', mine: 'A deploy you just did.', todo: ['Check the latest deploy and roll back if needed.'] },
  tfa_off: { means: 'Two-step login was turned off for an admin.', mine: 'You did it yourself.', todo: ['If not you: turn it back on, ' + ROTATE] },
  secret_replaced: { means: 'A service key (payment, messaging, courier…) was replaced from the admin.', mine: 'You rotated it.',
    todo: ['If not you: put the right key back from the provider dashboard and ' + ROTATE] },
  tamper: { means: 'Sensitive data in your database changed (admins, devices, coupons…).', mine: 'You or staff changed it in the admin.',
    todo: ['Check the change in your admin. If nobody did it: ' + ROTATE] },
  rows_deleted: { means: 'Rows were DELETED from a table that should only grow.', mine: 'A clean-up you ran on purpose.',
    todo: ['Restore from the latest backup if it was not you.', ROTATE] },
  price_drop: { means: 'Product prices dropped sharply.', mine: 'A sale you set up.', todo: ['If not you: put prices back and ' + ROTATE] },
  order_underpriced: { means: 'An order came in at a price that cannot be right: price tampering in the checkout.', mine: 'A test order.',
    todo: ['The order was held before courier booking.', 'Check how the total was computed (never trust a total from the browser).'] },
  cf_token_added: { means: 'A new Cloudflare API token was created.', mine: 'You made one.', todo: [CF_MEMBERS] },
  cf_member_added: { means: 'Someone new has access to your Cloudflare account.', mine: 'You invited them.', todo: [CF_MEMBERS, 'Check what they changed (audit log).'] },
  cf_2fa_off: { means: 'Two-factor login was turned OFF for a Cloudflare member.', mine: 'You turned it off.', todo: ['Turn it back on. Change that login\'s password.'] },
  dns_changed: { means: 'DNS records changed: traffic or email could be redirected.', mine: 'You changed DNS.', todo: ['Compare the records with what you expect; revert unknown ones.', CF_MEMBERS] },
  zone_settings_changed: { means: 'A site security setting changed (SSL mode, HTTPS, TLS, security level).', mine: 'You changed it.', todo: ['Put it back unless you meant it.'] },
  backups_public: { means: 'A bucket that holds private data (backups) has a PUBLIC address.', mine: '-',
    todo: ['R2 → bucket → Settings → turn off the r2.dev URL and remove custom domains NOW.', 'Assume the contents were downloaded: ' + ROTATE] },
  cf_change_by_stranger: { means: 'A Cloudflare change was made by a login or token that is not on your own list.', mine: 'A login of yours missing from OWN_EMAILS / OWN_TOKENS.',
    todo: ['Add it to the own list if it is yours; otherwise ' + CF_MEMBERS] },
  script_added: { means: 'A page now loads a script from a host never seen before.', mine: 'You added a new tool (analytics, chat…).', todo: ['If not you: find where it is injected (code, tag manager, CMS) and remove it.'] },
  payment_script_added: { means: 'Your PAYMENT page loads a script from a new outside host. This is how card-skimming code (Magecart) appears.', mine: 'You added a new payment / analytics tool.',
    todo: ['If not you: take the page offline or roll back NOW.', 'Find the injection point: repo, tag manager, a compromised dependency.'] },
  script_changed_no_deploy: { means: 'Your own script changed while no new version was deployed: someone is serving different code.', mine: '-',
    todo: ['Compare the live file with your repo.', 'Check Cloudflare Workers/Rules that could rewrite responses.', ROTATE] },
  csp_burst: { means: 'Browsers are reporting many blocked script/style loads: something is trying to load where it should not.', mine: 'A new tool you added but did not allow in the CSP.',
    todo: ['Look at the blocked URLs in the reports.'] },
  repo_public: { means: 'A repository became public. Its code and its whole history (old secrets too) are now readable.', mine: 'You made it public on purpose.',
    todo: ['Make it private again unless intended; rotate any secret ever committed.'] },
  selftest_failed: { means: 'A protection that used to work stopped working (found by the daily self-test).', mine: '-', todo: ['Fix the listed check; it is open to the public right now.'] },
  soc_blind: { means: 'The security monitor cannot read part of Cloudflare.', mine: 'A token was rotated or lost a permission.', todo: ['Check CF_TOKEN permissions (references/cloudflare-token.md).'] },
  soc_failing: { means: 'The security monitor itself keeps failing.', mine: '-', todo: ['Run GET /soc/run?wait=1 and read the errors.'] },
};

/** The four parts as text. */
export function fourParts(rule, { facts = '', from = null, who = '', why = '' } = {}) {
  const g = GUIDE[rule] || { means: '', mine: '', todo: [] };
  const where = from ? [from.ip && 'IP ' + from.ip + (from.country ? ' (' + from.country + ')' : '') + (from.asnOrg ? ', ' + from.asnOrg : ''), from.device, from.path].filter(Boolean).join(' · ') : '';
  return [
    'What happened: ' + facts,
    where && 'From where: ' + where,
    who && 'Who: ' + who + (why ? ' (' + why + ')' : ''),
    g.means && 'What it means: ' + g.means + (g.mine && g.mine !== '-' ? ' If it was you: ' + g.mine : ''),
    g.todo.length && 'What to do:\n' + g.todo.map((t, i) => (i + 1) + '. ' + t).join('\n'),
  ].filter(Boolean).join('\n');
}
