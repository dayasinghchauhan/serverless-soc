/**
 * Detect (every 5 min): new rows of the app's security_events (by id cursor) → rules.
 * The app writes them with templates/site/functions/api/_seclog.js (and _honey.js).
 */
import { SOC } from './config.js';
import { iso, parse, parseTs, netPrefix, netType, deviceClass, isCfWorkerIp, H, MIN, DAY } from './util.js';
import { blockIp, signOutAll, holdOrder } from './respond.js';

const BATCH = 2000;

async function count(db, kind, sinceIso, extra = '', binds = []) {
  return db.prepare(`SELECT COUNT(*) n FROM security_events WHERE kind = ? AND created_at >= ? ${extra}`).bind(kind, sinceIso, ...binds).first('n');
}

export async function detect(ctx, raise) {
  const { env, state, now } = ctx;
  const db = env.DB;
  state.networks ||= {};
  if (state.cursor == null) {
    // First run: learn the admin's networks from the last 30 days, alert on nothing that already happened.
    const { results } = await db.prepare("SELECT ip, created_at FROM security_events WHERE kind = 'admin_ok' AND created_at >= ?").bind(iso(now - 30 * DAY)).all();
    for (const r of results || []) { const n = netPrefix(r.ip); if (n && !state.networks[n]) state.networks[n] = parseTs(r.created_at); }
    state.cursor = (await db.prepare('SELECT MAX(id) m FROM security_events').first('m')) || 0;
    return { learned: Object.keys(state.networks).length };
  }

  const { results } = await db.prepare('SELECT * FROM security_events WHERE id > ? ORDER BY id LIMIT ?').bind(state.cursor, BATCH).all();
  const rows = results || [];
  if (rows.length) state.cursor = rows[rows.length - 1].id;
  // The daily self-test's own requests. The User-Agent alone proves nothing (anyone can send it),
  // so all three must hold: the self-test UA, Cloudflare's Workers network (where the sentinel's
  // requests come from), and a time inside the self-test run's window.
  const testAt = state.slots && state.slots.selftest;
  const isSelfTest = (r) => {
    if (!SOC.SELFTEST_UA || !testAt || !String(r.ua || '').includes(SOC.SELFTEST_UA) || !isCfWorkerIp(r.ip)) return false;
    const t = parseTs(r.created_at);
    return t >= testAt - MIN && t <= testAt + 10 * MIN;
  };
  const acted = new Set();
  const block = async (r, reason, caseId) => {
    if (!r.ip || acted.has('b' + r.ip)) return;
    acted.add('b' + r.ip);
    const b = await blockIp(env, db, { ip: r.ip, reason, incident: caseId, country: r.country, asnOrg: r.asn_org }, now);
    ctx.digest.blocked += b.ok && !b.already ? 1 : 0;
  };
  const from = (r) => ({ ip: r.ip, country: r.country, asnOrg: r.asn_org, device: deviceClass(r.ua), path: r.path });
  const kinds = new Set();

  for (const r of rows) {
    if (isSelfTest(r)) continue;
    const m = parse(r.meta, {}) || {};
    kinds.add(r.kind);

    if (r.kind.startsWith('honeytoken:')) {
      const kind = r.kind.slice(11);
      const id = await raise('CRITICAL', 'honeytoken:' + kind, 'Decoy ' + kind + ' used: your data has leaked', { facts: r.message || kind, from: from(r), quiet: !!m.paged, cooldownH: 1 });
      if (!acted.has('so') && SOC.AUTO.signOutOnHoneytoken) { acted.add('so'); await signOutAll(env, db, { incident: id, reason: 'decoy ' + kind + ' used' }, now); }
      await block(r, 'used the decoy ' + kind, id);
      continue;
    }

    if (r.kind === 'admin_ok') {
      const net = netPrefix(r.ip);
      if (!net || state.networks[net]) continue;
      state.networks[net] = now;   // learned from now on, whatever the verdict
      const type = netType(r.country, r.asn_org);
      const fails = ((await db.prepare("SELECT ip FROM security_events WHERE kind = 'admin_fail' AND created_at >= ? AND id < ?").bind(iso(parseTs(r.created_at) - H), r.id).all()).results || [])
        .filter((x) => netPrefix(x.ip) === net).length;
      if (fails >= SOC.KEY_GUESS_FAILS) {
        const id = await raise('HIGH', 'key_guessed:' + net, 'Admin key worked after ' + fails + ' wrong tries', { facts: 'Actor ' + (r.actor || '?') + ' on ' + (r.path || '?') + ', from a new network.', from: from(r), who: r.actor });
        if (SOC.AUTO.signOutOnKeyGuessed) await signOutAll(env, db, { incident: id, reason: 'key guessed' }, now);
        await block(r, 'admin key guessed', id);
      } else if (type === 'abroad' || type === 'hosting') {
        await raise('HIGH', 'admin_abroad:' + net, 'Admin used from ' + (type === 'hosting' ? 'a hosting network' : 'outside ' + SOC.HOME_COUNTRIES.join('/')) + ' (' + (r.country || '?') + ')',
          { facts: 'Actor ' + (r.actor || '?') + ' on ' + (r.path || '?') + ', a network the admin never used.', from: from(r), who: r.actor });
      } else if (deviceClass(r.ua) === 'script') {
        await raise('HIGH', 'admin_new_network:' + net, 'Admin used by a script from a new network', { facts: 'Agent: ' + String(r.ua || 'none').slice(0, 80), from: from(r), who: r.actor });
      } else ctx.note('Admin from a new home network (' + (r.country || '?') + ', ' + deviceClass(r.ua) + ')' + (r.actor ? ' by ' + r.actor : ''));
      continue;
    }

    if (r.kind === 'attack') {
      if (SOC.SENSITIVE_PATHS.test(r.path || '')) {
        const id = await raise('HIGH', 'attack_sensitive:' + r.ip, 'Injection attempt on a sensitive endpoint', { facts: (m.pattern || 'suspicious input') + ' on ' + r.path, from: from(r) });
        await block(r, 'injection on ' + r.path, id);
      } else ctx.digest.attacks++;
      continue;
    }
    if (r.kind === 'probe') {
      if (Number(m.status) === 200) await raise('HIGH', 'probe_succeeded:' + String(r.path).slice(0, 60), 'A scanner reached a private file', { facts: r.path + ' answered 200', from: from(r) });
      else ctx.digest.probes++;
      continue;
    }
    if (r.kind === 'tfa_off') await raise('HIGH', 'tfa_off:' + (r.actor || ''), 'Two-step login turned off', { facts: 'For ' + (r.actor || '?'), from: from(r), who: r.actor });
    if (r.kind === 'secret_replaced') await raise('HIGH', 'secret_replaced:' + (m.name || '?'), 'A service key was replaced', { facts: 'Key ' + (m.name || '?') + ' replaced from the admin', from: from(r), who: r.actor });
  }

  // Windowed counters (per run, on the kinds that appeared).
  const fivemin = iso(now - 5 * MIN), tenmin = iso(now - 10 * MIN), hour = iso(now - H), day = iso(now - DAY);
  if (kinds.has('admin_fail')) {
    const { results: ips } = await db.prepare("SELECT ip, country, asn_org, COUNT(*) n FROM security_events WHERE kind = 'admin_fail' AND created_at >= ? GROUP BY ip HAVING n >= ?").bind(tenmin, SOC.BRUTE_FAILS_10MIN).all();
    for (const r of ips || []) {
      const id = await raise('MEDIUM', 'brute_force:' + r.ip, r.n + ' wrong admin tries from one address in 10 min', { facts: 'Nothing worked.', from: { ip: r.ip, country: r.country, asnOrg: r.asn_org }, cooldownH: 24 });
      await block(r, 'admin brute force', id);
    }
  }
  if (kinds.has('attack')) {
    const { results: ips } = await db.prepare("SELECT ip, country, asn_org, COUNT(*) n FROM security_events WHERE kind = 'attack' AND created_at >= ? GROUP BY ip HAVING n >= ?").bind(hour, SOC.ATTACK_SCAN_PER_HOUR).all();
    for (const r of ips || []) { const id = await raise('HIGH', 'attack_scan:' + r.ip, 'Sustained injection scanning from one address', { facts: r.n + ' requests in 1 h', from: { ip: r.ip, country: r.country, asnOrg: r.asn_org } }); await block(r, 'injection scanning', id); }
  }
  if (kinds.has('otp_sent')) {
    const n = await count(db, 'otp_sent', hour);
    if (n >= SOC.OTP_PER_HOUR) await raise('HIGH', 'otp_abuse', n + ' sign-in codes sent in the last hour', { facts: 'Limit ' + SOC.OTP_PER_HOUR + '/h.' });
    const { results: ips } = await db.prepare("SELECT ip, country, asn_org, COUNT(*) n FROM security_events WHERE kind = 'otp_sent' AND created_at >= ? GROUP BY ip HAVING n >= ?").bind(hour, SOC.OTP_PER_IP_HOUR).all();
    for (const r of ips || []) { const id = await raise('HIGH', 'otp_abuse:' + r.ip, r.n + ' sign-in codes requested by one address in 1 h', { from: { ip: r.ip, country: r.country, asnOrg: r.asn_org } }); await block(r, 'OTP pumping', id); }
  }
  if (kinds.has('server_error')) { const n = await count(db, 'server_error', fivemin); if (n >= SOC.ERROR_SPIKE_5MIN) await raise('MEDIUM', 'error_spike', n + ' server errors in 5 min', { cooldownH: 2 }); }
  if (kinds.has('webhook_bad_sig')) { const n = await count(db, 'webhook_bad_sig', day); if (n >= SOC.WEBHOOK_BAD_SIG_DAY) await raise('MEDIUM', 'webhook_forged', n + ' webhook calls with a bad signature today', { cooldownH: 24 }); }
  if (kinds.has('csp')) { const n = await count(db, 'csp', hour); if (n >= SOC.CSP_PER_HOUR) await raise('MEDIUM', 'csp_burst', n + ' blocked loads reported by browsers in 1 h', { cooldownH: 6 }); }

  // Orders at a price that cannot be right → hold before the courier.
  if (SOC.UNDERPRICED_SQL) {
    try {
      const since = state.orderScanAt ? iso(state.orderScanAt - MIN) : iso(now - 10 * MIN);
      const { results: bad } = await db.prepare(SOC.UNDERPRICED_SQL).bind(since).all();
      for (const o of bad || []) {
        const id = await raise('HIGH', 'order_underpriced:' + o.id, 'Order with an impossible price', { facts: o.id + ': total ' + o.total, cooldownH: 24 * 30 });
        await holdOrder(env, db, o.id, { incident: id }, now);
      }
    } catch (e) { ctx.errors.push('underpriced check: ' + String(e.message || e).slice(0, 120)); }
    state.orderScanAt = now;
  }
  return { rows: rows.length };
}
