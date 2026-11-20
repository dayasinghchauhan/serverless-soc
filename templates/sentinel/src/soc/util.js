// Small helpers shared by the SOC modules.
import { SOC } from './config.js';

export const iso = (t = Date.now()) => new Date(t).toISOString().replace('T', ' ').slice(0, 19);
export const parseTs = (s) => Date.parse(String(s).replace(' ', 'T') + (/[zZ]|[+-]\d\d:?\d\d$/.test(String(s)) ? '' : 'Z'));
export const dayKey = (t) => new Date(t).toISOString().slice(0, 10);
export const parse = (s, d = null) => { try { return s ? JSON.parse(s) : d; } catch { return d; } };
export const H = 3_600_000, MIN = 60_000, DAY = 86_400_000;

export async function sha256Hex(s) {
  const d = await crypto.subtle.digest('SHA-256', typeof s === 'string' ? new TextEncoder().encode(s) : s);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** ISP-level network: IPv4 /16, IPv6 first 24 bits, so a home connection renumbering is not "new". */
export function netPrefix(ip) {
  ip = String(ip || '');
  if (ip.includes(':')) { const p = ip.split(':'); return p[0] + ':' + String(p[1] || '').padStart(4, '0').slice(0, 2); }
  return ip.split('.').slice(0, 2).join('.');
}

export function ipKind(ip) {
  const s = String(ip || '').trim();
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split('.').every((n) => Number(n) <= 255)) return 4;
  if (/^[0-9a-f:]+$/i.test(s) && s.includes(':') && s.length <= 45) return 6;
  return 0;
}
export const isPrivateIp = (ip) => /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip) || /^(::1$|f[cd]|fe80:)/i.test(ip);
// Cloudflare Workers' own egress range: your own Workers (and the self-test) come from here.
export const isCfWorkerIp = (ip) => /^2a06:98c[0-7]:/i.test(String(ip || ''));

const HOSTING = /amazon|aws|google cloud|google llc|microsoft|azure|digitalocean|linode|akamai|ovh|hetzner|contabo|vultr|choopa|leaseweb|alibaba|aliyun|tencent|oracle|m247|hostinger|scaleway|datacamp|hosting|server|cloud|vps|colo/i;
/** 'hosting' | 'abroad' | 'home': only the first two are ever blocked automatically. */
export function netType(country, asnOrg) {
  if (asnOrg && HOSTING.test(String(asnOrg))) return 'hosting';
  if (country && !SOC.HOME_COUNTRIES.includes(String(country).toUpperCase())) return 'abroad';
  return 'home';
}

export function deviceClass(ua) {
  ua = String(ua || '');
  if (!ua) return 'no browser';
  if (/curl|wget|python|go-http|node-fetch|axios|okhttp|java\/|libwww|httpclient|postman|insomnia/i.test(ua)) return 'script';
  const os = /android/i.test(ua) ? 'Android' : /iphone|ipad/i.test(ua) ? 'iOS' : /windows/i.test(ua) ? 'Windows' : /mac os/i.test(ua) ? 'Mac' : /linux/i.test(ua) ? 'Linux' : 'other';
  const br = /edg\//i.test(ua) ? 'Edge' : /chrome\//i.test(ua) ? 'Chrome' : /firefox\//i.test(ua) ? 'Firefox' : /safari\//i.test(ua) ? 'Safari' : 'app';
  return os + ' ' + br;
}

/** Key → value maps: what was added, removed, changed. */
export function diffMaps(before = {}, after = {}) {
  const added = [], removed = [], changed = [];
  for (const k of Object.keys(after)) { if (!(k in before)) added.push(k); else if (String(before[k]) !== String(after[k])) changed.push(k); }
  for (const k of Object.keys(before)) if (!(k in after)) removed.push(k);
  return { added, removed, changed };
}

export async function cfApi(env, path, opts = {}) {
  const r = await fetch('https://api.cloudflare.com/client/v4' + path, { ...opts, headers: { Authorization: 'Bearer ' + (opts.token || env.CF_TOKEN), 'Content-Type': 'application/json', ...(opts.headers || {}) } });
  const j = await r.json().catch(() => ({}));
  if (!j.success) throw new Error(path.split('?')[0] + ' ' + r.status + ' ' + JSON.stringify(j.errors || '').slice(0, 160));
  return j;
}
