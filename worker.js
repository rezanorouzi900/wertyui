/*
╔══════════════════════════════════════════════════════════════════╗
║  RIX PANEL v2.7 — Backend هماهنگ با yonggekkk (کامل)              ║
║  مسیرهای WS: /{uuid} | /{trojanPass} | /rix (سازگاری عقب)         ║
║  بک‌گراند: لینک مستقیم تصویر در دو خط زیر | KV با نام kv          ║
╚══════════════════════════════════════════════════════════════════╝
*/

import { connect } from 'cloudflare:sockets';

const BG_DARK_URL  = '';
const BG_LIGHT_URL = '';

const PANEL_VER = '2.8.0';
const WS_PATH = '/rix';
const MAX_CLIENTS = 20;
const MAX_CLEAN_IPS = 60;
const CONNECT_TIMEOUT = 2500;
const DNS_TIMEOUT = 1200;
const PING_TIMEOUT = 3000;
const CFG_CACHE_MS = 0; // بدون کش برای اعمال فوری تنظیمات روی همه کانفیگ‌ها
const BOOT_TIME = Date.now();

const NAT64 = {
  nl:  { code: 'NL',   label: 'هلند',    prefix: '2a02:898:146:64::' },
  us1: { code: 'US-1', label: 'آمریکا ۱', prefix: '2602:fc59:b0:64::' },
  us2: { code: 'US-2', label: 'آمریکا ۲', prefix: '2602:fc59:11:64::' }
};
const CLIENT_ROUTES = { ...NAT64, main: { code: 'MAIN', label: 'مثل اصلی' }, proxy: { code: 'PROXY', label: 'ProxyIP' }, direct: { code: 'DIRECT', label: 'مستقیم' } };
const PING_TARGETS = [['1.1.1.1', 443], ['8.8.8.8', 53]];

function ipv4ToNat64(prefix, ipv4) {
  const p = ipv4.split('.').map(Number);
  if (p.length !== 4 || p.some(n => isNaN(n) || n < 0 || n > 255)) return null;
  const g = (h, l) => ((h << 8) | l).toString(16);
  return prefix + g(p[0], p[1]) + ':' + g(p[2], p[3]);
}

const SHA224_K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);
function sha224Hex(input) {
  const msg = new TextEncoder().encode(input);
  const bitLen = msg.length * 8;
  const totalLen = ((msg.length + 9 + 63) >> 6) << 6;
  const buf = new Uint8Array(totalLen);
  buf.set(msg);
  buf[msg.length] = 0x80;
  new DataView(buf.buffer).setUint32(totalLen - 4, bitLen >>> 0, false);
  const H = new Uint32Array([0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4]);
  const w = new Uint32Array(64);
  const dv = new DataView(buf.buffer);
  for (let off = 0; off < totalLen; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const a = w[i-15], b = w[i-2];
      const s0 = ((a>>>7)|(a<<25)) ^ ((a>>>18)|(a<<14)) ^ (a>>>3);
      const s1 = ((b>>>17)|(b<<15)) ^ ((b>>>19)|(b<<13)) ^ (b>>>10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
    }
    let [a,b,c,d,e,f,g,h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e>>>6)|(e<<26)) ^ ((e>>>11)|(e<<21)) ^ ((e>>>25)|(e<<7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA224_K[i] + w[i]) >>> 0;
      const S0 = ((a>>>2)|(a<<30)) ^ ((a>>>13)|(a<<19)) ^ ((a>>>22)|(a<<10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
    }
    H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
  }
  return H.slice(0,7).map(x => x.toString(16).padStart(8,'0')).join('');
}

const b64 = { encode: (s) => btoa(String.fromCharCode(...new TextEncoder().encode(s))) };
const safeB64 = (s) => b64.encode(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const esc = (s) => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
function bytesToHex(bytes) { return Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join(''); }
function generateUUID() {
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
  const h = bytesToHex(b);
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}
function generatePassword(len = 16) {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  return Array.from(crypto.getRandomValues(new Uint8Array(len))).map(b => c[b % c.length]).join('');
}
function maskToken(t) { return t && t.length > 14 ? t.slice(0, 8) + '••••' + t.slice(-4) : '••••'; }
function b64urlDecode(str) {
  let s = String(str).replace(/-/g,'+').replace(/_/g,'/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function earlyDataToBytes(raw) {
  try {
    let out = new Uint8Array(0);
    for (const part of raw.split(',')) { if (!part) continue; out = concatBytes(out, b64urlDecode(part)); }
    return out.length ? out : null;
  } catch { return null; }
}
async function toBytes(data) {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (data && typeof data.arrayBuffer === 'function') return new Uint8Array(await data.arrayBuffer());
  if (typeof data === 'string') return new TextEncoder().encode(data);
  return new Uint8Array(data || []);
}
function concatBytes(a, b) { const out = new Uint8Array(a.length + b.length); out.set(a); out.set(b, a.length); return out; }
function timeoutPromise(ms) { let rej; const p = new Promise((_, r) => { rej = r; setTimeout(() => rej(new Error('t')), ms); }); p.catch(() => {}); return p; }
const isIPv4 = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
const isIPv6 = (s) => s.includes(':');
const isDomain = (s) => !isIPv4(s) && !isIPv6(s);
function parseHostPort(str) {
  str = String(str || '').trim();
  if (!str) return null;
  if (str.startsWith('[')) {
    const end = str.indexOf(']');
    if (end < 0) return null;
    const host = str.slice(1, end);
    const rest = str.slice(end + 1);
    if (!isIPv6(host)) return null;
    if (!rest) return { host, port: 443 };
    if (!/^:\d{1,5}$/.test(rest)) return null;
    const port = Number(rest.slice(1));
    return port >= 1 && port <= 65535 ? { host, port } : null;
  }
  if (isIPv6(str)) return { host: str, port: 443 };
  const m = str.match(/^(.+?)(?::(\d{1,5}))?$/);
  if (!m) return null;
  const host = m[1];
  const port = m[2] ? Number(m[2]) : 443;
  if (!port || port < 1 || port > 65535) return null;
  if (!(isIPv4(host) || isDomain(host))) return null;
  return { host, port };
}
const isValidClean = (s) => !!parseHostPort(s);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const todayStr = () => new Date().toISOString().slice(0,10).replace(/-/g,'');
const GB = 1073741824;

async function tcpPing(hostname, port) {
  const t0 = Date.now();
  let sock = null;
  try {
    sock = connect({ hostname, port });
    await Promise.race([sock.opened, timeoutPromise(PING_TIMEOUT)]);
    const ms = Date.now() - t0;
    try { sock.close(); } catch {}
    return { ok: true, ms };
  } catch { try { if (sock) sock.close(); } catch {} return { ok: false, ms: Date.now() - t0 }; }
}
async function nat64Probe(prefix) {
  for (const [ip, port] of PING_TARGETS) {
    const host = ipv4ToNat64(prefix, ip);
    if (!host) continue;
    const r = await tcpPing(host, port);
    if (r.ok) return { ok: true, ms: r.ms, via: host };
  }
  return { ok: false, ms: PING_TIMEOUT * PING_TARGETS.length, via: null };
}
const gwLat = new Map();
const setGwLat = (k, r) => gwLat.set(k, { ok: r.ok, ms: r.ms, at: Date.now() });
const getGwLat = (k) => gwLat.get(k) || null;

const dnsCache = new Map();
async function resolveHost(host) {
  const hit = dnsCache.get(host);
  if (hit && hit.exp > Date.now()) return hit.ips;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), DNS_TIMEOUT);
    const r = await fetch('https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(host) + '&type=A', { headers: { accept: 'application/dns-json' }, signal: ctrl.signal });
    clearTimeout(t);
    const j = await r.json();
    const ips = (j && j.Answer) ? j.Answer.filter(a => a.type === 1).map(a => a.data) : [];
    if (ips.length) dnsCache.set(host, { ips, exp: Date.now() + 300000 });
    return ips;
  } catch { return []; }
}

const gwFail = new Map();
const gwDead = (k) => { const e = gwFail.get(k); return e && e > Date.now(); };
const markGw = (k) => { if (k) gwFail.set(k, Date.now() + 60000); };

const CF_V4 = [
  ['173.245.48.0',20],['103.21.244.0',22],['103.22.200.0',22],['103.31.4.0',22],
  ['141.101.64.0',18],['108.162.192.0',18],['190.93.240.0',20],['188.114.96.0',20],
  ['197.234.240.0',22],['198.41.128.0',17],['162.158.0.0',15],['104.16.0.0',13],
  ['104.24.0.0',14],['172.64.0.0',13],['131.0.72.0',22]
].map(([b, bits]) => { const p = b.split('.').map(Number); return { base: ((p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3])>>>0, mask: ((0xFFFFFFFF << (32-bits))>>>0) }; });
function inCFRange(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4) return false;
  const n = ((p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3])>>>0;
  return CF_V4.some(r => (n & r.mask) === (r.base & r.mask));
}
function parseProxyIP(str) { return parseHostPort(str); }

// ═══ Credential registry — هر کانفیگ VLESS شناسهٔ مستقل خودش را دارد ═══
// کلید endpoint به صاحب + نوع + مقصد وابسته است تا با هر بار گرفتن Subscription
// شناسه‌ها عوض نشوند، ولی یک UUID هرگز بین دو کانفیگ مستقل share نشود.
function ensureEndpointRegistry(cfg) {
  const old = Array.isArray(cfg.endpoints) ? cfg.endpoints : [];
  const byKey = new Map();
  const used = new Set();
  for (const e of old) {
    if (!e || typeof e !== 'object' || !UUID_RE.test(String(e.uuid || ''))) continue;
    const key = String(e.key || '');
    if (!key || byKey.has(key) || used.has(e.uuid.toLowerCase())) continue;
    byKey.set(key, {
      key, uuid: e.uuid, owner: e.owner === 'client' ? 'client' : 'main',
      clientId: typeof e.clientId === 'string' ? e.clientId : null,
      kind: e.kind === 'clean' ? 'clean' : 'main',
      target: typeof e.target === 'string' ? e.target : 'main'
    });
    used.add(e.uuid.toLowerCase());
  }
  const out = [];
  const add = (key, owner, clientId, kind, target, preferred) => {
    let e = byKey.get(key);
    if (!e || used.has(String(preferred || '').toLowerCase()) && (!e || e.uuid !== preferred)) {
      let uuid = UUID_RE.test(String(preferred || '')) && !used.has(String(preferred).toLowerCase()) ? preferred : generateUUID();
      while (used.has(uuid.toLowerCase())) uuid = generateUUID();
      e = { key, uuid, owner, clientId: clientId || null, kind, target };
    } else {
      e = { ...e, owner, clientId: clientId || null, kind, target };
    }
    used.add(e.uuid.toLowerCase());
    out.push(e);
    return e.uuid;
  };

  // کانفیگ اصلی، UUID اصلی را حفظ می‌کند؛ همهٔ Clean IPها UUID جدا دارند.
  add('main|main', 'main', null, 'main', 'main', cfg.uuid);
  if (cfg.cleanIPsMain && cfg.vlessEnabled) {
    for (const ip of cfg.cleanIPs) add('main|clean|' + ip, 'main', null, 'clean', ip);
  }
  for (const c of cfg.clients) {
    add('client|' + c.id + '|main', 'client', c.id, 'main', 'main', c.uuid);
    if (c.cleanIPs !== false && cfg.vlessEnabled) {
      for (const ip of cfg.cleanIPs) add('client|' + c.id + '|clean|' + ip, 'client', c.id, 'clean', ip);
    }
  }
  const changed = JSON.stringify(old) !== JSON.stringify(out);
  cfg.endpoints = out;
  return changed;
}
function endpointByUUID(cfg, uuidHex) {
  const u = String(uuidHex || '').replace(/-/g, '').toLowerCase();
  return cfg.endpoints.find(e => e.uuid.replace(/-/g, '').toLowerCase() === u) || null;
}
function endpointUUID(cfg, owner, clientId, kind, target, fallback) {
  const key = owner === 'client' ? ('client|' + clientId + '|' + kind + (kind === 'clean' ? '|' + target : '')) : ('main|' + kind + (kind === 'clean' ? '|' + target : ''));
  const e = cfg.endpoints.find(x => x.key === key);
  return e ? e.uuid : fallback;
}

// ═══ KV + کش کوتاه — تنظیمات و endpoint registry مشترک بین همهٔ کانفیگ‌ها ═══
async function getConfig(env) {
  let s = {};
  try { s = (await env.kv.get('rix_config', 'json')) || {}; } catch { s = {}; }
  let clientChanged = false;
  const rawClients = Array.isArray(s.clients) ? s.clients.filter(c => c && typeof c === 'object').slice(0, MAX_CLIENTS) : [];
  const clients = rawClients.map(c => {
    const id = typeof c.id === 'string' && c.id ? c.id : 'c' + crypto.randomUUID().replace(/-/g,'').slice(0,12);
    const name = typeof c.name === 'string' && c.name.trim() ? c.name.trim().slice(0,32) : 'Client';
    const uuid = typeof c.uuid === 'string' && UUID_RE.test(c.uuid) ? c.uuid : generateUUID();
    const quotaGB = Math.max(0, Math.min(1000, Number(c.quotaGB) || 0));
    const country = CLIENT_ROUTES[c.country] ? c.country : 'main';
    const cleanIPs = c.cleanIPs !== false;
    const enabled = c.enabled !== false;
    const created = typeof c.created === 'number' ? c.created : Date.now();
    if (id !== c.id || name !== c.name || uuid !== c.uuid || quotaGB !== (Number(c.quotaGB) || 0) || country !== c.country || cleanIPs !== c.cleanIPs || enabled !== c.enabled || created !== c.created) clientChanged = true;
    return { id, name, uuid, quotaGB, country, cleanIPs, enabled, created };
  });
  if (!Array.isArray(s.clients) || rawClients.length !== s.clients.length) clientChanged = true;
  const cfg = {
    uuid: (typeof s.uuid === 'string' && UUID_RE.test(s.uuid)) ? s.uuid : generateUUID(),
    trojanPass: (typeof s.trojanPass === 'string' && s.trojanPass) ? s.trojanPass : generatePassword(16),
    panelPass: (typeof s.panelPass === 'string' && s.panelPass) ? s.panelPass : null,
    vlessEnabled: s.vlessEnabled !== false,
    trojanEnabled: s.trojanEnabled !== false,
    proxyIP: (typeof s.proxyIP === 'string') ? s.proxyIP.trim() : '',
    proxyEnabled: s.proxyEnabled !== false,
    nat64Enabled: s.nat64Enabled === true,
    nat64Prefix: NAT64[s.nat64Prefix] ? s.nat64Prefix : 'nl',
    cleanIPs: Array.isArray(s.cleanIPs) ? s.cleanIPs.filter(x => typeof x === 'string' && isValidClean(x)).slice(0, MAX_CLEAN_IPS) : [],
    cleanIPsMain: s.cleanIPsMain !== false,
    clients,
    endpoints: [],
    created: (typeof s.created === 'number') ? s.created : Date.now(),
    botToken: (typeof s.botToken === 'string') ? s.botToken : '',
    botChatId: (typeof s.botChatId === 'string') ? s.botChatId : '',
    botUser: (typeof s.botUser === 'string') ? s.botUser : '',
    botEnabled: s.botEnabled === true,
    botOnAuth: s.botOnAuth !== false,
    botOnClient: s.botOnClient !== false,
    botOnConn: s.botOnConn === true
  };
  const migrated = ensureEndpointRegistry(cfg);
  if (!s.uuid || migrated || clientChanged) {
    try { await env.kv.put('rix_config', JSON.stringify(cfg)); } catch {}
  }
  return cfg;
}
let _cfgCache = { data: null, exp: 0 };
async function getCachedConfig(env) {
  const now = Date.now();
  if (_cfgCache.data && _cfgCache.exp > now) return _cfgCache.data;
  const cfg = await getConfig(env);
  _cfgCache = { data: cfg, exp: now + CFG_CACHE_MS };
  return cfg;
}
async function saveConfig(env, config) {
  await env.kv.put('rix_config', JSON.stringify(config));
  _cfgCache = { data: null, exp: 0 }; // باطل‌سازی کش
}

function tgApi(token, method, body) {
  return fetch('https://api.telegram.org/bot' + token + '/' + method, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}
async function sendTgNow(env, html) {
  const cfg = await getConfig(env);
  if (!cfg.botToken || !cfg.botChatId) return { ok: false, err: 'ربات ذخیره نشده' };
  try {
    const r = await tgApi(cfg.botToken, 'sendMessage', { chat_id: cfg.botChatId, parse_mode: 'HTML', text: html });
    const j = await r.json();
    if (j && j.ok) return { ok: true };
    return { ok: false, err: (j && j.description) || 'خطای نامشخص تلگرام' };
  } catch { return { ok: false, err: 'اتصال به تلگرام برقرار نشد' }; }
}
async function logEvent(env, txt, ctx, type = 'client') {
  try {
    const logs = (await env.kv.get('rix_logs', 'json')) || [];
    logs.unshift({ t: Date.now(), txt: String(txt).slice(0, 120) });
    await env.kv.put('rix_logs', JSON.stringify(logs.slice(0, 50)));
  } catch {}
  try {
    const cfg = await getConfig(env);
    if (!cfg.botEnabled || !cfg.botToken || !cfg.botChatId) return;
    const on = (type === 'auth') ? cfg.botOnAuth : cfg.botOnClient;
    if (!on) return;
    const msg = '🛡 <b>RIX PANEL</b>\n' + esc(txt) + '\n🕰 ' + new Date().toLocaleString('fa-IR');
    const p = tgApi(cfg.botToken, 'sendMessage', { chat_id: cfg.botChatId, parse_mode: 'HTML', text: msg }).catch(() => {});
    if (ctx) ctx.waitUntil(p); else { try { await p; } catch {} }
  } catch {}
}
const connBuf = { n: 0, last: Date.now() };
function noteConn(env, ctx, label) {
  connBuf.n++;
  const now = Date.now();
  if (connBuf.n >= 10 || now - connBuf.last >= 60000) {
    const n = connBuf.n; connBuf.n = 0; connBuf.last = now;
    try {
      ctx.waitUntil((async () => {
        try {
          const cfg = await getConfig(env);
          if (cfg.botEnabled && cfg.botOnConn && cfg.botToken && cfg.botChatId)
            await tgApi(cfg.botToken, 'sendMessage', { chat_id: cfg.botChatId, text: '🔗 ' + n + ' اتصال جدید ثبت شد (' + label + ')' });
        } catch {}
      })());
    } catch {}
  }
}

async function isAuthed(request, env) {
  const cfg = await getConfig(env);
  if (!cfg.panelPass) return false;
  const m = (request.headers.get('Cookie') || '').match(/rix_session=([a-f0-9]+)/);
  if (!m) return false;
  return m[1] === sha224Hex(cfg.panelPass + '::rix-session-v1');
}
async function getUsage(env, clientId) { return parseInt(await env.kv.get('u_' + clientId + '_' + todayStr())) || 0; }
async function addUsage(env, clientId, bytes) {
  const k = 'u_' + clientId + '_' + todayStr();
  await env.kv.put(k, String((parseInt(await env.kv.get(k)) || 0) + bytes));
}
async function getLogs(env) { try { return (await env.kv.get('rix_logs', 'json')) || []; } catch { return []; } }

const isHexByte = (c) => (c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70);
function parsePacket(d) {
  if (!d || d.length === 0) return { needMore: true };
  const b0 = d[0];
  if (b0 === 0x00) {
    if (d.length < 18) return { needMore: true };
    const uuidHex = bytesToHex(d.slice(1, 17));
    const cmdPos = 18 + d[17];
    if (d.length < cmdPos + 1) return { needMore: true };
    if (d[cmdPos] !== 1) return { unsupported: true };
    const portPos = cmdPos + 1;
    if (d.length < portPos + 3) return { needMore: true };
    const port = (d[portPos] << 8) | d[portPos + 1];
    const atyp = d[portPos + 2];
    const aPos = portPos + 3;
    let addr, end;
    if (atyp === 1)      { if (d.length < aPos + 4) return { needMore: true }; addr = [...d.slice(aPos, aPos + 4)].join('.'); end = aPos + 4; }
    else if (atyp === 2) { if (d.length < aPos + 1) return { needMore: true }; const n = d[aPos]; if (d.length < aPos + 1 + n) return { needMore: true }; addr = new TextDecoder().decode(d.slice(aPos + 1, aPos + 1 + n)); end = aPos + 1 + n; }
    else if (atyp === 3) { if (d.length < aPos + 16) return { needMore: true }; const p = []; for (let j = 0; j < 16; j += 2) p.push(((d[aPos + j] << 8) | d[aPos + j + 1]).toString(16)); addr = p.join(':'); end = aPos + 16; }
    else return null;
    return { protocol: 'vless', uuidHex, addr, port, payload: d.slice(end) };
  }
  if (isHexByte(b0)) {
    if (d.length < 58) return { needMore: true };
    if (d[56] !== 0x0d || d[57] !== 0x0a) return null;
    if (d.length < 59) return { needMore: true };
    const trojanHash = new TextDecoder().decode(d.slice(0, 56)).toLowerCase();
    let i = 58;
    if (d[i] !== 1) return { unsupported: true };
    i++;
    if (d.length < i + 3) return { needMore: true };
    const port = (d[i] << 8) | d[i + 1]; i += 2;
    const atyp = d[i]; i++;
    let addr, end;
    if (atyp === 1)      { if (d.length < i + 4) return { needMore: true }; addr = [...d.slice(i, i + 4)].join('.'); end = i + 4; }
    else if (atyp === 3) { if (d.length < i + 1) return { needMore: true }; const n = d[i]; if (d.length < i + 1 + n) return { needMore: true }; addr = new TextDecoder().decode(d.slice(i + 1, i + 1 + n)); end = i + 1 + n; }
    else if (atyp === 4) { if (d.length < i + 16) return { needMore: true }; const p = []; for (let j = 0; j < 16; j += 2) p.push(((d[i + j] << 8) | d[i + j + 1]).toString(16)); addr = p.join(':'); end = i + 16; }
    else return null;
    return { protocol: 'trojan', trojanHash, addr, port, payload: d.slice(end) };
  }
  return null;
}

async function handleWSS(request, cfg, env, ctx, route) {
  const upgrade = (request.headers.get('Upgrade') || '').toLowerCase();
  if (upgrade !== 'websocket') return new Response('Expected WebSocket', { status: 426 });

  /*
   * Data-plane implementation follows the known-working Worker pattern:
   * one sequential WebSocket -> TCP stream, optional 0-RTT early data,
   * real outbound socket, initial payload written before VLESS response.
   * The RIX endpoint registry/auth/routing/quota logic stays intact.
   */
  const earlyRaw = request.headers.get('sec-websocket-protocol') || '';
  const pair = new WebSocketPair();
  const clientSocket = pair[0];
  const server = pair[1];
  server.accept();

  let remote = null;
  let remoteWriter = null;
  let identity = null;
  let headerBuffer = null;
  let closed = false;
  let usage = 0;
  let reportedUsage = 0;

  const flushUsage = () => {
    if (!identity || identity.quota !== true) return;
    if (usage <= reportedUsage) return;
    const delta = usage - reportedUsage;
    reportedUsage = usage;
    try { ctx.waitUntil(addUsage(env, identity.client.id, delta)); } catch {}
  };

  const count = (n) => {
    if (!identity || identity.quota !== true || !n) return;
    usage += n;
    if (usage - reportedUsage >= 1024 * 1024) flushUsage();
  };

  const closeAll = () => {
    if (closed) return;
    closed = true;
    flushUsage();
    try { server.close(); } catch {}
    try { if (remoteWriter) remoteWriter.releaseLock(); } catch {}
    try { if (remote) remote.close(); } catch {}
  };

  const authenticate = (p) => {
    if (!p) return null;
    if (route && route.proto && p.protocol !== route.proto) return null;

    if (p.protocol === 'vless') {
      if (route && route.uuidHex && route.uuidHex !== p.uuidHex) return null;
      const ep = route && route.endpoint ? route.endpoint : endpointByUUID(cfg, p.uuidHex);
      if (ep) {
        if (ep.owner === 'client') {
          const c = cfg.clients.find(c => c.id === ep.clientId && c.enabled !== false);
          if (!c) return null;
          return { type: 'client', client: c, endpoint: ep, quota: c.quotaGB > 0 };
        }
        if (!cfg.vlessEnabled) return null;
        return { type: 'main', endpoint: ep, quota: false };
      }

      const mainHex = cfg.uuid.replace(/-/g, '').toLowerCase();
      if (p.uuidHex === mainHex) {
        if (!cfg.vlessEnabled) return null;
        return { type: 'main', quota: false };
      }

      const c = cfg.clients.find(c => c.uuid.replace(/-/g, '').toLowerCase() === p.uuidHex && c.enabled !== false);
      if (!c) return null;
      return { type: 'client', client: c, quota: c.quotaGB > 0 };
    }

    if (!cfg.trojanEnabled) return null;
    if (p.trojanHash !== sha224Hex(cfg.trojanPass)) return null;
    return { type: 'main', quota: false };
  };

  const tryConnect = async (target, payload, key) => {
    let sock = null;
    let w = null;
    try {
      /* Match the working reference: create the socket and immediately write
         the initial payload. The platform handles the actual connection state
         while writable/opened errors surface through the write/read streams. */
      sock = connect({ hostname: target.hostname, port: target.port });
      w = sock.writable.getWriter();
      if (payload && payload.byteLength) await w.write(payload);
      return { sock, w };
    } catch {
      markGw(key);
      try { if (w) w.releaseLock(); } catch {}
      try { if (sock) sock.close(); } catch {}
      return null;
    }
  };

  const handleParsed = async (p) => {
    const id = authenticate(p);
    if (!id) { closeAll(); return; }
    identity = id;

    try { noteConn(env, ctx, id.type === 'client' ? id.client.name : 'اصلی'); } catch {}

    if (id.quota) {
      const used = await getUsage(env, id.client.id);
      if (used >= id.client.quotaGB * GB) { closeAll(); return; }
    }

    let mode = 'main', prefixKey = null;
    if (id.type === 'client') {
      const c = id.client;
      if (c.country === 'direct') mode = 'direct';
      else if (c.country === 'proxy') mode = 'proxy';
      else if (c.country && NAT64[c.country]) { mode = 'nat'; prefixKey = c.country; }
      else mode = 'main';
    }

    const attempts = await buildAttemptsForRIX(cfg, p.addr, p.port, mode, prefixKey);
    let opened = null;
    for (const a of attempts) {
      opened = await tryConnect(a.t, p.payload, a.key);
      if (opened) break;
    }
    if (!opened) { closeAll(); return; }

    remote = opened.sock;
    remoteWriter = opened.w;

    remote.readable.pipeTo(new WritableStream({
      write(chunk) {
        if (closed || server.readyState !== 1) return;
        try {
          const bytes = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
          server.send(bytes);
          count(bytes.byteLength);
        } catch { closeAll(); }
      },
      close() { closeAll(); },
      abort() { closeAll(); }
    })).catch(() => closeAll());

    /* VLESS response is sent only after a real outbound socket exists and
       initial payload (when present) has been accepted by the socket writer. */
    if (p.protocol === 'vless' && server.readyState === 1) {
      try { server.send(new Uint8Array([p.version || 0, 0])); } catch { closeAll(); return; }
    }
  };

  const processChunk = async (chunk) => {
    if (closed || !chunk || !chunk.byteLength) return;

    if (!identity || !remoteWriter) {
      headerBuffer = headerBuffer ? concatBytes(headerBuffer, chunk) : chunk;
      const parsed = parsePacket(headerBuffer);
      if (!parsed) { closeAll(); return; }
      if (parsed.needMore) {
        if (headerBuffer.byteLength > 17408) closeAll();
        return;
      }
      if (parsed.unsupported) { closeAll(); return; }
      const first = headerBuffer;
      headerBuffer = null;
      await handleParsed(parsed);
      if (closed || !remoteWriter) return;

      /* parsePacket payload belongs to the first chunk and has already been
         written by tryConnect(). Any bytes beyond the parsed packet are not
         separately visible here because parsePacket() returns them as payload. */
      void first;
      return;
    }

    await remoteWriter.write(chunk);
    count(chunk.byteLength);
  };

  const readable = new ReadableStream({
    start(controller) {
      if (earlyRaw) {
        try {
          const ed = earlyDataToBytes(earlyRaw);
          if (ed && ed.byteLength) controller.enqueue(ed);
        } catch {}
      }

      server.addEventListener('message', (event) => {
        toBytes(event.data).then(bytes => {
          if (!closed && bytes && bytes.byteLength) controller.enqueue(bytes);
        }).catch(() => closeAll());
      });
      server.addEventListener('close', () => { try { controller.close(); } catch {} });
      server.addEventListener('error', () => { try { controller.error(new Error('websocket error')); } catch {} });
    },
    cancel() { closeAll(); }
  });

  /* مهم: پاسخ 101 باید فوراً برگردد. منتظر ماندن برای pipeTo یعنی تا بسته‌شدن
     WebSocket صبر کنیم و کلاینت از همان ابتدا اتصال را مرده/ناموفق می‌بیند.
     پردازش استریم را در پس‌زمینه نگه می‌داریم، اما handshake واقعی را فوری می‌دهیم. */
  const streamPump = readable.pipeTo(new WritableStream({
    async write(chunk) { await processChunk(chunk); },
    close() { closeAll(); },
    abort() { closeAll(); }
  })).catch(() => closeAll());
  try { ctx.waitUntil(streamPump); } catch {}

  return new Response(null, { status: 101, webSocket: clientSocket });
}

/* Routing helper kept outside handleWSS so every client/config uses the exact
   same backend path-selection logic. */
async function buildAttemptsForRIX(cfg, addr, port, mode, prefixKey) {
  const out = [];
  const pr = cfg.proxyEnabled ? parseProxyIP(cfg.proxyIP) : null;
  let ip4 = isIPv4(addr) ? addr : null;
  let needDNS = false;
  if (!ip4 && isDomain(addr)) {
    if (mode === 'nat' || (mode === 'main' && cfg.nat64Enabled) || pr) needDNS = true;
  }
  if (needDNS) ip4 = (await resolveHost(addr))[0] || null;
  const isCF = ip4 ? inCFRange(ip4) : false;

  if (mode === 'nat' && ip4 && NAT64[prefixKey] && !gwDead('n:' + prefixKey)) {
    const n64 = ipv4ToNat64(NAT64[prefixKey].prefix, ip4);
    if (n64) out.push({ t: { hostname: n64, port }, key: 'n:' + prefixKey });
  } else if (mode === 'main' && cfg.nat64Enabled && ip4 && !gwDead('n:' + cfg.nat64Prefix)) {
    const n64 = ipv4ToNat64(NAT64[cfg.nat64Prefix].prefix, ip4);
    if (n64) out.push({ t: { hostname: n64, port }, key: 'n:' + cfg.nat64Prefix });
  }

  if (mode === 'proxy') {
    const prx = parseProxyIP(cfg.proxyIP);
    if (prx && !gwDead('p:' + cfg.proxyIP)) out.push({ t: { hostname: prx.host, port: prx.port }, key: 'p:' + cfg.proxyIP });
  } else if (pr && isCF && !gwDead('p:' + cfg.proxyIP)) {
    out.push({ t: { hostname: pr.host, port: pr.port }, key: 'p:' + cfg.proxyIP });
  }

  /* Always retain the direct target as final fallback. */
  out.push({ t: { hostname: addr, port }, key: null });
  return out;
}
// ═══ تولید کانفیگ — الگوی yonggekkk: path = /{اعتبار} ═══
function wsPathVless(uuid) { return encodeURIComponent('/?ed=2048'); }
function wsPathTrojan(pass) { return encodeURIComponent('/?ed=2048'); }
function linkFor(uuid, host, name, addrHost, addrPort) {
  const a = uriHost(addrHost || host);
  const port = addrPort || 443;
  return `vless://${uuid}@${a}:${port}?encryption=none&security=tls&sni=${host}&fp=randomized&type=ws&host=${host}&path=${wsPathVless(uuid)}#${encodeURIComponent(name)}`;
}
function trojanLinkFor(pass, host, name, addrHost, addrPort) {
  const a = uriHost(addrHost || host);
  const port = addrPort || 443;
  return `trojan://${pass}@${a}:${port}?security=tls&sni=${host}&fp=randomized&type=ws&host=${host}&path=${wsPathTrojan(pass)}#${encodeURIComponent(name)}`;
}
function cleanSplit(s) { return parseHostPort(s) || { host: String(s || '').trim(), port: 443 }; }
function uriHost(host) { return isIPv6(host) ? '[' + host + ']' : host; }
function mainLinks(cfg, host) {
  const out = [];
  if (cfg.vlessEnabled) {
    const u = endpointUUID(cfg, 'main', null, 'main', 'main', cfg.uuid);
    out.push(linkFor(u, host, 'RIX-VLESS'));
  }
  if (cfg.trojanEnabled) out.push(trojanLinkFor(cfg.trojanPass, host, 'RIX-Trojan'));
  return out;
}
function cleanMainLinks(cfg, host) {
  if (!cfg.cleanIPsMain || !cfg.vlessEnabled) return [];
  return cfg.cleanIPs.map(ip => {
    const c = cleanSplit(ip);
    const u = endpointUUID(cfg, 'main', null, 'clean', ip, generateUUID());
    return linkFor(u, host, 'RIX ' + ip, c.host, c.port);
  });
}
function clientWantsClean(c) { return c.cleanIPs !== false; }
function clientLinks(cfg, c, host) {
  if (!cfg.vlessEnabled || c.enabled === false) return [];
  const mainU = endpointUUID(cfg, 'client', c.id, 'main', 'main', c.uuid);
  const out = [linkFor(mainU, host, c.name)];
  if (clientWantsClean(c)) for (const ip of cfg.cleanIPs) {
    const cc = cleanSplit(ip);
    const u = endpointUUID(cfg, 'client', c.id, 'clean', ip, generateUUID());
    out.push(linkFor(u, host, `${c.name} - ${ip}`, cc.host, cc.port));
  }
  return out;
}
function linkMeta(l) {
  let name = 'کانفیگ';
  try { const i = l.indexOf('#'); if (i > -1) name = decodeURIComponent(l.slice(i + 1)); } catch {}
  let addr = '';
  const m = l.match(/@([^:?#]+):(\d+)/);
  if (m) addr = m[1] + ':' + m[2];
  return { name, addr };
}

// ═══ آیکون‌ها / UI (دست‌نخورده — v2.5/v2.6) ═══
const ICONS = {
  home:'<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>',
  box:'<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/>',
  users:'<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
  info:'<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
  sliders:'<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>',
  copy:'<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  trash:'<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
  power:'<path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/>',
  plus:'<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
  sun:'<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>',
  moon:'<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>',
  logout:'<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
  zap:'<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
  globe:'<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
  shield:'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/>',
  key:'<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>',
  refresh:'<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
  check:'<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
  activity:'<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
  ext:'<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>',
  save:'<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>',
  alert:'<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
  lock:'<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  pencil:'<path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/>',
  send:'<line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>',
  heart:'<path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/>',
  bell:'<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>',
  clock:'<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
  calendar:'<rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/>',
  db:'<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
  swap:'<polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/>',
  link:'<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
  arrow:'<line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>',
  map:'<polygon points="1 6 1 22 8 18 16 22 23 18 23 2 16 6 8 2 1 6"/><line x1="8" y1="2" x2="8" y2="18"/><line x1="16" y1="6" x2="16" y2="22"/>',
  star:'<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>',
  bot:'<rect x="4" y="8" width="16" height="12" rx="2"/><path d="M12 8V4"/><circle cx="12" cy="3" r="1"/><circle cx="9" cy="13" r="1"/><circle cx="15" cy="13" r="1"/><path d="M9 17h6"/>',
  code:'<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>'
};
const svg = (name, size = 18) => `<svg class="ic" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name]}</svg>`;
const sunSvg = svg('sun', 15);
const moonSvg = svg('moon', 15);

const FOOTER_HTML = `
<div class="footer">
  <div class="creator">
    <a href="https://t.me/RG7YT" target="_blank" rel="noopener">${svg('send',13)}<span dir="ltr">@RG7YT</span></a>
    <a href="https://t.me/RIXPANEL" target="_blank" rel="noopener">${svg('star',13)}<span dir="ltr">@RIXPANEL</span></a>
  </div>
  <p class="love">سخته شده با ${svg('heart',13)} عشق توسط <b>رضا</b></p>
</div>`;

function cfgItemHTML(name, link) {
  const m = linkMeta(link);
  return `<div class="cfg-item" data-copy="${esc(link)}" title="${esc(link)}"><span class="cfg-name">${esc(name)}</span><span class="cfg-host mono">${esc(m.addr)}</span><button class="icon-btn" data-copy="${esc(link)}" title="کپی">${svg('copy', 14)}</button></div>`;
}
function cfgGroupHTML(title, icon, items) {
  if (!items || !items.length) return '';
  return `<div class="card"><div class="vhead"><span class="ci">${svg(icon, 17)}</span><h2>${esc(title)}</h2><span class="sp"></span><span class="pill code">${items.length}</span></div>${items.map(it => cfgItemHTML(it.name, it.link)).join('')}</div>`;
}

const CSS = `
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0b0c16;--card:rgba(17,18,30,.72);--card2:rgba(26,28,46,.5);--border:rgba(120,120,180,.18);--text:#ebedf8;--dim:#9298b5;--accent:#7c85f5;--accent2:#a98ef5;--accent3:#5f8df0;--success:#4fc48c;--danger:#ef7286;--warn:#e6b269;--glow:rgba(124,133,245,.16);--shadow:0 14px 44px rgba(3,4,10,.5);--r:20px;--tb:rgba(15,16,28,.6)}
html[data-theme='light']{--bg:#e9ecf7;--card:rgba(255,255,255,.5);--card2:rgba(255,255,255,.38);--border:rgba(255,255,255,.75);--text:#2a2e48;--dim:#6a6f90;--accent:#6a72ea;--accent2:#9a7ee6;--accent3:#5c86ea;--success:#2f9d6d;--danger:#d94f66;--warn:#c08a3e;--glow:rgba(106,114,234,.14);--shadow:0 14px 40px rgba(100,105,170,.14);--tb:rgba(255,255,255,.5)}
html,body{height:100%}
body{font-family:'Vazirmatn',system-ui,-apple-system,'Segoe UI',Tahoma,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;direction:rtl;font-size:15px;overflow-x:hidden;transition:background .5s,color .5s}
.bg{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}
.bg .neb{position:absolute;border-radius:50%;filter:blur(90px);opacity:.5}
html[data-theme='light'] .bg .neb{opacity:.35}
.bg .n1{width:55vw;height:55vw;top:-20vw;left:-14vw;background:radial-gradient(circle,rgba(124,90,240,.5),transparent 65%);animation:drift1 28s ease-in-out infinite}
.bg .n2{width:46vw;height:46vw;bottom:-18vw;right:-12vw;background:radial-gradient(circle,rgba(90,70,220,.4),transparent 65%);animation:drift2 34s ease-in-out infinite}
.bg .stars{position:absolute;inset:0;background-image:radial-gradient(rgba(220,215,255,.5) 1px,transparent 1.4px),radial-gradient(rgba(200,190,255,.28) 1px,transparent 1.4px);background-size:200px 200px,130px 130px;background-position:22px 34px,74px 96px;animation:twk 7s ease-in-out infinite}
html[data-theme='light'] .bg .stars{opacity:.4}
@keyframes drift1{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(6vw,4vw) scale(1.1)}}
@keyframes drift2{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(-5vw,-4vw) scale(1.08)}}
@keyframes twk{0%,100%{opacity:.7}50%{opacity:1}}
html[data-theme='dark'] body.has-bg .bg{background:url('${BG_DARK_URL}') center/cover no-repeat}
html[data-theme='light'] body.has-bg .bg{background:url('${BG_LIGHT_URL||BG_DARK_URL}') center/cover no-repeat}
body.has-bg .bg .neb,body.has-bg .bg .stars{display:none}
.veil{position:fixed;inset:0;z-index:0;pointer-events:none}
html[data-theme='dark'] body.has-bg .veil{background:linear-gradient(180deg,rgba(10,11,20,.5),rgba(10,11,20,.72))}
html[data-theme='light'] body.has-bg .veil{background:linear-gradient(180deg,rgba(238,240,248,.22),rgba(238,240,248,.5))}
html[data-theme='dark'] body:not(.has-bg) .veil{background:linear-gradient(180deg,rgba(10,11,20,.25),rgba(10,11,20,.55))}
html[data-theme='light'] body:not(.has-bg) .veil{background:linear-gradient(180deg,rgba(238,240,248,.4),rgba(238,240,248,.72))}
@keyframes pageIn{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:none}}
@keyframes rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
@keyframes gradShift{0%,100%{background-position:0% 50%}50%{background-position:100% 50%}}
@keyframes shimmer{to{transform:translateX(100%)}}
@keyframes pulseDot{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.85)}}
@keyframes floaty{0%,100%{transform:translateY(0)}50%{transform:translateY(-5px)}}
@keyframes toastIn{0%{opacity:0;transform:translateX(-50%) translateY(60px) scale(.95)}60%{transform:translateX(-50%) translateY(-5px) scale(1.01)}100%{opacity:1;transform:translateX(-50%) translateY(0) scale(1)}}
@keyframes ringPulse{0%,100%{box-shadow:0 0 0 0 rgba(79,196,140,.35)}50%{box-shadow:0 0 0 14px rgba(79,196,140,0)}}
@keyframes spin{to{transform:rotate(360deg)}}
.spin{animation:spin 1s linear infinite}
.ic{flex-shrink:0;vertical-align:middle}
.layout{position:relative;z-index:1;display:flex;min-height:100vh;animation:pageIn .7s cubic-bezier(.2,.8,.3,1) both}
.sbar{width:250px;flex-shrink:0;padding:1.4rem .9rem;display:flex;flex-direction:column;gap:1rem;position:sticky;top:0;height:100vh}
.sb-card{background:var(--card);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:var(--r);box-shadow:var(--shadow)}
.sb-brand{display:flex;flex-direction:column;align-items:center;gap:.7rem;padding:1.5rem 1rem}
.sb-brand .mark{display:flex;align-items:center;justify-content:center;width:52px;height:52px;border-radius:16px;color:#fff;background:linear-gradient(135deg,var(--accent),var(--accent2),var(--accent));background-size:220% 220%;animation:gradShift 8s ease infinite,floaty 5s ease-in-out infinite;box-shadow:0 8px 26px var(--glow);font-weight:900;font-size:1.4rem;font-family:ui-monospace,monospace}
.sb-brand h1{font-size:1.15rem;font-weight:900;letter-spacing:.14em}
.sb-brand h1 i{font-style:normal;background:linear-gradient(120deg,var(--accent),var(--accent2));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.sb-brand small{color:var(--dim);font-size:.6rem;letter-spacing:.34em}
.sb-nav{display:flex;flex-direction:column;gap:.3rem;padding:.8rem}
.sb-nav button{display:flex;align-items:center;justify-content:space-between;padding:.85rem 1rem;border-radius:13px;font-size:.86rem;font-weight:600;color:var(--dim);cursor:pointer;transition:all .3s;border:none;background:none;font-family:inherit}
.sb-nav button .ic{order:-1;margin-left:.65rem}
.sb-nav button span{flex:1;text-align:right}
.sb-nav button:hover{color:var(--text);background:var(--card2)}
.sb-nav button.active{color:var(--accent);background:var(--card2);box-shadow:inset 0 0 0 1px var(--border),0 4px 14px var(--glow)}
.sb-foot{margin-top:auto;text-align:center;color:var(--dim);font-size:.62rem;letter-spacing:.14em;padding:.9rem;opacity:.75}
.main{flex:1;min-width:0;padding:1.4rem 1.6rem 3rem;display:flex;flex-direction:column;gap:1.3rem}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:1rem;padding:.8rem 1.1rem;background:var(--tb);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:var(--r);box-shadow:var(--shadow)}
.tb-tg{display:flex;align-items:center;gap:.55rem;color:var(--dim);text-decoration:none;font-size:.8rem;padding:.55rem .9rem;border-radius:12px;transition:all .3s}
.tb-tg:hover{color:var(--accent);background:var(--card2)}
.tb-actions{display:flex;align-items:center;gap:.55rem}
.icon-btn{display:inline-flex;align-items:center;justify-content:center;width:40px;height:40px;border-radius:12px;background:var(--card2);border:1px solid var(--border);color:var(--dim);cursor:pointer;transition:all .3s;position:relative;text-decoration:none}
.icon-btn:hover{color:var(--accent);border-color:var(--accent);transform:translateY(-2px)}
.icon-btn .dot{position:absolute;top:9px;left:10px;width:7px;height:7px;border-radius:50%;background:var(--accent);animation:pulseDot 2s ease infinite}
.theme-pil{display:flex;align-items:center;gap:.25rem;background:var(--card2);border:1px solid var(--border);border-radius:12px;padding:.3rem;cursor:pointer;transition:all .3s}
.theme-pil:hover{border-color:var(--accent)}
.theme-pil .tp{display:flex;align-items:center;justify-content:center;width:30px;height:30px;border-radius:9px;color:var(--dim);transition:all .3s}
.theme-pil .tp.on{background:var(--card);color:var(--accent);box-shadow:0 2px 8px var(--glow)}
.userchip{display:flex;align-items:center;gap:.6rem;padding:.35rem .8rem .35rem .5rem;background:var(--card2);border:1px solid var(--border);border-radius:14px}
.userchip .av{display:flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:11px;color:#fff;background:linear-gradient(135deg,var(--accent),var(--accent2));font-weight:900}
.userchip .un{font-size:.78rem;font-weight:700;line-height:1.2}
.userchip .un small{display:block;color:var(--success);font-size:.62rem;font-weight:500}
.tbtn{display:inline-flex;align-items:center;gap:.45rem;background:var(--card2);border:1px solid var(--border);border-radius:12px;padding:.5rem .9rem;cursor:pointer;color:var(--dim);font-size:.78rem;font-family:inherit;transition:all .3s;text-decoration:none}
.tbtn:hover{color:var(--danger);border-color:var(--danger);transform:translateY(-2px)}
.card{background:var(--card);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:var(--r);padding:1.5rem;box-shadow:var(--shadow);transition:transform .4s cubic-bezier(.2,.8,.3,1),border-color .4s,box-shadow .4s}
.card:hover{transform:translateY(-3px);border-color:var(--accent);box-shadow:var(--shadow),0 0 0 4px var(--glow)}
.vhead{display:flex;align-items:center;gap:.7rem;margin-bottom:1.2rem;flex-wrap:wrap}
.vhead .ci{display:flex;align-items:center;justify-content:center;width:38px;height:38px;border-radius:12px;background:var(--glow);color:var(--accent)}
.vhead h2{font-size:1.05rem;font-weight:800}
.vhead .sp{flex:1}
.pill{display:inline-flex;align-items:center;gap:.4rem;padding:.25rem .7rem;border-radius:20px;font-size:.68rem;font-weight:700;background:var(--card2);border:1px solid var(--border);color:var(--dim)}
.pill .dot{width:7px;height:7px;border-radius:50%;background:var(--dim)}
.pill.on{color:var(--success)}.pill.on .dot{background:var(--success);animation:pulseDot 2.2s ease infinite}
.pill.off{color:var(--danger)}.pill.off .dot{background:var(--danger)}
.pill.code{font-family:ui-monospace,monospace;letter-spacing:.06em;color:var(--accent)}
.pill.warn{color:var(--warn)}
.label{font-size:.78rem;color:var(--dim);margin-bottom:.55rem;display:block;line-height:1.8}
.input,.select,textarea.input{width:100%;padding:.85rem 1.05rem;background:var(--card2);border:1px solid var(--border);border-radius:12px;color:var(--text);font-size:.9rem;outline:none;transition:all .3s;font-family:inherit}
html[data-theme='light'] .input,html[data-theme='light'] .select,html[data-theme='light'] textarea.input{background:rgba(255,255,255,.55)}
.select{appearance:none;cursor:pointer}
textarea.input{min-height:120px;resize:vertical;direction:ltr;text-align:left;font-family:ui-monospace,monospace;font-size:.76rem;line-height:1.9}
.input:focus,.select:focus,textarea.input:focus{border-color:var(--accent);box-shadow:0 0 0 4px var(--glow)}
.btn{flex:1;display:inline-flex;align-items:center;justify-content:center;gap:.55rem;padding:.85rem;background:linear-gradient(135deg,var(--accent),var(--accent2),var(--accent));background-size:220% 220%;animation:gradShift 8s ease infinite;border:none;border-radius:13px;color:#fff;font-size:.86rem;font-weight:700;cursor:pointer;transition:all .35s;font-family:inherit;text-decoration:none;position:relative;overflow:hidden}
.btn::before{content:'';position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,.25),transparent);transform:translateX(-100%);transition:transform .6s}
.btn:hover::before{transform:translateX(100%)}
.btn:hover{transform:translateY(-2px);box-shadow:0 8px 26px var(--glow)}
.btn.ghost{background:var(--card2);animation:none;border:1px solid var(--border);color:var(--dim)}
.btn.ghost:hover{border-color:var(--accent);color:var(--accent)}
.btn.danger{background:var(--card2);animation:none;border:1px solid rgba(239,114,134,.35);color:var(--danger)}
.btn.danger:hover{border-color:var(--danger)}
.btn.sm{flex:none;padding:.55rem .95rem;font-size:.77rem}
.btn[disabled]{opacity:.6;pointer-events:none}
.brow{display:flex;gap:.6rem;margin-top:.9rem;flex-wrap:wrap}
.rows{display:flex;flex-direction:column}
.row{display:flex;justify-content:space-between;align-items:center;gap:1rem;padding:.72rem 0;border-bottom:1px solid var(--border);font-size:.85rem}
.row:last-child{border-bottom:none}
.row .k{color:var(--dim);flex-shrink:0}
.row .v{direction:ltr;text-align:left;word-break:break-all}
.mono{font-family:ui-monospace,monospace}
.tg{display:flex;justify-content:space-between;align-items:center;gap:1.2rem;padding:.9rem 0;border-bottom:1px solid var(--border)}
.tg:last-child{border-bottom:none}
.tg .tt{font-size:.88rem;font-weight:600}
.tg .ts{font-size:.72rem;color:var(--dim);margin-top:.25rem;line-height:1.7}
.sw{position:relative;display:inline-block;width:50px;height:27px;flex-shrink:0}
.sw input{opacity:0;width:0;height:0}
.sl{position:absolute;inset:0;background:var(--card2);border:1px solid var(--border);border-radius:27px;cursor:pointer;transition:.35s}
.sl::before{content:'';position:absolute;height:19px;width:19px;right:3px;top:3px;background:var(--dim);border-radius:50%;transition:.35s cubic-bezier(.68,-.4,.27,1.4)}
.sw input:checked + .sl{background:linear-gradient(135deg,var(--accent),var(--accent2));border-color:transparent}
.sw input:checked + .sl::before{transform:translateX(-23px);background:#fff}
.srow{display:flex;gap:.6rem}
.srow .input{flex:1}
.natgrid{display:grid;grid-template-columns:repeat(3,1fr);gap:.8rem;margin-top:1rem}
.natc{border:1px solid var(--border);border-radius:13px;padding:1.1rem .9rem;cursor:pointer;text-align:center;transition:all .35s;background:var(--card2)}
.natc:hover{border-color:var(--accent);transform:translateY(-3px)}
.natc.sel{border-color:var(--accent);box-shadow:0 0 0 3px var(--glow)}
.natc .nc{font-family:ui-monospace,monospace;font-weight:800;font-size:1rem;color:var(--accent)}
.natc .nl{font-size:.78rem;margin:.35rem 0}
.natc .np{font-size:.58rem;color:var(--dim);direction:ltr;font-family:ui-monospace,monospace;word-break:break-all}
.cfg-item{display:flex;align-items:center;gap:.75rem;padding:.75rem .2rem;border-bottom:1px solid var(--border);cursor:pointer;transition:all .25s}
.cfg-item:last-child{border-bottom:none}
.cfg-item:hover{transform:translateX(-5px)}
.cfg-item:hover .cfg-name{color:var(--accent)}
.cfg-item .cfg-name{font-weight:700;font-size:.82rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:48%;transition:color .25s}
.cfg-item .cfg-host{color:var(--dim);font-size:.7rem;flex:1;direction:ltr;text-align:left;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cfg-item .icon-btn{width:34px;height:34px;border-radius:10px;flex-shrink:0}
.pingrow{display:flex;align-items:center;gap:.8rem;padding:.65rem .2rem;border-bottom:1px solid var(--border);font-size:.8rem}
.pingrow:last-child{border-bottom:none}
.pingrow .pr-name{flex:1;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pingrow .pr-host{color:var(--dim);font-size:.68rem;direction:ltr;max-width:38%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pingrow .pr-ms{font-family:ui-monospace,monospace;font-weight:800;padding:.2rem .65rem;border-radius:9px;min-width:74px;text-align:center}
.pr-ms.g{color:var(--success);background:rgba(79,196,140,.1)}
.pr-ms.y{color:var(--warn);background:rgba(230,178,105,.1)}
.pr-ms.r{color:var(--danger);background:rgba(239,114,134,.1)}
.pbar{height:8px;background:var(--card2);border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-top:.5rem}
.pfill{height:100%;background:linear-gradient(90deg,var(--accent3),var(--accent),var(--accent2));border-radius:8px;position:relative;overflow:hidden;transition:width 1s cubic-bezier(.2,.8,.3,1)}
.pfill::after{content:'';position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,.4),transparent);transform:translateX(-100%);animation:shimmer 2.6s infinite}
.hero{display:flex;flex-wrap:wrap;align-items:center;gap:1.4rem;position:relative;overflow:hidden}
.hero-ring{display:flex;align-items:center;justify-content:center;width:88px;height:88px;border-radius:50%;background:radial-gradient(circle,rgba(79,196,140,.18),transparent 70%);border:2px solid rgba(79,196,140,.5);animation:ringPulse 2.6s ease infinite;color:var(--success)}
.hero-body{flex:1;min-width:220px}
.hero-body h2{font-size:1.35rem;font-weight:900;display:flex;align-items:center;gap:.55rem}
.hero-body p{color:var(--dim);font-size:.82rem;margin-top:.35rem}
.hero-chips{display:flex;gap:.8rem;flex-wrap:wrap}
.chip{display:flex;flex-direction:column;gap:.3rem;padding:.8rem 1.1rem;background:var(--card2);border:1px solid var(--border);border-radius:14px;min-width:140px}
.chip .ck{display:flex;align-items:center;gap:.4rem;color:var(--dim);font-size:.7rem}
.chip .cv{font-size:.92rem;font-weight:800}
.chip .cv.mono{font-family:ui-monospace,monospace;direction:ltr;text-align:left}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1.1rem}
.stat{display:flex;flex-direction:column;gap:.55rem}
.stat .st-top{display:flex;align-items:center;justify-content:space-between}
.stat .st-ic{display:flex;align-items:center;justify-content:center;width:40px;height:40px;border-radius:12px;background:var(--glow);color:var(--accent)}
.stat .st-t{font-size:.75rem;color:var(--dim);font-weight:600}
.stat .st-v{font-size:1.5rem;font-weight:900;letter-spacing:-.01em}
.stat .st-v small{font-size:.72rem;color:var(--dim);font-weight:600}
.stat .st-s{font-size:.68rem;color:var(--dim)}
.dash-grid{display:grid;grid-template-columns:1.5fr 1fr;gap:1.1rem}
.dash-grid2{display:grid;grid-template-columns:1.4fr 1fr 1fr;gap:1.1rem}
.subbox{background:var(--card2);border:1px solid var(--border);border-radius:14px;padding:1rem 1.1rem;font-size:.8rem;color:var(--dim);direction:ltr;text-align:left;word-break:break-all;font-family:ui-monospace,monospace;display:flex;align-items:center;gap:.7rem}
.subbox .txt{flex:1;line-height:1.7;max-height:72px;overflow:hidden;cursor:pointer}
.acts{display:flex;flex-direction:column}
.act{display:flex;align-items:center;gap:.8rem;padding:.75rem 0;border-bottom:1px solid var(--border);font-size:.8rem}
.act:last-child{border-bottom:none}
.act .a-ic{display:flex;align-items:center;justify-content:center;width:32px;height:32px;border-radius:10px;background:var(--glow);color:var(--accent);flex-shrink:0}
.act .a-t{flex:1;color:var(--text)}
.act .a-time{color:var(--dim);font-size:.68rem;white-space:nowrap}
.qa{display:flex;flex-direction:column;gap:.7rem}
.qa .q{display:flex;align-items:center;gap:.8rem;padding:.9rem;background:var(--card2);border:1px solid var(--border);border-radius:14px;cursor:pointer;transition:all .3s;font-family:inherit;font-size:.82rem;font-weight:600;color:var(--text);text-align:right;width:100%}
.qa .q:hover{border-color:var(--accent);transform:translateX(-4px)}
.qa .q .ic{color:var(--accent)}
.qa .q small{display:block;color:var(--dim);font-weight:500;font-size:.68rem;margin-top:.15rem}
.promo{background:linear-gradient(150deg,rgba(124,133,245,.2),rgba(169,142,245,.12),rgba(95,141,240,.18));border:1px solid var(--border);border-radius:var(--r);padding:1.6rem;display:flex;flex-direction:column;gap:.8rem;position:relative;overflow:hidden}
.promo::before{content:'';position:absolute;top:-60px;left:-60px;width:180px;height:180px;border-radius:50%;background:radial-gradient(circle,var(--glow),transparent 70%);animation:floaty 6s ease-in-out infinite}
.promo .p-logo{display:flex;align-items:center;gap:.55rem;font-weight:900;letter-spacing:.12em}
.promo .p-logo .m{display:flex;align-items:center;justify-content:center;width:40px;height:40px;border-radius:12px;color:#fff;background:linear-gradient(135deg,var(--accent),var(--accent2));font-family:ui-monospace,monospace}
.promo h3{font-size:1.1rem;font-weight:900}
.promo p{color:var(--dim);font-size:.76rem;line-height:2}
.promo .btn{align-self:flex-start;margin-top:auto}
.note{background:rgba(230,178,105,.08);border:1px solid rgba(230,178,105,.25);border-radius:12px;padding:1.05rem;font-size:.78rem;color:var(--warn);line-height:2;display:flex;gap:.65rem}
.ok{color:var(--success)}.bad{color:var(--danger)}
.view{display:none;flex-direction:column;gap:1.3rem}
.view.active{display:flex}
.view.anim>*{animation:rise .5s ease both}
.view.anim>*:nth-child(2){animation-delay:.05s}
.view.anim>*:nth-child(3){animation-delay:.1s}
.view.anim>*:nth-child(4){animation-delay:.15s}
.view.anim>*:nth-child(5){animation-delay:.2s}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1.2rem}
.span2{grid-column:1/-1}
.client-card{display:flex;flex-direction:column}
.linkbox{background:var(--card2);border:1px solid var(--border);border-radius:12px;padding:.9rem;font-size:.7rem;color:var(--dim);word-break:break-all;direction:ltr;text-align:left;margin-bottom:.7rem;cursor:pointer;transition:all .3s;font-family:ui-monospace,monospace;line-height:1.8;max-height:100px;overflow:hidden}
.linkbox:hover{border-color:var(--accent);color:var(--text)}
.toast{position:fixed;bottom:2rem;left:50%;transform:translateX(-50%);background:var(--card);backdrop-filter:blur(20px);border:1px solid var(--border);color:var(--text);padding:.8rem 1.6rem;border-radius:12px;font-size:.82rem;font-weight:600;opacity:0;z-index:99;pointer-events:none;box-shadow:var(--shadow);display:flex;align-items:center;gap:.55rem;max-width:88vw}
.toast.show{animation:toastIn .45s cubic-bezier(.22,1.2,.36,1) both}
.center{text-align:center;color:var(--dim);font-size:.88rem;padding:2rem 0}
.footer{text-align:center;padding:1.6rem 0 .3rem;color:var(--dim)}
.footer .creator{display:flex;align-items:center;justify-content:center;gap:.7rem;flex-wrap:wrap;margin-bottom:.8rem}
.footer .creator a{display:inline-flex;align-items:center;gap:.45rem;color:var(--dim);text-decoration:none;padding:.45rem 1rem;border:1px solid var(--border);border-radius:24px;background:var(--card2);transition:all .35s;font-weight:700;font-size:.75rem}
.footer .creator a:hover{color:var(--accent);border-color:var(--accent);transform:translateY(-3px)}
.footer .love{font-size:.8rem;color:var(--text);display:flex;align-items:center;justify-content:center;gap:.4rem;opacity:.9}
.footer .love b{background:linear-gradient(120deg,var(--accent),var(--accent2));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;font-weight:900}
.footer .love .ic{color:var(--danger);animation:pulseDot 1.6s ease infinite}
.hidden{display:none}
.err{color:var(--danger);font-size:.82rem;margin-bottom:.9rem}
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.5rem;position:relative;z-index:1}
.login-box{width:100%;max-width:430px;display:flex;flex-direction:column;gap:1.1rem}
.sub-wrap{max-width:680px;margin:0 auto;padding:2rem 1.4rem 3rem;position:relative;z-index:1;display:flex;flex-direction:column;gap:1.2rem;animation:pageIn .7s cubic-bezier(.2,.8,.3,1) both}
.apps{display:grid;grid-template-columns:repeat(3,1fr);gap:.7rem;margin-top:1rem}
.app{display:flex;align-items:center;justify-content:center;padding:.95rem;background:var(--card2);border:1px solid var(--border);border-radius:12px;color:var(--text);font-size:.8rem;font-weight:600;text-decoration:none;transition:all .3s}
.app:hover{border-color:var(--accent);color:var(--accent);transform:translateY(-3px)}
.bigsub{background:var(--card2);border:1px dashed var(--accent);border-radius:13px;padding:1.15rem;font-size:.76rem;color:var(--accent);direction:ltr;text-align:left;word-break:break-all;cursor:pointer;font-family:ui-monospace,monospace;line-height:1.8;transition:all .3s}
.bigsub:hover{background:var(--glow)}
@media(max-width:1080px){.stats{grid-template-columns:1fr 1fr}.dash-grid,.dash-grid2{grid-template-columns:1fr}}
@media(max-width:860px){.layout{flex-direction:column}.sbar{width:100%;height:auto;position:static;padding:.8rem}.sb-brand{flex-direction:row;padding:.8rem 1rem;gap:.8rem}.sb-brand .mark{width:40px;height:40px;font-size:1.05rem;border-radius:12px}.sb-nav{flex-direction:row;overflow-x:auto;padding:.5rem}.sb-nav button{white-space:nowrap;padding:.6rem .9rem}.sb-nav button .ic{margin-left:.4rem}.sb-foot{display:none}.main{padding:1rem .9rem 2.5rem}.grid{grid-template-columns:1fr}.apps{grid-template-columns:1fr 1fr}.userchip .un{display:none}.tb-tg span{display:none}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
`;
const THEME_HEAD = `<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800;900&display=swap" rel="stylesheet"><script>try{document.documentElement.setAttribute('data-theme',localStorage.getItem('rix_theme')||'dark')}catch(e){document.documentElement.setAttribute('data-theme','dark')}</script>`;
const THEME_JS = `
function setTheme(n){document.documentElement.setAttribute('data-theme',n);try{localStorage.setItem('rix_theme',n)}catch(e){}syncThemeUI(n)}
function toggleTheme(){setTheme(document.documentElement.getAttribute('data-theme')==='light'?'dark':'light')}
function syncThemeUI(n){var s=document.getElementById('tpSun'),m=document.getElementById('tpMoon');if(s)s.classList.toggle('on',n==='dark');if(m)m.classList.toggle('on',n==='light')}`;
const BG_EL = `<div class="bg"><div class="neb n1"></div><div class="neb n2"></div><div class="stars"></div></div><div class="veil"></div>`;
const BODY_CLASS = (BG_DARK_URL || BG_LIGHT_URL) ? ' class="has-bg"' : '';
const htmlHeaders = { 'Content-Type': 'text/html; charset=utf-8' };
const jsonHeaders = { 'Content-Type': 'application/json' };

const COPY_JS = `
function doCopy(text){
  var ok=function(){toast('کپی شد')};
  var fail=function(){
    try{
      var ta=document.createElement('textarea');
      ta.value=text;ta.style.position='fixed';ta.style.opacity='0';
      document.body.appendChild(ta);ta.focus();ta.select();
      var done=document.execCommand('copy');
      document.body.removeChild(ta);
      toast(done?'کپی شد':'کپی نشد — دستی انتخاب کن',done?'':'bad');
    }catch(e){toast('کپی نشد','bad')}
  };
  try{
    if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(text).then(ok,fail);
    else fail();
  }catch(e){fail()}
}
document.addEventListener('click',function(e){
  var a=e.target.closest?e.target.closest('a[href]'):null;
  if(a)return;
  var el=e.target;
  while(el&&el!==document&&!el.hasAttribute('data-copy'))el=el.parentElement;
  if(el&&el!==document){e.preventDefault();doCopy(el.getAttribute('data-copy'))}
},true);`;

function heroHTML(cfg) {
  const srv = cfg.nat64Enabled ? (NAT64[cfg.nat64Prefix].code + ' ' + NAT64[cfg.nat64Prefix].label) : 'خودکار — ورکر';
  return `<div class="card hero"><div class="hero-ring">${svg('check', 34)}</div><div class="hero-body"><h2>${svg('shield', 20)} اتصال امن</h2><p>سرویس فعال است — برای اتصال، لینک اشتراک را در برنامه خود وارد کنید</p></div><div class="hero-chips"><div class="chip"><span class="ck">${svg('map', 13)} سرور فعلی</span><span class="cv">${esc(srv)}</span></div><div class="chip"><span class="ck">${svg('zap', 13)} پینگ</span><span class="cv mono" id="heroPing">— ms</span></div><div class="chip"><span class="ck">${svg('clock', 13)} زمان کارکرد</span><span class="cv mono" id="heroClock">—</span></div></div></div>`;
}
function statsHTML(cfg, usageTotal) {
  const days = Math.max(1, Math.ceil((Date.now() - (cfg.created || Date.now())) / 86400000));
  const activeClients = cfg.clients.filter(c => c.enabled !== false).length;
  const hasUnlimited = cfg.clients.some(c => !(c.quotaGB > 0));
  let remainTxt = 'نامحدود', remainPct = 100;
  if (!hasUnlimited && cfg.clients.length) {
    const totalQ = cfg.clients.reduce((s, c) => s + c.quotaGB * GB, 0);
    const remain = Math.max(0, totalQ - usageTotal);
    remainTxt = (remain / GB).toFixed(1) + ' GB';
    remainPct = totalQ ? Math.round((remain / totalQ) * 100) : 100;
  }
  const usedGB = (usageTotal / GB).toFixed(1);
  return `<div class="stats">
    <div class="card stat"><div class="st-top"><span class="st-ic">${svg('calendar', 18)}</span><span class="st-t">زمان اعتبار</span></div><div class="st-v">${days} <small>روز</small></div><div class="st-s">تا پایان اشتراک</div><div class="pbar"><div class="pfill" style="width:100%"></div></div></div>
    <div class="card stat"><div class="st-top"><span class="st-ic">${svg('db', 18)}</span><span class="st-t">حجم باقیمانده</span></div><div class="st-v">${remainTxt}</div><div class="st-s">مجموع کلاینت‌ها</div><div class="pbar"><div class="pfill" style="width:${remainPct}%"></div></div></div>
    <div class="card stat"><div class="st-top"><span class="st-ic">${svg('swap', 18)}</span><span class="st-t">ترافیک مصرفی</span></div><div class="st-v">${usedGB} <small>GB</small></div><div class="st-s">مصرف امروز</div><div class="pbar"><div class="pfill" style="width:${Math.min(100, Math.round((usageTotal / GB / 50) * 100))}%"></div></div></div>
    <div class="card stat"><div class="st-top"><span class="st-ic">${svg('users', 18)}</span><span class="st-t">کلاینت فعال</span></div><div class="st-v">${activeClients}</div><div class="st-s">دستگاه متصل</div><div class="pbar"><div class="pfill" style="width:${Math.min(100, Math.round((activeClients / Math.max(1, MAX_CLIENTS)) * 100))}%"></div></div></div>
  </div>`;
}

// ═══ پنل (UI دست‌نخورده) ═══
async function panelPage(request, env) {
  const cfg = await getConfig(env);
  const url = new URL(request.url);
  const host = url.hostname;
  const origin = url.origin;
  const subUrl = origin + '/sub';

  const usageList = await Promise.all(cfg.clients.map(c => getUsage(env, c.id)));
  const usageTotal = usageList.reduce((a, b) => a + b, 0);
  const logs = await getLogs(env);

  const mainItems = mainLinks(cfg, host).map(l => { const m = linkMeta(l); return { name: m.name, link: l }; });
  const cleanItems = cleanMainLinks(cfg, host).map(l => { const m = linkMeta(l); return { name: m.name, link: l }; });
  const configTab =
    cfgGroupHTML('کانفیگ‌های اصلی', 'box', mainItems) +
    cfgGroupHTML('IPهای تمیز', 'zap', cleanItems) +
    (cfg.clients.length ? `<div class="card"><div class="vhead"><span class="ci">${svg('users', 17)}</span><h2>کلاینت‌ها</h2><span class="sp"></span><span class="pill code">${cfg.clients.length}</span></div>${cfg.clients.map(c => {
      const n = clientLinks(cfg, c, host).length;
      const cSub = `${origin}/sub/${c.id}`;
      return `<div class="cfg-item" data-copy="${esc(cSub)}" title="کلیک = کپی ساب اختصاصی"><span class="cfg-name">${esc(c.name)}</span><span class="cfg-host">${n} کانفیگ</span><a class="icon-btn" href="${esc(cSub)}" target="_blank" rel="noopener" title="صفحه ساب">${svg('ext', 14)}</a><button class="icon-btn" data-copy="${esc(cSub)}" title="کپی ساب">${svg('copy', 14)}</button></div>`;
    }).join('')}</div>` : '');

  const clientCards = [];
  for (let i = 0; i < cfg.clients.length; i++) {
    const c = cfg.clients[i];
    const r = CLIENT_ROUTES[c.country] || CLIENT_ROUTES.main;
    const cSub = `${origin}/sub/${c.id}`;
    const clinks = clientLinks(cfg, c, host);
    const used = usageList[i];
    const pct = c.quotaGB > 0 ? Math.min(100, (used / (c.quotaGB * GB)) * 100) : 0;
    const on = c.enabled !== false;
    const cleanOn = clientWantsClean(c);
    clientCards.push(`<div class="card client-card">
      <div class="vhead"><span class="ci">${svg('users', 17)}</span><h2>${esc(c.name)}</h2><span class="sp"></span><span class="pill code">${r.code}</span>${cleanOn && cfg.cleanIPs.length ? `<span class="pill warn">${svg('zap', 11)} ${cfg.cleanIPs.length} Clean</span>` : ''}<span class="pill ${on ? 'on' : 'off'}"><span class="dot"></span>${on ? 'فعال' : 'خاموش'}</span></div>
      ${c.quotaGB > 0 ? `<div class="rows"><div class="row"><span class="k">مصرف امروز</span><span class="v mono">${(used/GB).toFixed(2)} / ${c.quotaGB} GB</span></div></div><div class="pbar"><div class="pfill" style="width:${pct}%;${pct>=100?'background:var(--danger)':''}"></div></div>` : `<div class="rows"><div class="row"><span class="k">حجم</span><span class="v ok">نامحدود</span></div></div>`}
      <p class="label" style="margin-top:.9rem;color:var(--dim);font-size:.72rem">ساب اختصاصی — همه کانفیگ‌ها با اسم «${esc(c.name)}»</p>
      <div class="linkbox" data-copy="${esc(cSub)}">${esc(cSub)}</div>
      <div class="brow">
        <button class="btn ghost sm" data-copy="${esc(cSub)}">${svg('copy', 14)} ساب</button>
        ${clinks[0] ? `<button class="btn ghost sm" data-copy="${esc(clinks[0])}">${svg('copy', 14)} کانفیگ</button>` : ''}
        <a class="btn ghost sm" href="${esc(cSub)}" target="_blank" rel="noopener">${svg('ext', 14)} صفحه ساب</a>
      </div>
      <div class="brow" style="align-items:center"><label class="sw"><input type="checkbox" data-cl-clean="${c.id}" ${cleanOn?'checked':''}><span class="sl"></span></label><span style="flex:1;font-size:.72rem;color:var(--dim)">تزریق IPهای تمیز به ساب این کلاینت</span></div>
      <div class="brow">
        <button class="btn ghost sm" data-cl-rename="${c.id}" data-name="${esc(c.name)}">${svg('pencil', 14)} اسم</button>
        <button class="btn ${on?'danger':'ghost'} sm" data-cl-toggle="${c.id}" data-next="${on?'false':'true'}">${svg('power', 14)} ${on?'خاموش':'روشن'}</button>
        <button class="btn danger sm" data-cl-del="${c.id}" data-name="${esc(c.name)}">${svg('trash', 14)} حذف</button>
      </div>
    </div>`);
  }

  const routeOptions = Object.entries(CLIENT_ROUTES).map(([k, r]) => `<option value="${k}">${r.label} (${r.code})</option>`).join('');
  const natCards = Object.entries(NAT64).map(([k, n]) => {
    const lat = getGwLat('n:' + k);
    const latTxt = lat ? (lat.ok ? ' · ' + lat.ms + 'ms' : ' · بی‌پاسخ') : '';
    return `<div class="natc ${cfg.nat64Prefix === k ? 'sel' : ''}" data-nat="${k}"><div class="nc">${n.code}</div><div class="nl">${n.label}${latTxt}</div><div class="np">${n.prefix}</div></div>`;
  }).join('');

  const logItems = logs.slice(0, 8).map(l => `<div class="act"><span class="a-ic">${svg('activity', 15)}</span><span class="a-t">${esc(l.txt)}</span><span class="a-time" data-ts="${l.t}"></span></div>`).join('') || '<div class="center">فعالیتی ثبت نشده</div>';
  const botSaved = !!(cfg.botToken && cfg.botChatId);

  return new Response(`<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RIX PANEL</title>${THEME_HEAD}<style>${CSS}</style></head><body${BODY_CLASS}>${BG_EL}
<div class="layout">
  <aside class="sbar">
    <div class="sb-card sb-brand"><span class="mark">R</span><div style="text-align:center"><h1>R<i>IX</i></h1><small>PANEL</small></div></div>
    <nav class="sb-card sb-nav" id="nav">
      <button class="active" data-view="dash"><span>داشبورد</span>${svg('home', 17)}</button>
      <button data-view="config"><span>کانفیگ‌ها</span>${svg('box', 17)}</button>
      <button data-view="clients"><span>کلاینت‌ها</span>${svg('users', 17)}</button>
      <button data-view="bot"><span>ربات</span>${svg('bot', 17)}</button>
      <button data-view="info"><span>اطلاعات</span>${svg('info', 17)}</button>
      <button data-view="settings"><span>تنظیمات</span>${svg('sliders', 17)}</button>
    </nav>
    <div class="sb-foot">RIX PANEL v${PANEL_VER}</div>
  </aside>
  <div class="main">
    <header class="topbar">
      <a class="tb-tg" href="https://t.me/RG7YT" target="_blank" rel="noopener">${svg('send', 15)}<span>ارتباط با پشتیبانی بدون محدودیت</span></a>
      <div class="tb-actions">
        <button class="icon-btn" id="bellBtn">${svg('bell', 16)}<span class="dot"></span></button>
        <div class="theme-pil" onclick="toggleTheme()" title="تغییر تم"><span class="tp on" id="tpSun">${sunSvg}</span><span class="tp" id="tpMoon">${moonSvg}</span></div>
        <div class="userchip"><span class="av">R</span><div class="un">کاربر عزیز<small>آنلاین</small></div></div>
        <a class="tbtn" href="/logout">${svg('logout', 15)} خروج</a>
      </div>
    </header>
    <section id="view-dash" class="view active anim">
      ${heroHTML(cfg)}
      ${statsHTML(cfg, usageTotal)}
      <div class="dash-grid">
        <div class="card">
          <div class="vhead"><span class="ci">${svg('link', 17)}</span><h2>لینک کانفیگ اشتراکی</h2></div>
          <p class="label" style="color:var(--dim);font-size:.75rem">این لینک را در برنامه‌های مورد نظر خود وارد کنید</p>
          <div class="subbox">${svg('link', 15)}<span class="txt" data-copy="${esc(subUrl)}">${esc(subUrl)}</span><button class="icon-btn" data-copy="${esc(subUrl)}" style="width:36px;height:36px">${svg('copy', 15)}</button></div>
          <div class="brow"><button class="btn" data-copy="${esc(subUrl)}">${svg('copy', 15)} کپی لینک</button><a class="btn ghost" href="${esc(subUrl)}" target="_blank" rel="noopener">${svg('ext', 15)} صفحه اشتراک</a></div>
        </div>
        <div class="card" style="display:flex;flex-direction:column;justify-content:center">
          <div class="pill" style="align-self:flex-start;margin-bottom:.8rem">${svg('star', 12)} سریع &nbsp;•&nbsp; امن &nbsp;•&nbsp; پایدار</div>
          <p style="font-size:.86rem;line-height:2.2;color:var(--dim)">با جدیدترین پروتکل‌ها و سرورهای قدرتمند به راحتی و با خیال راحت محافظت شوید.<br><b style="color:var(--text)">${cfg.clients.length} کلاینت</b> فعال با <b style="color:var(--text)">${cfg.cleanIPs.length} IP تمیز</b> آماده اتصال هستند.</p>
        </div>
      </div>
      <div class="dash-grid2">
        <div class="card"><div class="vhead"><span class="ci">${svg('activity', 17)}</span><h2>آخرین فعالیت‌ها</h2></div><div class="acts" id="logList">${logItems}</div></div>
        <div class="card"><div class="vhead"><span class="ci">${svg('zap', 17)}</span><h2>دسترسی سریع</h2></div>
          <div class="qa">
            <button class="q" data-goto="clients"><span class="ci" style="display:flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:10px;background:var(--glow);color:var(--accent)">${svg('plus', 16)}</span><span>ساخت کلاینت جدید<small>اطلاعات اتصال جدید</small></span></button>
            <button class="q" data-goto="clients"><span class="ci" style="display:flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:10px;background:var(--glow);color:var(--accent)">${svg('users', 16)}</span><span>مدیریت کلاینت‌ها<small>مشاهده و ویرایش اتصال‌ها</small></span></button>
            <button class="q" data-goto="settings"><span class="ci" style="display:flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:10px;background:var(--glow);color:var(--accent)">${svg('activity', 16)}</span><span>تست شبکه و پینگ<small>سلامت مسیرها و IPها</small></span></button>
            <button class="q" data-goto="bot"><span class="ci" style="display:flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:10px;background:var(--glow);color:var(--accent)">${svg('bot', 16)}</span><span>ربات اعلان<small>${botSaved ? (cfg.botUser ? 'متصل: @' + esc(cfg.botUser) : 'متصل') : 'اتصال ربات تلگرام'}</small></span></button>
          </div>
        </div>
        <div class="promo">
          <div class="p-logo"><span class="m">R</span><div><h3>R<i style="font-style:normal;background:linear-gradient(120deg,var(--accent),var(--accent2));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent">IX</i> PANEL</h3></div></div>
          <h3>آزادی در دستان شماست</h3>
          <p>بدون محدودیت، بدون نگرانی — فقط اتصال را آغاز کنید.</p>
          <a class="btn" href="https://t.me/RIXPANEL" target="_blank" rel="noopener">${svg('arrow', 15)} کانال ما</a>
        </div>
      </div>
    </section>
    <section id="view-config" class="view">${configTab || '<div class="card"><div class="note">' + svg('alert', 18) + '<span>هیچ کانفیگ فعالی نیست — از تنظیمات پروتکل‌ها را فعال کن.</span></div></div>'}</section>
    <section id="view-clients" class="view">
      <div class="card">
        <div class="vhead"><span class="ci">${svg('plus', 17)}</span><h2>ساخت کلاینت جدید</h2></div>
        <p class="label" style="color:var(--dim);font-size:.75rem">مسیر خروج: کشورهای NAT64، ProxyIP، مثل اصلی یا مستقیم — IPهای تمیز هم خودکار تزریق می‌شوند</p>
        <div class="srow" style="margin-bottom:.7rem"><input type="text" class="input" id="clName" placeholder="اسم دلخواه (در برنامه دیده می‌شود)" maxlength="32"><select class="select" id="clCountry" style="max-width:230px">${routeOptions}</select></div>
        <div class="srow"><input type="number" class="input" id="clQuota" placeholder="حجم روزانه به گیگابایت — خالی یعنی نامحدود" min="0" max="1000"></div>
        <button class="btn" id="btnAddClient">${svg('plus', 16)} ساخت کلاینت</button>
      </div>
      ${clientCards.join('')}
      ${cfg.clients.length ? '' : '<div class="card center">هنوز کلاینتی نساخته‌ای</div>'}
    </section>
    <section id="view-bot" class="view">
      <div class="card span2">
        <div class="vhead"><span class="ci">${svg('bot', 17)}</span><h2>ربات اعلان تلگرام</h2><span class="sp"></span>${cfg.botUser ? `<span class="pill code" dir="ltr">@${esc(cfg.botUser)}</span>` : ''}<span class="pill ${botSaved ? 'on' : 'off'}"><span class="dot"></span>${botSaved ? 'ذخیره شده' : 'ذخیره نشده'}</span><span class="pill ${cfg.botEnabled ? 'on' : 'off'}"><span class="dot"></span>${cfg.botEnabled ? 'فعال' : 'غیرفعال'}</span></div>
        <div class="tg" style="border:none;padding-top:0"><div><div class="tt">فعال‌سازی ربات</div><div class="ts">بعد از ذخیره موفق توکن و Chat ID، این را روشن کن</div></div><label class="sw"><input type="checkbox" id="botEnabled" ${cfg.botEnabled?'checked':''}><span class="sl"></span></label></div>
        <label class="label" style="margin-top:.9rem">توکن ربات (از @BotFather)</label>
        <input type="text" class="input" id="botToken" placeholder="${botSaved ? 'ذخیره شده: ' + esc(maskToken(cfg.botToken)) + ' — برای تغییر، توکن جدید را وارد کن' : '123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ'}" dir="ltr">
        <label class="label" style="margin-top:.9rem">Chat ID مقصد</label>
        <div class="srow"><input type="text" class="input" id="botChatId" value="${esc(cfg.botChatId)}" placeholder="مثال: 123456789" dir="ltr"><button class="btn ghost sm" id="btnFetchChats" style="flex:none">${svg('refresh', 15)} دریافت</button></div>
        <div id="chatList" class="qa" style="margin-top:.7rem"></div>
        <div class="brow"><button class="btn" id="btnBotSave">${svg('save', 15)} ذخیره و تأیید ربات</button><button class="btn ghost" id="btnBotTest">${svg('send', 15)} پیام تست</button></div>
      </div>
      <div class="card span2">
        <div class="vhead"><span class="ci">${svg('bell', 17)}</span><h2>نوع اعلان‌ها</h2></div>
        <div class="tg"><div><div class="tt">ورود و خروج پنل</div><div class="ts">هر ورود و خروج به پنل اطلاع داده می‌شود</div></div><label class="sw"><input type="checkbox" data-bot-ev="botOnAuth" ${cfg.botOnAuth?'checked':''}><span class="sl"></span></label></div>
        <div class="tg"><div><div class="tt">مدیریت کلاینت‌ها و تنظیمات</div><div class="ts">ساخت، حذف، تغییر نام، خاموش/روشن و تغییرات تنظیمات</div></div><label class="sw"><input type="checkbox" data-bot-ev="botOnClient" ${cfg.botOnClient?'checked':''}><span class="sl"></span></label></div>
        <div class="tg"><div><div class="tt">اتصال‌ها</div><div class="ts">خلاصه دسته‌ای (هر ۱۰ اتصال یا ۶۰ ثانیه)</div></div><label class="sw"><input type="checkbox" data-bot-ev="botOnConn" ${cfg.botOnConn?'checked':''}><span class="sl"></span></label></div>
      </div>
      <div class="card span2">
        <div class="vhead"><span class="ci">${svg('info', 17)}</span><h2>راهنمای رفع اشکال</h2></div>
        <div class="rows">
          <div class="row"><span class="k">۱</span><span class="v">@BotFather → /newbot → توکن را کپی کن</span></div>
          <div class="row"><span class="k">۲</span><span class="v">«ذخیره و تأیید» بزن — توکن با getMe واقعاً چک می‌شود</span></div>
          <div class="row"><span class="k">۳</span><span class="v">به ربات /start بده → «دریافت» → Chat ID → دوباره ذخیره</span></div>
          <div class="row"><span class="k">۴</span><span class="v">«پیام تست» — اگر خطا داد، متن دقیق خطای تلگرام نمایش داده می‌شود</span></div>
        </div>
      </div>
    </section>
    <section id="view-info" class="view">
      <div class="grid">
        <div class="card"><div class="vhead"><span class="ci">${svg('globe', 17)}</span><h2>سرور</h2></div>
          <div class="rows"><div class="row"><span class="k">آدرس</span><span class="v">${esc(host)}</span></div><div class="row"><span class="k">مسیر WS</span><span class="v mono">/?ed=2048</span></div><div class="row"><span class="k">TLS</span><span class="v ok">فعال</span></div><div class="row"><span class="k">هسته</span><span class="v mono">v${PANEL_VER}</span></div></div>
        </div>
        <div class="card"><div class="vhead"><span class="ci">${svg('activity', 17)}</span><h2>وضعیت</h2></div>
          <div class="rows"><div class="row"><span class="k">VLESS</span><span class="v ${cfg.vlessEnabled?'ok':'bad'}">${cfg.vlessEnabled?'فعال':'خاموش'}</span></div><div class="row"><span class="k">Trojan</span><span class="v ${cfg.trojanEnabled?'ok':'bad'}">${cfg.trojanEnabled?'فعال':'خاموش'}</span></div><div class="row"><span class="k">NAT64</span><span class="v">${cfg.nat64Enabled ? esc(NAT64[cfg.nat64Prefix].code + ' — ' + NAT64[cfg.nat64Prefix].label) : 'خاموش'}</span></div><div class="row"><span class="k">IP تمیز</span><span class="v">${cfg.cleanIPs.length}</span></div><div class="row"><span class="k">ربات</span><span class="v ${cfg.botEnabled?'ok':'bad'}">${cfg.botEnabled?'متصل':'غیرفعال'}</span></div></div>
        </div>
        <div class="card span2"><div class="vhead"><span class="ci">${svg('key', 17)}</span><h2>کلیدها</h2></div>
          <div class="rows"><div class="row"><span class="k">UUID اصلی</span><span class="v mono">${esc(cfg.uuid)}</span></div><div class="row"><span class="k">Trojan</span><span class="v mono">${esc(cfg.trojanPass)}</span></div></div>
        </div>
        <div class="card span2"><div class="vhead"><span class="ci">${svg('code', 17)}</span><h2>مرجع API</h2></div>
          <div class="rows"><div class="row"><span class="k">GET /health</span><span class="v">وضعیت زنده — بدون احراز</span></div><div class="row"><span class="k">GET /api/status</span><span class="v">وضعیت کامل JSON — نیاز به کوکی پنل</span></div><div class="row"><span class="k">GET /sub?raw=1</span><span class="v">کانفیگ‌ها به‌صورت متن خام</span></div><div class="row"><span class="k">POST /api/nettest</span><span class="v">پینگ: nat64 / proxy / clean (+save:true)</span></div><div class="row"><span class="k">POST /api/bot</span><span class="v">save / test / chatids</span></div><div class="row"><span class="k">POST /api/settings · /api/clients · /api/cleanips</span><span class="v">مدیریت کامل</span></div></div>
        </div>
      </div>
    </section>
    <section id="view-settings" class="view">
      <div class="grid">
        <div class="card span2">
          <div class="vhead"><span class="ci" style="color:var(--success)">${svg('activity', 17)}</span><h2>سلامت شبکه — تست پینگ واقعی</h2></div>
          <p class="label" style="color:var(--dim);font-size:.74rem">TCP handshake واقعی از داخل ورکر. هر گیت‌وی NAT64 با دو مقصد چک می‌شود تا نتیجه قابل اعتماد باشد. بعد از تست، گیت‌وی‌های مرده ۶۰ ثانیه از مسیر ترافیک حذف می‌شوند.</p>
          <div class="brow" style="margin-top:0">
            <button class="btn ghost sm" id="btnTestNat">${svg('globe', 14)} تست NAT64</button>
            <button class="btn ghost sm" id="btnBestNat">${svg('star', 14)} انتخاب بهترین</button>
            <button class="btn ghost sm" id="btnTestProxy">${svg('shield', 14)} تست ProxyIP</button>
            <button class="btn ghost sm" id="btnTestClean">${svg('zap', 14)} تست IPهای تمیز</button>
          </div>
          <div class="tg" style="border:none;padding:.6rem 0 0"><div><div class="tt">پاکسازی هوشمند IP تمیز</div><div class="ts">بعد از تست، مرده‌ها حذف و زنده‌ها بر اساس پینگ مرتب و ذخیره شوند</div></div><label class="sw"><input type="checkbox" id="chkSaveClean" checked><span class="sl"></span></label></div>
          <div id="netResults" style="margin-top:.8rem"></div>
        </div>
        <div class="card span2">
          <div class="vhead"><span class="ci" style="color:var(--warn)">${svg('zap', 17)}</span><h2>IPهای تمیز کلادفلر</h2></div>
          <p class="label" style="color:var(--dim);font-size:.74rem">هر خط یک IP یا دامنه با پورت اختیاری — به ساب اصلی و همه کلاینت‌ها تزریق می‌شود</p>
          <textarea class="input" id="cleanTa" placeholder="104.16.0.7&#10;172.64.0.1:2053">${esc(cfg.cleanIPs.join('\n'))}</textarea>
          <div class="brow"><button class="btn" id="btnSaveClean" style="flex:0 0 auto">${svg('save', 15)} ذخیره لیست</button></div>
          <div class="tg"><div><div class="tt">تزریق در ساب اصلی</div><div class="ts">کانفیگ‌های IP تمیز با UUID اصلی داخل ساب اصلی هم قرار بگیرند</div></div><label class="sw"><input type="checkbox" data-setting="cleanIPsMain" ${cfg.cleanIPsMain?'checked':''}><span class="sl"></span></label></div>
        </div>
        <div class="card span2">
          <div class="vhead"><span class="ci">${svg('globe', 17)}</span><h2>NAT64 — مسیر کشورها</h2></div>
          <div class="tg" style="border:none;padding-top:0"><div><div class="tt">خروج از کشور انتخابی</div><div class="ts">اگر گیت‌وی بی‌پاسخ باشد خودکار fallback می‌شود</div></div><label class="sw"><input type="checkbox" data-setting="nat64Enabled" ${cfg.nat64Enabled?'checked':''}><span class="sl"></span></label></div>
          <div class="natgrid">${natCards}</div>
        </div>
        <div class="card span2">
          <div class="vhead"><span class="ci">${svg('shield', 17)}</span><h2>ProxyIP</h2></div>
          <p class="label" style="color:var(--dim);font-size:.72rem">هم برای مسیر هوشمند و هم به‌عنوان مسیر اختصاصی کلاینت (گزینه PROXY در کشوی کشور)</p>
          <div class="tg" style="border:none;padding-top:0"><div><div class="tt">مسیریابی هوشمند</div><div class="ts">مقصدهای پشت کلادفلر به‌طور خودکار از ProxyIP بروند</div></div><label class="sw"><input type="checkbox" data-setting="proxyEnabled" ${cfg.proxyEnabled?'checked':''}><span class="sl"></span></label></div>
          <div class="srow" style="margin-top:.9rem"><input type="text" class="input" id="proxyInput" value="${esc(cfg.proxyIP)}" placeholder="1.2.3.4 یا domain.com:443" dir="ltr"><button class="btn ghost sm" id="btnSaveProxy">${svg('save', 15)}</button></div>
        </div>
        <div class="card span2">
          <div class="vhead"><span class="ci">${svg('box', 17)}</span><h2>پروتکل‌های اصلی</h2></div>
          <div class="tg"><div><div class="tt">VLESS</div><div class="ts">روی کانفیگ اصلی و همه کلاینت‌ها اثر می‌گذارد</div></div><label class="sw"><input type="checkbox" data-setting="vlessEnabled" ${cfg.vlessEnabled?'checked':''}><span class="sl"></span></label></div>
          <div class="tg"><div><div class="tt">Trojan</div><div class="ts">فقط کانفیگ اصلی</div></div><label class="sw"><input type="checkbox" data-setting="trojanEnabled" ${cfg.trojanEnabled?'checked':''}><span class="sl"></span></label></div>
        </div>
        <div class="card"><div class="vhead"><span class="ci">${svg('key', 17)}</span><h2>UUID اصلی</h2></div>
          <div class="srow"><input type="text" class="input" id="newUuid" value="${esc(cfg.uuid)}" dir="ltr"><button class="btn ghost sm" id="btnGenUuid">${svg('refresh', 15)}</button></div>
          <div class="brow"><button class="btn" id="btnSaveUuid">${svg('save', 15)} ذخیره</button></div>
        </div>
        <div class="card"><div class="vhead"><span class="ci">${svg('key', 17)}</span><h2>رمز Trojan</h2></div>
          <div class="srow"><input type="text" class="input" id="newTrojan" value="${esc(cfg.trojanPass)}" dir="ltr"><button class="btn ghost sm" id="btnGenPass">${svg('refresh', 15)}</button></div>
          <div class="brow"><button class="btn" id="btnSaveTrojan">${svg('save', 15)} ذخیره</button></div>
        </div>
        <div class="card span2"><div class="vhead"><span class="ci">${svg('lock', 17)}</span><h2>رمز پنل</h2></div>
          <div class="srow"><input type="password" class="input" id="newPanelPass" placeholder="رمز جدید"></div>
          <div class="brow"><button class="btn" id="btnSavePanelPass">${svg('check', 15)} تغییر رمز پنل</button></div>
        </div>
      </div>
    </section>
    ${FOOTER_HTML}
  </div>
</div>
<div class="toast" id="toast">${svg('check', 15)}<span id="toastMsg"></span></div>
<script>
 ${THEME_JS}
function toast(m,c){var t=document.getElementById('toast');document.getElementById('toastMsg').textContent=m;t.classList.remove('show');void t.offsetWidth;t.classList.add('show');t.style.borderColor=c==='bad'?'rgba(239,114,134,.55)':'rgba(79,196,140,.55)';setTimeout(function(){t.classList.remove('show')},2600)}
syncThemeUI(document.documentElement.getAttribute('data-theme')||'dark');
(function(){
  function hesc(s){return String(s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
  var SPIN='<svg class="ic spin" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M21 12a9 9 0 1 1-9-9"/></svg>';
  function busy(btn,on,label){if(on){if(!btn.dataset.orig)btn.dataset.orig=btn.innerHTML;btn.disabled=true;btn.innerHTML=SPIN+'<span style="margin-right:.3rem">'+hesc(label||'...')+'</span>'}else{btn.disabled=false;if(btn.dataset.orig){btn.innerHTML=btn.dataset.orig;delete btn.dataset.orig}}}
  function api(ep,body){return fetch(ep,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})}
  async function saveSetting(type,value){var r=await api('/api/settings',{type:type,value:value});if(r.ok)toast('ذخیره شد');else toast(await r.text().catch(function(){return 'خطا'}),'bad')}
  var navBtns=document.querySelectorAll('#nav button');
  navBtns.forEach(function(b){b.addEventListener('click',function(){navBtns.forEach(function(x){x.classList.toggle('active',x===b)});document.querySelectorAll('.view').forEach(function(v){v.classList.remove('active','anim')});var v=document.getElementById('view-'+b.dataset.view);v.classList.add('active');void v.offsetWidth;v.classList.add('anim')})});
  document.querySelectorAll('[data-goto]').forEach(function(el){el.addEventListener('click',function(){var b=document.querySelector('#nav button[data-view="'+el.dataset.goto+'"]');if(b)b.click()})});
  function ping(){var t0=performance.now();fetch('/health?_='+Date.now(),{cache:'no-store'}).then(function(){var el=document.getElementById('heroPing');if(el)el.textContent=Math.round(performance.now()-t0)+' ms'}).catch(function(){var el=document.getElementById('heroPing');if(el)el.textContent='— ms'})}
  ping();setInterval(ping,15000);
  setInterval(function(){var el=document.getElementById('heroClock');if(el)el.textContent=new Date().toLocaleTimeString('fa-IR')},1000);
  function ago(t){var s=(Date.now()-t)/1000;if(s<60)return'همین حالا';if(s<3600)return Math.floor(s/60)+' دقیقه پیش';if(s<86400)return Math.floor(s/3600)+' ساعت پیش';return Math.floor(s/86400)+' روز پیش'}
  document.querySelectorAll('[data-ts]').forEach(function(el){el.textContent=ago(parseInt(el.dataset.ts))});
  var bell=document.getElementById('bellBtn');if(bell)bell.addEventListener('click',function(){var d=this.querySelector('.dot');if(d)d.remove();toast('اعلان جدیدی نیست')});
  function msClass(r){if(!r.ok)return'r';if(r.ms<150)return'g';if(r.ms<400)return'y';return'r'}
  function renderResults(results,saved){
    var box=document.getElementById('netResults');
    if(!results||!results.length){box.innerHTML='';return}
    var html='<div class="rows">';
    results.forEach(function(r){html+='<div class="pingrow"><span class="pr-name">'+hesc(r.label)+'</span><span class="pr-host mono">'+hesc(r.host||'—')+'</span>';html+=r.ok?'<span class="pr-ms '+msClass(r)+'">'+r.ms+' ms</span>':'<span class="pr-ms r">بی‌پاسخ</span>';html+='</div>'});
    html+='</div>';
    if(saved>0)html+='<p class="label" style="margin-top:.7rem;color:var(--success)">ذخیره شد: '+saved+' IP زنده مرتب بر اساس پینگ</p>';
    else if(saved===0)html+='<p class="label" style="margin-top:.7rem;color:var(--danger)">هیچ IP زنده‌ای نبود — لیست را عوض کن</p>';
    var nat=results.filter(function(r){return r.kind==='nat64'});
    if(nat.length&&!nat.some(function(r){return r.ok}))html+='<div class="note" style="margin-top:.7rem"><svg class="ic" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg><span>هیچ گیت‌وی NAT64 از داخل ورکر در دسترس نیست — کانفیگ‌ها خودکار از مسیر ProxyIP/مستقیم وصل می‌شوند و قطع نمی‌شوند.</span></div>';
    box.innerHTML=html;
  }
  async function netTest(kind,btn,save){busy(btn,true,'در حال تست...');try{var r=await api('/api/nettest',{kind:kind,save:!!save});var j=await r.json();if(!r.ok){toast(j.error||'خطا','bad');return null}renderResults(j.results,(j.saved!==undefined)?j.saved:-1);return j.results}catch(e){toast('خطا در تست','bad');return null}finally{busy(btn,false)}}
  var lastNat=null;
  document.getElementById('btnTestNat').addEventListener('click',async function(){lastNat=await netTest('nat64',this,false)});
  document.getElementById('btnTestProxy').addEventListener('click',function(){netTest('proxy',this,false)});
  document.getElementById('btnTestClean').addEventListener('click',function(){netTest('clean',this,document.getElementById('chkSaveClean').checked)});
  document.getElementById('btnBestNat').addEventListener('click',async function(){
    busy(this,true,'در حال سنجش...');
    try{
      var res=lastNat;
      if(!res){var r=await api('/api/nettest',{kind:'nat64'});var j=await r.json();if(!r.ok)return toast(j.error||'خطا','bad');res=j.results;lastNat=res;renderResults(res,-1)}
      var alive=res.filter(function(x){return x.ok}).sort(function(a,b){return a.ms-b.ms});
      if(alive.length){await saveSetting('nat64Prefix',alive[0].k);toast('بهترین انتخاب شد: '+alive[0].label+' — '+alive[0].ms+'ms')}
      else toast('هیچ گیت‌وی زنده‌ای نیست — fallback مستقیم فعال است','bad');
    }finally{busy(this,false)}
  });
  document.querySelectorAll('[data-setting]').forEach(function(el){el.addEventListener('change',function(){saveSetting(el.dataset.setting,el.checked)})});
  document.querySelectorAll('.natc').forEach(function(el){el.addEventListener('click',function(){document.querySelectorAll('.natc').forEach(function(x){x.classList.toggle('sel',x===el)});saveSetting('nat64Prefix',el.dataset.nat)})});
  document.getElementById('btnSaveProxy').addEventListener('click',async function(){busy(this,true,'...');try{var r=await api('/api/settings',{type:'proxyIP',value:document.getElementById('proxyInput').value.trim()});if(r.ok)toast('ProxyIP ذخیره شد');else toast(await r.text().catch(function(){return 'فرمت اشتباه'}),'bad')}finally{busy(this,false)}});
  document.getElementById('btnSaveClean').addEventListener('click',async function(){busy(this,true,'در حال ذخیره...');try{var ips=document.getElementById('cleanTa').value.split(/[\\n,]+/).map(function(x){return x.trim()}).filter(Boolean);var r=await api('/api/cleanips',{ips:ips});if(r.ok){toast('ذخیره شد — ساب‌ها را آپدیت کن');setTimeout(function(){location.reload()},900)}else toast(await r.text().catch(function(){return 'خطا'}),'bad')}finally{busy(this,false)}});
  function botApi(body){return api('/api/bot',body)}
  document.querySelectorAll('[data-bot-ev]').forEach(function(el){el.addEventListener('change',async function(){var r=await botApi({action:'save',ev:el.dataset.botEv,value:el.checked});if(r.ok)toast('ذخیره شد');else toast(await r.text().catch(function(){return 'خطا'}),'bad')})});
  document.getElementById('btnBotSave').addEventListener('click',async function(){busy(this,true,'در حال ذخیره...');try{var body={action:'save',enabled:document.getElementById('botEnabled').checked,chatId:document.getElementById('botChatId').value.trim()};var tk=document.getElementById('botToken').value.trim();if(tk)body.token=tk;var r=await botApi(body);if(r.ok){toast('ربات ذخیره و تأیید شد ✅');setTimeout(function(){location.reload()},900)}else toast(await r.text().catch(function(){return 'خطا'}),'bad')}finally{busy(this,false)}});
  document.getElementById('btnBotTest').addEventListener('click',async function(){busy(this,true,'در حال ارسال...');try{var r=await botApi({action:'test'});var t=await r.text();toast(t,r.ok?'':'bad')}finally{busy(this,false)}});
  document.getElementById('btnFetchChats').addEventListener('click',async function(){busy(this,true,'...');try{var r=await botApi({action:'chatids'});var t=await r.text();if(!r.ok)return toast(t,'bad');var list=JSON.parse(t);var box=document.getElementById('chatList');if(!list.length){box.innerHTML='<div class="center">چیزی پیدا نشد — اول به ربات /start بده</div>';return}box.innerHTML=list.map(function(c){return '<button class="q" data-chatid="'+hesc(c.id)+'"><span class="ci" style="display:flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:10px;background:var(--glow);color:var(--accent)"><svg class="ic" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></svg></span><span>'+hesc(c.name)+'<small dir="ltr">'+hesc(c.id)+'</small></span></button>'}).join('');box.querySelectorAll('[data-chatid]').forEach(function(b){b.addEventListener('click',function(){document.getElementById('botChatId').value=b.dataset.chatid;toast('انتخاب شد — حالا «ذخیره و تأیید» را بزن')})})}catch(e){toast('خطا','bad')}finally{busy(this,false)}});
  document.getElementById('btnAddClient').addEventListener('click',async function(){busy(this,true,'در حال ساخت...');try{var name=document.getElementById('clName').value.trim();var quota=parseFloat(document.getElementById('clQuota').value)||0;var country=document.getElementById('clCountry').value;if(!name)return toast('اسم کلاینت را بنویس','bad');var r=await api('/api/clients',{action:'add',name:name,quotaGB:quota,country:country});if(r.ok){toast('کلاینت ساخته شد ✅');setTimeout(function(){location.reload()},800)}else toast(await r.text().catch(function(){return 'خطا'}),'bad')}finally{busy(this,false)}});
  document.querySelectorAll('[data-cl-clean]').forEach(function(el){el.addEventListener('change',async function(){var r=await api('/api/clients',{action:'update',id:el.dataset.clClean,cleanIPs:el.checked});if(r.ok)toast('ثبت شد — ساب را آپدیت کن');else toast('خطا','bad')})});
  document.querySelectorAll('[data-cl-toggle]').forEach(function(el){el.addEventListener('click',async function(){var r=await api('/api/clients',{action:'update',id:el.dataset.clToggle,enabled:el.dataset.next==='true'});if(r.ok){toast('ثبت شد');setTimeout(function(){location.reload()},700)}else toast('خطا','bad')})});
  document.querySelectorAll('[data-cl-rename]').forEach(function(el){el.addEventListener('click',async function(){var nn=prompt('اسم جدید:',el.dataset.name);if(!nn||!nn.trim())return;var r=await api('/api/clients',{action:'update',id:el.dataset.clRename,name:nn.trim()});if(r.ok){toast('اسم عوض شد — ساب را آپدیت کن');setTimeout(function(){location.reload()},800)}else toast('خطا','bad')})});
  document.querySelectorAll('[data-cl-del]').forEach(function(el){el.addEventListener('click',async function(){if(!confirm('کلاینت «'+el.dataset.name+'» حذف شود؟'))return;var r=await api('/api/clients',{action:'delete',id:el.dataset.clDel});if(r.ok){toast('حذف شد');setTimeout(function(){location.reload()},700)}else toast('خطا','bad')})});
  function genUuid(){var b=crypto.getRandomValues(new Uint8Array(16));b[6]=(b[6]&15)|64;b[8]=(b[8]&63)|128;var h=Array.from(b).map(function(x){return x.toString(16).padStart(2,'0')}).join('');document.getElementById('newUuid').value=h.slice(0,8)+'-'+h.slice(8,12)+'-'+h.slice(12,16)+'-'+h.slice(16,20)+'-'+h.slice(20)}
  function genPass(){var c='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';document.getElementById('newTrojan').value=Array.from(crypto.getRandomValues(new Uint8Array(16))).map(function(x){return c[x%c.length]}).join('')}
  document.getElementById('btnGenUuid').addEventListener('click',genUuid);
  document.getElementById('btnGenPass').addEventListener('click',genPass);
  document.getElementById('btnSaveUuid').addEventListener('click',async function(){busy(this,true,'...');try{var r=await api('/api/settings',{type:'uuid',value:document.getElementById('newUuid').value.trim()});if(r.ok){toast('ذخیره شد — ساب‌ها را آپدیت کن');setTimeout(function(){location.reload()},900)}else toast(await r.text().catch(function(){return 'UUID نامعتبر'}),'bad')}finally{busy(this,false)}});
  document.getElementById('btnSaveTrojan').addEventListener('click',async function(){busy(this,true,'...');try{var r=await api('/api/settings',{type:'trojan',value:document.getElementById('newTrojan').value.trim()});if(r.ok){toast('ذخیره شد — ساب‌ها را آپدیت کن');setTimeout(function(){location.reload()},900)}else toast(await r.text().catch(function(){return 'خطا'}),'bad')}finally{busy(this,false)}});
  document.getElementById('btnSavePanelPass').addEventListener('click',async function(){busy(this,true,'...');try{var v=document.getElementById('newPanelPass').value;if(!v)return toast('خالی است','bad');var r=await api('/api/settings',{type:'panelPass',value:v});if(r.ok){toast('رمز عوض شد — دوباره وارد شو');setTimeout(function(){location.href='/logout'},1000)}else toast('خطا','bad')}finally{busy(this,false)}});
})();
 ${COPY_JS}
</script>
</body></html>`, { headers: htmlHeaders });
}

function setupHelpPage() {
  return new Response(`<!DOCTYPE html><html lang="fa" dir="rtl" data-theme="dark"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RIX PANEL</title>${THEME_HEAD}<style>${CSS}</style></head><body${BODY_CLASS}>${BG_EL}<div class="login-wrap"><div class="login-box">
  <div class="sb-card sb-brand" style="flex-direction:row;justify-content:center"><span class="mark">R</span><div><h1>R<i>IX</i></h1><small>PANEL</small></div></div>
  <div class="card"><div class="vhead"><span class="ci">${svg('alert', 18)}</span><h2>اتصال KV الزامی است</h2></div>
  <div class="rows"><div class="row"><span class="k">۱</span><span class="v">ورکر → Settings → Bindings</span></div><div class="row"><span class="k">۲</span><span class="v">Add → KV Namespace</span></div><div class="row"><span class="k">۳</span><span class="v">Variable name: kv</span></div><div class="row"><span class="k">۴</span><span class="v">Save → Deploy → رفرش</span></div></div></div>
  ${FOOTER_HTML}</div></div></body></html>`, { status: 503, headers: htmlHeaders });
}

function loginPage(error = '') {
  return new Response(`<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RIX PANEL</title>${THEME_HEAD}<style>${CSS}</style></head><body${BODY_CLASS}>${BG_EL}<div class="login-wrap"><div class="login-box">
  <div class="sb-card sb-brand" style="flex-direction:row;justify-content:space-between;padding:1rem 1.2rem"><div style="display:flex;align-items:center;gap:.7rem"><span class="mark" style="width:44px;height:44px;font-size:1.15rem;border-radius:13px">R</span><div><h1 style="font-size:1.05rem">R<i>IX</i></h1><small style="letter-spacing:.3em;color:var(--dim);font-size:.58rem">PANEL</small></div></div><div class="theme-pil" onclick="toggleTheme()"><span class="tp on" id="tpSun">${sunSvg}</span><span class="tp" id="tpMoon">${moonSvg}</span></div></div>
  <p style="text-align:center;color:var(--dim);font-size:.66rem;letter-spacing:.3em;margin-top:-.4rem">FASTER / SAFER / STRONGER</p>
  <div class="card">
    <div class="vhead"><span class="ci">${svg('lock', 18)}</span><h2>ورود به پنل</h2></div>
    ${error ? `<p class="err">${esc(error)}</p>` : ''}
    <form method="POST" action="/login"><label class="label" style="color:var(--dim);font-size:.75rem">رمز ورود</label><input type="password" name="pass" class="input" placeholder="••••••••" required autofocus><div class="brow"><button type="submit" class="btn">${svg('check', 15)} ورود</button></div></form>
  </div>
  ${FOOTER_HTML}</div></div></body></html>`, { headers: htmlHeaders });
}

function subPageHTML(title, subUrl, groups) {
  const groupCards = (groups && groups.length) ? groups.map(g => cfgGroupHTML(g.t, g.icon, g.items)).join('') : `<div class="card center">کانفیگ فعالی در این اشتراک نیست</div>`;
  const apps = [
    ['v2rayNG', 'v2rayng://install-sub?url=' + encodeURIComponent(subUrl)],
    ['Hiddify', 'hiddify://import/sub?url=' + encodeURIComponent(subUrl)],
    ['Streisand', 'streisand://import/' + subUrl],
    ['NekoBox', 'sn://subscription?url=' + encodeURIComponent(subUrl)],
    ['V2Box', 'v2box://install-sub?url=' + encodeURIComponent(subUrl)],
    ['Happ', 'happ://add/' + subUrl]
  ];
  return new Response(`<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>${THEME_HEAD}<style>${CSS}</style></head><body${BODY_CLASS}>${BG_EL}<div class="sub-wrap">
  <div class="sb-card sb-brand" style="flex-direction:row;justify-content:space-between;padding:1rem 1.2rem"><div style="display:flex;align-items:center;gap:.7rem"><span class="mark" style="width:44px;height:44px;font-size:1.15rem;border-radius:13px">R</span><div><h1 style="font-size:1.05rem">R<i>IX</i></h1><small style="letter-spacing:.2em;color:var(--dim);font-size:.6rem">${esc(title)}</small></div></div><div class="theme-pil" onclick="toggleTheme()"><span class="tp on" id="tpSun">${sunSvg}</span><span class="tp" id="tpMoon">${moonSvg}</span></div></div>
  <div class="card"><div class="vhead"><span class="ci">${svg('link', 17)}</span><h2>لینک اشتراک</h2></div><div class="bigsub" data-copy="${esc(subUrl)}">${esc(subUrl)}</div></div>
  <div class="card"><div class="vhead"><span class="ci">${svg('zap', 17)}</span><h2>اتصال یک‌کلیکی</h2></div><div class="apps">${apps.map(([n, u]) => `<a class="app" href="${esc(u)}">${n}</a>`).join('')}</div></div>
  ${groupCards}
  ${FOOTER_HTML}</div>
  <div class="toast" id="toast">${svg('check', 15)}<span id="toastMsg"></span></div>
  <script>${THEME_JS}syncThemeUI(document.documentElement.getAttribute('data-theme')||'dark');
  function toast(m,c){var t=document.getElementById('toast');document.getElementById('toastMsg').textContent=m;t.classList.remove('show');void t.offsetWidth;t.classList.add('show');t.style.borderColor=c==='bad'?'rgba(239,114,134,.5)':'rgba(79,196,140,.5)';setTimeout(function(){t.classList.remove('show')},2400)}
  ${COPY_JS}
  </script></body></html>`, { headers: htmlHeaders });
}

// ═══ روتر اصلی ═══
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      if (path === '/health') return new Response(JSON.stringify({ ok: true, ver: PANEL_VER }), { headers: jsonHeaders });

      // ─── WS: /rix (قدیمی) | /{uuid} | /{trojanPass} — مطابق مرجع yonggekkk ───
      const isWS = (request.headers.get('Upgrade') || '').toLowerCase() === 'websocket';
      if (isWS) {
        if (!env.kv) return new Response('KV binding "kv" missing', { status: 500 });
        const cfg = await getCachedConfig(env); // ⬅️ فیکس پینگ: بدون خواندن KV در هر اتصال
        // Working-reference compatibility: generated configs use /?ed=2048.
        // Credential authentication is performed from the VLESS/Trojan payload.
        if (path === '/' || path === WS_PATH || path === WS_PATH + '/') return handleWSS(request, cfg, env, ctx, null);
        const seg = decodeURIComponent(path.replace(/^\/+|\/+$/g, ''));
        if (seg === cfg.trojanPass) {
          if (!cfg.trojanEnabled) return new Response('RIX: Trojan غیرفعال است', { status: 403 });
          return handleWSS(request, cfg, env, ctx, { proto: 'trojan' });
        }
        if (UUID_RE.test(seg)) {
          if (!cfg.vlessEnabled) return new Response('RIX: VLESS غیرفعال است', { status: 403 });
          const segHex = seg.replace(/-/g, '').toLowerCase();
          const ep = endpointByUUID(cfg, segHex);
          if (ep) {
            if (ep.owner === 'client') {
              const c = cfg.clients.find(x => x.id === ep.clientId && x.enabled !== false);
              if (!c) return new Response('RIX: کلاینت غیرفعال یا حذف شده', { status: 403 });
            }
            return handleWSS(request, cfg, env, ctx, { proto: 'vless', uuidHex: segHex, endpoint: ep });
          }
          // سازگاری با کانفیگ‌های قدیمی که قبل از endpoint registry ساخته شده‌اند
          const mainHex = cfg.uuid.replace(/-/g, '').toLowerCase();
          if (segHex === mainHex || cfg.clients.some(c => c.uuid.replace(/-/g, '').toLowerCase() === segHex && c.enabled !== false)) {
            return handleWSS(request, cfg, env, ctx, { proto: 'vless', uuidHex: segHex });
          }
        }
        return new Response('RIX: مسیر WebSocket نامعتبر', { status: 404 });
      }

      if (!env.kv) return setupHelpPage();

      if (path === '/api/status') {
        if (!(await isAuthed(request, env))) return new Response('Unauthorized', { status: 401 });
        const cfg = await getConfig(env);
        const usageTotal = (await Promise.all(cfg.clients.map(c => getUsage(env, c.id)))).reduce((a, b) => a + b, 0);
        return new Response(JSON.stringify({
          ok: true, ver: PANEL_VER, host: url.hostname,
          uptimeSec: Math.floor((Date.now() - BOOT_TIME) / 1000),
          vless: cfg.vlessEnabled, trojan: cfg.trojanEnabled,
          nat64: { enabled: cfg.nat64Enabled, prefix: cfg.nat64Prefix },
          proxy: { enabled: cfg.proxyEnabled, ip: cfg.proxyIP || null },
          cleanIPs: cfg.cleanIPs.length,
          clients: cfg.clients.length,
          activeClients: cfg.clients.filter(c => c.enabled !== false).length,
          endpoints: cfg.endpoints.length,
          uniqueVlessUUIDs: new Set(cfg.endpoints.map(e => e.uuid.toLowerCase())).size,
          usageTodayGB: +(usageTotal / GB).toFixed(3),
          bot: { enabled: cfg.botEnabled, saved: !!(cfg.botToken && cfg.botChatId), user: cfg.botUser || null },
          gw: Object.fromEntries([...gwLat.entries()])
        }), { headers: jsonHeaders });
      }

      if (path === '/api/nettest' && method === 'POST') {
        if (!(await isAuthed(request, env))) return new Response('Unauthorized', { status: 401 });
        const body = await request.json();
        const cfg = await getConfig(env);
        const kind = body.kind;

        if (kind === 'nat64') {
          const entries = Object.entries(NAT64);
          const probes = await Promise.all(entries.map(async ([k, n]) => {
            const probe = await nat64Probe(n.prefix);
            if (probe.ok) gwFail.delete('n:' + k); else markGw('n:' + k);
            setGwLat('n:' + k, probe);
            return { kind: 'nat64', k, label: n.label + ' (' + n.code + ')', host: probe.via || ('PREFIX ' + n.prefix), port: 443, ok: probe.ok, ms: probe.ms };
          }));
          probes.sort((a, b) => (b.ok - a.ok) || (a.ms - b.ms));
          return new Response(JSON.stringify({ results: probes }), { headers: jsonHeaders });
        }
        if (kind === 'proxy') {
          const pr = parseProxyIP(cfg.proxyIP);
          if (!pr) return new Response(JSON.stringify({ error: 'اول ProxyIP را در تنظیمات وارد کن' }), { status: 400, headers: jsonHeaders });
          const r = await tcpPing(pr.host, pr.port);
          if (r.ok) gwFail.delete('p:' + cfg.proxyIP); else markGw('p:' + cfg.proxyIP);
          setGwLat('p:x', r);
          return new Response(JSON.stringify({ results: [{ kind: 'proxy', label: 'ProxyIP — ' + cfg.proxyIP, host: pr.host, port: pr.port, ok: r.ok, ms: r.ms }] }), { headers: jsonHeaders });
        }
        if (kind === 'clean') {
          if (!cfg.cleanIPs.length) return new Response(JSON.stringify({ error: 'لیست IP تمیز خالی است' }), { status: 400, headers: jsonHeaders });
          const parsed = cfg.cleanIPs.map(ip => { const c = cleanSplit(ip); return { ip, host: c.host, port: c.port }; });
          const out = [];
          for (let i = 0; i < parsed.length; i += 8) {
            await Promise.all(parsed.slice(i, i + 8).map(p => tcpPing(p.host, p.port).then(r => { out.push({ kind: 'clean', label: p.ip, host: p.host + ':' + p.port, port: p.port, ok: r.ok, ms: r.ms }); })));
          }
          out.sort((a, b) => (b.ok - a.ok) || (a.ms - b.ms));
          let saved = -1;
          if (body.save === true) {
            const alive = out.filter(o => o.ok).map(o => o.ip);
            if (alive.length) { cfg.cleanIPs = alive; await saveConfig(env, cfg); saved = alive.length; await logEvent(env, 'پاکسازی IP تمیز: ' + alive.length + ' زنده ذخیره شد', ctx, 'client'); }
            else saved = 0;
          }
          return new Response(JSON.stringify({ results: out, saved }), { headers: jsonHeaders });
        }
        return new Response(JSON.stringify({ error: 'kind نامعتبر — nat64 | proxy | clean' }), { status: 400, headers: jsonHeaders });
      }

      if (path === '/logout') {
        await logEvent(env, 'خروج از پنل', ctx, 'auth');
        return new Response(null, { status: 302, headers: { 'Location': '/login', 'Set-Cookie': 'rix_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax' } });
      }

      if (path === '/api/bot' && method === 'POST') {
        if (!(await isAuthed(request, env))) return new Response('Unauthorized', { status: 401 });
        const body = await request.json();
        const cfg = await getConfig(env);
        if (body.action === 'save') {
          if (typeof body.token === 'string' && body.token.trim()) {
            const t = body.token.trim();
            if (!/^\d+:[A-Za-z0-9_-]{30,}$/.test(t)) return new Response('فرمت توکن نامعتبر — باید مثل 123456789:ABCdef... باشد', { status: 400 });
            try {
              const mr = await fetch('https://api.telegram.org/bot' + t + '/getMe');
              const mj = await mr.json();
              if (!mj.ok) return new Response('توکن رد شد — تلگرام می‌گوید: ' + (mj.description || 'Unauthorized'), { status: 400 });
              cfg.botToken = t;
              cfg.botUser = mj.result.username || '';
            } catch { return new Response('اتصال به تلگرام برقرار نشد — دوباره تلاش کن', { status: 400 }); }
          }
          if (typeof body.chatId === 'string') {
            const c = body.chatId.trim();
            if (c && !/^(-?\d+|@[A-Za-z0-9_]{4,})$/.test(c)) return new Response('Chat ID نامعتبر — عدد یا @نام‌کانال', { status: 400 });
            cfg.botChatId = c;
          }
          if (typeof body.enabled === 'boolean') {
            if (body.enabled && (!cfg.botToken || !cfg.botChatId)) return new Response('برای فعال‌سازی، اول توکن و Chat ID را ذخیره کن', { status: 400 });
            cfg.botEnabled = body.enabled;
          }
          if (typeof body.ev === 'string' && ['botOnAuth','botOnClient','botOnConn'].includes(body.ev) && typeof body.value === 'boolean') cfg[body.ev] = body.value;
          await saveConfig(env, cfg);
          await logEvent(env, 'ربات ذخیره شد' + (cfg.botUser ? ' (@' + cfg.botUser + ')' : ''), ctx, 'client');
          return new Response('OK');
        }
        if (body.action === 'test') {
          if (!cfg.botToken || !cfg.botChatId) return new Response('اول توکن و Chat ID را ذخیره کن', { status: 400 });
          const res = await sendTgNow(env, '🛡 <b>RIX PANEL</b>\nپیام تست — ربات متصل است ✅\n📦 نسخه: ' + PANEL_VER);
          if (res.ok) { await logEvent(env, 'پیام تست ربات ارسال شد', ctx, 'client'); return new Response('پیام تست ارسال شد ✅'); }
          return new Response('خطای تلگرام: ' + res.err + ' — Chat ID را چک کن و به ربات /start بده', { status: 400 });
        }
        if (body.action === 'chatids') {
          if (!cfg.botToken) return new Response('اول توکن ربات را ذخیره کن', { status: 400 });
          try {
            const r = await fetch('https://api.telegram.org/bot' + cfg.botToken + '/getUpdates?limit=30');
            const j = await r.json();
            if (!j.ok) return new Response('تلگرام: ' + (j.description || 'خطا'), { status: 400 });
            const seen = new Map();
            for (const u of (j.result || [])) {
              const m = u.message || u.channel_post || u.edited_message;
              if (m && m.chat) seen.set(String(m.chat.id), (m.chat.title || m.chat.first_name || m.chat.username || ('چت ' + m.chat.id)));
            }
            return new Response(JSON.stringify([...seen.entries()].map(([id, name]) => ({ id, name }))), { headers: jsonHeaders });
          } catch { return new Response('اتصال به تلگرام برقرار نشد', { status: 400 }); }
        }
        return new Response('Invalid action', { status: 400 });
      }

      if (path === '/api/settings' && method === 'POST') {
        if (!(await isAuthed(request, env))) return new Response('Unauthorized', { status: 401 });
        const body = await request.json();
        const cfg = await getConfig(env);
        if (body.type === 'uuid' && typeof body.value === 'string' && /^[0-9a-f-]{36}$/i.test(body.value)) { cfg.uuid = body.value; await logEvent(env, 'UUID اصلی تغییر کرد', ctx, 'client'); }
        else if (body.type === 'trojan' && typeof body.value === 'string' && body.value.length >= 8) { cfg.trojanPass = body.value; await logEvent(env, 'رمز Trojan تغییر کرد', ctx, 'client'); }
        else if (body.type === 'panelPass' && typeof body.value === 'string' && body.value.length >= 4) { cfg.panelPass = body.value; await logEvent(env, 'رمز پنل تغییر کرد', ctx, 'client'); }
        else if (body.type === 'proxyIP' && typeof body.value === 'string' && (body.value.trim() === '' || parseProxyIP(body.value))) { cfg.proxyIP = body.value.trim(); await logEvent(env, 'ProxyIP به‌روزرسانی شد', ctx, 'client'); }
        else if (body.type === 'proxyEnabled' && typeof body.value === 'boolean') cfg.proxyEnabled = body.value;
        else if (body.type === 'vlessEnabled' && typeof body.value === 'boolean') { cfg.vlessEnabled = body.value; await logEvent(env, 'VLESS ' + (body.value ? 'فعال' : 'غیرفعال') + ' شد', ctx, 'client'); }
        else if (body.type === 'trojanEnabled' && typeof body.value === 'boolean') { cfg.trojanEnabled = body.value; await logEvent(env, 'Trojan ' + (body.value ? 'فعال' : 'غیرفعال') + ' شد', ctx, 'client'); }
        else if (body.type === 'nat64Enabled' && typeof body.value === 'boolean') cfg.nat64Enabled = body.value;
        else if (body.type === 'nat64Prefix' && NAT64[body.value]) { cfg.nat64Prefix = body.value; await logEvent(env, 'کشور NAT64: ' + NAT64[body.value].label, ctx, 'client'); }
        else if (body.type === 'cleanIPsMain' && typeof body.value === 'boolean') cfg.cleanIPsMain = body.value;
        else return new Response('Invalid', { status: 400 });
        ensureEndpointRegistry(cfg);
        await saveConfig(env, cfg);
        return new Response('OK');
      }

      if (path === '/api/cleanips' && method === 'POST') {
        if (!(await isAuthed(request, env))) return new Response('Unauthorized', { status: 401 });
        const body = await request.json();
        if (!Array.isArray(body.ips)) return new Response('Invalid', { status: 400 });
        const ips = [...new Set(body.ips.map(x => String(x).trim()).filter(x => x && isValidClean(x)))].slice(0, MAX_CLEAN_IPS);
        const cfg = await getConfig(env);
        cfg.cleanIPs = ips;
        ensureEndpointRegistry(cfg);
        await saveConfig(env, cfg);
        await logEvent(env, 'لیست IP تمیز ذخیره شد (' + ips.length + ' مورد)', ctx, 'client');
        return new Response('OK');
      }

      if (path === '/api/clients' && method === 'POST') {
        if (!(await isAuthed(request, env))) return new Response('Unauthorized', { status: 401 });
        const body = await request.json();
        const cfg = await getConfig(env);
        if (body.action === 'add') {
          if (cfg.clients.length >= MAX_CLIENTS) return new Response('حداکثر ' + MAX_CLIENTS + ' کلاینت', { status: 400 });
          const name = (typeof body.name === 'string' ? body.name : '').trim().slice(0, 32);
          if (!name) return new Response('اسم نامعتبر', { status: 400 });
          if (!CLIENT_ROUTES[body.country]) return new Response('مسیر نامعتبر', { status: 400 });
          const quotaGB = Math.max(0, Math.min(1000, Number(body.quotaGB) || 0));
          cfg.clients.push({ id: 'c' + crypto.randomUUID().replace(/-/g, '').slice(0, 12), name, uuid: generateUUID(), quotaGB, country: body.country, cleanIPs: true, enabled: true, created: Date.now() });
          ensureEndpointRegistry(cfg);
          await saveConfig(env, cfg);
          await logEvent(env, 'کلاینت «' + name + '» ساخته شد (' + CLIENT_ROUTES[body.country].label + (quotaGB ? ' — ' + quotaGB + 'GB' : ' — نامحدود') + ')', ctx, 'client');
          return new Response('OK');
        }
        if (body.action === 'update') {
          const c = cfg.clients.find(c => c.id === body.id);
          if (!c) return new Response('پیدا نشد', { status: 404 });
          if (typeof body.enabled === 'boolean') { c.enabled = body.enabled; await logEvent(env, 'کلاینت «' + c.name + '» ' + (body.enabled ? 'روشن' : 'خاموش') + ' شد', ctx, 'client'); }
          if (typeof body.cleanIPs === 'boolean') c.cleanIPs = body.cleanIPs;
          if (typeof body.name === 'string' && body.name.trim()) { const old = c.name; c.name = body.name.trim().slice(0, 32); await logEvent(env, 'کلاینت «' + old + '» به «' + c.name + '» تغییر نام یافت', ctx, 'client'); }
          if (body.quotaGB !== undefined) c.quotaGB = Math.max(0, Math.min(1000, Number(body.quotaGB) || 0));
          if (CLIENT_ROUTES[body.country]) c.country = body.country;
          ensureEndpointRegistry(cfg);
          await saveConfig(env, cfg);
          return new Response('OK');
        }
        if (body.action === 'delete') {
          const i = cfg.clients.findIndex(c => c.id === body.id);
          if (i === -1) return new Response('پیدا نشد', { status: 404 });
          const nm = cfg.clients[i].name;
          cfg.clients.splice(i, 1);
          ensureEndpointRegistry(cfg);
          await saveConfig(env, cfg);
          await logEvent(env, 'کلاینت «' + nm + '» حذف شد', ctx, 'client');
          return new Response('OK');
        }
        return new Response('Invalid action', { status: 400 });
      }

      const subMatch = path.match(/^\/sub(?:\/([A-Za-z0-9_-]+))?\/?$/);
      if (subMatch) {
        const cfg = await getConfig(env); // خواندن تازه — تغییرات فوراً در ساب دیده می‌شود
        const subUrl = url.origin + path;
        const wantRaw = url.searchParams.get('raw') === '1';
        const wantHtml = !wantRaw && (request.headers.get('accept') || '').includes('text/html');
        let links, title;
        if (subMatch[1]) {
          const c = cfg.clients.find(c => c.id === subMatch[1]);
          if (!c) { if (wantHtml) return subPageHTML('کلاینت پیدا نشد', subUrl, []); return new Response('RIX: کلاینت پیدا نشد', { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }); }
          links = clientLinks(cfg, c, url.hostname);
          title = c.name + ' — RIX';
          if (wantHtml) {
            const groups = [{ t: 'کانفیگ اصلی', icon: 'box', items: [{ name: c.name, link: linkFor(endpointUUID(cfg, 'client', c.id, 'main', 'main', c.uuid), url.hostname, c.name) }] }];
            if (clientWantsClean(c) && cfg.cleanIPs.length) {
              groups.push({ t: 'IPهای تمیز', icon: 'zap', items: cfg.cleanIPs.map(ip => {
                const cc = cleanSplit(ip);
                return { name: c.name + ' — ' + ip, link: linkFor(endpointUUID(cfg, 'client', c.id, 'clean', ip, generateUUID()), url.hostname, c.name + ' - ' + ip, cc.host, cc.port) };
              }) });
            }
            return subPageHTML(title, subUrl, groups);
          }
        } else {
          links = [...mainLinks(cfg, url.hostname), ...cleanMainLinks(cfg, url.hostname)];
          title = 'RIX PANEL';
          if (wantHtml) {
            const groups = [];
            const mains = mainLinks(cfg, url.hostname).map(l => { const m = linkMeta(l); return { name: m.name, link: l }; });
            if (mains.length) groups.push({ t: 'کانفیگ‌های اصلی', icon: 'box', items: mains });
            const cleans = cleanMainLinks(cfg, url.hostname).map(l => { const m = linkMeta(l); return { name: m.name, link: l }; });
            if (cleans.length) groups.push({ t: 'IPهای تمیز', icon: 'zap', items: cleans });
            return subPageHTML(title, subUrl, groups);
          }
        }
        if (!links.length) return new Response('RIX: کانفیگی فعال نیست', { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
        const body = links.join('\n');
        return new Response(wantRaw ? body : b64.encode(body), {
          headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Profile-Title': safeB64(title), 'Profile-Update-Interval': '6', 'Cache-Control': 'no-store' }
        });
      }

      if (path === '/login') {
        if (method === 'GET') {
          if (await isAuthed(request, env)) return Response.redirect(url.origin + '/panel', 302);
          return loginPage();
        }
        if (method === 'POST') {
          const form = await request.formData();
          const pass = (form.get('pass') || '').toString();
          if (!pass) return loginPage('رمز خالیه');
          const cfg = await getConfig(env);
          if (!cfg.panelPass) { cfg.panelPass = pass; await saveConfig(env, cfg); await logEvent(env, 'پنل راه‌اندازی شد', ctx, 'auth'); }
          else if (cfg.panelPass !== pass) return loginPage('رمز اشتباه است!');
          await logEvent(env, 'ورود موفق به پنل', ctx, 'auth');
          const token = sha224Hex(cfg.panelPass + '::rix-session-v1');
          return new Response(null, { status: 302, headers: { 'Location': '/panel', 'Set-Cookie': 'rix_session=' + token + '; Path=/; HttpOnly; Secure; Max-Age=604800; SameSite=Lax' } });
        }
      }

      if (path === '/panel') {
        if (!(await isAuthed(request, env))) return Response.redirect(url.origin + '/login', 302);
        return panelPage(request, env);
      }

      if (path === '/') return Response.redirect(url.origin + '/login', 302);
      return new Response('404', { status: 404 });

    } catch (err) {
      return new Response('RIX Error: ' + (err && err.message ? err.message : 'unknown'), { status: 500 });
    }
  }
};