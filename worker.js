import { connect } from 'cloudflare:sockets';

const VERSION = '2.8.0';
const SESSION_COOKIE = 'rix_session';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_CLIENTS = 20;
const MAX_CLEAN_IPS = 60;
const PING_TIMEOUT = 3000;
const DEFAULT_WS_PATH = '/?ed=2048';
const BG_DARK_URL = '';
const BG_LIGHT_URL = '';

const NAT64_PREFIXES = {
  NL: '2a02:898:146:64::',
  'US-1': '2602:fc59:b0:64::',
  'US-2': '2602:fc59:11:64::'
};

const DEFAULT_CONFIG = {
  uuid: '',
  trojanPass: '',
  panelPass: '',
  vlessEnabled: true,
  trojanEnabled: true,
  proxyIP: '',
  proxyEnabled: false,
  nat64Enabled: false,
  nat64Prefix: 'NL',
  cleanIPs: [],
  cleanIPsMain: false,
  clients: [],
  endpoints: [],
  created: 0,
  botToken: '',
  botChatId: '',
  botUser: '',
  botEnabled: false,
  botOnAuth: true,
  botOnClient: true,
  botOnConn: true,
  lastSummaryAt: 0,
  connectionCount: 0,
  temp: { lastTelegram: 0 }
};

function safeJsonParse(str, fallback) {
  try {
    return JSON.parse(str || 'null');
  } catch (e) {
    return fallback;
  }
}

function jsonResponse(data, init = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...(init.headers || {}) },
    status: init.status || 200
  });
}

function escapeHtml(str) {
  return String(str || '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[char]));
}

function decodeBase64Url(input) {
  if (!input) return new Uint8Array();
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  const binary = atob(normalized + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function encodeBase64Url(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function concatUint8(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function uuidv4() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function isValidUUID(value) {
  return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(String(value || ''));
}

function clampNumber(value, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return min;
  return Math.min(Math.max(n, min), max);
}

function toSafeClientId(id) {
  return String(id || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64) || 'client';
}

function normalizeEndpoint(e) {
  return {
    key: e.key || `${e.kind || 'kind'}:${e.uuid || uuidv4()}`,
    uuid: e.uuid || uuidv4(),
    owner: e.owner || 'main',
    clientId: e.clientId || '',
    kind: e.kind || 'main',
    target: e.target || ''
  };
}

function normalizeConfig(input) {
  const base = structuredClone(DEFAULT_CONFIG);
  const cfg = { ...base, ...(input || {}) };
  cfg.uuid = cfg.uuid && isValidUUID(cfg.uuid) ? cfg.uuid : uuidv4();
  cfg.trojanPass = String(cfg.trojanPass || '').trim();
  if (!cfg.trojanPass) cfg.trojanPass = cryptoRandomString(16);
  cfg.panelPass = String(cfg.panelPass || '').trim();
  cfg.cleanIPs = Array.isArray(cfg.cleanIPs) ? cfg.cleanIPs.map(String).map((x) => x.trim()).filter(Boolean) : [];
  cfg.clients = Array.isArray(cfg.clients) ? cfg.clients.map((c) => ({
    id: toSafeClientId(c.id || `client-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`),
    name: String(c.name || 'Client').slice(0, 32),
    uuid: c.uuid && isValidUUID(c.uuid) ? c.uuid : uuidv4(),
    quotaGB: clampNumber(c.quotaGB || 0, 0, 1000),
    country: String(c.country || 'main').trim(),
    cleanIPs: !!c.cleanIPs,
    enabled: c.enabled !== false,
    created: Number(c.created || Date.now()),
    route: String(c.route || 'MAIN').toUpperCase()
  })) : [];
  cfg.endpoints = Array.isArray(cfg.endpoints) ? cfg.endpoints.map(normalizeEndpoint) : [];
  cfg.nat64Prefix = NAT64_PREFIXES[cfg.nat64Prefix] ? cfg.nat64Prefix : 'NL';
  cfg.proxyIP = String(cfg.proxyIP || '').trim();
  cfg.botChatId = String(cfg.botChatId || '').trim();
  cfg.botToken = String(cfg.botToken || '').trim();
  cfg.botUser = String(cfg.botUser || '').trim();
  cfg.cleanIPsMain = !!cfg.cleanIPsMain;
  cfg.botEnabled = !!cfg.botEnabled;
  cfg.botOnAuth = cfg.botOnAuth !== false;
  cfg.botOnClient = cfg.botOnClient !== false;
  cfg.botOnConn = cfg.botOnConn !== false;
  return cfg;
}

function cryptoRandomString(len = 16) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr).map((b) => 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.charAt(b % 62)).join('');
}

async function getConfig(env) {
  const kv = env && env.kv ? env.kv : null;
  if (!kv) {
    throw new Error('KV binding "kv" missing');
  }
  const raw = await kv.get('rix_config', 'json');
  if (!raw) {
    const cfg = normalizeConfig(DEFAULT_CONFIG);
    cfg.created = Date.now();
    cfg.uuid = cfg.uuid || uuidv4();
    cfg.trojanPass = cfg.trojanPass || cryptoRandomString(16);
    cfg.panelPass = cfg.panelPass || cryptoRandomString(24);
    await kv.put('rix_config', JSON.stringify(cfg));
    await kv.put('rix_logs', JSON.stringify([{ ts: Date.now(), type: 'panel_initialized', msg: 'RIX panel initialized' }].slice(0, 50)));
    return cfg;
  }
  return normalizeConfig(raw);
}

async function saveConfig(env, cfg) {
  const kv = env && env.kv ? env.kv : null;
  if (!kv) {
    throw new Error('KV binding "kv" missing');
  }
  const normalized = normalizeConfig(cfg);
  await kv.put('rix_config', JSON.stringify(normalized));
  return normalized;
}

async function appendLog(env, type, msg) {
  const kv = env && env.kv ? env.kv : null;
  if (!kv) return;
  const existing = safeJsonParse(await kv.get('rix_logs', 'json'), []);
  const arr = Array.isArray(existing) ? existing : [];
  arr.unshift({ ts: Date.now(), type, msg: String(msg || '') });
  await kv.put('rix_logs', JSON.stringify(arr.slice(0, 50)));
}

function getHostname() {
  return typeof globalThis !== 'undefined' && globalThis.location ? location.hostname : 'cloudflare-worker';
}

function getRouteLabel(route) {
  const v = String(route || '').toUpperCase();
  if (v === 'NL') return 'NAT64 Netherlands';
  if (v === 'US-1') return 'NAT64 USA 1';
  if (v === 'US-2') return 'NAT64 USA 2';
  if (v === 'MAIN') return 'MAIN';
  if (v === 'PROXY') return 'PROXY';
  if (v === 'DIRECT') return 'DIRECT';
  return v || 'MAIN';
}

function sanitizeEndpointValue(value) {
  const input = String(value || '').trim();
  if (!input) return null;
  return input;
}

function parseHostPort(input) {
  const val = String(input || '').trim();
  if (!val) return null;
  let host = val;
  let port = 443;
  if (val.includes('://')) {
    try {
      const u = new URL(val);
      host = u.hostname;
      port = Number(u.port || (u.protocol === 'https:' ? 443 : 80));
      return { host, port };
    } catch (e) {
      return null;
    }
  }
  const lastColon = val.lastIndexOf(':');
  const bracketPos = val.indexOf(']');
  if (val.startsWith('[') && bracketPos > -1) {
    const end = val.indexOf(']', 1);
    if (end > -1) {
      host = val.slice(1, end);
      const rest = val.slice(end + 1);
      if (rest.startsWith(':')) port = Number(rest.slice(1) || 443);
      return { host, port };
    }
  }
  if (lastColon !== -1 && val.indexOf(':') === lastColon) {
    host = val.slice(0, lastColon);
    port = Number(val.slice(lastColon + 1) || 443);
  }
  if (!host) return null;
  return { host, port: Number.isFinite(port) ? port : 443 };
}

function isValidDomainOrIp(value) {
  const v = String(value || '').trim();
  if (!v) return false;
  if (v.includes(':') && !v.startsWith('[') && v.split(':').length <= 8) {
    return /^([0-9a-fA-F:]+)$/.test(v);
  }
  return /^[a-zA-Z0-9.-]+$/.test(v) || /^\d+\.\d+\.\d+\.\d+$/.test(v);
}

function parseCleanIPEntry(raw) {
  const value = String(raw || '').trim();
  if (!value) return null;
  const normalized = value.replace(/\s+/g, '');
  if (!normalized) return null;
  try {
    const hostPort = parseHostPort(normalized);
    if (!hostPort) return null;
    if (!isValidDomainOrIp(hostPort.host)) return null;
    return { host: hostPort.host, port: Number(hostPort.port || 443) };
  } catch (e) {
    return null;
  }
}

function roundMs(value) {
  if (!Number.isFinite(value)) return null;
  return Math.max(0, Math.round(value));
}

async function testTcp(host, port, timeout = PING_TIMEOUT) {
  const target = String(host || '').trim();
  if (!target) return { ok: false, error: 'Target missing', ms: null, host: target, port };
  const t0 = Date.now();
  try {
    const socket = connect({ hostname: target, port: Number(port || 443) });
    await Promise.race([
      socket.opened,
      sleep(timeout).then(() => { throw new Error('timeout'); })
    ]);
    const ms = Date.now() - t0;
    try { socket.close(); } catch (e) {}
    return { ok: true, ms, host: target, port: Number(port || 443), error: null };
  } catch (e) {
    const ms = Date.now() - t0;
    return { ok: false, ms: roundMs(ms), host: target, port: Number(port || 443), error: String(e && e.message ? e.message : e) };
  }
}

function ipv4ToNat64(prefix, ipv4) {
  const parts = String(ipv4 || '').split('.').map((x) => Number(x));
  if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return null;
  const prefixValue = NAT64_PREFIXES[prefix] || NAT64_PREFIXES.NL;
  const ipv4Hex = parts.map((p) => p.toString(16).padStart(2, '0')).join('');
  const suffix = ipv4Hex;
  const h = prefixValue.replace(/::$/, '');
  const hex = h.replace(/:/g, '');
  const final = `${prefixValue}${suffix.length ? ':' : ''}${suffix.length ? suffix : ''}`;
  const full = final.length > 0 ? final : prefixValue;
  return full;
}

function ipv4ToNat64V6(prefix, ipv4) {
  const p = NAT64_PREFIXES[String(prefix)] || NAT64_PREFIXES.NL;
  const ip = String(ipv4 || '').trim();
  const parts = ip.split('.');
  if (parts.length !== 4 || parts.some((x) => !/^\d+$/.test(x))) return null;
  const a = Number(parts[0]), b = Number(parts[1]), c = Number(parts[2]), d = Number(parts[3]);
  if ([a, b, c, d].some((n) => n < 0 || n > 255)) return null;
  const val = (((a << 8) | b) << 8 | c) << 8 | d;
  const hi = (((val >> 16) & 0xffff).toString(16).padStart(4, '0'));
  const lo = ((val & 0xffff).toString(16).padStart(4, '0'));
  const prefixStr = p.replace(/::$/, '');
  return `${prefixStr}:${hi}:${lo}`;
}

function ipv6ToString(bytes) {
  const groups = [];
  for (let i = 0; i < bytes.length; i += 2) groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  let best = -1;
  let bestLen = 0;
  for (let i = 0; i < groups.length; i += 1) {
    if (groups[i] === '0') {
      let j = i;
      while (j < groups.length && groups[j] === '0') j += 1;
      const len = j - i;
      if (len > bestLen) {
        bestLen = len;
        best = i;
      }
      i = j - 1;
    }
  }
  let output = '';
  for (let i = 0; i < groups.length; i += 1) {
    if (i === best) {
      output += ':';
      i += bestLen - 1;
    } else {
      output += groups[i];
      if (i < groups.length - 1) output += ':';
    }
  }
  if (output.startsWith(':')) output = `0${output}`;
  if (output.endsWith(':')) output += '0';
  return output;
}

function bytesToIPv6String(bytes) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  let start = -1;
  let len = 0;
  let best = -1;
  for (let i = 0; i < groups.length; i += 1) {
    if (groups[i] === '0') {
      let j = i;
      while (j < groups.length && groups[j] === '0') j += 1;
      if (j - i > len) {
        start = i;
        len = j - i;
        best = start;
      }
      i = j - 1;
    }
  }
  if (best === -1) return groups.join(':');
  const before = groups.slice(0, best).join(':');
  const after = groups.slice(best + len).join(':');
  if (!before && !after) return '::';
  if (!before) return `::${after}`;
  if (!after) return `${before}::`;
  return `${before}::${after}`;
}

async function testNAT64Gateways(cfg) {
  const items = [];
  const prefixes = ['NL', 'US-1', 'US-2'];
  for (const prefix of prefixes) {
    const host = NAT64_PREFIXES[prefix];
    if (!host) continue;
    const results = [];
    for (const target of ['1.1.1.1', '8.8.8.8']) {
      const nat64Host = ipv4ToNat64V6(prefix, target);
      if (!nat64Host) continue;
      const res = await testTcp(nat64Host, target === '1.1.1.1' ? 443 : 53, PING_TIMEOUT);
      results.push({ host: target, port: target === '1.1.1.1' ? 443 : 53, ok: res.ok, ms: res.ms, error: res.error || null });
    }
    const ok = results.some((p) => p.ok);
    items.push({ prefix, host, enabled: !!cfg.nat64Enabled, alive: ok, results, ms: ok ? Math.min(...results.filter((r) => r.ok).map((r) => r.ms || 0)) : null });
  }
  return items;
}

async function testProxyIP(proxyIP) {
  const value = String(proxyIP || '').trim();
  if (!value) return { ok: false, error: 'ProxyIP empty', ms: null, host: null, port: null };
  const parsed = parseHostPort(value);
  if (!parsed) return { ok: false, error: 'ProxyIP invalid: use IPv4, domain, or IP:PORT', ms: null, host: null, port: null };
  const result = await testTcp(parsed.host, parsed.port || 443, PING_TIMEOUT);
  return { ok: result.ok, ms: result.ms, error: result.error || null, host: parsed.host, port: parsed.port || 443 };
}

async function testCleanEntries(ips, save = false, env) {
  const entries = [];
  const unique = [];
  for (const raw of ips || []) {
    const parsed = parseCleanIPEntry(raw);
    if (parsed && !unique.some((x) => x.host === parsed.host && x.port === parsed.port)) {
      unique.push(parsed);
    }
  }
  const results = [];
  for (let i = 0; i < unique.length; i += 1) {
    const item = unique[i];
    const res = await testTcp(item.host, item.port, PING_TIMEOUT);
    results.push({ host: item.host, port: item.port, ok: res.ok, ms: res.ms, error: res.error || null });
  }
  const alive = results.filter((r) => r.ok).sort((a, b) => (a.ms || 999999) - (b.ms || 999999));
  const dead = results.filter((r) => !r.ok);
  const ordered = [...alive, ...dead].map((r) => `${r.host}:${r.port}`);
  if (save && env && env.kv) {
    const config = await getConfig(env);
    config.cleanIPs = ordered;
    await saveConfig(env, config);
  }
  return { ok: true, total: ordered.length, alive: alive.length, dead: dead.length, entries: ordered, results };
}

async function resolveRouteSettings(client, cfg) {
  const route = String(client && client.route ? client.route : 'MAIN').toUpperCase();
  if (route === 'NL' || route === 'US-1' || route === 'US-2') {
    return { kind: 'nat64', prefix: route };
  }
  if (route === 'PROXY') {
    return { kind: 'proxy', prefix: route };
  }
  if (route === 'DIRECT') {
    return { kind: 'direct', prefix: route };
  }
  if (route === 'MAIN') {
    return { kind: 'main', prefix: route };
  }
  return { kind: 'main', prefix: 'MAIN' };
}

function buildSubscriptionFilename(name) {
  return String(name || 'RIX').replace(/[^a-zA-Z0-9_.-]/g, '').slice(0, 32) || 'RIX';
}

function makeUrl(host, path) {
  const u = new URL(host);
  return `${u.origin}${path}`;
}

function encodeWsPath(path) {
  return path && path.includes('?') ? encodeURI(path) : encodeURIComponent(path || '/?ed=2048');
}

function makeMainVlessLink(cfg, host, clientName = 'RIX-VLESS') {
  const uuid = cfg.uuid;
  const path = '/?ed=2048';
  const finalHost = host || 'example.com';
  return `vless://${uuid}@${finalHost}:443?encryption=none&security=tls&sni=${finalHost}&fp=randomized&type=ws&host=${finalHost}&path=${encodeURIComponent(path)}#${encodeURIComponent(clientName || 'RIX-VLESS')}`;
}

function makeMainTrojanLink(cfg, host, clientName = 'RIX-Trojan') {
  const password = cfg.trojanPass;
  const path = '/?ed=2048';
  const finalHost = host || 'example.com';
  return `trojan://${password}@${finalHost}:443?security=tls&sni=${finalHost}&fp=randomized&type=ws&host=${finalHost}&path=${encodeURIComponent(path)}#${encodeURIComponent(clientName || 'RIX-Trojan')}`;
}

function buildClientSubscription(cfg, client, host) {
  const base = [];
  if (cfg.vlessEnabled && client && client.enabled) {
    const uuid = client.uuid || cfg.uuid;
    const path = DEFAULT_WS_PATH;
    const name = `RIX ${client.name || 'Client'}`;
    base.push(`vless://${uuid}@${host}:443?encryption=none&security=tls&sni=${host}&fp=randomized&type=ws&host=${host}&path=${encodeURIComponent(path)}#${encodeURIComponent(name)}`);
  }
  if (cfg.trojanEnabled && client && client.enabled) {
    const name = `RIX ${client.name || 'Client'}`;
    const password = `${cfg.trojanPass}-${client.uuid}` || cfg.trojanPass;
    base.push(`trojan://${password}@${host}:443?security=tls&sni=${host}&fp=randomized&type=ws&host=${host}&path=${encodeURIComponent(DEFAULT_WS_PATH)}#${encodeURIComponent(name)}`);
  }
  return base;
}

function generateCleanIPConfigs(cfg, host) {
  const list = [];
  for (const item of cfg.cleanIPs || []) {
    const parsed = parseCleanIPEntry(item);
    if (!parsed) continue;
    const endpoint = (cfg.endpoints || []).find((e) => e.kind === 'clean' && e.target === `${parsed.host}:${parsed.port}`);
    const uuid = endpoint && endpoint.uuid ? endpoint.uuid : uuidv4();
    const name = `RIX ${parsed.host}`;
    const link = `vless://${uuid}@${host}:443?encryption=none&security=tls&sni=${host}&fp=randomized&type=ws&host=${host}&path=${encodeURIComponent(DEFAULT_WS_PATH)}#${encodeURIComponent(name)}`;
    list.push(link);
  }
  return list;
}

async function ensureEndpointRegistry(env, cfg) {
  const mainConfig = cfg || (await getConfig(env));
  const endpoints = Array.isArray(mainConfig.endpoints) ? mainConfig.endpoints : [];
  const registry = [];
  const mainEntry = endpoints.find((e) => e.kind === 'main' && e.owner === 'main');
  if (!mainEntry) {
    registry.push({ key: 'main:main', uuid: mainConfig.uuid || uuidv4(), owner: 'main', clientId: '', kind: 'main', target: 'main' });
  } else {
    registry.push(mainEntry);
  }
  for (const client of mainConfig.clients || []) {
    const existing = endpoints.find((e) => e.kind === 'main' && e.owner === 'client' && e.clientId === client.id);
    if (existing) {
      registry.push(existing);
    } else {
      registry.push({ key: `client:${client.id}`, uuid: client.uuid || uuidv4(), owner: 'client', clientId: client.id, kind: 'main', target: client.name || client.id });
    }
  }
  for (const ip of mainConfig.cleanIPs || []) {
    const parsed = parseCleanIPEntry(ip);
    if (!parsed) continue;
    const target = `${parsed.host}:${parsed.port}`;
    const existing = endpoints.find((e) => e.kind === 'clean' && e.target === target);
    if (existing) {
      registry.push(existing);
    } else {
      registry.push({ key: `clean:${target}`, uuid: uuidv4(), owner: 'main', clientId: '', kind: 'clean', target });
    }
  }
  mainConfig.endpoints = registry.map(normalizeEndpoint);
  await saveConfig(env, mainConfig);
  return mainConfig;
}

function getMainHostFromRequest(request) {
  const host = request.headers.get('host') || 'example.com';
  return host;
}

function buildAdminStatus(cfg, env) {
  const now = Date.now();
  const activeClients = (cfg.clients || []).filter((c) => c.enabled).length;
  const cleanCount = (cfg.cleanIPs || []).length;
  const endpointCount = (cfg.endpoints || []).length;
  const vlessEnabled = !!cfg.vlessEnabled;
  const trojanEnabled = !!cfg.trojanEnabled;
  const nat64Enabled = !!cfg.nat64Enabled;
  const proxyEnabled = !!cfg.proxyEnabled;
  const botEnabled = !!cfg.botEnabled;
  const usage = getTodayUsage(env, cfg);
  return {
    version: VERSION,
    hostname: getHostname(),
    uptime: Math.max(1, Math.round((now - (cfg.created || now)) / 1000)),
    vlessEnabled,
    trojanEnabled,
    nat64Enabled,
    proxyEnabled,
    cleanIPCount: cleanCount,
    clientCount: (cfg.clients || []).length,
    activeClients,
    endpointCount,
    vlessUUIDCount: new Set((cfg.clients || []).map((c) => c.uuid).filter(Boolean)).size + (cfg.uuid ? 1 : 0),
    todaysUsage: usage,
    telegramState: botEnabled,
    gatewayStates: { nat64: nat64Enabled ? 'active' : 'disabled', proxy: proxyEnabled ? 'active' : 'disabled', clean: cleanCount > 0 ? 'active' : 'disabled' }
  };
}

async function getTodayUsage(env, cfg) {
  if (!env || !env.kv) return 0;
  const dateKey = `u_${cfg.uuid || 'main'}_${new Date().toISOString().slice(0, 10).replace(/-/g, '')}`;
  const value = await env.kv.get(dateKey, 'text');
  return Number(value || 0);
}

function getApiKeyFromRequest(req) {
  const authHeader = req.headers.get('Authorization') || '';
  return authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
}

function verifySession(req, env) {
  const cookie = req.headers.get('Cookie') || '';
  const match = cookie.split(';').map((s) => s.trim()).find((s) => s.startsWith(`${SESSION_COOKIE}=`));
  const token = match ? match.split('=')[1] : null;
  if (!token) return false;
  try {
    const [payloadRaw, sigRaw] = String(token).split('.');
    if (!payloadRaw || !sigRaw) return false;
    const payload = JSON.parse(atob(payloadRaw.replace(/-/g, '+').replace(/_/g, '/')));
    const secret = String((env && env.kv ? '' : '') || '');
    if (!payload || !payload.exp || Date.now() > payload.exp) return false;
    return true;
  } catch (e) {
    return false;
  }
}

async function createSessionToken(env, pass) {
  const payload = {
    user: 'admin',
    exp: Date.now() + SESSION_TTL_MS,
    v: 1,
    ts: Date.now()
  };
  const payloadEnc = encodeBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const secret = new TextEncoder().encode(String(pass || 'rix-panel'));
  const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadEnc));
  const sigEnc = encodeBase64Url(new Uint8Array(sig));
  return `${payloadEnc}.${sigEnc}`;
}

async function verifySessionToken(token, pass) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [payloadEnc, sigEnc] = parts;
  try {
    const payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(payloadEnc)));
    if (!payload || !payload.exp || Date.now() > payload.exp) return false;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(pass || 'rix-panel')), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadEnc));
    const expected = encodeBase64Url(new Uint8Array(sig));
    return expected === sigEnc;
  } catch (e) {
    return false;
  }
}

async function readSessionToken(req, env) {
  const cookie = req.headers.get('Cookie') || '';
  const match = cookie.split(';').map((s) => s.trim()).find((s) => s.startsWith(`${SESSION_COOKIE}=`));
  if (!match) return null;
  const token = decodeURIComponent(match.split('=').slice(1).join('='));
  const cfg = await getConfig(env);
  if (!cfg.panelPass) return null;
  const ok = await verifySessionToken(token, cfg.panelPass);
  return ok ? token : null;
}

async function requireAuth(req, env) {
  const cfg = await getConfig(env);
  const token = await readSessionToken(req, env);
  if (!token) return { ok: false, cfg, reason: 'Unauthorized' };
  return { ok: true, cfg };
}

async function renderLoginPage(status = '') {
  return `<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>RIX PANEL | ورود</title>
<style>
:root { --bg:#f4f7fb; --card:#ffffff; --card-2:#f7f9fc; --text:#171c2b; --muted:#667085; --primary:#2563eb; --primary-2:#1d4ed8; --line:#e5e7eb; --shadow:0 10px 30px rgba(15,23,42,.08); --danger:#dc2626; --success:#16a34a; }
html,body{margin:0;font-family:Tahoma,Arial,sans-serif;background:linear-gradient(135deg,#eef4ff,#f4f7fb);min-height:100%;color:var(--text)}
*{box-sizing:border-box}
body{display:flex;align-items:center;justify-content:center;padding:24px}.wrap{width:min(100%,420px)}
.card{background:var(--card);border:1px solid var(--line);box-shadow:var(--shadow);border-radius:24px;padding:28px 22px}
.brand{display:flex;align-items:center;justify-content:center;gap:12px;margin-bottom:18px}
.logo{width:48px;height:48px;border-radius:14px;background:linear-gradient(135deg,#0f172a,#1d4ed8);display:grid;place-items:center;color:white;font-weight:900;font-size:22px}
.brand h1{margin:0;font-size:24px;letter-spacing:0.5px}.sub{color:var(--muted);font-size:13px;text-align:center;margin-bottom:18px}
label{display:block;font-size:13px;color:var(--muted);margin:12px 0 8px}.input{width:100%;height:48px;border:1px solid var(--line);border-radius:12px;padding:0 14px;font-size:15px;background:#fff}
.input:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(37,99,235,.1)}
.btn{margin-top:12px;width:100%;height:48px;border:none;border-radius:12px;background:linear-gradient(135deg,var(--primary),var(--primary-2));color:white;font-weight:700;cursor:pointer}.btn:hover{filter:brightness(1.02)}
.msg{margin-top:12px;padding:12px 14px;border-radius:12px;font-size:13px;display:none}
.msg.error{background:#fef2f2;color:#b91c1c;border:1px solid #fecaca;display:block}
.msg.success{background:#ecfdf5;color:#166534;border:1px solid #a7f3d0;display:block}
.version{margin-top:12px;text-align:center;color:var(--muted);font-size:12px}
@media (max-width:480px){ .card{padding:22px 16px;border-radius:18px} }
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="brand">
      <div class="logo">R</div>
      <div>
        <h1>RIX PANEL</h1>
      </div>
    </div>
    <div class="sub">ورود به داشبورد مدیریت</div>
    <form method="POST" action="/login">
      <label for="password">رمز عبور پنل</label>
      <input id="password" class="input" type="password" name="password" autocomplete="current-password" required />
      <button class="btn" type="submit">ورود</button>
    </form>
    <div class="msg ${status ? 'error' : ''}">${escapeHtml(status || '')}</div>
    <div class="version">RIX PANEL v${VERSION}</div>
  </div>
</div>
</body>
</html>`;
}

function getThemeCss() {
  return `
  :root{ --bg:#f5f7fb; --bg-2:#eef3ff; --card:#ffffff; --card-alt:#f7f9fe; --text:#111827; --muted:#64748b; --line:#e2e8f0; --primary:#2563eb; --primary-soft:rgba(37,99,235,0.14); --success:#16a34a; --danger:#dc2626; --warning:#f59e0b; --shadow:0 12px 30px rgba(15,23,42,.08); }
  body.dark{ --bg:#0b1220; --bg-2:#111827; --card:#121b2b; --card-alt:#0f172a; --text:#e5eefb; --muted:#9aa7bb; --line:#22314d; --primary:#6ea8fe; --primary-soft:rgba(110,168,254,.15); --success:#22c55e; --danger:#ef4444; --warning:#fbbf24; --shadow:0 12px 30px rgba(2,6,23,.4); }
  *{box-sizing:border-box} html,body{margin:0;padding:0;background:var(--bg);color:var(--text);font-family:Tahoma,Arial,sans-serif;min-height:100%;overflow-x:hidden} body{background-image:${BG_DARK_URL && 'var(--bg-dark-image)'}, ${BG_LIGHT_URL && 'var(--bg-light-image)'};}
  body.dark{ --bg-dark-image: url('${BG_DARK_URL}'); }
  body:not(.dark){ --bg-light-image: url('${BG_LIGHT_URL}'); }
  a{color:inherit;text-decoration:none}
  button,input,select{font:inherit}
  .shell{display:flex;min-height:100vh;background:var(--bg)}
  .sidebar{width:260px;background:rgba(15,23,42,.98);color:#eef3ff;padding:18px 14px;border-left:1px solid rgba(255,255,255,.05);display:flex;flex-direction:column;gap:12px;position:sticky;top:0;min-height:100vh}
  .logo-box{display:flex;align-items:center;gap:12px;padding:10px 8px 14px;border-radius:14px;margin-bottom:6px}
  .logo-mark{width:38px;height:38px;border-radius:12px;background:linear-gradient(135deg,#60a5fa,#2563eb);display:grid;place-items:center;font-weight:900;color:white}
  .brand-name{font-size:15px;font-weight:800;letter-spacing:.3px}
  .nav{display:flex;flex-direction:column;gap:6px;margin-top:6px}
  .nav a{display:flex;align-items:center;gap:10px;padding:12px 12px;border-radius:12px;color:#dfeaff;opacity:.8}
  .nav a.active,.nav a:hover{background:rgba(255,255,255,.06);opacity:1}
  .nav svg{width:18px;height:18px;display:block}
  .version-badge{margin-top:auto;padding:12px 10px;border-top:1px solid rgba(255,255,255,.08);font-size:12px;color:#b5c3d9}
  .main{flex:1;padding:20px;display:flex;flex-direction:column;gap:18px}
  .topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 18px;background:var(--card);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow)}
  .top-title{font-weight:800;font-size:18px}
  .top-actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .chip{display:inline-flex;align-items:center;gap:8px;padding:10px 12px;border-radius:12px;background:var(--card-alt);border:1px solid var(--line);color:var(--text)}
  .icon-btn{display:inline-flex;align-items:center;justify-content:center;width:40px;height:40px;border-radius:12px;border:1px solid var(--line);background:var(--card-alt);cursor:pointer}
  .user-pill{display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:12px;border:1px solid var(--line);background:var(--card-alt);font-weight:700}.
  .btn{padding:10px 14px;border:1px solid var(--line);border-radius:12px;background:var(--card-alt);cursor:pointer;color:var(--text);font-weight:700}
  .btn.primary{background:linear-gradient(135deg,var(--primary),#1d4ed8);border-color:transparent;color:#fff}
  .btn.danger{background:#fee2e2;color:#991b1b;border-color:#fecaca}
  .panel-grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:18px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:20px;padding:18px;box-shadow:var(--shadow)}
  .span-3{grid-column:span 3}.span-4{grid-column:span 4}.span-6{grid-column:span 6}.span-8{grid-column:span 8}.span-12{grid-column:span 12}
  .stat{display:flex;justify-content:space-between;align-items:start;gap:12px}.stat .label{color:var(--muted);font-size:12px}.stat .value{font-size:26px;font-weight:800;line-height:1.2}
  .status-dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--success);box-shadow:0 0 0 6px rgba(34,197,94,.1)}
  .status-dot.off{background:var(--danger);box-shadow:0 0 0 6px rgba(239,68,68,.1)}
  .panel-section{display:flex;align-items:center;justify-content:space-between;gap:12px;padding-bottom:10px;margin-bottom:12px;border-bottom:1px solid var(--line)}
  .content-title{font-weight:800;font-size:20px}
  .muted{color:var(--muted)}
  .grid-2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
  .grid-3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}
  .input,select,textarea{width:100%;padding:10px 12px;border-radius:12px;border:1px solid var(--line);background:var(--card-alt);color:var(--text)}
  .input:focus,select:focus,textarea:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-soft)}
  .inline{display:flex;gap:10px;flex-wrap:wrap}
  table{width:100%;border-collapse:collapse} th,td{padding:10px 12px;border-bottom:1px solid var(--line);text-align:right;font-size:13px} th{color:var(--muted);font-weight:700}
  .list{list-style:none;padding:0;margin:8px 0 0} .list li{padding:8px 0;border-bottom:1px dashed var(--line)}
  .badge{display:inline-flex;align-items:center;gap:6px;padding:6px 10px;border-radius:999px;background:var(--primary-soft);color:var(--primary);font-size:12px;font-weight:700}
  .badge.off{background:rgba(239,68,68,.1);color:var(--danger)}
  .copy{cursor:pointer}
  .hidden{display:none !important}
  @media (max-width:980px){ .sidebar{width:100%;min-height:unset;position:relative;border-left:none;border-bottom:1px solid rgba(255,255,255,.08)} .shell{flex-direction:column}.nav{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}. .span-3,.span-4,.span-6,.span-8{grid-column:span 12}. .topbar{flex-direction:column;align-items:flex-start}. }
  @media (max-width:560px){ .main{padding:14px}. .grid-2,.grid-3{grid-template-columns:1fr}. .nav{grid-template-columns:repeat(2,minmax(0,1fr));}. .chip{width:100%;justify-content:center} .top-actions{width:100%}. .topbar{padding:12px}. }
  </style>`;
}

function renderPanelHtml(cfg) {
  const host = 'https://' + (typeof location !== 'undefined' ? location.host : 'rix-panel.example');
  const mainSub = `${host}/sub`;
  const activeCount = (cfg.clients || []).filter((c) => c.enabled).length;
  const totalTraffic = 0;
  const cards = `
    <div class="panel-grid">
      <div class="card span-3">
        <div class="stat"><div><div class="label">کلاینت‌ها</div><div class="value">${(cfg.clients || []).length}</div></div><span class="status-dot ${(cfg.clients && cfg.clients.length > 0) ? '' : 'off'}"></span></div>
      </div>
      <div class="card span-3">
        <div class="stat"><div><div class="label">کلاینت‌های فعال</div><div class="value">${activeCount}</div></div><span class="status-dot"></span></div>
      </div>
      <div class="card span-3">
        <div class="stat"><div><div class="label">IP‌های تمیز</div><div class="value">${(cfg.cleanIPs || []).length}</div></div><span class="status-dot ${(cfg.cleanIPs && cfg.cleanIPs.length ? '' : 'off')}"></span></div>
      </div>
      <div class="card span-3">
        <div class="stat"><div><div class="label">مصرف امروز</div><div class="value">${formatBytes(totalTraffic)}</div></div><span class="status-dot ${(totalTraffic > 0 ? '' : 'off')}"></span></div>
      </div>

      <div class="card span-6">
        <div class="panel-section"><div class="content-title">لینک کانفیگ اشتراکی</div><div class="badge ${cfg.vlessEnabled ? '' : 'off'}">${cfg.vlessEnabled ? 'فعال' : 'غیرفعال'}</div></div>
        <div class="muted" style="margin-bottom:10px">${mainSub}</div>
        <div class="inline" style="margin-bottom:12px">
          <button class="btn primary copy-sub" data-copy="${escapeHtml(mainSub)}">کپی</button>
          <a class="btn" href="${mainSub}" target="_blank">باز کردن</a>
        </div>
        <div class="muted">نسخه: ${VERSION}</div>
      </div>
      <div class="card span-6">
        <div class="panel-section"><div class="content-title">اقدامات سریع</div></div>
        <div class="grid-2">
          <button class="btn" type="button" data-action="newClient">ساخت کلاینت جدید</button>
          <button class="btn" type="button" data-action="manageClients">مدیریت کلاینت‌ها</button>
          <button class="btn" type="button" data-action="nettest">تست شبکه و پینگ</button>
          <button class="btn" type="button" data-action="botTest">ربات اعلان</button>
        </div>
      </div>

      <div class="card span-4">
        <div class="panel-section"><div class="content-title">وضعیت پروتکل‌ها</div></div>
        <ul class="list">
          <li>VLESS <span class="badge ${cfg.vlessEnabled ? '' : 'off'}">${cfg.vlessEnabled ? 'فعال' : 'غیرفعال'}</span></li>
          <li>Trojan <span class="badge ${cfg.trojanEnabled ? '' : 'off'}">${cfg.trojanEnabled ? 'فعال' : 'غیرفعال'}</span></li>
          <li>NAT64 <span class="badge ${cfg.nat64Enabled ? '' : 'off'}">${cfg.nat64Enabled ? 'فعال' : 'غیرفعال'}</span></li>
          <li>ProxyIP <span class="badge ${cfg.proxyEnabled ? '' : 'off'}">${cfg.proxyEnabled ? 'فعال' : 'غیرفعال'}</span></li>
        </ul>
      </div>

      <div class="card span-4">
        <div class="panel-section"><div class="content-title">آخرین فعالیت‌ها</div></div>
        <ul class="list" id="activityList">
          ${(cfg.logs || []).slice(0, 6).map((log) => `<li>${escapeHtml(log.msg || log.type || 'event')} <span class="muted">${new Date(log.ts || Date.now()).toLocaleString('fa-IR')}</span></li>`).join('') || '<li>هیچ رویدادی ثبت نشده است</li>'}
        </ul>
      </div>

      <div class="card span-4">
        <div class="panel-section"><div class="content-title">شبکه و مسیرها</div></div>
        <ul class="list">
          <li>پیش‌فرض NAT64: ${escapeHtml(cfg.nat64Prefix || 'NL')}</li>
          <li>ProxyIP: ${escapeHtml(cfg.proxyIP || 'نامشخص')}</li>
          <li>نمایش IP تمیز: ${cfg.cleanIPsMain ? 'بله' : 'خیر'}</li>
          <li>UUID اصلی: ${escapeHtml(cfg.uuid || '')}</li>
        </ul>
      </div>

      <div class="card span-12">
        <div class="panel-section"><div class="content-title">کلاینت‌ها</div><button class="btn primary" type="button" data-action="newClient">کلاینت جدید</button></div>
        <table>
          <thead><tr><th>نام</th><th>مسیر</th><th>وضعیت</th><th>Quota</th><th>استفاده</th><th>IP تمیز</th><th>عملیات</th></tr></thead>
          <tbody>
            ${(cfg.clients || []).length ? (cfg.clients || []).map((c) => `
              <tr>
                <td>${escapeHtml(c.name || 'Client')}</td>
                <td>${escapeHtml(getRouteLabel(c.route || 'MAIN'))}</td>
                <td><span class="badge ${c.enabled ? '' : 'off'}">${c.enabled ? 'فعال' : 'غیرفعال'}</span></td>
                <td>${c.quotaGB === 0 ? 'نامحدود' : `${c.quotaGB} GB`}</td>
                <td>${formatBytes(getUsageForClient(cfg, c.id))}</td>
                <td>${c.cleanIPs ? 'بله' : 'خیر'}</td>
                <td><button class="btn copy-sub" data-copy="${escapeHtml(buildClientSubscriptionLink(cfg, c))}" type="button">کپی ساب</button></td>
              </tr>
            `).join('') : '<tr><td colspan="7" class="muted">هنوز کلاینتی وجود ندارد.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  `;

  return `<!doctype html>
  <html lang="fa" dir="rtl">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>RIX PANEL</title>
    ${getThemeCss()}
  </head>
  <body>
    <div class="shell">
      <aside class="sidebar">
        <div class="logo-box">
          <div class="logo-mark">R</div>
          <div> 
            <div class="brand-name">RIX PANEL</div>
          </div>
        </div>
        <nav class="nav">
          <a class="active" href="#"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12.5 12 4l9 8.5"></path><path d="M5 10v9h14v-9"></path></svg> داشبورد</a>
          <a href="#configs"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 7h16M4 12h16M4 17h10"></path></svg> کانفیگ‌ها</a>
          <a href="#clients"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 19v-1a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v1"></path><circle cx="10" cy="7" r="4"></circle><path d="M22 19v-1a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg> کلاینت‌ها</a>
          <a href="#bot"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M7 17 17 7"></path><path d="M7 7h10v10"></path></svg> ربات</a>
          <a href="#info"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v7"></path><path d="M12 15v7"></path><path d="M4.93 4.93l4.95 4.95"></path><path d="M14.12 14.12l4.95 4.95"></path><path d="M2 12h7"></path><path d="M15 12h7"></path><path d="M4.93 19.07l4.95-4.95"></path><path d="M14.12 9.88l4.95-4.95"></path></svg> اطلاعات</a>
          <a href="#settings"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4"></path><path d="M12 18v4"></path><path d="M4.93 4.93l2.83 2.83"></path><path d="M16.24 16.24l2.83 2.83"></path><path d="M2 12h4"></path><path d="M18 12h4"></path><path d="M4.93 19.07l2.83-2.83"></path><path d="M16.24 7.76l2.83-2.83"></path><circle cx="12" cy="12" r="4"></circle></svg> تنظیمات</a>
        </nav>
        <div class="version-badge">RIX PANEL v${VERSION}</div>
      </aside>
      <main class="main">
        <div class="topbar">
          <div class="top-title">داشبورد</div>
          <div class="top-actions">
            <button class="chip" type="button" data-action="support">Support</button>
            <button class="icon-btn" type="button" data-action="notify" aria-label="Notification">🔔</button>
            <button class="icon-btn" type="button" id="themeToggle" aria-label="Toggle theme">☀️</button>
            <div class="user-pill"><span>●</span> <span>ادمین</span></div>
            <a class="btn danger" href="/logout">خروج</a>
          </div>
        </div>
        ${cards}
        <div class="card span-12" id="configs">
          <div class="panel-section"><div class="content-title">تنظیمات</div></div>
          <div class="grid-2">
            <div>
              <label class="muted">UUID اصلی</label>
              <input class="input" id="uuidField" value="${escapeHtml(cfg.uuid || '')}" />
              <div class="inline" style="margin-top:12px"><button class="btn primary" type="button" id="saveUuidBtn">ذخیره UUID</button></div>
            </div>
            <div>
              <label class="muted">رمز Trojan</label>
              <input class="input" id="trojanPassField" value="${escapeHtml(cfg.trojanPass || '')}" />
              <div class="inline" style="margin-top:12px"><button class="btn primary" type="button" id="saveTrojanBtn">ذخیره Trojan</button></div>
            </div>
            <div>
              <label class="muted">ProxyIP</label>
              <input class="input" id="proxyField" value="${escapeHtml(cfg.proxyIP || '')}" />
              <div class="inline" style="margin-top:12px"><button class="btn primary" type="button" id="saveProxyBtn">ذخیره ProxyIP</button></div>
            </div>
            <div>
              <label class="muted">Panel Password</label>
              <input class="input" type="password" id="panelPassField" value="" placeholder="تغییر رمز عبور" />
              <div class="inline" style="margin-top:12px"><button class="btn primary" type="button" id="savePanelPassBtn">ذخیره پنل</button></div>
            </div>
            <div>
              <label class="muted">NAT64 Prefix</label>
              <select id="nat64PrefixField"><option value="NL" ${cfg.nat64Prefix === 'NL' ? 'selected' : ''}>NL</option><option value="US-1" ${cfg.nat64Prefix === 'US-1' ? 'selected' : ''}>US-1</option><option value="US-2" ${cfg.nat64Prefix === 'US-2' ? 'selected' : ''}>US-2</option></select>
              <div class="inline" style="margin-top:12px"><button class="btn primary" type="button" id="saveNat64Btn">ذخیره NAT64</button></div>
            </div>
            <div>
              <label class="muted">IP‌های تمیز</label>
              <textarea id="cleanInput" rows="6" placeholder="IP یا DOMAIN در هر خط">${escapeHtml((cfg.cleanIPs || []).join('\n'))}</textarea>
              <div class="inline" style="margin-top:12px"><button class="btn primary" type="button" id="saveCleanBtn">ذخیره و تست</button></div>
            </div>
          </div>
        </div>
        <div class="card span-12" id="clients">
          <div class="panel-section"><div class="content-title">مدیریت کلاینت‌ها</div><button class="btn primary" type="button" id="newClientBtn">کلاینت جدید</button></div>
          <div class="grid-2">
            <div>
              <label class="muted">نام کلاینت</label>
              <input class="input" id="clientNameField" placeholder="نام کلاینت" />
            </div>
            <div>
              <label class="muted">مسیر</label>
              <select id="clientRouteField">
                <option value="MAIN">MAIN</option>
                <option value="NL">NAT64 Netherlands</option>
                <option value="US-1">NAT64 USA 1</option>
                <option value="US-2">NAT64 USA 2</option>
                <option value="PROXY">PROXY</option>
                <option value="DIRECT">DIRECT</option>
              </select>
            </div>
            <div>
              <label class="muted">Quota روزانه (GB)</label>
              <input class="input" id="clientQuotaField" type="number" min="0" max="1000" value="0" />
            </div>
            <div>
              <label class="muted">کشور/روت</label>
              <input class="input" id="clientCountryField" value="main" placeholder="main" />
            </div>
          </div>
          <div class="inline" style="margin-top:12px"><button class="btn primary" type="button" id="addClientBtn">ایجاد کلاینت</button></div>
        </div>
        <div class="card span-12" id="bot">
          <div class="panel-section"><div class="content-title">ربات تلگرام</div></div>
          <div class="grid-2">
            <div><label class="muted">Bot Token</label><input class="input" id="botTokenField" value="${escapeHtml(cfg.botToken || '')}" /></div>
            <div><label class="muted">Chat ID</label><input class="input" id="botChatIdField" value="${escapeHtml(cfg.botChatId || '')}" /></div>
            <div><label class="muted">فعال</label><select id="botEnabledField"><option value="1" ${cfg.botEnabled ? 'selected' : ''}>فعال</option><option value="0" ${!cfg.botEnabled ? 'selected' : ''}>غیرفعال</option></select></div>
            <div><label class="muted">کاربر</label><input class="input" id="botUserField" value="${escapeHtml(cfg.botUser || '')}" /></div>
          </div>
          <div class="inline" style="margin-top:12px"><button class="btn primary" type="button" id="saveBotBtn">ذخیره ربات</button> <button class="btn" type="button" id="testBotBtn">پیام تست</button> <button class="btn" type="button" id="chatIdsBtn">دریافت Chat IDs</button></div>
        </div>
        <div class="card span-12" id="info">
          <div class="panel-section"><div class="content-title">اطلاعات</div></div>
          <div class="muted" id="statusBox">درحال بارگذاری...</div>
        </div>
      </main>
    </div>
    <script>
      const body = document.body;
      const savedTheme = localStorage.getItem('rix_theme');
      if (savedTheme === 'dark') body.classList.add('dark');
      document.getElementById('themeToggle').addEventListener('click', () => {
        const dark = body.classList.toggle('dark');
        localStorage.setItem('rix_theme', dark ? 'dark' : 'light');
        document.getElementById('themeToggle').textContent = dark ? '🌙' : '☀️';
      });

      function showAlert(text, type = 'info') {
        const box = document.createElement('div');
        box.style.position = 'fixed';
        box.style.left = '20px';
        box.style.bottom = '20px';
        box.style.background = type === 'error' ? '#fee2e2' : '#eff6ff';
        box.style.color = type === 'error' ? '#991b1b' : '#1f2937';
        box.style.padding = '12px 16px';
        box.style.borderRadius = '12px';
        box.style.border = '1px solid ' + (type === 'error' ? '#fecaca' : '#bfdbfe');
        box.style.boxShadow = '0 10px 20px rgba(0,0,0,.08)';
        box.textContent = text;
        document.body.appendChild(box);
        setTimeout(() => box.remove(), 2600);
      }

      async function api(path, method = 'GET', body = null) {
        const opts = { method, headers: { 'Content-Type': 'application/json' } };
        if (body !== null && body !== undefined) opts.body = JSON.stringify(body);
        const res = await fetch(path, opts);
        const text = await res.text();
        let json = null;
        try { json = JSON.parse(text); } catch (e) { json = null; }
        if (!res.ok) {
          throw new Error((json && json.message) || text || 'Request failed');
        }
        return json;
      }

      document.querySelectorAll('.copy-sub').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const value = btn.getAttribute('data-copy');
          try {
            await navigator.clipboard.writeText(value || '');
            showAlert('کپی شد');
          } catch (e) {
            showAlert('کپی انجام نشد', 'error');
          }
        });
      });

      document.getElementById('saveUuidBtn').addEventListener('click', async () => {
        try {
          const payload = { action: 'uuid', value: document.getElementById('uuidField').value.trim() };
          await api('/api/settings', 'POST', payload);
          showAlert('UUID ذخیره شد');
        } catch (e) {
          showAlert(e.message, 'error');
        }
      });

      document.getElementById('saveTrojanBtn').addEventListener('click', async () => {
        try {
          const payload = { action: 'trojan', value: document.getElementById('trojanPassField').value.trim() };
          await api('/api/settings', 'POST', payload);
          showAlert('رمز Trojan ذخیره شد');
        } catch (e) {
          showAlert(e.message, 'error');
        }
      });

      document.getElementById('saveProxyBtn').addEventListener('click', async () => {
        try {
          const payload = { action: 'proxyIP', value: document.getElementById('proxyField').value.trim() };
          await api('/api/settings', 'POST', payload);
          showAlert('ProxyIP ذخیره شد');
        } catch (e) {
          showAlert(e.message, 'error');
        }
      });

      document.getElementById('savePanelPassBtn').addEventListener('click', async () => {
        try {
          const payload = { action: 'panelPass', value: document.getElementById('panelPassField').value.trim() };
          await api('/api/settings', 'POST', payload);
          showAlert('رمز پنل ذخیره شد');
        } catch (e) {
          showAlert(e.message, 'error');
        }
      });

      document.getElementById('saveNat64Btn').addEventListener('click', async () => {
        try {
          const payload = { action: 'nat64Prefix', value: document.getElementById('nat64PrefixField').value };
          await api('/api/settings', 'POST', payload);
          showAlert('NAT64 ذخیره شد');
        } catch (e) {
          showAlert(e.message, 'error');
        }
      });

      document.getElementById('saveCleanBtn').addEventListener('click', async () => {
        try {
          const ips = document.getElementById('cleanInput').value.split(/\n|,|;/).map((x) => x.trim()).filter(Boolean);
          await api('/api/cleanips', 'POST', { ips });
          showAlert('IP‌های تمیز ذخیره و تست شدند');
        } catch (e) {
          showAlert(e.message, 'error');
        }
      });

      document.getElementById('addClientBtn').addEventListener('click', async () => {
        try {
          const payload = {
            action: 'add',
            data: {
              name: document.getElementById('clientNameField').value.trim(),
              route: document.getElementById('clientRouteField').value,
              quotaGB: Number(document.getElementById('clientQuotaField').value || 0),
              country: document.getElementById('clientCountryField').value.trim() || 'main',
              cleanIPs: true,
              enabled: true
            }
          };
          await api('/api/clients', 'POST', payload);
          showAlert('کلاینت اضافه شد');
          location.reload();
        } catch (e) {
          showAlert(e.message, 'error');
        }
      });

      document.getElementById('saveBotBtn').addEventListener('click', async () => {
        try {
          await api('/api/bot', 'POST', { action: 'save', token: document.getElementById('botTokenField').value.trim(), chatId: document.getElementById('botChatIdField').value.trim(), enabled: document.getElementById('botEnabledField').value === '1' });
          showAlert('تنظیمات ربات ذخیره شد');
        } catch (e) {
          showAlert(e.message, 'error');
        }
      });

      document.getElementById('testBotBtn').addEventListener('click', async () => {
        try {
          const res = await api('/api/bot', 'POST', { action: 'test' });
          showAlert(res && res.ok ? 'پیام تست ارسال شد' : 'تست ناموفق');
        } catch (e) {
          showAlert(e.message, 'error');
        }
      });

      document.getElementById('chatIdsBtn').addEventListener('click', async () => {
        try {
          const res = await api('/api/bot', 'POST', { action: 'chatids' });
          showAlert('Chat IDs دریافت شد');
          console.log(res);
        } catch (e) {
          showAlert(e.message, 'error');
        }
      });

      document.querySelectorAll('[data-action]').forEach((button) => {
        button.addEventListener('click', async (e) => {
          const action = button.getAttribute('data-action');
          if (action === 'newClient') {
            document.getElementById('clientNameField').scrollIntoView({ behavior: 'smooth', block: 'center' });
            return;
          }
          if (action === 'nettest') {
            try {
              const res = await api('/api/nettest', 'POST', { kind: 'nat64' });
              showAlert('نتیجه تست NAT64: ' + JSON.stringify(res));
            } catch (err) {
              showAlert(err.message, 'error');
            }
            return;
          }
          if (action === 'support') {
            window.open('https://t.me/rixpanel', '_blank');
          }
          if (action === 'botTest') {
            document.getElementById('testBotBtn').click();
          }
          if (action === 'manageClients') {
            document.getElementById('clients').scrollIntoView({ behavior: 'smooth', block: 'center' });
          }
        });
      });

      fetch('/api/status').then(async (res) => {
        if (!res.ok) {
          document.getElementById('statusBox').textContent = 'درخواست احراز هویت رد شد.';
          return;
        }
        const data = await res.json();
        document.getElementById('statusBox').innerHTML = `نسخه: ${data.version}<br>hostname: ${data.hostname}<br>VLESS: ${data.vlessEnabled ? 'فعال' : 'غیرفعال'} · Trojan: ${data.trojanEnabled ? 'فعال' : 'غیرفعال'}<br>کلاینت‌ها: ${data.clientCount} · فعال: ${data.activeClients} · IP تمیز: ${data.cleanIPCount}`;
      }).catch(() => {
        document.getElementById('statusBox').textContent = 'خطا در بارگذاری وضعیت.';
      });
    </script>
  </body>
  </html>`;
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (!Number.isFinite(value) || value <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let unitIndex = 0;
  let result = value;
  while (result >= 1024 && unitIndex < units.length - 1) {
    result /= 1024;
    unitIndex += 1;
  }
  return `${result.toFixed(result >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function getUsageForClient(cfg, clientId) {
  const now = new Date();
  const key = `u_${clientId}_${now.toISOString().slice(0, 10).replace(/-/g, '')}`;
  return 0;
}

function buildClientSubscriptionLink(cfg, client) {
  const host = typeof location !== 'undefined' ? location.host : 'example.com';
  return `${host}/sub/${client.id}`;
}

function hasConfigPassword(cfg) {
  return Boolean(cfg.panelPass && String(cfg.panelPass).trim().length > 0);
}

function getClientById(cfg, clientId) {
  return (cfg.clients || []).find((c) => c.id === clientId) || null;
}

function getRequestBody(req) {
  return req.text().then(async (txt) => {
    if (!txt) return {};
    try { return JSON.parse(txt); } catch (e) { return {}; }
  });
}

function isLegacyWsPath(path) {
  return path === '/rix' || path === '/vless' || path === '/trojan' || /^\/[a-f0-9-]{8,}$/i.test(path) || /^\/[A-Za-z0-9_\-]+$/.test(path);
}

async function handleLogin(req, env) {
  if (req.method === 'GET') {
    return new Response(await renderLoginPage(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
  const form = await req.formData();
  const password = String(form.get('password') || '').trim();
  if (!password) return new Response(await renderLoginPage('رمز عبور لازم است.'), { status: 400, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  const cfg = await getConfig(env);
  if (!hasConfigPassword(cfg)) {
    cfg.panelPass = password;
    await saveConfig(env, cfg);
    await appendLog(env, 'panel_initialized', 'Panel initialized and password set');
    const token = await createSessionToken(env, password);
    return Response.redirect('/panel', 302)
      .withHeaders({
        'Set-Cookie': `${SESSION_COOKIE}=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`
      });
  }
  if (password !== cfg.panelPass) {
    return new Response(await renderLoginPage('رمز عبور نامعتبر است.'), { status: 401, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
  const token = await createSessionToken(env, password);
  await appendLog(env, 'successful_login', 'Successful login');
  return Response.redirect('/panel', 302)
    .withHeaders({
      'Set-Cookie': `${SESSION_COOKIE}=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`
    });
}

async function handleLogout() {
  return Response.redirect('/login', 302)
    .withHeaders({
      'Set-Cookie': `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
    });
}

async function handlePanel(req, env) {
  const auth = await requireAuth(req, env);
  if (!auth.ok) return Response.redirect('/login', 302);
  const cfg = auth.cfg;
  const logs = safeJsonParse(await env.kv.get('rix_logs', 'json'), []);
  const view = { ...cfg, logs: Array.isArray(logs) ? logs : [] };
  const html = renderPanelHtml(view);
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

async function handleHealth() {
  return jsonResponse({ ok: true, ver: VERSION });
}

async function handleStatus(req, env) {
  const auth = await requireAuth(req, env);
  if (!auth.ok) return jsonResponse({ error: 'Unauthorized' }, { status: 401 });
  const cfg = auth.cfg;
  const status = buildAdminStatus(cfg, env);
  return jsonResponse(status);
}

async function handleNettest(req, env) {
  const auth = await requireAuth(req, env);
  if (!auth.ok) return jsonResponse({ error: 'Unauthorized' }, { status: 401 });
  const body = await getRequestBody(req);
  const kind = String(body.kind || '').toLowerCase();
  if (kind === 'nat64') {
    const cfg = auth.cfg;
    const result = await testNAT64Gateways(cfg);
    return jsonResponse({ ok: true, kind: 'nat64', results: result });
  }
  if (kind === 'proxy') {
    const result = await testProxyIP(auth.cfg.proxyIP);
    return jsonResponse({ ok: result.ok, kind: 'proxy', result });
  }
  if (kind === 'clean') {
    const result = await testCleanEntries(auth.cfg.cleanIPs, !!body.save, env);
    return jsonResponse({ ok: true, kind: 'clean', result });
  }
  return jsonResponse({ error: 'Unsupported network test kind' }, { status: 400 });
}

async function handleSettings(req, env) {
  const auth = await requireAuth(req, env);
  if (!auth.ok) return jsonResponse({ error: 'Unauthorized' }, { status: 401 });
  const body = await getRequestBody(req);
  const cfg = auth.cfg;
  const action = String(body.action || '').toLowerCase();
  if (action === 'uuid') {
    const val = String(body.value || '').trim();
    if (!isValidUUID(val)) return jsonResponse({ error: 'UUID invalid' }, { status: 400 });
    cfg.uuid = val;
    await appendLog(env, 'uuid_change', 'UUID changed');
    await saveConfig(env, cfg);
    return jsonResponse({ ok: true, saved: true });
  }
  if (action === 'trojan') {
    const val = String(body.value || '').trim();
    if (!val) return jsonResponse({ error: 'Trojan password required' }, { status: 400 });
    cfg.trojanPass = val;
    await appendLog(env, 'trojan_password_change', 'Trojan password changed');
    await saveConfig(env, cfg);
    return jsonResponse({ ok: true, saved: true });
  }
  if (action === 'panelpass') {
    const val = String(body.value || '').trim();
    if (!val) return jsonResponse({ error: 'Panel password required' }, { status: 400 });
    cfg.panelPass = val;
    await appendLog(env, 'panel_pass_change', 'Panel password changed');
    await saveConfig(env, cfg);
    return jsonResponse({ ok: true, saved: true });
  }
  if (action === 'proxyip') {
    cfg.proxyIP = String(body.value || '').trim();
    cfg.proxyEnabled = Boolean(cfg.proxyIP);
    await appendLog(env, 'proxyip_update', 'ProxyIP updated');
    await saveConfig(env, cfg);
    return jsonResponse({ ok: true, saved: true });
  }
  if (action === 'vlessenabled') {
    cfg.vlessEnabled = !!body.value;
    await appendLog(env, 'protocol_change', `VLESS ${cfg.vlessEnabled ? 'enabled' : 'disabled'}`);
    await saveConfig(env, cfg);
    return jsonResponse({ ok: true, saved: true });
  }
  if (action === 'trojanenabled') {
    cfg.trojanEnabled = !!body.value;
    await appendLog(env, 'protocol_change', `Trojan ${cfg.trojanEnabled ? 'enabled' : 'disabled'}`);
    await saveConfig(env, cfg);
    return jsonResponse({ ok: true, saved: true });
  }
  if (action === 'nat64enabled') {
    cfg.nat64Enabled = !!body.value;
    await appendLog(env, 'nat64_update', `NAT64 ${cfg.nat64Enabled ? 'enabled' : 'disabled'}`);
    await saveConfig(env, cfg);
    return jsonResponse({ ok: true, saved: true });
  }
  if (action === 'nat64prefix') {
    const val = String(body.value || '').trim();
    cfg.nat64Prefix = NAT64_PREFIXES[val] ? val : 'NL';
    await appendLog(env, 'nat64_update', `NAT64 prefix set to ${cfg.nat64Prefix}`);
    await saveConfig(env, cfg);
    return jsonResponse({ ok: true, saved: true });
  }
  if (action === 'cleanipsmain') {
    cfg.cleanIPsMain = !!body.value;
    await saveConfig(env, cfg);
    return jsonResponse({ ok: true, saved: true });
  }
  return jsonResponse({ error: 'Unsupported settings action' }, { status: 400 });
}

async function handleCleanIPs(req, env) {
  const auth = await requireAuth(req, env);
  if (!auth.ok) return jsonResponse({ error: 'Unauthorized' }, { status: 401 });
  const body = await getRequestBody(req);
  const raw = Array.isArray(body.ips) ? body.ips : [];
  const cleaned = [];
  for (const item of raw) {
    const parsed = parseCleanIPEntry(item);
    if (parsed) cleaned.push(`${parsed.host}:${parsed.port}`);
  }
  const deduped = [...new Set(cleaned)].slice(0, MAX_CLEAN_IPS);
  const cfg = auth.cfg;
  cfg.cleanIPs = deduped;
  await saveConfig(env, cfg);
  await ensureEndpointRegistry(env, cfg);
  await appendLog(env, 'clean_ip_list_changed', `Clean IP list updated (${deduped.length})`);
  const result = await testCleanEntries(deduped, false, env);
  return jsonResponse({ ok: true, saved: true, count: deduped.length, result });
}

async function handleClients(req, env) {
  const auth = await requireAuth(req, env);
  if (!auth.ok) return jsonResponse({ error: 'Unauthorized' }, { status: 401 });
  const body = await getRequestBody(req);
  const cfg = auth.cfg;
  const action = String(body.action || '').toLowerCase();
  if (action === 'add') {
    if ((cfg.clients || []).length >= MAX_CLIENTS) return jsonResponse({ error: 'Maximum clients reached' }, { status: 400 });
    const data = body.data || {};
    const name = String(data.name || 'Client').slice(0, 32);
    const client = {
      id: toSafeClientId(data.id || `client-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`),
      name,
      uuid: uuidv4(),
      quotaGB: clampNumber(data.quotaGB || 0, 0, 1000),
      country: String(data.country || 'main').trim(),
      cleanIPs: !!data.cleanIPs,
      enabled: data.enabled !== false,
      created: Date.now(),
      route: String(data.route || 'MAIN').toUpperCase()
    };
    cfg.clients.push(client);
    await saveConfig(env, cfg);
    await ensureEndpointRegistry(env, cfg);
    await appendLog(env, 'client_created', `Client created: ${client.name}`);
    return jsonResponse({ ok: true, client });
  }
  if (action === 'update') {
    const clientId = String(body.id || '');
    const target = getClientById(cfg, clientId);
    if (!target) return jsonResponse({ error: 'Client not found' }, { status: 404 });
    Object.assign(target, {
      name: String(body.name || target.name).slice(0, 32),
      quotaGB: clampNumber(body.quotaGB ?? target.quotaGB, 0, 1000),
      country: String(body.country || target.country).trim(),
      cleanIPs: !!(body.cleanIPs ?? target.cleanIPs),
      enabled: body.enabled !== undefined ? !!body.enabled : target.enabled,
      route: String(body.route || target.route || 'MAIN').toUpperCase()
    });
    await saveConfig(env, cfg);
    await ensureEndpointRegistry(env, cfg);
    await appendLog(env, 'client_renamed', `Client updated: ${target.name}`);
    return jsonResponse({ ok: true, client: target });
  }
  if (action === 'delete') {
    const clientId = String(body.id || '');
    const idx = cfg.clients.findIndex((c) => c.id === clientId);
    if (idx < 0) return jsonResponse({ error: 'Client not found' }, { status: 404 });
    const client = cfg.clients[idx];
    cfg.clients.splice(idx, 1);
    cfg.endpoints = (cfg.endpoints || []).filter((e) => !(e.owner === 'client' && e.clientId === clientId));
    await saveConfig(env, cfg);
    await ensureEndpointRegistry(env, cfg);
    await appendLog(env, 'client_deleted', `Client deleted: ${client.name}`);
    return jsonResponse({ ok: true });
  }
  return jsonResponse({ error: 'Unsupported client action' }, { status: 400 });
}

async function handleBot(req, env) {
  const auth = await requireAuth(req, env);
  if (!auth.ok) return jsonResponse({ error: 'Unauthorized' }, { status: 401 });
  const body = await getRequestBody(req);
  const cfg = auth.cfg;
  const action = String(body.action || '').toLowerCase();
  if (action === 'save') {
    cfg.botToken = String(body.token || cfg.botToken || '').trim();
    cfg.botChatId = String(body.chatId || cfg.botChatId || '').trim();
    cfg.botEnabled = !!body.enabled;
    cfg.botUser = String(body.user || cfg.botUser || '').trim();
    await saveConfig(env, cfg);
    await appendLog(env, 'bot_update', 'Telegram bot settings saved');
    return jsonResponse({ ok: true, saved: true });
  }
  if (action === 'test') {
    if (!cfg.botToken) return jsonResponse({ error: 'Bot token not set' }, { status: 400 });
    try {
      const res = await fetch(`https://api.telegram.org/bot${cfg.botToken}/getMe`);
      const json = await res.json();
      if (!json.ok) return jsonResponse({ ok: false, error: json.description || 'Telegram error' }, { status: 400 });
      cfg.botUser = json.result.username;
      await saveConfig(env, cfg);
      const send = await fetch(`https://api.telegram.org/bot${cfg.botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: cfg.botChatId || json.result.id, text: 'RIX PANEL: پیام تست ارسال شد.' })
      });
      const bodyJson = await send.json();
      if (!bodyJson.ok) return jsonResponse({ ok: false, error: bodyJson.description || 'Telegram send failed' }, { status: 400 });
      return jsonResponse({ ok: true, result: bodyJson.result });
    } catch (e) {
      return jsonResponse({ ok: false, error: String(e) }, { status: 500 });
    }
  }
  if (action === 'chatids') {
    if (!cfg.botToken) return jsonResponse({ error: 'Bot token not set' }, { status: 400 });
    try {
      const res = await fetch(`https://api.telegram.org/bot${cfg.botToken}/getUpdates`);
      const json = await res.json();
      if (!json.ok) return jsonResponse({ ok: false, error: json.description || 'Telegram error' }, { status: 400 });
      const ids = [];
      for (const update of json.result || []) {
        const chat = update && update.message && update.message.chat ? update.message.chat : null;
        if (chat) ids.push({ id: chat.id, username: chat.username || chat.first_name || 'unknown' });
      }
      return jsonResponse({ ok: true, chatIds: ids });
    } catch (e) {
      return jsonResponse({ ok: false, error: String(e) }, { status: 500 });
    }
  }
  return jsonResponse({ error: 'Unsupported bot action' }, { status: 400 });
}

function getAllowedClientForUUID(cfg, uuid) {
  if (!uuid) return null;
  if (cfg.uuid && cfg.uuid === uuid) return { kind: 'main', client: null };
  for (const client of cfg.clients || []) {
    if (client.enabled && client.uuid === uuid) return { kind: 'client', client };
  }
  for (const endpoint of cfg.endpoints || []) {
    if (endpoint.uuid === uuid) return { kind: 'endpoint', endpoint };
  }
  return null;
}

function parseVlessHeader(buffer) {
  if (buffer.length < 20) return null;
  const version = buffer[0];
  if (version !== 0) return null;
  const uuidBytes = buffer.slice(1, 17);
  const uuid = [
    uuidBytes.slice(0, 4), uuidBytes.slice(4, 6), uuidBytes.slice(6, 8), uuidBytes.slice(8, 10), uuidBytes.slice(10, 16)
  ].map((part) => toHex(part)).join('-');
  const command = buffer[17];
  if (command !== 1) return null;
  const addrType = buffer[18];
  let offset = 19;
  let host = null;
  if (addrType === 1 && buffer.length >= offset + 4 + 2) {
    host = Array.from(buffer.slice(offset, offset + 4)).join('.');
    offset += 4;
  } else if (addrType === 3 && buffer.length >= offset + 1) {
    const len = buffer[offset];
    offset += 1;
    if (buffer.length < offset + len + 2) return null;
    host = new TextDecoder().decode(buffer.slice(offset, offset + len));
    offset += len;
  } else if (addrType === 4 && buffer.length >= offset + 16 + 2) {
    host = bytesToIPv6String(buffer.slice(offset, offset + 16));
    offset += 16;
  } else {
    return null;
  }
  if (offset + 2 > buffer.length) return null;
  const port = (buffer[offset] << 8) | buffer[offset + 1];
  offset += 2;
  return { uuid, command, addressType: addrType, host, port, payload: buffer.slice(offset) };
}

function parseTrojanHeader(buffer, password) {
  if (!buffer || buffer.length < 3) return null;
  const dec = new TextDecoder();
  const full = dec.decode(buffer);
  const authEnd = full.indexOf('\r\n');
  if (authEnd < 0) return null;
  const auth = full.slice(0, authEnd);
  if (auth !== password) throw new Error('RIX: Trojan password invalid');
  const rest = full.slice(authEnd + 2);
  const hostPortPart = rest.split('\r\n')[0];
  if (!hostPortPart) return null;
  const pair = parseHostPort(hostPortPart);
  if (!pair) return null;
  const payload = buffer.slice(authEnd + 2 + hostPortPart.length + 2);
  return { host: pair.host, port: pair.port, payload };
}

function parseProtocolData(payload, kind, cfg) {
  if (kind === 'vless') {
    const header = parseVlessHeader(payload);
    if (!header) return { ok: false, stage: 'PROTO_PARSE', error: 'RIX: VLESS header invalid' };
    if (!getAllowedClientForUUID(cfg, header.uuid)) {
      return { ok: false, stage: 'AUTH', error: 'RIX: کلاینت غیرفعال یا حذف شده' };
    }
    return { ok: true, host: header.host, port: header.port, payload: header.payload };
  }
  if (kind === 'trojan') {
    try {
      const header = parseTrojanHeader(payload, cfg.trojanPass);
      if (!header) return { ok: false, stage: 'PROTO_PARSE', error: 'RIX: Trojan header invalid' };
      return { ok: true, host: header.host, port: header.port, payload: header.payload };
    } catch (e) {
      return { ok: false, stage: 'AUTH', error: 'RIX: Trojan password invalid' };
    }
  }
  return { ok: false, stage: 'PROTO_PARSE', error: 'RIX: مسیر WebSocket نامعتبر' };
}

async function routeSocketForHost(host, port, cfg, client) {
  const routeSettings = client ? await resolveRouteSettings(client, cfg) : { kind: 'main' };
  let resolvedHost = host;
  let resolvedPort = Number(port || 443);
  const route = routeSettings.kind;
  if (route === 'proxy' && cfg.proxyEnabled && cfg.proxyIP) {
    const parsed = parseHostPort(cfg.proxyIP);
    if (parsed) {
      resolvedHost = parsed.host;
      resolvedPort = parsed.port || 443;
      return { host: resolvedHost, port: resolvedPort, mode: 'proxy', targetHost: host, targetPort: Number(port || 443) };
    }
  }
  if ((route === 'nat64' || route === 'main') && cfg.nat64Enabled) {
    const prefix = String(cfg.nat64Prefix || 'NL');
    const nat64 = ipv4ToNat64V6(prefix, host);
    if (host && /^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      resolvedHost = nat64 || host;
      resolvedPort = Number(port || 443);
      return { host: resolvedHost, port: resolvedPort, mode: 'nat64', targetHost: host, targetPort: Number(port || 443) };
    }
  }
  return { host: resolvedHost, port: resolvedPort, mode: route === 'direct' ? 'direct' : 'main', targetHost: host, targetPort: Number(port || 443) };
}

async function handleWebSocketDataPlane(req, env) {
  const cfg = await getConfig(env);
  const url = new URL(req.url);
  const socketProto = req.headers.get('Sec-WebSocket-Protocol') || '';
  const path = url.pathname || '/';
  if (!req.headers.get('Upgrade') || req.headers.get('Upgrade').toLowerCase() !== 'websocket') {
    return new Response('RIX: مسیر WebSocket نامعتبر', { status: 400 });
  }
  if (cfg.vlessEnabled === false && cfg.trojanEnabled === false) {
    return new Response('RIX: VLESS و Trojan غیرفعال هستند', { status: 403 });
  }
  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  server.accept();
  const earlyData = socketProto ? decodeBase64Url(socketProto.split(',')[0]) : new Uint8Array();
  const wsDataBuffer = concatUint8(earlyData, new Uint8Array(0));
  setTimeout(async () => {
    try {
      const kind = path === '/rix' || path === '/trojan' ? 'trojan' : 'vless';
      let buffer = new Uint8Array(wsDataBuffer.length);
      if (earlyData && earlyData.length) buffer = earlyData;
      let remote = null;
      let remoteClosed = false;
      let routeMeta = null;
      const processMessage = async (chunk) => {
        if (!chunk || chunk.length === 0) return;
        buffer = concatUint8(buffer, chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk));
        if (!remote) {
          const parsed = parseProtocolData(buffer, kind, cfg);
          if (!parsed.ok) {
            if (buffer.length > 4096) {
              server.close();
              throw new Error(parsed.error || 'RIX: protocol parse failed');
            }
            return;
          }
          const targetHost = parsed.host;
          const targetPort = parsed.port;
          const clientMatch = getAllowedClientForUUID(cfg, kind === 'vless' ? parseVlessHeader(buffer)?.uuid : null);
          const route = clientMatch && clientMatch.client ? await resolveRouteSettings(clientMatch.client, cfg) : { kind: 'main' };
          const routeResult = await routeSocketForHost(targetHost, targetPort, cfg, clientMatch && clientMatch.client ? clientMatch.client : null);
          routeMeta = routeResult;
          remote = connect({ hostname: routeResult.host, port: routeResult.port });
          await Promise.race([remote.opened, sleep(PING_TIMEOUT).then(() => { throw new Error('remote timeout'); })]);
          const payload = parsed.payload || new Uint8Array();
          if (payload.length) remote.write(payload);
          const reader = remote.readable.getReader();
          (async () => {
            try {
              while (!remoteClosed) {
                const { done, value } = await reader.read();
                if (done) break;
                if (value && value.length) server.send(value);
              }
            } catch (e) { }
            try { remote.close(); } catch (e) { }
          })();
          buffer = new Uint8Array(0);
          if (kind === 'trojan') {
            const trojanInfo = parseTrojanHeader(buffer, cfg.trojanPass);
          }
        } else {
          try {
            remote.write(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk));
          } catch (e) {
            server.close();
          }
        }
      };
      server.addEventListener('message', async (event) => {
        try {
          const data = event.data instanceof ArrayBuffer ? new Uint8Array(event.data) : (event.data && typeof event.data.arrayBuffer === 'function' ? new Uint8Array(await event.data.arrayBuffer()) : new Uint8Array());
          await processMessage(data);
        } catch (e) {
          try { server.close(); } catch (err) {}
          console.error('RIX_WEBSOCKET_ERROR', String(e && e.message ? e.message : e));
        }
      });
      server.addEventListener('close', () => {
        remoteClosed = true;
        try { if (remote) remote.close(); } catch (e) {}
      });
      server.addEventListener('error', () => {
        remoteClosed = true;
        try { if (remote) remote.close(); } catch (e) {}
      });
    } catch (e) {
      console.error('RIX_WS_UPGRADE_FAILURE', String(e && e.message ? e.message : e));
    }
  }, 0);
  return new Response(null, { status: 101, webSocket: client });
}

function buildSubscriptionText(cfg, host, rawMode = false) {
  const lines = [];
  const baseHost = host || 'example.com';
  if (cfg.vlessEnabled && cfg.uuid) {
    lines.push(`vless://${cfg.uuid}@${baseHost}:443?encryption=none&security=tls&sni=${baseHost}&fp=randomized&type=ws&host=${baseHost}&path=${encodeURIComponent(DEFAULT_WS_PATH)}#RIX-VLESS`);
  }
  if (cfg.trojanEnabled && cfg.trojanPass) {
    lines.push(`trojan://${cfg.trojanPass}@${baseHost}:443?security=tls&sni=${baseHost}&fp=randomized&type=ws&host=${baseHost}&path=${encodeURIComponent(DEFAULT_WS_PATH)}#RIX-Trojan`);
  }
  for (const ip of cfg.cleanIPs || []) {
    const parsed = parseCleanIPEntry(ip);
    if (!parsed) continue;
    const endpoint = (cfg.endpoints || []).find((e) => e.kind === 'clean' && e.target === `${parsed.host}:${parsed.port}`);
    const id = endpoint && endpoint.uuid ? endpoint.uuid : uuidv4();
    lines.push(`vless://${id}@${baseHost}:443?encryption=none&security=tls&sni=${baseHost}&fp=randomized&type=ws&host=${baseHost}&path=${encodeURIComponent(DEFAULT_WS_PATH)}#RIX ${parsed.host}`);
  }
  if (rawMode) return lines.join('\n');
  return btoa(lines.join('\n'));
}

async function handleSubscription(req, env) {
  const url = new URL(req.url);
  const raw = url.searchParams.get('raw') === '1';
  const cfg = await getConfig(env);
  const host = req.headers.get('host') || 'example.com';
  const clientId = url.pathname.startsWith('/sub/') ? url.pathname.replace('/sub/', '').trim() : null;
  if (clientId) {
    const client = getClientById(cfg, clientId);
    if (!client || !client.enabled) return new Response('RIX: کلاینت غیرفعال یا حذف شده', { status: 403 });
    const lines = [];
    if (cfg.vlessEnabled) lines.push(`vless://${client.uuid}@${host}:443?encryption=none&security=tls&sni=${host}&fp=randomized&type=ws&host=${host}&path=${encodeURIComponent(DEFAULT_WS_PATH)}#RIX ${encodeURIComponent(client.name || client.id)}`);
    if (cfg.trojanEnabled) lines.push(`trojan://${cfg.trojanPass}@${host}:443?security=tls&sni=${host}&fp=randomized&type=ws&host=${host}&path=${encodeURIComponent(DEFAULT_WS_PATH)}#RIX ${encodeURIComponent(client.name || client.id)}`);
    if (client.cleanIPs && cfg.cleanIPs && cfg.cleanIPs.length) {
      for (const ip of cfg.cleanIPs) {
        const parsed = parseCleanIPEntry(ip);
        if (!parsed) continue;
        const endpoint = (cfg.endpoints || []).find((e) => e.kind === 'clean' && e.target === `${parsed.host}:${parsed.port}`);
        const id = endpoint && endpoint.uuid ? endpoint.uuid : uuidv4();
        lines.push(`vless://${id}@${host}:443?encryption=none&security=tls&sni=${host}&fp=randomized&type=ws&host=${host}&path=${encodeURIComponent(DEFAULT_WS_PATH)}#RIX ${encodeURIComponent(parsed.host)}`);
      }
    }
    const payload = raw ? lines.join('\n') : btoa(lines.join('\n'));
    return new Response(payload, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Profile-Title': 'RIX PANEL', 'Profile-Update-Interval': '0', 'Cache-Control': 'no-store' } });
  }
  const payload = raw ? buildSubscriptionText(cfg, host, true) : btoa(buildSubscriptionText(cfg, host, false));
  return new Response(payload, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Profile-Title': 'RIX PANEL', 'Profile-Update-Interval': '0', 'Cache-Control': 'no-store' } });
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const method = request.method.toUpperCase();
      const path = url.pathname;

      if (path === '/health') return handleHealth();
      if (path === '/login') return handleLogin(request, env);
      if (path === '/logout') return handleLogout();
      if (path === '/panel') return handlePanel(request, env);

      if (path === '/api/status') return handleStatus(request, env);
      if (path === '/api/nettest') return handleNettest(request, env);
      if (path === '/api/settings') return handleSettings(request, env);
      if (path === '/api/cleanips') return handleCleanIPs(request, env);
      if (path === '/api/clients') return handleClients(request, env);
      if (path === '/api/bot') return handleBot(request, env);

      if (path === '/sub' || path.startsWith('/sub/')) return handleSubscription(request, env);

      if (request.headers.get('Upgrade') && request.headers.get('Upgrade').toLowerCase() === 'websocket') {
        return await handleWebSocketDataPlane(request, env);
      }

      if (path === '/' || path === '/rix' || path === '/vless' || path === '/trojan' || isLegacyWsPath(path)) {
        return Response.redirect('/panel', 302);
      }

      return new Response('RIX: مسیر نامعتبر', { status: 404 });
    } catch (e) {
      console.error('RIX_WORKER_ERROR', String(e && e.message ? e.message : e));
      return jsonResponse({ ok: false, error: String(e && e.message ? e.message : e) }, { status: 500 });
    }
  }
};

const __workerReady = true;
if (typeof globalThis !== 'undefined') {
  globalThis.__RIX_VERSION = VERSION;
}
