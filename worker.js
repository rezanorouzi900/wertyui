import { connect } from 'cloudflare:sockets';

const VERSION = '2.8.0';
const SESSION_COOKIE = 'rix_session';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_CLIENTS = 20;
const MAX_CLEAN_IPS = 60;
const PING_TIMEOUT = 3000;
const DEFAULT_WS_PATH = '/?ed=2048';

const NAT64_PREFIXES = {
  NL: '2a02:898:146:64::',
  'US-1': '2602:fc59:b0:64::',
  'US-2': '2602:fc59:11:64::'
};

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...extraHeaders
    }
  });
}

function redirectResponse(location, cookieHeader) {
  const headers = { Location: location };
  if (cookieHeader) headers['Set-Cookie'] = cookieHeader;
  return new Response(null, { status: 302, headers });
}

function escapeHtml(value) {
  return String(value || '').replace(/[&<>"']/g, function (ch) {
    return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch] || ch;
  });
}

function b64UrlEncode(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function b64UrlDecode(value) {
  if (!value) return new Uint8Array();
  const normalized = String(value).replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  const binary = atob(normalized + pad);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function randomHex(length) {
  const chars = 'abcdef0123456789';
  let out = '';
  for (let i = 0; i < length; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

function uuidv4() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
  return hex.slice(0,8) + '-' + hex.slice(8,12) + '-' + hex.slice(12,16) + '-' + hex.slice(16,20) + '-' + hex.slice(20);
}

function isValidUuid(value) {
  return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(String(value || ''));
}

function clamp(value, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return min;
  return Math.min(Math.max(n, min), max);
}

function safeJsonParse(value, fallback) {
  try {
    return JSON.parse(value || 'null');
  } catch (_err) {
    return fallback;
  }
}

function defaultConfig() {
  return {
    uuid: uuidv4(),
    trojanPass: randomHex(16),
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
    created: Date.now(),
    botToken: '',
    botChatId: '',
    botUser: '',
    botEnabled: false,
    botOnAuth: true,
    botOnClient: true,
    botOnConn: true
  };
}

function normalizeConfig(input) {
  const base = defaultConfig();
  const cfg = { ...base, ...(input || {}) };
  cfg.uuid = isValidUuid(cfg.uuid) ? cfg.uuid : uuidv4();
  cfg.trojanPass = String(cfg.trojanPass || '').trim() || randomHex(16);
  cfg.panelPass = String(cfg.panelPass || '').trim();
  cfg.cleanIPs = Array.isArray(cfg.cleanIPs) ? cfg.cleanIPs.map(function (item) { return String(item || '').trim(); }).filter(Boolean).slice(0, MAX_CLEAN_IPS) : [];
  cfg.clients = Array.isArray(cfg.clients) ? cfg.clients.map(function (client) {
    return {
      id: String(client.id || 'client-' + Date.now() + '-' + Math.random().toString(16).slice(2,8)).replace(/[^a-zA-Z0-9_-]/g, '').slice(0,64) || 'client',
      name: String(client.name || 'Client').slice(0, 32),
      uuid: isValidUuid(client.uuid) ? client.uuid : uuidv4(),
      quotaGB: clamp(Number(client.quotaGB || 0), 0, 1000),
      country: String(client.country || 'main'),
      cleanIPs: !!client.cleanIPs,
      enabled: client.enabled !== false,
      created: Number(client.created || Date.now()),
      route: String(client.route || 'MAIN').toUpperCase()
    };
  }) : [];
  cfg.endpoints = Array.isArray(cfg.endpoints) ? cfg.endpoints.map(function (item) {
    return {
      key: String(item.key || (item.kind || 'main') + ':' + (item.uuid || uuidv4())),
      uuid: item.uuid || uuidv4(),
      owner: item.owner || 'main',
      clientId: item.clientId || '',
      kind: item.kind || 'main',
      target: item.target || ''
    };
  }) : [];
  cfg.nat64Prefix = NAT64_PREFIXES[cfg.nat64Prefix] ? cfg.nat64Prefix : 'NL';
  cfg.proxyIP = String(cfg.proxyIP || '').trim();
  cfg.cleanIPsMain = !!cfg.cleanIPsMain;
  cfg.botEnabled = !!cfg.botEnabled;
  cfg.botOnAuth = cfg.botOnAuth !== false;
  cfg.botOnClient = cfg.botOnClient !== false;
  cfg.botOnConn = cfg.botOnConn !== false;
  return cfg;
}

async function getConfig(env) {
  if (!env || !env.kv) throw new Error('KV binding "kv" missing');
  const stored = await env.kv.get('rix_config', 'json');
  if (!stored) {
    const cfg = normalizeConfig(defaultConfig());
    await env.kv.put('rix_config', JSON.stringify(cfg));
    await env.kv.put('rix_logs', JSON.stringify([{ ts: Date.now(), type: 'panel_initialized', msg: 'RIX panel initialized' }]));
    return cfg;
  }
  return normalizeConfig(stored);
}

async function saveConfig(env, cfg) {
  if (!env || !env.kv) throw new Error('KV binding "kv" missing');
  await env.kv.put('rix_config', JSON.stringify(normalizeConfig(cfg)));
}

async function appendLog(env, type, message) {
  if (!env || !env.kv) return;
  const current = safeJsonParse(await env.kv.get('rix_logs', 'json'), []);
  const logs = Array.isArray(current) ? current : [];
  logs.unshift({ ts: Date.now(), type: String(type || 'event'), msg: String(message || '') });
  await env.kv.put('rix_logs', JSON.stringify(logs.slice(0, 50)));
}

function sessionCookieHeader(token) {
  return SESSION_COOKIE + '=' + encodeURIComponent(token) + '; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=' + Math.floor(SESSION_TTL_MS / 1000);
}

async function createSessionToken(password) {
  const payload = { user: 'admin', exp: Date.now() + SESSION_TTL_MS, ts: Date.now() };
  const payloadText = JSON.stringify(payload);
  const payloadB64 = b64UrlEncode(new TextEncoder().encode(payloadText));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(password || 'rix-panel')), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
  return payloadB64 + '.' + b64UrlEncode(new Uint8Array(sig));
}

async function verifySessionToken(token, password) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  try {
    const payloadB64 = parts[0];
    const payload = JSON.parse(new TextDecoder().decode(b64UrlDecode(payloadB64)));
    if (!payload || !payload.exp || Date.now() > payload.exp) return false;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(password || 'rix-panel')), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
    const expected = b64UrlEncode(new Uint8Array(sig));
    return expected === parts[1];
  } catch (_err) {
    return false;
  }
}

async function readSessionToken(req, env) {
  const cookieHeader = req.headers.get('Cookie') || '';
  const match = cookieHeader.split(';').map(function (s) { return s.trim(); }).find(function (s) { return s.startsWith(SESSION_COOKIE + '='); });
  if (!match) return null;
  const token = decodeURIComponent(match.substring((SESSION_COOKIE + '=').length));
  const cfg = await getConfig(env);
  if (!cfg.panelPass) return null;
  const ok = await verifySessionToken(token, cfg.panelPass);
  return ok ? token : null;
}

async function requireAuth(req, env) {
  const cfg = await getConfig(env);
  const token = await readSessionToken(req, env);
  return token ? { ok: true, cfg } : { ok: false, cfg };
}

function parseHostPort(value) {
  const input = String(value || '').trim();
  if (!input) return null;
  if (input.includes('://')) {
    try {
      const u = new URL(input);
      return { host: u.hostname, port: Number(u.port || (u.protocol === 'https:' ? 443 : 80)) };
    } catch (_err) { return null; }
  }
  if (input.startsWith('[')) {
    const end = input.indexOf(']');
    if (end > -1) {
      const host = input.slice(1, end);
      let port = 443;
      const rest = input.slice(end + 1);
      if (rest.startsWith(':')) port = Number(rest.slice(1) || 443);
      return { host, port: Number.isFinite(port) ? port : 443 };
    }
  }
  const lastColon = input.lastIndexOf(':');
  if (lastColon > -1 && input.indexOf(':') === lastColon) {
    return { host: input.slice(0, lastColon), port: Number(input.slice(lastColon + 1) || 443) };
  }
  return { host: input, port: 443 };
}

function isValidIpOrDomain(value) {
  const s = String(value || '').trim();
  if (!s) return false;
  return /^[a-zA-Z0-9.-]+$/.test(s) || /^\d+\.\d+\.\d+\.\d+$/.test(s) || /^([0-9a-fA-F:]+)$/.test(s);
}

function parseCleanIp(raw) {
  const input = String(raw || '').trim();
  if (!input) return null;
  const parsed = parseHostPort(input.replace(/\s+/g, ''));
  if (!parsed || !isValidIpOrDomain(parsed.host)) return null;
  return { host: parsed.host, port: Number(parsed.port || 443) };
}

async function tcpCheck(host, port, timeoutMs = PING_TIMEOUT) {
  const target = String(host || '').trim();
  if (!target) return { ok: false, ms: null, host: target, port: Number(port || 443), error: 'Target missing' };
  const t0 = Date.now();
  try {
    const socket = connect({ hostname: target, port: Number(port || 443) });
    await Promise.race([
      socket.opened,
      new Promise(function (_resolve, reject) {
        setTimeout(function () { reject(new Error('timeout')); }, timeoutMs);
      })
    ]);
    const ms = Date.now() - t0;
    try { socket.close(); } catch (_err) {}
    return { ok: true, ms, host: target, port: Number(port || 443), error: null };
  } catch (err) {
    return { ok: false, ms: Date.now() - t0, host: target, port: Number(port || 443), error: String(err && err.message ? err.message : err) };
  }
}

function ipv4ToNat64(prefix, ipv4) {
  const base = NAT64_PREFIXES[String(prefix)] || NAT64_PREFIXES.NL;
  const parts = String(ipv4 || '').split('.');
  if (parts.length !== 4) return null;
  const nums = parts.map(function (p) { return Number(p); });
  if (nums.some(function (n) { return !Number.isFinite(n) || n < 0 || n > 255; })) return null;
  const hi = ((nums[0] << 8) | nums[1]).toString(16).padStart(4, '0');
  const lo = ((nums[2] << 8) | nums[3]).toString(16).padStart(4, '0');
  return base.replace(/::$/, '') + ':' + hi + ':' + lo;
}

async function testNat64Gateway(cfg) {
  const results = [];
  for (const prefix of ['NL', 'US-1', 'US-2']) {
    const entries = [];
    for (const target of ['1.1.1.1:443', '8.8.8.8:53']) {
      const parts = target.split(':');
      const nat64Host = ipv4ToNat64(prefix, parts[0]);
      if (!nat64Host) continue;
      const res = await tcpCheck(nat64Host, Number(parts[1] || 443), PING_TIMEOUT);
      entries.push({ host: parts[0], port: Number(parts[1] || 443), ok: res.ok, ms: res.ms, error: res.error || null });
    }
    results.push({ prefix, alive: entries.some(function (x) { return x.ok; }), ms: entries.filter(function (x) { return x.ok; }).map(function (x) { return x.ms || 0; }).reduce(function (a, b) { return a + b; }, 0) || null, results: entries });
  }
  return results;
}

async function testProxy(proxyIp) {
  const parsed = parseHostPort(proxyIp);
  if (!parsed) return { ok: false, ms: null, host: null, port: null, error: 'ProxyIP invalid: use IPv4, domain, or IP:PORT' };
  const result = await tcpCheck(parsed.host, parsed.port || 443, PING_TIMEOUT);
  return { ok: result.ok, ms: result.ms, host: parsed.host, port: parsed.port || 443, error: result.error || null };
}

async function testCleanEntries(entries, saveToKv, env) {
  const unique = [];
  for (const raw of entries || []) {
    const parsed = parseCleanIp(raw);
    if (!parsed) continue;
    const key = parsed.host + ':' + parsed.port;
    if (!unique.includes(key)) unique.push(key);
  }
  const results = [];
  for (const key of unique.slice(0, MAX_CLEAN_IPS)) {
    const parts = key.split(':');
    const res = await tcpCheck(parts[0], Number(parts[1] || 443), PING_TIMEOUT);
    results.push({ host: parts[0], port: Number(parts[1] || 443), ok: res.ok, ms: res.ms, error: res.error || null });
  }
  const alive = results.filter(function (item) { return item.ok; }).sort(function (a, b) { return (a.ms || 999999) - (b.ms || 999999); });
  const dead = results.filter(function (item) { return !item.ok; });
  const ordered = alive.concat(dead).map(function (item) { return item.host + ':' + item.port; });
  if (saveToKv && env && env.kv) {
    const cfg = await getConfig(env);
    cfg.cleanIPs = ordered;
    await saveConfig(env, cfg);
  }
  return { ok: true, total: ordered.length, alive: alive.length, dead: dead.length, entries: ordered, results };
}

function getClientById(cfg, id) {
  return (cfg.clients || []).find(function (client) { return client.id === id; }) || null;
}

function getRouteTarget(cfg, client, host, port) {
  if (client && client.route === 'PROXY' && cfg.proxyEnabled && cfg.proxyIP) {
    const parsed = parseHostPort(cfg.proxyIP);
    if (parsed) return { host: parsed.host, port: parsed.port || 443, mode: 'proxy' };
  }
  if ((client && (client.route === 'NL' || client.route === 'US-1' || client.route === 'US-2')) || cfg.nat64Enabled) {
    const prefix = client && client.route ? client.route : (cfg.nat64Prefix || 'NL');
    const mapped = ipv4ToNat64(prefix, host);
    if (mapped && /^\d+\.\d+\.\d+\.\d+$/.test(String(host || ''))) {
      return { host: mapped, port: Number(port || 443), mode: 'nat64' };
    }
  }
  return { host: String(host || 'example.com'), port: Number(port || 443), mode: 'direct' };
}

function getAllowedClient(cfg, uuid) {
  if (!uuid) return null;
  if (cfg.uuid === uuid) return { kind: 'main', client: null };
  for (const client of cfg.clients || []) {
    if (client.enabled && client.uuid === uuid) return { kind: 'client', client };
  }
  return null;
}

function parseVlessHeader(buffer) {
  if (!buffer || buffer.length < 20) return null;
  if (buffer[0] !== 0) return null;
  const uuidBytes = buffer.subarray(1, 17);
  const uuid = Array.from(uuidBytes).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
  const uuidText = uuid.slice(0,8) + '-' + uuid.slice(8,12) + '-' + uuid.slice(12,16) + '-' + uuid.slice(16,20) + '-' + uuid.slice(20);
  if (buffer[17] !== 1) return null;
  const addrType = buffer[18];
  let offset = 19;
  let host = '';
  if (addrType === 1) {
    if (buffer.length < offset + 4 + 2) return null;
    host = Array.from(buffer.subarray(offset, offset + 4)).join('.');
    offset += 4;
  } else if (addrType === 3) {
    const len = buffer[offset];
    offset += 1;
    if (buffer.length < offset + len + 2) return null;
    host = new TextDecoder().decode(buffer.subarray(offset, offset + len));
    offset += len;
  } else if (addrType === 4) {
    if (buffer.length < offset + 16 + 2) return null;
    const bytes = buffer.subarray(offset, offset + 16);
    const pairs = [];
    for (let i = 0; i < bytes.length; i += 2) pairs.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    host = pairs.join(':');
    offset += 16;
  } else {
    return null;
  }
  if (offset + 2 > buffer.length) return null;
  const port = (buffer[offset] << 8) | buffer[offset + 1];
  offset += 2;
  return { uuid: uuidText, host, port, payload: buffer.subarray(offset) };
}

function parseTrojanHeader(buffer, password) {
  if (!buffer || buffer.length < 4) return null;
  const text = new TextDecoder().decode(buffer);
  const eolIndex = text.indexOf('\r\n');
  if (eolIndex < 0) return null;
  const auth = text.slice(0, eolIndex);
  if (auth !== password) throw new Error('RIX: Trojan password invalid');
  const rest = text.slice(eolIndex + 2);
  const hostLine = rest.split('\r\n')[0];
  if (!hostLine) return null;
  const parsed = parseHostPort(hostLine);
  if (!parsed) return null;
  const body = buffer.subarray(eolIndex + 2 + hostLine.length + 2);
  return { host: parsed.host, port: parsed.port || 443, payload: body };
}

async function handleWebSocketUpgrade(request, env) {
  const cfg = await getConfig(env);
  const path = new URL(request.url).pathname;
  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  server.accept();

  const protocolHeader = request.headers.get('Sec-WebSocket-Protocol') || '';
  const earlyBytes = protocolHeader ? b64UrlDecode(protocolHeader.split(',')[0]) : new Uint8Array();

  setTimeout(function () {
    let buffer = earlyBytes;
    let remote = null;
    let ready = false;

    const startRemote = async function (parsed) {
      const matched = getAllowedClient(cfg, parsed.uuid || null);
      if (parsed.uuid && !matched) {
        server.close();
        return;
      }
      const target = getRouteTarget(cfg, matched && matched.client, parsed.host, parsed.port);
      remote = connect({ hostname: target.host, port: target.port });
      try {
        await Promise.race([
          remote.opened,
          new Promise(function (_resolve, reject) {
            setTimeout(function () { reject(new Error('remote timeout')); }, PING_TIMEOUT);
          })
        ]);
      } catch (_err) {
        server.close();
        return;
      }
      ready = true;
      if (parsed.payload && parsed.payload.length > 0) remote.write(parsed.payload);
      const reader = remote.readable.getReader();
      (async function () {
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value && value.length) server.send(value);
          }
        } catch (_err) {
          try { server.close(); } catch (_e) {}
        }
      })();
    };

    server.addEventListener('message', function (event) {
      const data = event.data instanceof ArrayBuffer ? new Uint8Array(event.data) : new Uint8Array();
      if (data.length === 0) return;
      if (ready) {
        try { remote.write(data); } catch (_err) { server.close(); }
        return;
      }
      buffer = new Uint8Array(buffer.length + data.length);
      buffer.set(data, 0);

      const kind = (path === '/trojan' || path === '/rix') ? 'trojan' : 'vless';
      let parsed = null;
      try {
        if (kind === 'vless') parsed = parseVlessHeader(buffer);
        else parsed = parseTrojanHeader(buffer, cfg.trojanPass);
      } catch (_err) {
        server.close();
        return;
      }
      if (!parsed) {
        if (buffer.length > 4096) server.close();
        return;
      }
      startRemote(parsed).catch(function () { server.close(); });
    });

    server.addEventListener('close', function () {
      try { if (remote) remote.close(); } catch (_err) {}
    });
  }, 0);

  return new Response(null, { status: 101, webSocket: client });
}

function renderLoginPage(message) {
  const msgHtml = message ? '<div class="message error">' + escapeHtml(message) + '</div>' : '<div class="message ok">ورود به RIX PANEL</div>';
  return [
    '<!doctype html>',
    '<html lang="fa" dir="rtl">',
    '<head>',
    '  <meta charset="utf-8">',
    '  <meta name="viewport" content="width=device-width, initial-scale=1">',
    '  <title>RIX PANEL | ورود</title>',
    '  <style>',
    '    * { box-sizing: border-box; }',
    '    body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:linear-gradient(135deg,#eef4ff,#f8fafc); font-family:Tahoma,Arial,sans-serif; color:#0f172a; }',
    '    .box { width:min(420px,92vw); padding:28px 24px; border-radius:24px; background:#fff; border:1px solid #e5e7eb; box-shadow:0 18px 50px rgba(15,23,42,.08); }',
    '    .brand { display:flex; align-items:center; justify-content:center; gap:12px; margin-bottom:16px; }',
    '    .logo { width:46px; height:46px; border-radius:16px; display:grid; place-items:center; font-weight:900; color:#fff; background:linear-gradient(135deg,#2563eb,#60a5fa); }',
    '    h1 { margin:0; font-size:26px; }',
    '    .sub { text-align:center; color:#475569; margin-bottom:16px; font-size:14px; }',
    '    label { display:block; margin:12px 0 8px; font-size:13px; color:#475569; }',
    '    input { width:100%; height:48px; border-radius:12px; border:1px solid #e5e7eb; padding:0 14px; font-size:15px; }',
    '    input:focus { outline:none; border-color:#2563eb; box-shadow:0 0 0 3px rgba(37,99,235,.15); }',
    '    button { width:100%; height:48px; margin-top:14px; border:none; border-radius:12px; background:linear-gradient(135deg,#2563eb,#1d4ed8); color:#fff; font-weight:700; cursor:pointer; }',
    '    .message { margin-top:14px; padding:12px 14px; font-size:13px; border-radius:12px; }',
    '    .message.error { background:#fef2f2; border:1px solid #fecaca; color:#991b1b; }',
    '    .message.ok { background:#ecfdf5; border:1px solid #a7f3d0; color:#166534; }',
    '    .version { margin-top:14px; text-align:center; color:#64748b; font-size:12px; }',
    '  </style>',
    '</head>',
    '<body>',
    '  <div class="box">',
    '    <div class="brand">',
    '      <div class="logo">R</div>',
    '      <h1>RIX PANEL</h1>',
    '    </div>',
    '    <div class="sub">ورود به داشبورد مدير</div>',
    '    <form method="POST" action="/login">',
    '      <label for="password">رمز عبور پنل</label>',
    '      <input id="password" type="password" name="password" autocomplete="current-password" required>',
    '      <button type="submit">ورود</button>',
    '    </form>',
    msgHtml,
    '    <div class="version">RIX PANEL v' + VERSION + '</div>',
    '  </div>',
    '</body>',
    '</html>'
  ].join('\n');
}

function renderPanelPage(cfg, logs) {
  const clients = Array.isArray(cfg.clients) ? cfg.clients : [];
  const rows = clients.length > 0 ? clients.map(function (client) {
    return [
      '<tr>',
      '<td>' + escapeHtml(client.name || 'Client') + '</td>',
      '<td>' + escapeHtml(client.route || 'MAIN') + '</td>',
      '<td><span class="badge ' + (client.enabled ? '' : 'off') + '">' + (client.enabled ? 'فعال' : 'غیرفعال') + '</span></td>',
      '<td>' + (client.quotaGB === 0 ? 'نامحدود' : client.quotaGB + ' GB') + '</td>',
      '<td>' + (client.cleanIPs ? 'بله' : 'خیر') + '</td>',
      '<td><button class="tiny" type="button" data-copy="/sub/' + client.id + '">کپی</button></td>',
      '</tr>'
    ].join('');
  }).join('') : '<tr><td colspan="6">هنوز کلاینتی وجود ندارد.</td></tr>';

  const logHtml = Array.isArray(logs) && logs.length > 0 ? logs.slice(0, 6).map(function (entry) {
    return '<li>' + escapeHtml(entry.msg || entry.type || 'event') + '</li>';
  }).join('') : '<li>هيچ رويدادي ثبت نشده است.</li>';

  return [
    '<!doctype html>',
    '<html lang="fa" dir="rtl">',
    '<head>',
    '  <meta charset="utf-8">',
    '  <meta name="viewport" content="width=device-width, initial-scale=1">',
    '  <title>RIX PANEL</title>',
    '  <style>',
    '    * { box-sizing:border-box; }',
    '    body { margin:0; min-height:100vh; background:#f5f7fb; color:#0f172a; font-family:Tahoma,Arial,sans-serif; }',
    '    body.dark { background:#0b1220; color:#e2e8f0; }',
    '    a { color:inherit; text-decoration:none; }',
    '    .shell { display:flex; min-height:100vh; }',
    '    .sidebar { width:248px; background:#0f172a; color:#e2e8f0; padding:18px 14px; display:flex; flex-direction:column; }',
    '    .logo-box { display:flex; align-items:center; gap:12px; padding:10px 10px 16px; border-bottom:1px solid rgba(255,255,255,.08); }',
    '    .logo { width:38px; height:38px; border-radius:12px; background:linear-gradient(135deg,#60a5fa,#2563eb); display:grid; place-items:center; font-weight:900; }',
    '    .brand { font-weight:800; font-size:18px; }',
    '    .nav { display:flex; flex-direction:column; gap:8px; margin-top:18px; }',
    '    .nav a { display:flex; align-items:center; gap:10px; padding:12px 10px; border-radius:12px; color:#dfeafc; opacity:.9; }',
    '    .nav a.active, .nav a:hover { background:rgba(255,255,255,.06); opacity:1; }',
    '    .version { margin-top:auto; color:#a9b9d3; font-size:12px; padding-top:12px; border-top:1px solid rgba(255,255,255,.08); }',
    '    .main { flex:1; padding:20px; }',
    '    .topbar { display:flex; align-items:center; justify-content:space-between; gap:12px; padding:14px 18px; background:#fff; border:1px solid #e5e7eb; border-radius:18px; box-shadow:0 10px 25px rgba(15,23,42,.06); }',
    '    body.dark .topbar { background:#111827; border-color:#1f2937; }',
    '    .title { font-size:20px; font-weight:800; }',
    '    .top-actions { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }',
    '    .button, .icon, .tiny { border-radius:12px; border:1px solid #e5e7eb; padding:10px 12px; cursor:pointer; background:#fff; color:#0f172a; }',
    '    body.dark .button, body.dark .icon, body.dark .tiny { background:#111827; border-color:#1f2937; color:#e2e8f0; }',
    '    .button.primary { background:linear-gradient(135deg,#2563eb,#1d4ed8); border:none; color:#fff; }',
    '    .button.danger { background:#fee2e2; border-color:#fecaca; color:#991b1b; }',
    '    .grid { display:grid; grid-template-columns:repeat(12, minmax(0,1fr)); gap:18px; margin-top:18px; }',
    '    .card { grid-column:span 4; background:#fff; border:1px solid #e5e7eb; border-radius:18px; padding:18px; box-shadow:0 10px 25px rgba(15,23,42,.06); }',
    '    body.dark .card { background:#111827; border-color:#1f2937; }',
    '    .card.full { grid-column:span 12; }',
    '    .card.half { grid-column:span 6; }',
    '    .head { display:flex; align-items:center; justify-content:space-between; margin-bottom:12px; }',
    '    h3 { margin:0; font-size:18px; }',
    '    .stat { font-size:28px; font-weight:800; }',
    '    .muted { color:#64748b; }',
    '    .badge { display:inline-block; padding:6px 10px; border-radius:999px; background:rgba(37,99,235,.12); color:#2563eb; font-size:12px; font-weight:700; }',
    '    .badge.off { background:rgba(220,38,38,.08); color:#dc2626; }',
    '    ul { list-style:none; padding:0; margin:0; }',
    '    li { padding:8px 0; border-bottom:1px dashed #e5e7eb; }',
    '    table { width:100%; border-collapse:collapse; }',
    '    th, td { padding:10px 8px; border-bottom:1px solid #e5e7eb; text-align:right; }',
    '    .tiny { padding:7px 10px; font-size:12px; }',
    '    @media (max-width: 900px) { .shell { display:block; } .sidebar { width:100%; min-height:auto; } .card, .card.half { grid-column:span 12; } .grid { grid-template-columns:1fr; } }',
    '  </style>',
    '</head>',
    '<body>',
    '  <div class="shell">',
    '    <aside class="sidebar">',
    '      <div class="logo-box">',
    '        <div class="logo">R</div>',
    '        <div class="brand">RIX PANEL</div>',
    '      </div>',
    '      <nav class="nav">',
    '        <a href="#" class="active">داشبورد</a>',
    '        <a href="#">کانفیگ‌ها</a>',
    '        <a href="#">کلاینت‌ها</a>',
    '        <a href="#">ربات</a>',
    '        <a href="#">اطلاعات</a>',
    '        <a href="#">تنظیمات</a>',
    '      </nav>',
    '      <div class="version">RIX PANEL v' + VERSION + '</div>',
    '    </aside>',
    '    <main class="main">',
    '      <div class="topbar">',
    '        <div class="title">داشبورد</div>',
    '        <div class="top-actions">',
    '          <button class="icon" type="button">Support</button>',
    '          <button class="icon" type="button" id="themeToggle">☀️</button>',
    '          <span class="muted">ادمین</span>',
    '          <a class="button danger" href="/logout">خروج</a>',
    '        </div>',
    '      </div>',
    '      <div class="grid">',
    '        <div class="card">',
    '          <div class="head"><h3>کلاینت‌ها</h3><span class="badge">' + clients.length + '</span></div>',
    '          <div class="stat">' + clients.length + '</div>',
    '        </div>',
    '        <div class="card">',
    '          <div class="head"><h3>فعال</h3><span class="badge">' + clients.filter(function (c) { return c.enabled; }).length + '</span></div>',
    '          <div class="stat">' + clients.filter(function (c) { return c.enabled; }).length + '</div>',
    '        </div>',
    '        <div class="card">',
    '          <div class="head"><h3>IP تمیز</h3><span class="badge">' + (cfg.cleanIPs || []).length + '</span></div>',
    '          <div class="stat">' + (cfg.cleanIPs || []).length + '</div>',
    '        </div>',
    '        <div class="card full">',
    '          <div class="head"><h3>لینک اشتراک</h3><span class="badge">فعال</span></div>',
    '          <div class="muted">/sub</div>',
    '          <div style="margin-top:12px"><button class="button primary" type="button" data-copy="/sub">کپی لینک اشتراک</button></div>',
    '        </div>',
    '        <div class="card half">',
    '          <div class="head"><h3>آخرین فعاليت‌ها</h3></div>',
    '          <ul>' + logHtml + '</ul>',
    '        </div>',
    '        <div class="card half">',
    '          <div class="head"><h3>وضعيت</h3></div>',
    '          <div id="statusBox" class="muted">درحال بارگذاري...</div>',
    '        </div>',
    '        <div class="card full">',
    '          <div class="head"><h3>مديريت کلاینت‌ها</h3></div>',
    '          <table>',
    '            <thead><tr><th>نام</th><th>مسير</th><th>وضعيت</th><th>Quota</th><th>IP تمیز</th><th>ساب</th></tr></thead>',
    '            <tbody>' + rows + '</tbody>',
    '          </table>',
    '        </div>',
    '      </div>',
    '    </main>',
    '  </div>',
    '  <script>',
    '    document.getElementById("themeToggle").addEventListener("click", function () {',
    '      var dark = document.body.classList.toggle("dark");',
    '      localStorage.setItem("rix_theme", dark ? "dark" : "light");',
    '    });',
    '    document.querySelectorAll("[data-copy]").forEach(function (button) {',
    '      button.addEventListener("click", function () {',
    '        navigator.clipboard.writeText(button.getAttribute("data-copy")).then(function () { alert("کپی شد"); }).catch(function () { alert("کپی انجام نشد"); });',
    '      });',
    '    });',
    '    fetch("/api/status").then(function (res) { return res.json(); }).then(function (data) {',
    '      document.getElementById("statusBox").innerHTML = "نسخه: " + data.version + "<br>کلاینت‌ها: " + data.clientCount + "<br>VLESS: " + (data.vlessEnabled ? "فعال" : "غیرفعال") + " | Trojan: " + (data.trojanEnabled ? "فعال" : "غیرفعال");',
    '    }).catch(function () { document.getElementById("statusBox").textContent = "خطا در بارگذاري وضعيت."; });',
    '  </script>',
    '</body>',
    '</html>'
  ].join('\n');
}

async function handleLogin(request, env) {
  if (request.method === 'GET') {
    return new Response(renderLoginPage(''), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
  const form = await request.formData();
  const password = String(form.get('password') || '').trim();
  if (!password) {
    return new Response(renderLoginPage('رمز عبور لازم است.'), { status: 400, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
  const cfg = await getConfig(env);
  if (!cfg.panelPass) {
    cfg.panelPass = password;
    await saveConfig(env, cfg);
    await appendLog(env, 'panel_initialized', 'Password initialized');
    const token = await createSessionToken(password);
    return redirectResponse('/panel', sessionCookieHeader(token));
  }
  if (password !== cfg.panelPass) {
    return new Response(renderLoginPage('رمز عبور نامعتبر است.'), { status: 401, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
  const token = await createSessionToken(password);
  await appendLog(env, 'successful_login', 'Successful login');
  return redirectResponse('/panel', sessionCookieHeader(token));
}

async function handlePanel(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return redirectResponse('/login');
  const logs = safeJsonParse(await env.kv.get('rix_logs', 'json'), []);
  return new Response(renderPanelPage(auth.cfg, logs), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

async function handleLogout() {
  return redirectResponse('/login', SESSION_COOKIE + '=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');
}

async function handleStatus(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return jsonResponse({ error: 'Unauthorized' }, 401);
  const cfg = auth.cfg;
  return jsonResponse({
    version: VERSION,
    hostname: 'cloudflare-worker',
    uptime: Math.max(1, Math.round((Date.now() - (cfg.created || Date.now())) / 1000)),
    vlessEnabled: !!cfg.vlessEnabled,
    trojanEnabled: !!cfg.trojanEnabled,
    nat64Enabled: !!cfg.nat64Enabled,
    proxyEnabled: !!cfg.proxyEnabled,
    cleanIPCount: (cfg.cleanIPs || []).length,
    clientCount: (cfg.clients || []).length,
    activeClients: (cfg.clients || []).filter(function (c) { return c.enabled; }).length,
    endpointCount: (cfg.endpoints || []).length,
    vlessUUIDCount: ((cfg.clients || []).length + (cfg.uuid ? 1 : 0)),
    todaysUsage: 0,
    telegramState: !!cfg.botEnabled,
    gatewayStates: {
      nat64: cfg.nat64Enabled ? 'active' : 'disabled',
      proxy: cfg.proxyEnabled ? 'active' : 'disabled',
      clean: (cfg.cleanIPs || []).length > 0 ? 'active' : 'disabled'
    }
  });
}

async function handleNettest(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return jsonResponse({ error: 'Unauthorized' }, 401);
  const body = request.method === 'POST' ? safeJsonParse(await request.text(), {}) : {};
  const kind = String(body.kind || '').toLowerCase();
  if (kind === 'nat64') {
    return jsonResponse({ ok: true, kind: 'nat64', result: await testNat64Gateway(auth.cfg) });
  }
  if (kind === 'proxy') {
    return jsonResponse({ ok: true, kind: 'proxy', result: await testProxy(auth.cfg.proxyIP || '') });
  }
  if (kind === 'clean') {
    return jsonResponse({ ok: true, kind: 'clean', result: await testCleanEntries(auth.cfg.cleanIPs || [], !!body.save, env) });
  }
  return jsonResponse({ error: 'Unsupported network test kind' }, 400);
}

async function handleSettings(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return jsonResponse({ error: 'Unauthorized' }, 401);
  const body = safeJsonParse(await request.text(), {});
  const cfg = auth.cfg;
  const action = String(body.action || '').toLowerCase();
  if (action === 'uuid') {
    const value = String(body.value || '').trim();
    if (!isValidUuid(value)) return jsonResponse({ error: 'UUID invalid' }, 400);
    cfg.uuid = value;
    await saveConfig(env, cfg);
    await appendLog(env, 'uuid_change', 'UUID updated');
    return jsonResponse({ ok: true, saved: true });
  }
  if (action === 'trojan') {
    const value = String(body.value || '').trim();
    if (!value) return jsonResponse({ error: 'Trojan password required' }, 400);
    cfg.trojanPass = value;
    await saveConfig(env, cfg);
    await appendLog(env, 'trojan_password_change', 'Trojan password changed');
    return jsonResponse({ ok: true, saved: true });
  }
  if (action === 'panelpass') {
    const value = String(body.value || '').trim();
    if (!value) return jsonResponse({ error: 'Panel password required' }, 400);
    cfg.panelPass = value;
    await saveConfig(env, cfg);
    await appendLog(env, 'panel_pass_change', 'Panel password changed');
    return jsonResponse({ ok: true, saved: true });
  }
  if (action === 'proxyip') {
    cfg.proxyIP = String(body.value || '').trim();
    cfg.proxyEnabled = !!cfg.proxyIP;
    await saveConfig(env, cfg);
    await appendLog(env, 'proxyip_update', 'ProxyIP updated');
    return jsonResponse({ ok: true, saved: true });
  }
  if (action === 'nat64prefix') {
    const value = String(body.value || 'NL');
    cfg.nat64Prefix = NAT64_PREFIXES[value] ? value : 'NL';
    await saveConfig(env, cfg);
    await appendLog(env, 'nat64_update', 'NAT64 prefix updated');
    return jsonResponse({ ok: true, saved: true });
  }
  if (action === 'cleanipsmain') {
    cfg.cleanIPsMain = !!body.value;
    await saveConfig(env, cfg);
    return jsonResponse({ ok: true, saved: true });
  }
  return jsonResponse({ error: 'Unsupported settings action' }, 400);
}

async function handleCleanIps(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return jsonResponse({ error: 'Unauthorized' }, 401);
  const body = safeJsonParse(await request.text(), {});
  const items = Array.isArray(body.ips) ? body.ips : [];
  const dedup = [];
  for (const item of items) {
    const parsed = parseCleanIp(item);
    if (!parsed) continue;
    const key = parsed.host + ':' + parsed.port;
    if (!dedup.includes(key)) dedup.push(key);
  }
  const cfg = auth.cfg;
  cfg.cleanIPs = dedup.slice(0, MAX_CLEAN_IPS);
  await saveConfig(env, cfg);
  await appendLog(env, 'clean_ip_list_changed', 'Clean IP list updated');
  return jsonResponse({ ok: true, saved: true, count: cfg.cleanIPs.length });
}

async function handleClients(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return jsonResponse({ error: 'Unauthorized' }, 401);
  const body = safeJsonParse(await request.text(), {});
  const cfg = auth.cfg;
  const action = String(body.action || '').toLowerCase();

  if (action === 'add') {
    if ((cfg.clients || []).length >= MAX_CLIENTS) return jsonResponse({ error: 'Maximum clients reached' }, 400);
    const data = body.data || {};
    const client = {
      id: String(Date.now()) + '-' + Math.random().toString(16).slice(2,8),
      name: String(data.name || 'Client').slice(0, 32),
      uuid: uuidv4(),
      quotaGB: clamp(Number(data.quotaGB || 0), 0, 1000),
      country: String(data.country || 'main'),
      cleanIPs: !!data.cleanIPs,
      enabled: data.enabled !== false,
      created: Date.now(),
      route: String(data.route || 'MAIN').toUpperCase()
    };
    cfg.clients.push(client);
    await saveConfig(env, cfg);
    await appendLog(env, 'client_created', 'Client created: ' + client.name);
    return jsonResponse({ ok: true, client });
  }

  if (action === 'update') {
    const target = getClientById(cfg, String(body.id || ''));
    if (!target) return jsonResponse({ error: 'Client not found' }, 404);
    Object.assign(target, {
      name: String(body.name || target.name).slice(0, 32),
      quotaGB: clamp(Number(body.quotaGB ?? target.quotaGB), 0, 1000),
      country: String(body.country || target.country),
      cleanIPs: !!(body.cleanIPs ?? target.cleanIPs),
      enabled: body.enabled !== undefined ? !!body.enabled : target.enabled,
      route: String(body.route || target.route || 'MAIN').toUpperCase()
    });
    await saveConfig(env, cfg);
    await appendLog(env, 'client_updated', 'Client updated: ' + target.name);
    return jsonResponse({ ok: true, client: target });
  }

  if (action === 'delete') {
    const idx = cfg.clients.findIndex(function (c) { return c.id === String(body.id || ''); });
    if (idx < 0) return jsonResponse({ error: 'Client not found' }, 404);
    const removed = cfg.clients[idx];
    cfg.clients.splice(idx, 1);
    await saveConfig(env, cfg);
    await appendLog(env, 'client_deleted', 'Client deleted: ' + removed.name);
    return jsonResponse({ ok: true });
  }

  return jsonResponse({ error: 'Unsupported client action' }, 400);
}

async function handleBot(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return jsonResponse({ error: 'Unauthorized' }, 401);
  const body = safeJsonParse(await request.text(), {});
  const cfg = auth.cfg;
  const action = String(body.action || '').toLowerCase();

  if (action === 'save') {
    cfg.botToken = String(body.token || '').trim();
    cfg.botChatId = String(body.chatId || '').trim();
    cfg.botEnabled = !!body.enabled;
    await saveConfig(env, cfg);
    await appendLog(env, 'bot_update', 'Telegram bot settings saved');
    return jsonResponse({ ok: true, saved: true });
  }

  if (action === 'test') {
    if (!cfg.botToken) return jsonResponse({ error: 'Bot token not set' }, 400);
    try {
      const res = await fetch('https://api.telegram.org/bot' + cfg.botToken + '/getMe');
      const json = await res.json();
      if (!json.ok) return jsonResponse({ ok: false, error: json.description || 'Telegram error' }, 400);
      return jsonResponse({ ok: true, result: json.result });
    } catch (err) {
      return jsonResponse({ ok: false, error: String(err) }, 500);
    }
  }

  if (action === 'chatids') {
    if (!cfg.botToken) return jsonResponse({ error: 'Bot token not set' }, 400);
    try {
      const res = await fetch('https://api.telegram.org/bot' + cfg.botToken + '/getUpdates');
      const json = await res.json();
      if (!json.ok) return jsonResponse({ ok: false, error: json.description || 'Telegram error' }, 400);
      const items = [];
      for (const update of json.result || []) {
        const chat = update && update.message && update.message.chat ? update.message.chat : null;
        if (chat) items.push({ id: chat.id, username: chat.username || chat.first_name || 'unknown' });
      }
      return jsonResponse({ ok: true, chatIds: items });
    } catch (err) {
      return jsonResponse({ ok: false, error: String(err) }, 500);
    }
  }

  return jsonResponse({ error: 'Unsupported bot action' }, 400);
}

function buildSubscriptionLines(cfg, host, client) {
  const lines = [];
  if (cfg.vlessEnabled && cfg.uuid) {
    const uuid = client ? client.uuid : cfg.uuid;
    lines.push('vless://' + uuid + '@' + host + ':443?encryption=none&security=tls&sni=' + host + '&fp=randomized&type=ws&host=' + host + '&path=' + encodeURIComponent(DEFAULT_WS_PATH) + '#RIX-' + encodeURIComponent(client ? (client.name || client.id) : 'RIX-VLESS'));
  }
  if (cfg.trojanEnabled && cfg.trojanPass) {
    lines.push('trojan://' + cfg.trojanPass + '@' + host + ':443?security=tls&sni=' + host + '&fp=randomized&type=ws&host=' + host + '&path=' + encodeURIComponent(DEFAULT_WS_PATH) + '#RIX-Trojan');
  }
  for (const raw of cfg.cleanIPs || []) {
    const parsed = parseCleanIp(raw);
    if (!parsed) continue;
    const uuid = uuidv4();
    lines.push('vless://' + uuid + '@' + host + ':443?encryption=none&security=tls&sni=' + host + '&fp=randomized&type=ws&host=' + host + '&path=' + encodeURIComponent(DEFAULT_WS_PATH) + '#RIX-' + encodeURIComponent(parsed.host));
  }
  return lines;
}

async function handleSubscription(request, env) {
  const url = new URL(request.url);
  const cfg = await getConfig(env);
  const host = request.headers.get('host') || 'example.com';
  const rawMode = url.searchParams.get('raw') === '1';
  const pathParts = url.pathname.split('/');
  const clientId = pathParts.length > 2 ? pathParts[2] : null;

  if (clientId) {
    const client = getClientById(cfg, clientId);
    if (!client || !client.enabled) return new Response('RIX: کلاینت غیرفعال یا حذف شده', { status: 403 });
    const lines = buildSubscriptionLines(cfg, host, client);
    const output = rawMode ? lines.join('\n') : btoa(lines.join('\n'));
    return new Response(output, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Profile-Title': 'RIX PANEL', 'Profile-Update-Interval': '0', 'Cache-Control': 'no-store' } });
  }

  const lines = buildSubscriptionLines(cfg, host, null);
  const output = rawMode ? lines.join('\n') : btoa(lines.join('\n'));
  return new Response(output, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Profile-Title': 'RIX PANEL', 'Profile-Update-Interval': '0', 'Cache-Control': 'no-store' } });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path === '/health') return jsonResponse({ ok: true, ver: VERSION });
      if (path === '/login') return handleLogin(request, env);
      if (path === '/logout') return handleLogout();
      if (path === '/panel') return handlePanel(request, env);
      if (path === '/api/status') return handleStatus(request, env);
      if (path === '/api/nettest') return handleNettest(request, env);
      if (path === '/api/settings') return handleSettings(request, env);
      if (path === '/api/cleanips') return handleCleanIps(request, env);
      if (path === '/api/clients') return handleClients(request, env);
      if (path === '/api/bot') return handleBot(request, env);
      if (path === '/sub' || path.startsWith('/sub/')) return handleSubscription(request, env);

      if (request.headers.get('Upgrade') && request.headers.get('Upgrade').toLowerCase() === 'websocket') {
        return handleWebSocketUpgrade(request, env);
      }

      if (path === '/' || path === '/rix' || path === '/vless' || path === '/trojan') {
        return redirectResponse('/panel');
      }

      return new Response('RIX: مسیر نامعتبر', { status: 404 });
    } catch (err) {
      console.error('RIX_WORKER_ERROR', String(err && err.message ? err.message : err));
      return jsonResponse({ ok: false, error: String(err && err.message ? err.message : err) }, 500);
    }
  }
};

if (typeof globalThis !== 'undefined') globalThis.__RIX_VERSION = VERSION;
