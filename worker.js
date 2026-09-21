import { connect } from 'cloudflare:sockets';

const VERSION = '2.8.0';
const SESSION_COOKIE = 'rix_session';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const DEFAULT_WS_PATH = '/?ed=2048';
const MAX_CLIENTS = 20;
const MAX_CLEAN_IPS = 60;
const PING_TIMEOUT = 3000;

const NAT64_PREFIXES = {
  NL: '2a02:898:146:64::',
  'US-1': '2602:fc59:b0:64::',
  'US-2': '2602:fc59:11:64::'
};

function safeJsonParse(raw, fallback) {
  try {
    return JSON.parse(raw || 'null');
  } catch (err) {
    return fallback;
  }
}

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
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
  return String(value || '').replace(/[&<>"']/g, function (char) {
    const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    };
    return map[char] || char;
  });
}

function b64UrlEncode(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function b64UrlDecode(input) {
  if (!input) return new Uint8Array();
  const normalized = String(input).replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  const binary = atob(normalized + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function randomHex(len) {
  const out = [];
  for (let i = 0; i < len; i += 1) {
    out.push(Math.floor(Math.random() * 16).toString(16));
  }
  return out.join('');
}

function uuidv4() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes).map(function (b) {
    return b.toString(16).padStart(2, '0');
  }).join('');
  return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20);
}

function isValidUuid(value) {
  return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(String(value || ''));
}

function toSafeClientId(source) {
  const base = String(source || '').trim();
  const safe = base.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
  return safe || 'client';
}

function clampNumber(value, min, max) {
  const num = Number(value);
  if (!Number.isFinite(num)) return min;
  return Math.min(Math.max(num, min), max);
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
  cfg.cleanIPs = Array.isArray(cfg.cleanIPs) ? cfg.cleanIPs.map(function (x) { return String(x || '').trim(); }).filter(Boolean).slice(0, MAX_CLEAN_IPS) : [];
  cfg.clients = Array.isArray(cfg.clients) ? cfg.clients.map(function (client) {
    return {
      id: toSafeClientId(client.id || ('client-' + Date.now() + '-' + Math.random().toString(16).slice(2, 8))),
      name: String(client.name || 'Client').slice(0, 32),
      uuid: isValidUuid(client.uuid) ? client.uuid : uuidv4(),
      quotaGB: clampNumber(client.quotaGB || 0, 0, 1000),
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
  const raw = await env.kv.get('rix_config', 'json');
  if (!raw) {
    const cfg = normalizeConfig(defaultConfig());
    await env.kv.put('rix_config', JSON.stringify(cfg));
    await env.kv.put('rix_logs', JSON.stringify([{ ts: Date.now(), type: 'panel_initialized', msg: 'RIX panel initialized' }]));
    return cfg;
  }
  return normalizeConfig(raw);
}

async function saveConfig(env, cfg) {
  if (!env || !env.kv) throw new Error('KV binding "kv" missing');
  await env.kv.put('rix_config', JSON.stringify(normalizeConfig(cfg)));
}

async function appendLog(env, type, message) {
  if (!env || !env.kv) return;
  const current = safeJsonParse(await env.kv.get('rix_logs', 'json'), []);
  const arr = Array.isArray(current) ? current : [];
  arr.unshift({ ts: Date.now(), type: String(type || 'event'), msg: String(message || '') });
  await env.kv.put('rix_logs', JSON.stringify(arr.slice(0, 50)));
}

function sessionCookieValue(token) {
  return SESSION_COOKIE + '=' + encodeURIComponent(token) + '; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=' + Math.floor(SESSION_TTL_MS / 1000);
}

async function createSessionToken(password) {
  const payload = {
    user: 'admin',
    exp: Date.now() + SESSION_TTL_MS,
    ts: Date.now()
  };
  const payloadText = JSON.stringify(payload);
  const payloadEnc = b64UrlEncode(new TextEncoder().encode(payloadText));
  const keyBytes = new TextEncoder().encode(String(password || 'rix-panel'));
  const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(payloadEnc));
  return payloadEnc + '.' + b64UrlEncode(new Uint8Array(sig));
}

async function verifySessionToken(token, password) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  try {
    const payloadEnc = parts[0];
    const payloadJson = new TextDecoder().decode(b64UrlDecode(payloadEnc));
    const payload = JSON.parse(payloadJson);
    if (!payload || !payload.exp || Date.now() > payload.exp) return false;
    const keyBytes = new TextEncoder().encode(String(password || 'rix-panel'));
    const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(payloadEnc));
    const expected = b64UrlEncode(new Uint8Array(sig));
    return expected === parts[1];
  } catch (err) {
    return false;
  }
}

async function readSessionToken(req, env) {
  const cookieHeader = req.headers.get('Cookie') || '';
  const cookies = cookieHeader.split(';').map(function (item) { return item.trim(); });
  const target = cookies.find(function (item) { return item.startsWith(SESSION_COOKIE + '='); });
  if (!target) return null;
  const raw = decodeURIComponent(target.substring((SESSION_COOKIE + '=').length));
  const cfg = await getConfig(env);
  if (!cfg.panelPass) return null;
  const ok = await verifySessionToken(raw, cfg.panelPass);
  return ok ? raw : null;
}

async function requireAuth(req, env) {
  const cfg = await getConfig(env);
  const token = await readSessionToken(req, env);
  if (!token) return { ok: false, cfg };
  return { ok: true, cfg };
}

function parseHostPort(value) {
  const input = String(value || '').trim();
  if (!input) return null;
  if (input.includes('://')) {
    try {
      const url = new URL(input);
      return { host: url.hostname, port: Number(url.port || (url.protocol === 'https:' ? 443 : 80)) };
    } catch (err) {
      return null;
    }
  }

  if (input.startsWith('[')) {
    const end = input.indexOf(']');
    if (end > -1) {
      const host = input.slice(1, end);
      const rest = input.slice(end + 1);
      const port = rest.startsWith(':') ? Number(rest.slice(1) || '443') : 443;
      return { host, port: Number.isFinite(port) ? port : 443 };
    }
  }

  const lastColon = input.lastIndexOf(':');
  if (lastColon > -1 && input.indexOf(':') === lastColon) {
    const host = input.slice(0, lastColon);
    const port = Number(input.slice(lastColon + 1) || 443);
    return { host, port: Number.isFinite(port) ? port : 443 };
  }

  return { host: input, port: 443 };
}

function isValidDomainOrIp(value) {
  const source = String(value || '').trim();
  if (!source) return false;
  return /^[a-zA-Z0-9.-]+$/.test(source) || /^\d+\.\d+\.\d+\.\d+$/.test(source) || /^([0-9a-fA-F:]+)$/.test(source);
}

function parseCleanIp(raw) {
  const value = String(raw || '').trim();
  if (!value) return null;
  const parsed = parseHostPort(value.replace(/\s+/g, ''));
  if (!parsed || !isValidDomainOrIp(parsed.host)) return null;
  return { host: parsed.host, port: Number(parsed.port || 443) };
}

async function tcpTest(host, port, timeoutMs = PING_TIMEOUT) {
  const target = String(host || '').trim();
  if (!target) {
    return { ok: false, ms: null, host: target, port: Number(port || 443), error: 'Target missing' };
  }

  const started = Date.now();
  try {
    const socket = connect({ hostname: target, port: Number(port || 443) });
    await Promise.race([
      socket.opened,
      new Promise(function (_, reject) {
        setTimeout(function () { reject(new Error('timeout')); }, timeoutMs); 
      })
    ]);
    const elapsed = Date.now() - started;
    try { socket.close(); } catch (err) {}
    return { ok: true, ms: elapsed, host: target, port: Number(port || 443), error: null };
  } catch (err) {
    const elapsed = Date.now() - started;
    return { ok: false, ms: elapsed, host: target, port: Number(port || 443), error: String(err && err.message ? err.message : err) };
  }
}

function ipv4ToNat64(prefix, ipv4) {
  const p = NAT64_PREFIXES[String(prefix)] || NAT64_PREFIXES.NL;
  const parts = String(ipv4 || '').split('.');
  if (parts.length !== 4) return null;
  const nums = parts.map(function (part) { return Number(part); });
  if (nums.some(function (n) { return !Number.isFinite(n) || n < 0 || n > 255; })) return null;
  const val = ((nums[0] << 8) | nums[1]) << 8;
  const hi = ((val >> 16) & 0xffff).toString(16).padStart(4, '0');
  const lo = (nums[2] << 8 | nums[3]).toString(16).padStart(4, '0');
  return p.replace(/::$/, '') + ':' + hi + ':' + lo;
}

async function testNat64(cfg) {
  const results = [];
  for (const prefix of ['NL', 'US-1', 'US-2']) {
    const pref = NAT64_PREFIXES[prefix];
    const list = ['1.1.1.1:443', '8.8.8.8:53'];
    const itemRes = [];
    for (const target of list) {
      const hostPort = target.split(':');
      const natHost = ipv4ToNat64(prefix, hostPort[0]);
      const res = natHost ? await tcpTest(natHost, Number(hostPort[1] || 443), PING_TIMEOUT) : { ok: false, ms: null, host: hostPort[0], port: Number(hostPort[1] || 443), error: 'invalid nat64 mapping' };
      itemRes.push({ host: hostPort[0], port: Number(hostPort[1] || 443), ok: res.ok, ms: res.ms, error: res.error || null });
    }
    results.push({ prefix, enabled: !!cfg.nat64Enabled, alive: itemRes.some(function (x) { return x.ok; }), ms: itemRes.filter(function (x) { return x.ok; }).map(function (x) { return x.ms || 0; }).reduce(function (a, b) { return a + b; }, 0) || null, results: itemRes });
  }
  return results;
}

async function testProxy(value) {
  const parsed = parseHostPort(value);
  if (!parsed) {
    return { ok: false, ms: null, host: null, port: null, error: 'ProxyIP invalid: use IPv4, domain, or IP:PORT' };
  }
  const result = await tcpTest(parsed.host, parsed.port || 443, PING_TIMEOUT);
  return { ok: result.ok, ms: result.ms, host: parsed.host, port: parsed.port || 443, error: result.error || null };
}

async function testCleanEntries(entries, saveToKv) {
  const deduped = [];
  for (const raw of entries || []) {
    const item = parseCleanIp(raw);
    if (!item) continue;
    const key = item.host + ':' + item.port;
    if (!deduped.includes(key)) deduped.push(key);
  }

  const results = [];
  for (const key of deduped.slice(0, MAX_CLEAN_IPS)) {
    const [host, port] = key.split(':');
    const result = await tcpTest(host, Number(port || 443), PING_TIMEOUT);
    results.push({ host, port: Number(port || 443), ok: result.ok, ms: result.ms, error: result.error || null });
  }

  const alive = results.filter(function (x) { return x.ok; }).sort(function (a, b) { return (a.ms || 999999) - (b.ms || 999999); });
  const dead = results.filter(function (x) { return !x.ok; });
  const ordered = alive.concat(dead).map(function (x) { return x.host + ':' + x.port; });

  if (saveToKv && globalThis.__ENV__) {
    const cfg = await getConfig(globalThis.__ENV__);
    cfg.cleanIPs = ordered;
    await saveConfig(globalThis.__ENV__, cfg);
  }

  return { ok: true, total: ordered.length, alive: alive.length, dead: dead.length, entries: ordered, results };
}

function getClientById(cfg, clientId) {
  return (cfg.clients || []).find(function (client) { return client.id === clientId; }) || null;
}

function getTargetFromRoute(cfg, client, host, port) {
  if (client && client.route === 'PROXY' && cfg.proxyEnabled && cfg.proxyIP) {
    const parsed = parseHostPort(cfg.proxyIP);
    if (parsed) return { host: parsed.host, port: parsed.port || 443, route: 'proxy' };
  }

  if ((client && (client.route === 'NL' || client.route === 'US-1' || client.route === 'US-2')) || cfg.nat64Enabled) {
    const prefix = String(client && client.route ? client.route : cfg.nat64Prefix || 'NL');
    const target = ipv4ToNat64(prefix, host);
    if (target && /^\d+\.\d+\.\d+\.\d+$/.test(String(host || ''))) {
      return { host: target, port: Number(port || 443), route: 'nat64' };
    }
  }

  return { host: String(host || 'example.com'), port: Number(port || 443), route: 'direct' };
}

function getAllowedClientForUuid(cfg, uuid) {
  if (!uuid) return null;
  if (cfg.uuid === uuid) return { kind: 'main', client: null };
  for (const client of cfg.clients || []) {
    if (client.enabled && client.uuid === uuid) return { kind: 'client', client };
  }
  return null;
}

function parseVlessHeader(buffer) {
  if (!buffer || buffer.length < 20) return null;
  const version = buffer[0];
  if (version !== 0) return null;
  const uuidBytes = buffer.subarray(1, 17);
  const uuid = [
    uuidBytes.subarray(0, 4),
    uuidBytes.subarray(4, 6),
    uuidBytes.subarray(6, 8),
    uuidBytes.subarray(8, 10),
    uuidBytes.subarray(10, 16)
  ].map(function (part) {
    return Array.from(part).map(function (byte) { return byte.toString(16).padStart(2, '0'); }).join('');
  }).join('-');

  const command = buffer[17];
  if (command !== 1) return null;
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
    const groups = [];
    for (let i = 0; i < bytes.length; i += 2) {
      groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    }
    host = groups.join(':');
    offset += 16;
  } else {
    return null;
  }

  if (offset + 2 > buffer.length) return null;
  const port = (buffer[offset] << 8) | buffer[offset + 1];
  offset += 2;
  return { uuid, host, port, payload: buffer.subarray(offset) };
}

function parseTrojanHeader(buffer, password) {
  if (!buffer || buffer.length < 4) return null;
  const text = new TextDecoder().decode(buffer);
  const lineBreak = text.indexOf('\r\n');
  if (lineBreak < 0) return null;
  const auth = text.slice(0, lineBreak);
  if (auth !== password) {
    throw new Error('RIX: Trojan password invalid');
  }
  const rest = text.slice(lineBreak + 2);
  const hostLine = rest.split('\r\n')[0];
  if (!hostLine) return null;
  const parsed = parseHostPort(hostLine);
  if (!parsed) return null;
  return { host: parsed.host, port: parsed.port || 443, payload: buffer.subarray(lineBreak + 2 + hostLine.length + 2) };
}

async function handleWebSocketUpgrade(req, env) {
  const cfg = await getConfig(env);
  const upgradeHeader = req.headers.get('Upgrade');
  if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
    return new Response('RIX: مسیر WebSocket نامعتبر', { status: 400 });
  }

  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  server.accept();

  const url = new URL(req.url);
  const path = url.pathname;
  const protoHeader = req.headers.get('Sec-WebSocket-Protocol') || '';
  const early = protoHeader ? b64UrlDecode(protoHeader.split(',')[0]) : new Uint8Array();

  setTimeout(async function () {
    let buffer = early;
    let remoteSocket = null;
    let connected = false;

    const processChunk = async function (chunk) {
      if (!chunk || chunk.length === 0) return;
      buffer = new Uint8Array(buffer.length + chunk.length);
      buffer.set(chunk, 0);
      
      if (connected) {
        try {
          remoteSocket.write(chunk);
        } catch (err) {
          server.close();
        }
        return;
      }

      const kind = path === '/trojan' || path === '/rix' ? 'trojan' : 'vless';
      let parsed = null;
      if (kind === 'vless') {
        parsed = parseVlessHeader(buffer);
      } else {
        try {
          parsed = parseTrojanHeader(buffer, cfg.trojanPass);
        } catch (err) {
          server.close();
          return;
        }
      }

      if (!parsed) {
        if (buffer.length > 4096) {
          server.close();
        }
        return;
      }

      const clientMatch = getAllowedClientForUuid(cfg, kind === 'vless' ? parsed.uuid : null);
      if (kind === 'vless' && !clientMatch) {
        server.close();
        return;
      }

      const target = getTargetFromRoute(cfg, clientMatch && clientMatch.client, parsed.host, parsed.port);
      remoteSocket = connect({ hostname: target.host, port: target.port });
      try {
        await Promise.race([
          remoteSocket.opened,
          new Promise(function (_, reject) {
            setTimeout(function () { reject(new Error('remote timeout')); }, PING_TIMEOUT); 
          })
        ]);
      } catch (err) {
        server.close();
        return;
      }

      connected = true;
      if (parsed.payload && parsed.payload.length > 0) {
        remoteSocket.write(parsed.payload);
      }

      const reader = remoteSocket.readable.getReader();
      (async function () {
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value) server.send(value);
          }
        } catch (err) {
          server.close();
        }
      })();
    };

    server.addEventListener('message', function (event) {
      const data = event.data instanceof ArrayBuffer ? new Uint8Array(event.data) : new Uint8Array();
      processChunk(data).catch(function () {
        server.close();
      });
    });

    server.addEventListener('close', function () {
      try { if (remoteSocket) remoteSocket.close(); } catch (err) {}
    });
  }, 0);

  return new Response(null, { status: 101, webSocket: client });
}

function renderLoginPage(errorMessage) {
  const error = errorMessage ? '<div class="message error">' + escapeHtml(errorMessage) + '</div>' : '<div class="message success">ورود به RIX PANEL</div>';
  const html = [
    '<!doctype html>',
    '<html lang="fa" dir="rtl">',
    '<head>',
    '  <meta charset="utf-8">',
    '  <meta name="viewport" content="width=device-width, initial-scale=1">',
    '  <title>RIX PANEL | ورود</title>',
    '  <style>',
    '    :root { --bg:#f6f8fc; --card:#ffffff; --line:#e5e7eb; --text:#0f172a; --muted:#475569; --primary:#2563eb; --shadow:0 16px 50px rgba(15,23,42,.08); }',
    '    * { box-sizing:border-box; }',
    '    body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:linear-gradient(135deg,#edf4ff,#f8fafc); font-family:Tahoma,Arial,sans-serif; color:var(--text); }',
    '    .box { width:min(92vw,420px); background:var(--card); border:1px solid var(--line); border-radius:24px; box-shadow:var(--shadow); padding:28px 24px; }',
    '    .brand { display:flex; align-items:center; justify-content:center; gap:12px; margin-bottom:18px; }',
    '    .logo { width:46px; height:46px; border-radius:14px; background:linear-gradient(135deg,#1d4ed8,#60a5fa); color:#fff; display:grid; place-items:center; font-size:22px; font-weight:900; }',
    '    h1 { margin:0; font-size:26px; }',
    '    .sub { text-align:center; color:var(--muted); margin-bottom:18px; font-size:14px; }',
    '    label { display:block; font-size:13px; color:var(--muted); margin:12px 0 8px; }',
    '    input { width:100%; height:48px; border:1px solid var(--line); border-radius:12px; background:#fff; padding:0 14px; font-size:15px; }',
    '    input:focus { outline:none; border-color:var(--primary); box-shadow:0 0 0 3px rgba(37,99,235,.15); }',
    '    button { width:100%; height:48px; border:none; border-radius:12px; background:linear-gradient(135deg,#2563eb,#1d4ed8); color:#fff; font-weight:700; cursor:pointer; margin-top:14px; }',
    '    .message { margin-top:14px; padding:12px 14px; border-radius:12px; font-size:13px; }',
    '    .message.error { background:#fef2f2; border:1px solid #fecaca; color:#991b1b; }',
    '    .message.success { background:#ecfdf5; border:1px solid #a7f3d0; color:#166534; }',
    '    .version { margin-top:14px; color:var(--muted); text-align:center; font-size:12px; }',
    '  </style>',
    '</head>',
    '<body>',
    '  <div class="box">',
    '    <div class="brand">',
    '      <div class="logo">R</div>',
    '      <h1>RIX PANEL</h1>',
    '    </div>',
    '    <div class="sub">ورود به داشبورد مدیر</div>',
    '    <form method="POST" action="/login">',
    '      <label for="password">رمز عبور پنل</label>',
    '      <input id="password" name="password" type="password" autocomplete="current-password" required>',
    '      <button type="submit">ورود</button>',
    '    </form>',
    error,
    '    <div class="version">RIX PANEL v' + VERSION + '</div>',
    '  </div>',
    '</body>',
    '</html>'
  ].join('\n');
  return html;
}

function renderPanelPage(cfg, logs) {
  const clients = Array.isArray(cfg.clients) ? cfg.clients : [];
  const rows = clients.length ? clients.map(function (client) {
    return [
      '        <tr>',
      '          <td>' + escapeHtml(client.name || 'Client') + '</td>',
      '          <td>' + escapeHtml(client.route || 'MAIN') + '</td>',
      '          <td><span class="badge ' + (client.enabled ? '' : 'off') + '">' + (client.enabled ? 'فعال' : 'غیرفعال') + '</span></td>',
      '          <td>' + (client.quotaGB === 0 ? 'نامحدود' : client.quotaGB + ' GB') + '</td>',
      '          <td>' + escapeHtml(String(client.cleanIPs ? 'بله' : 'خیر')) + '</td>',
      '          <td><button class="tiny" type="button" data-copy="' + escapeHtml('/sub/' + client.id) + '">کپی ساب</button></td>',
      '        </tr>'
    ].join('');
  }).join('\n') : '<tr><td colspan="6">هنوز کلاینتی ثبت نشده است.</td></tr>';

  const history = Array.isArray(logs) && logs.length ? logs.slice(0, 6).map(function (entry) {
    return '<li>' + escapeHtml(entry.msg || entry.type || 'event') + '</li>';
  }).join('') : '<li>هیچ رویدادی ثبت نشده است.</li>';

  const script = [
    'document.addEventListener("DOMContentLoaded", function () {',
    '  var themeSaved = localStorage.getItem("rix_theme");',
    '  if (themeSaved === "dark") document.body.classList.add("dark");',
    '  document.getElementById("themeToggle").addEventListener("click", function () {',
    '    var dark = document.body.classList.toggle("dark");',
    '    localStorage.setItem("rix_theme", dark ? "dark" : "light");',
    '  });',
    '  document.querySelectorAll("[data-copy]").forEach(function (button) {',
    '    button.addEventListener("click", function () {',
    '      navigator.clipboard.writeText(button.getAttribute("data-copy")).then(function () {',
    '        alert("کپی شد");',
    '      }).catch(function () { alert("کپی انجام نشد"); });',
    '    });',
    '  });',
    '  fetch("/api/status").then(function (res) { return res.json(); }).then(function (data) {',
    '    document.getElementById("statusBox").innerHTML = "نسخه: " + data.version + "<br>کلاینت‌ها: " + data.clientCount + "<br>VLESS: " + (data.vlessEnabled ? "فعال" : "غیرفعال") + " | Trojan: " + (data.trojanEnabled ? "فعال" : "غیرفعال");',
    '  }).catch(function () { document.getElementById("statusBox").textContent = "خطا در بارگذاری وضعیت."; });',
    '});'
  ].join('\n');

  const html = [
    '<!doctype html>',
    '<html lang="fa" dir="rtl">',
    '<head>',
    '  <meta charset="utf-8">',
    '  <meta name="viewport" content="width=device-width, initial-scale=1">',
    '  <title>RIX PANEL</title>',
    '  <style>',
    '    :root { --bg:#f5f7fb; --card:#ffffff; --line:#e5e7eb; --text:#0f172a; --muted:#475569; --primary:#2563eb; --soft:rgba(37,99,235,.12); --danger:#dc2626; --shadow:0 14px 35px rgba(15,23,42,.08); }',
    '    body.dark { --bg:#0b1220; --card:#111827; --line:#1f2937; --text:#ecf3ff; --muted:#a7b7d3; --soft:rgba(96,165,250,.14); --danger:#f87171; --shadow:0 16px 40px rgba(2,6,23,.5); }',
    '    * { box-sizing:border-box; }',
    '    html, body { margin:0; min-height:100%; background:var(--bg); color:var(--text); font-family:Tahoma,Arial,sans-serif; }',
    '    a { color:inherit; text-decoration:none; }',
    '    body { display:flex; }',
    '    .sidebar { width:240px; background:#0f172a; color:#e8eefc; min-height:100vh; padding:18px 14px; display:flex; flex-direction:column; }',
    '    .brand { display:flex; align-items:center; gap:12px; padding:8px 10px 18px; border-bottom:1px solid rgba(255,255,255,.08); }',
    '    .logo { width:38px; height:38px; border-radius:12px; background:linear-gradient(135deg,#60a5fa,#2563eb); display:grid; place-items:center; font-weight:900; }',
    '    .brand-name { font-size:18px; font-weight:800; }',
    '    .nav { display:flex; flex-direction:column; gap:6px; margin-top:14px; }',
    '    .nav a { display:flex; align-items:center; gap:10px; padding:12px 12px; border-radius:12px; color:#dfe9ff; opacity:.9; }',
    '    .nav a.active, .nav a:hover { background:rgba(255,255,255,.08); }',
    '    .version { margin-top:auto; color:#a7b7d3; font-size:12px; padding:12px 8px 0; border-top:1px solid rgba(255,255,255,.08); }',
    '    .main { flex:1; padding:18px; }',
    '    .topbar { display:flex; align-items:center; justify-content:space-between; gap:12px; padding:14px 18px; background:var(--card); border:1px solid var(--line); border-radius:18px; box-shadow:var(--shadow); }',
    '    .topbar-title { font-weight:800; font-size:20px; }',
    '    .top-actions { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }',
    '    .icon, .button, .tiny { border:1px solid var(--line); background:var(--card); color:var(--text); border-radius:12px; padding:10px 12px; cursor:pointer; }',
    '    .button.primary { background:linear-gradient(135deg,#2563eb,#1d4ed8); color:#fff; border:none; }',
    '    .button.danger { background:#fee2e2; color:#991b1b; border-color:#fecaca; }',
    '    .grid { display:grid; grid-template-columns:repeat(12, minmax(0,1fr)); gap:18px; margin-top:18px; }',
    '    .card { grid-column:span 4; background:var(--card); border:1px solid var(--line); border-radius:18px; padding:18px; box-shadow:var(--shadow); }',
    '    .card.full { grid-column:span 12; }',
    '    .card.half { grid-column:span 6; }',
    '    .card .head { display:flex; align-items:center; justify-content:space-between; margin-bottom:12px; }',
    '    h3 { margin:0; font-size:18px; }',
    '    .stat { font-size:28px; font-weight:800; }',
    '    .muted { color:var(--muted); }',
    '    .badge { display:inline-block; padding:6px 10px; border-radius:999px; background:var(--soft); color:var(--primary); font-size:12px; font-weight:700; }',
    '    .badge.off { background:rgba(220,38,38,.08); color:var(--danger); }',
    '    ul { list-style:none; padding:0; margin:0; }',
    '    li { padding:8px 0; border-bottom:1px dashed var(--line); }',
    '    table { width:100%; border-collapse:collapse; }',
    '    th,td { padding:10px 8px; border-bottom:1px solid var(--line); text-align:right; }',
    '    .tiny { padding:8px 10px; font-size:12px; }',
    '    @media (max-width: 900px) { .sidebar { width:100%; min-height:auto; } body { display:block; } .card, .card.half, .card.full { grid-column:span 12; } }',
    '  </style>',
    '</head>',
    '<body>',
    '  <aside class="sidebar">',
    '    <div class="brand">',
    '      <div class="logo">R</div>',
    '      <div class="brand-name">RIX PANEL</div>',
    '    </div>',
    '    <nav class="nav">',
    '      <a class="active" href="#">داشبورد</a>',
    '      <a href="#configs">کانفیگ‌ها</a>',
    '      <a href="#clients">کلاینت‌ها</a>',
    '      <a href="#bot">ربات</a>',
    '      <a href="#info">اطلاعات</a>',
    '      <a href="#settings">تنظیمات</a>',
    '    </nav>',
    '    <div class="version">RIX PANEL v' + VERSION + '</div>',
    '  </aside>',
    '  <main class="main">',
    '    <div class="topbar">',
    '      <div class="topbar-title">داشبورد</div>',
    '      <div class="top-actions">',
    '        <button class="icon" type="button">Support</button>',
    '        <button class="icon" type="button" id="themeToggle">☀️</button>',
    '        <span class="muted">ادمین</span>',
    '        <a class="button danger" href="/logout">خروج</a>',
    '      </div>',
    '    </div>',
    '    <div class="grid">',
    '      <div class="card">',
    '        <div class="head"><h3>کلاینت‌ها</h3><span class="badge">' + clients.length + '</span></div>',
    '        <div class="stat">' + clients.length + '</div>',
    '      </div>',
    '      <div class="card">',
    '        <div class="head"><h3>کلاینت‌های فعال</h3><span class="badge">' + clients.filter(function (c) { return c.enabled; }).length + '</span></div>',
    '        <div class="stat">' + clients.filter(function (c) { return c.enabled; }).length + '</div>',
    '      </div>',
    '      <div class="card">',
    '        <div class="head"><h3>IP تمیز</h3><span class="badge">' + (cfg.cleanIPs || []).length + '</span></div>',
    '        <div class="stat">' + (cfg.cleanIPs || []).length + '</div>',
    '      </div>',
    '      <div class="card full">',
    '        <div class="head"><h3>لینک اشتراک</h3><span class="badge ' + (cfg.vlessEnabled ? '' : 'off') + '">' + (cfg.vlessEnabled ? 'فعال' : 'غیرفعال') + '</span></div>',
    '        <div class="muted">/sub</div>',
    '        <div style="margin-top:12px"><button class="button primary" type="button" data-copy="/sub">کپی لینک اشتراک</button></div>',
    '      </div>',
    '      <div class="card half">',
    '        <div class="head"><h3>آخرین فعالیت‌ها</h3></div>',
    '        <ul>' + history + '</ul>',
    '      </div>',
    '      <div class="card half">',
    '        <div class="head"><h3>وضعیت</h3></div>',
    '        <div id="statusBox" class="muted">درحال بارگذاری...</div>',
    '      </div>',
    '      <div class="card full">',
    '        <div class="head"><h3>کلاینت‌ها</h3></div>',
    '        <table>',
    '          <thead><tr><th>نام</th><th>مسیر</th><th>وضعیت</th><th>Quota</th><th>IP تمیز</th><th>ساب</th></tr></thead>',
    '          <tbody>' + rows + '</tbody>',
    '        </table>',
    '      </div>',
    '    </div>',
    '  </main>',
    '  <script>' + script + '</script>',
    '</body>',
    '</html>'
  ].join('\n');

  return html;
}

async function handleLogin(req, env) {
  if (req.method === 'GET') {
    return new Response(renderLoginPage(''), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }

  const form = await req.formData();
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
    return redirectResponse('/panel', sessionCookieValue(token));
  }

  if (password !== cfg.panelPass) {
    return new Response(renderLoginPage('رمز عبور نامعتبر است.'), { status: 401, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }

  const token = await createSessionToken(password);
  await appendLog(env, 'successful_login', 'Successful login');
  return redirectResponse('/panel', sessionCookieValue(token));
}

async function handlePanel(req, env) {
  const auth = await requireAuth(req, env);
  if (!auth.ok) return redirectResponse('/login');
  const logs = safeJsonParse(await env.kv.get('rix_logs', 'json'), []);
  return new Response(renderPanelPage(auth.cfg, logs), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

async function handleLogout() {
  return redirectResponse('/login', SESSION_COOKIE + '=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');
}

async function handleStatus(req, env) {
  const auth = await requireAuth(req, env);
  if (!auth.ok) return jsonResponse({ error: 'Unauthorized' }, 401);
  const cfg = auth.cfg;
  const totalClients = (cfg.clients || []).length;
  const activeClients = (cfg.clients || []).filter(function (client) { return client.enabled; }).length;
  return jsonResponse({
    version: VERSION,
    hostname: 'cloudflare-worker',
    uptime: Math.max(1, Math.round((Date.now() - (cfg.created || Date.now())) / 1000)),
    vlessEnabled: !!cfg.vlessEnabled,
    trojanEnabled: !!cfg.trojanEnabled,
    nat64Enabled: !!cfg.nat64Enabled,
    proxyEnabled: !!cfg.proxyEnabled,
    cleanIPCount: (cfg.cleanIPs || []).length,
    clientCount: totalClients,
    activeClients,
    endpointCount: (cfg.endpoints || []).length,
    vlessUUIDCount: (cfg.clients || []).filter(function (client) { return isValidUuid(client.uuid); }).length + (isValidUuid(cfg.uuid) ? 1 : 0),
    todaysUsage: 0,
    telegramState: !!cfg.botEnabled,
    gatewayStates: {
      nat64: cfg.nat64Enabled ? 'active' : 'disabled',
      proxy: cfg.proxyEnabled ? 'active' : 'disabled',
      clean: (cfg.cleanIPs || []).length ? 'active' : 'disabled'
    }
  });
}

async function handleNettest(req, env) {
  const auth = await requireAuth(req, env);
  if (!auth.ok) return jsonResponse({ error: 'Unauthorized' }, 401);
  const body = await req.text();
  const data = body ? safeJsonParse(body, {}) : {};
  const kind = String(data.kind || '').toLowerCase();
  if (kind === 'nat64') {
    return jsonResponse({ ok: true, kind: 'nat64', result: await testNat64(auth.cfg) });
  }
  if (kind === 'proxy') {
    return jsonResponse({ ok: true, kind: 'proxy', result: await testProxy(auth.cfg.proxyIP || '') });
  }
  if (kind === 'clean') {
    const result = await testCleanEntries(auth.cfg.cleanIPs || [], !!data.save);
    return jsonResponse({ ok: true, kind: 'clean', result });
  }
  return jsonResponse({ error: 'Unsupported network test kind' }, 400);
}

async function handleSettings(req, env) {
  const auth = await requireAuth(req, env);
  if (!auth.ok) return jsonResponse({ error: 'Unauthorized' }, 401);
  const body = await req.text();
  const data = body ? safeJsonParse(body, {}) : {};
  const cfg = auth.cfg;
  const action = String(data.action || '').toLowerCase();

  if (action === 'uuid') {
    const value = String(data.value || '').trim();
    if (!isValidUuid(value)) return jsonResponse({ error: 'UUID invalid' }, 400);
    cfg.uuid = value;
    await saveConfig(env, cfg);
    await appendLog(env, 'uuid_change', 'UUID updated');
    return jsonResponse({ ok: true, saved: true });
  }

  if (action === 'trojan') {
    const value = String(data.value || '').trim();
    if (!value) return jsonResponse({ error: 'Trojan password required' }, 400);
    cfg.trojanPass = value;
    await saveConfig(env, cfg);
    await appendLog(env, 'trojan_password_change', 'Trojan password changed');
    return jsonResponse({ ok: true, saved: true });
  }

  if (action === 'panelpass') {
    const value = String(data.value || '').trim();
    if (!value) return jsonResponse({ error: 'Panel password required' }, 400);
    cfg.panelPass = value;
    await saveConfig(env, cfg);
    await appendLog(env, 'panel_pass_change', 'Panel password changed');
    return jsonResponse({ ok: true, saved: true });
  }

  if (action === 'proxyip') {
    cfg.proxyIP = String(data.value || '').trim();
    cfg.proxyEnabled = !!cfg.proxyIP;
    await saveConfig(env, cfg);
    await appendLog(env, 'proxyip_update', 'ProxyIP updated');
    return jsonResponse({ ok: true, saved: true });
  }

  if (action === 'nat64prefix') {
    const value = String(data.value || 'NL');
    cfg.nat64Prefix = NAT64_PREFIXES[value] ? value : 'NL';
    await saveConfig(env, cfg);
    await appendLog(env, 'nat64_update', 'NAT64 prefix updated');
    return jsonResponse({ ok: true, saved: true });
  }

  if (action === 'cleanipsmain') {
    cfg.cleanIPsMain = !!data.value;
    await saveConfig(env, cfg);
    return jsonResponse({ ok: true, saved: true });
  }

  return jsonResponse({ error: 'Unsupported settings action' }, 400);
}

async function handleCleanIPs(req, env) {
  const auth = await requireAuth(req, env);
  if (!auth.ok) return jsonResponse({ error: 'Unauthorized' }, 401);
  const body = await req.text();
  const data = body ? safeJsonParse(body, {}) : {};
  const rawList = Array.isArray(data.ips) ? data.ips : [];
  const items = [];
  for (const item of rawList) {
    const parsed = parseCleanIp(item);
    if (parsed) items.push(parsed.host + ':' + parsed.port);
  }
  const deduped = Array.from(new Set(items)).slice(0, MAX_CLEAN_IPS);
  const cfg = auth.cfg;
  cfg.cleanIPs = deduped;
  await saveConfig(env, cfg);
  await appendLog(env, 'clean_ip_list_changed', 'Clean IP list updated');
  return jsonResponse({ ok: true, saved: true, count: deduped.length });
}

async function handleClients(req, env) {
  const auth = await requireAuth(req, env);
  if (!auth.ok) return jsonResponse({ error: 'Unauthorized' }, 401);
  const body = await req.text();
  const data = body ? safeJsonParse(body, {}) : {};
  const cfg = auth.cfg;
  const action = String(data.action || '').toLowerCase();

  if (action === 'add') {
    if ((cfg.clients || []).length >= MAX_CLIENTS) return jsonResponse({ error: 'Maximum clients reached' }, 400);
    const client = {
      id: toSafeClientId(String(Date.now()) + '-' + Math.random().toString(16).slice(2, 8)),
      name: String((data.data && data.data.name) || 'Client').slice(0, 32),
      uuid: uuidv4(),
      quotaGB: clampNumber((data.data && data.data.quotaGB) || 0, 0, 1000),
      country: String((data.data && data.data.country) || 'main'),
      cleanIPs: !!(data.data && data.data.cleanIPs),
      enabled: (data.data && data.data.enabled) !== false,
      created: Date.now(),
      route: String((data.data && data.data.route) || 'MAIN').toUpperCase()
    };
    cfg.clients.push(client);
    await saveConfig(env, cfg);
    await appendLog(env, 'client_created', 'Client created: ' + client.name);
    return jsonResponse({ ok: true, client });
  }

  if (action === 'update') {
    const id = String(data.id || '');
    const target = getClientById(cfg, id);
    if (!target) return jsonResponse({ error: 'Client not found' }, 404);
    Object.assign(target, {
      name: String(data.name || target.name).slice(0, 32),
      quotaGB: clampNumber(data.quotaGB ?? target.quotaGB, 0, 1000),
      country: String(data.country || target.country),
      cleanIPs: !!(data.cleanIPs ?? target.cleanIPs),
      enabled: data.enabled !== undefined ? !!data.enabled : target.enabled,
      route: String(data.route || target.route || 'MAIN').toUpperCase()
    });
    await saveConfig(env, cfg);
    await appendLog(env, 'client_updated', 'Client updated: ' + target.name);
    return jsonResponse({ ok: true, client: target });
  }

  if (action === 'delete') {
    const id = String(data.id || '');
    const idx = cfg.clients.findIndex(function (client) { return client.id === id; });
    if (idx < 0) return jsonResponse({ error: 'Client not found' }, 404);
    const removed = cfg.clients[idx];
    cfg.clients.splice(idx, 1);
    await saveConfig(env, cfg);
    await appendLog(env, 'client_deleted', 'Client deleted: ' + removed.name);
    return jsonResponse({ ok: true });
  }

  return jsonResponse({ error: 'Unsupported client action' }, 400);
}

async function handleBot(req, env) {
  const auth = await requireAuth(req, env);
  if (!auth.ok) return jsonResponse({ error: 'Unauthorized' }, 401);
  const body = await req.text();
  const data = body ? safeJsonParse(body, {}) : {};
  const cfg = auth.cfg;
  const action = String(data.action || '').toLowerCase();

  if (action === 'save') {
    cfg.botToken = String(data.token || '').trim();
    cfg.botChatId = String(data.chatId || '').trim();
    cfg.botEnabled = !!data.enabled;
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
      return jsonResponse({ ok: true, chatIds: (json.result || []).map(function (update) { return update.message && update.message.chat ? { id: update.message.chat.id, username: update.message.chat.username || update.message.chat.first_name || 'unknown' } : null; }).filter(Boolean) });
    } catch (err) {
      return jsonResponse({ ok: false, error: String(err) }, 500);
    }
  }

  return jsonResponse({ error: 'Unsupported bot action' }, 400);
}

function buildSubscriptionText(cfg, host, rawMode) {
  const lines = [];
  const baseHost = host || 'example.com';
  if (cfg.vlessEnabled && cfg.uuid) {
    lines.push('vless://' + cfg.uuid + '@' + baseHost + ':443?encryption=none&security=tls&sni=' + baseHost + '&fp=randomized&type=ws&host=' + baseHost + '&path=' + encodeURIComponent(DEFAULT_WS_PATH) + '#RIX-VLESS');
  }
  if (cfg.trojanEnabled && cfg.trojanPass) {
    lines.push('trojan://' + cfg.trojanPass + '@' + baseHost + ':443?security=tls&sni=' + baseHost + '&fp=randomized&type=ws&host=' + baseHost + '&path=' + encodeURIComponent(DEFAULT_WS_PATH) + '#RIX-Trojan');
  }
  for (const item of cfg.cleanIPs || []) {
    const parsed = parseCleanIp(item);
    if (!parsed) continue;
    const uuid = cfg.uuid || uuidv4();
    lines.push('vless://' + uuid + '@' + baseHost + ':443?encryption=none&security=tls&sni=' + baseHost + '&fp=randomized&type=ws&host=' + baseHost + '&path=' + encodeURIComponent(DEFAULT_WS_PATH) + '#RIX-' + parsed.host);
  }
  const final = lines.join('\n');
  return rawMode ? final : btoa(final);
}

async function handleSubscription(req, env) {
  const url = new URL(req.url);
  const cfg = await getConfig(env);
  const host = req.headers.get('host') || 'example.com';
  const raw = url.searchParams.get('raw') === '1';
  const pathParts = url.pathname.split('/');
  const clientId = pathParts.length > 2 ? pathParts[2] : null;

  if (clientId) {
    const client = getClientById(cfg, clientId);
    if (!client || !client.enabled) return new Response('RIX: کلاینت غیرفعال یا حذف شده', { status: 403 });
    const lines = [];
    if (cfg.vlessEnabled) {
      lines.push('vless://' + client.uuid + '@' + host + ':443?encryption=none&security=tls&sni=' + host + '&fp=randomized&type=ws&host=' + host + '&path=' + encodeURIComponent(DEFAULT_WS_PATH) + '#RIX-' + encodeURIComponent(client.name || client.id));
    }
    if (cfg.trojanEnabled) {
      lines.push('trojan://' + cfg.trojanPass + '@' + host + ':443?security=tls&sni=' + host + '&fp=randomized&type=ws&host=' + host + '&path=' + encodeURIComponent(DEFAULT_WS_PATH) + '#RIX-' + encodeURIComponent(client.name || client.id));
    }
    const payload = raw ? lines.join('\n') : btoa(lines.join('\n'));
    return new Response(payload, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Profile-Title': 'RIX PANEL', 'Profile-Update-Interval': '0', 'Cache-Control': 'no-store' } });
  }

  const payload = buildSubscriptionText(cfg, host, raw);
  return new Response(payload, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Profile-Title': 'RIX PANEL', 'Profile-Update-Interval': '0', 'Cache-Control': 'no-store' } });
}

export default {
  async fetch(request, env, ctx) {
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
      if (path === '/api/cleanips') return handleCleanIPs(request, env);
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

if (typeof globalThis !== 'undefined') {
  globalThis.__RIX_VERSION = VERSION;
}

if (typeof globalThis !== 'undefined') {
  globalThis.__ENV__ = globalThis.__ENV__ || undefined;
}
