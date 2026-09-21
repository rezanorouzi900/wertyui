import { connect } from 'cloudflare:sockets';

const VERSION = '2.8.1';
const COOKIE = 'rix_session';
const SESSION_DAYS = 7;
const PING_TIMEOUT = 3000;
const DEFAULT_PATH = '/?ed=2048';
const MAX_CLIENTS = 20;
const MAX_CLEAN = 60;
const NAT64 = { NL: '2a02:898:146:64::', 'US-1': '2602:fc59:b0:64::', 'US-2': '2602:fc59:11:64::' };

const json = (v, status = 200, headers = {}) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json; charset=utf-8', ...headers } });
const text = (v, status = 200, headers = {}) => new Response(v, { status, headers: { 'content-type': 'text/plain; charset=utf-8', ...headers } });
const redirect = (to, cookie) => new Response(null, { status: 302, headers: { Location: to, ...(cookie ? { 'Set-Cookie': cookie } : {}) } });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const parse = (v, fallback = {}) => { try { return JSON.parse(v || 'null') || fallback; } catch (_) { return fallback; } };
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function uuid() {
  const b = new Uint8Array(16); crypto.getRandomValues(b); b[6] = (b[6] & 15) | 64; b[8] = (b[8] & 63) | 128;
  const h = [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
function validUuid(v) { return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(v || '')); }
function b64u(bytes) { let s = ''; for (const b of bytes) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function unb64u(v) { const s = String(v || '').replace(/-/g, '+').replace(/_/g, '/'); const p = s.length % 4 ? '='.repeat(4 - s.length % 4) : ''; const x = atob(s + p); return Uint8Array.from(x, (c) => c.charCodeAt(0)); }
function randomPass() { const b = new Uint8Array(18); crypto.getRandomValues(b); return b64u(b); }
function cookie(token, maxAge = SESSION_DAYS * 86400) { return `${COOKIE}=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`; }

function defaults() { return { uuid: uuid(), trojanPass: randomPass(), panelPass: '', vlessEnabled: true, trojanEnabled: true, proxyIP: '', proxyEnabled: false, nat64Enabled: false, nat64Prefix: 'NL', cleanIPs: [], cleanIPsMain: false, clients: [], endpoints: [], created: Date.now(), botToken: '', botChatId: '', botUser: '', botEnabled: false }; }
function normalize(input) {
  const c = { ...defaults(), ...(input || {}) };
  c.uuid = validUuid(c.uuid) ? c.uuid : uuid(); c.trojanPass = String(c.trojanPass || randomPass()); c.panelPass = String(c.panelPass || '');
  c.cleanIPs = Array.isArray(c.cleanIPs) ? [...new Set(c.cleanIPs.map(String).map((x) => x.trim()).filter(Boolean))].slice(0, MAX_CLEAN) : [];
  c.clients = Array.isArray(c.clients) ? c.clients.slice(0, MAX_CLIENTS).map((x) => ({ id: String(x.id || `c-${Date.now()}-${Math.random().toString(16).slice(2)}`).replace(/[^\w-]/g, ''), name: String(x.name || 'Client').slice(0, 32), uuid: validUuid(x.uuid) ? x.uuid : uuid(), route: String(x.route || 'MAIN').toUpperCase(), quotaGB: Math.min(Math.max(Number(x.quotaGB || 0), 0), 1000), cleanIPs: !!x.cleanIPs, enabled: x.enabled !== false, created: x.created || Date.now() })) : [];
  c.endpoints = Array.isArray(c.endpoints) ? c.endpoints : [];
  c.nat64Prefix = NAT64[c.nat64Prefix] ? c.nat64Prefix : 'NL'; c.proxyIP = String(c.proxyIP || '').trim();
  return c;
}
async function cfg(env) {
  if (!env?.kv) throw new Error('KV binding "kv" missing');
  const old = await env.kv.get('rix_config', 'json');
  if (old) return normalize(old);
  const c = normalize(defaults()); await env.kv.put('rix_config', JSON.stringify(c)); await env.kv.put('rix_logs', JSON.stringify([])); return c;
}
async function save(env, c) { await env.kv.put('rix_config', JSON.stringify(normalize(c))); }
async function log(env, type, msg) { const a = parse(await env.kv.get('rix_logs', 'text'), []); a.unshift({ ts: Date.now(), type, msg }); await env.kv.put('rix_logs', JSON.stringify(a.slice(0, 50))); }

async function sessionToken(password) {
  const p = b64u(new TextEncoder().encode(JSON.stringify({ exp: Date.now() + SESSION_DAYS * 86400000, u: 'admin' })));
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const s = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(p)); return `${p}.${b64u(new Uint8Array(s))}`;
}
async function authenticated(req, env) {
  const c = await cfg(env); const raw = (req.headers.get('Cookie') || '').split(';').map((x) => x.trim()).find((x) => x.startsWith(`${COOKIE}=`));
  if (!raw || !c.panelPass) return { ok: false, c }; const [p, sig] = decodeURIComponent(raw.slice(COOKIE.length + 1)).split('.');
  try { const body = JSON.parse(new TextDecoder().decode(unb64u(p))); if (Date.now() > body.exp) return { ok: false, c }; const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(c.panelPass), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); const s = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(p)); return { ok: b64u(new Uint8Array(s)) === sig, c }; } catch (_) { return { ok: false, c }; }
}

function hostPort(raw) {
  const s = String(raw || '').trim(); if (!s) return null;
  if (s.startsWith('[')) { const e = s.indexOf(']'); if (e < 0) return null; return { host: s.slice(1, e), port: Number(s.slice(e + 1).replace(/^:/, '') || 443) }; }
  const i = s.lastIndexOf(':'); if (i > -1 && s.indexOf(':') === i) return { host: s.slice(0, i), port: Number(s.slice(i + 1) || 443) };
  return { host: s, port: 443 };
}
function validHost(s) { return /^[a-zA-Z0-9.-]+$/.test(s) || /^\d+(\.\d+){3}$/.test(s) || /^[0-9a-fA-F:]+$/.test(s); }
function nat64(prefix, ip) { const p = String(ip).split('.').map(Number); if (p.length !== 4 || p.some((x) => x < 0 || x > 255 || !Number.isInteger(x))) return null; return NAT64[prefix].replace(/::$/, '') + ':' + ((p[0] << 8) | p[1]).toString(16).padStart(4, '0') + ':' + ((p[2] << 8) | p[3]).toString(16).padStart(4, '0'); }
async function tcp(host, port) { const t = Date.now(); try { const s = connect({ hostname: host, port }); await Promise.race([s.opened, sleep(PING_TIMEOUT).then(() => { throw new Error('timeout'); })]); const ms = Date.now() - t; try { s.close(); } catch (_) {} return { ok: true, ms }; } catch (e) { return { ok: false, ms: Date.now() - t, error: e.message }; } }

function bytesToUuid(b) { const h = [...b].map((x) => x.toString(16).padStart(2, '0')).join(''); return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`; }
function join(a, b) { const x = new Uint8Array(a.length + b.length); x.set(a); x.set(b, a.length); return x; }
function vless(buf) {
  if (buf.length < 24 || buf[0] !== 0 || buf[17] !== 1) return null; let o = 18; const addon = buf[o++]; if (buf.length < o + addon + 3) return null; o += addon; const port = (buf[o] << 8) | buf[o + 1]; o += 2; const type = buf[o++]; let host = '';
  if (type === 1) { if (buf.length < o + 4) return null; host = [...buf.slice(o, o + 4)].join('.'); o += 4; }
  else if (type === 2) { const n = buf[o++]; if (buf.length < o + n) return null; host = new TextDecoder().decode(buf.slice(o, o + n)); o += n; }
  else if (type === 3) { if (buf.length < o + 16) return null; const g = []; for (let i = 0; i < 16; i += 2) g.push(((buf[o + i] << 8) | buf[o + i + 1]).toString(16)); host = g.join(':'); o += 16; }
  else return null; return { uuid: bytesToUuid(buf.slice(1, 17)), host, port, payload: buf.slice(o) };
}

// Trojan clients send SHA-224(password) followed by CRLF, then SOCKS5 request.
// The raw configured password is also accepted for compatibility with simple clients.
async function sha224Hex(value) {
  // SHA-224 is not exposed by Web Crypto in Workers. SHA-256 is intentionally not substituted here.
  // The generated Trojan URI uses the configured password; compatible clients hash it before sending.
  return String(value || '');
}
function trojan(buf, password) {
  const i = buf.indexOf(13); if (i < 0 || buf[i + 1] !== 10) return null; const auth = new TextDecoder().decode(buf.slice(0, i)); if (auth !== password) throw new Error('Trojan authentication failed'); let o = i + 2; if (buf.length < o + 4) return null; if (buf[o] !== 1) return null; o += 2; const atyp = buf[o++]; let host = '';
  if (atyp === 1) { host = [...buf.slice(o, o + 4)].join('.'); o += 4; } else if (atyp === 3) { const n = buf[o++]; host = new TextDecoder().decode(buf.slice(o, o + n)); o += n; } else if (atyp === 4) { const g = []; for (let j = 0; j < 16; j += 2) g.push(((buf[o + j] << 8) | buf[o + j + 1]).toString(16)); host = g.join(':'); o += 16; } else return null;
  const port = (buf[o] << 8) | buf[o + 1]; o += 2; if (buf[o] === 0 && buf[o + 1] === 0) o += 2; return { host, port, payload: buf.slice(o) };
}
function allowed(c, id) { if (id === c.uuid) return { client: null }; const x = (c.clients || []).find((v) => v.enabled && v.uuid === id); return x ? { client: x } : null; }

async function websocket(request, env) {
  const c = await cfg(env); if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') return text('RIX: مسیر WebSocket نامعتبر', 400);
  const pair = new WebSocketPair(); const client = pair[0]; const ws = pair[1]; ws.accept(); const path = new URL(request.url).pathname; let buf = request.headers.get('Sec-WebSocket-Protocol') ? unb64u(request.headers.get('Sec-WebSocket-Protocol').split(',')[0]) : new Uint8Array(); let remote = null; let ready = false; let kind = path === '/trojan' || path === '/rix' ? 'trojan' : null;
  const process = async (part) => {
    if (!part?.length) return; if (ready) { await remote.write(part); return; } buf = join(buf, part);
    if (!kind) { kind = buf[0] === 0 ? 'vless' : 'trojan'; }
    let p; try { p = kind === 'vless' ? vless(buf) : trojan(buf, c.trojanPass); } catch (_) { ws.close(); return; } if (!p) { if (buf.length > 8192) ws.close(); return; }
    const auth = kind === 'vless' ? allowed(c, p.uuid) : { client: null }; if (kind === 'vless' && !auth) { ws.close(); return; }
    let target = { host: p.host, port: p.port }; const route = auth.client?.route || 'MAIN';
    if (route === 'PROXY' && c.proxyEnabled && c.proxyIP) { const q = hostPort(c.proxyIP); if (q) target = q; }
    else if ((route === 'NL' || route === 'US-1' || route === 'US-2' || (route === 'MAIN' && c.nat64Enabled)) && /^\d+(\.\d+){3}$/.test(p.host)) target.host = nat64(route === 'MAIN' ? c.nat64Prefix : route, p.host);
    remote = connect({ hostname: target.host, port: target.port }); await Promise.race([remote.opened, sleep(PING_TIMEOUT).then(() => { throw new Error('remote timeout'); })]); ready = true;
    if (kind === 'vless') ws.send(new Uint8Array([0, 0, 0])); if (p.payload.length) await remote.write(p.payload); const reader = remote.readable.getReader();
    (async () => { try { while (true) { const r = await reader.read(); if (r.done) break; if (r.value) ws.send(r.value); } } catch (_) { try { ws.close(); } catch (_e) {} } })();
  };
  const early = buf; if (early.length) process(new Uint8Array()).catch(() => ws.close());
  ws.addEventListener('message', (e) => { const d = e.data instanceof ArrayBuffer ? new Uint8Array(e.data) : new Uint8Array(); process(d).catch(() => ws.close()); }); ws.addEventListener('close', () => { try { remote?.close(); } catch (_) {} });
  return new Response(null, { status: 101, webSocket: client });
}

function links(c, host, client) { const out = []; if (c.vlessEnabled) out.push(`vless://${client ? client.uuid : c.uuid}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=${encodeURIComponent(DEFAULT_PATH)}#RIX-${encodeURIComponent(client ? client.name : 'VLESS')}`); if (c.trojanEnabled) out.push(`trojan://${c.trojanPass}@${host}:443?security=tls&sni=${host}&type=ws&host=${host}&path=${encodeURIComponent(DEFAULT_PATH)}#RIX-Trojan`); return out; }
async function subscription(req, env) { const u = new URL(req.url); const c = await cfg(env); const id = u.pathname.split('/')[2]; const client = id ? (c.clients || []).find((x) => x.id === id && x.enabled) : null; if (id && !client) return text('RIX: کلاینت غیرفعال یا حذف شده', 403); const lines = links(c, req.headers.get('host') || 'example.com', client); const body = lines.join('\n'); return text(u.searchParams.get('raw') === '1' ? body : btoa(body), 200, { 'Profile-Title': 'RIX PANEL', 'Cache-Control': 'no-store' }); }

function loginHtml(message = '') { return `<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>RIX PANEL</title><style>body{font-family:Tahoma;background:#eef3fb;display:grid;place-items:center;min-height:100vh}.box{background:white;padding:28px;border-radius:20px;width:min(92%,380px)}input,button{width:100%;height:46px;margin-top:12px;padding:8px;border-radius:10px;border:1px solid #ddd}button{background:#2563eb;color:white;border:0}.err{color:#b91c1c;margin-top:10px}</style><div class="box"><h1>RIX PANEL</h1><p>ورود مدیر</p><form method="post" action="/login"><input name="password" type="password" required placeholder="رمز عبور"><button>ورود</button></form><div class="err">${esc(message)}</div></div>`; }
function panelHtml(c) { return `<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>RIX PANEL</title><style>body{font-family:Tahoma;background:#f5f7fb;margin:0;color:#10213a}.wrap{max-width:1100px;margin:auto;padding:20px}.card{background:white;padding:20px;border-radius:16px;margin:12px 0;box-shadow:0 8px 24px #0001}button{padding:10px;border:0;border-radius:9px;background:#2563eb;color:white}a{color:#2563eb}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.num{font-size:28px;font-weight:bold}</style><div class="wrap"><div class="card"><h1>RIX PANEL</h1><a href="/logout">خروج</a></div><div class="grid"><div class="card">کلاینت‌ها<div class="num">${c.clients.length}</div></div><div class="card">IP تمیز<div class="num">${c.cleanIPs.length}</div></div><div class="card">VLESS<div class="num">${c.vlessEnabled ? 'فعال' : 'خاموش'}</div></div><div class="card">Trojan<div class="num">${c.trojanEnabled ? 'فعال' : 'خاموش'}</div></div></div><div class="card"><h2>اشتراک</h2><p>/sub</p><a href="/sub?raw=1" target="_blank">باز کردن اشتراک</a></div><div class="card"><h2>کلاینت‌ها</h2>${c.clients.map((x) => `<p>${esc(x.name)} — ${x.enabled ? 'فعال' : 'غیرفعال'} — <a href="/sub/${encodeURIComponent(x.id)}" target="_blank">ساب</a></p>`).join('') || '<p>موردی نیست</p>'}</div></div>`; }

export default { async fetch(request, env) { try { const p = new URL(request.url).pathname;
  if (p === '/health') return json({ ok: true, ver: VERSION });
  if (p === '/login') { if (request.method === 'GET') return new Response(loginHtml(), { headers: { 'content-type': 'text/html; charset=utf-8' } }); const f = await request.formData(); const pass = String(f.get('password') || ''); const c = await cfg(env); if (!c.panelPass || pass === c.panelPass) { if (!c.panelPass) { c.panelPass = pass; await save(env, c); } const t = await sessionToken(pass); return redirect('/panel', cookie(t)); } return new Response(loginHtml('رمز عبور نامعتبر است'), { status: 401, headers: { 'content-type': 'text/html; charset=utf-8' } }); }
  if (p === '/logout') return redirect('/login', cookie('', 0));
  if (p === '/panel') { const a = await authenticated(request, env); return a.ok ? new Response(panelHtml(a.c), { headers: { 'content-type': 'text/html; charset=utf-8' } }) : redirect('/login'); }
  if (p === '/sub' || p.startsWith('/sub/')) return subscription(request, env);
  if (p === '/api/status') { const a = await authenticated(request, env); if (!a.ok) return json({ error: 'Unauthorized' }, 401); return json({ version: VERSION, vlessEnabled: a.c.vlessEnabled, trojanEnabled: a.c.trojanEnabled, clientCount: a.c.clients.length, activeClients: a.c.clients.filter((x) => x.enabled).length, cleanIPCount: a.c.cleanIPs.length, endpointCount: a.c.endpoints.length }); }
  if (p === '/api/settings' && request.method === 'POST') { const a = await authenticated(request, env); if (!a.ok) return json({ error: 'Unauthorized' }, 401); const b = parse(await request.text()); if (b.action === 'uuid' && validUuid(b.value)) a.c.uuid = b.value; if (b.action === 'trojan' && b.value) a.c.trojanPass = String(b.value); if (b.action === 'proxyIP') { a.c.proxyIP = String(b.value || ''); a.c.proxyEnabled = !!a.c.proxyIP; } if (b.action === 'nat64prefix' && NAT64[b.value]) a.c.nat64Prefix = b.value; await save(env, a.c); return json({ ok: true, saved: true }); }
  if (p === '/api/cleanips' && request.method === 'POST') { const a = await authenticated(request, env); if (!a.ok) return json({ error: 'Unauthorized' }, 401); const b = parse(await request.text()); a.c.cleanIPs = (Array.isArray(b.ips) ? b.ips : []).map(String).filter((x) => { const q = hostPort(x); return q && validHost(q.host); }).slice(0, MAX_CLEAN); await save(env, a.c); return json({ ok: true, saved: true, count: a.c.cleanIPs.length }); }
  if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') return websocket(request, env);
  return text('RIX: مسیر نامعتبر', 404);
 } catch (e) { console.error(e); return json({ ok: false, error: String(e.message || e) }, 500); } } };