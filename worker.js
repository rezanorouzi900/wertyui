import { connect } from "cloudflare:sockets";

/* =========================================================
   RIX PANEL
   VLESS + WebSocket + TLS
   Multi User / Multi Config / Clean IP
   SQLite Durable Object
   ========================================================= */

/* =========================================================
   CONFIG
   ========================================================= */

const WS_PATH = "/ws";

/*
  بکگراند DARK
  لینک عکس خودت را اینجا قرار بده
*/
const DARK_BACKGROUND_URL =
  "https://YOUR-DARK-BACKGROUND.jpg";

/*
  بکگراند LIGHT
  لینک عکس خودت را اینجا قرار بده
*/
const LIGHT_BACKGROUND_URL =
  "https://YOUR-LIGHT-BACKGROUND.jpg";

/*
  این مقدار را به عنوان Worker Secret تنظیم کن.

  مثال:
  ADMIN_TOKEN = rix-panel-secret-2026

  هیچ‌وقت توکن واقعی را داخل کد عمومی قرار نده.
*/
const ADMIN_TOKEN_ENV = "ADMIN_TOKEN";


/* =========================================================
   GLOBAL HELPERS
   ========================================================= */

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: JSON_HEADERS
  });
}

function text(data, status = 200, headers = {}) {
  return new Response(data, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      ...headers
    }
  });
}

function now() {
  return Date.now();
}

function randomId() {
  return crypto.randomUUID();
}

function randomToken() {
  return crypto.randomUUID().replaceAll("-", "") +
    crypto.randomUUID().replaceAll("-", "");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeJsString(value) {
  return JSON.stringify(String(value ?? ""))
    .replaceAll("<", "\\u003C")
    .replaceAll(">", "\\u003E")
    .replaceAll("&", "\\u0026");
}

function isValidUUID(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    .test(String(value || ""));
}

function isValidIPv4(ip) {
  const parts = String(ip).split(".");
  if (parts.length !== 4) return false;

  return parts.every((part) => {
    if (!/^\d+$/.test(part)) return false;
    const n = Number(part);
    return n >= 0 && n <= 255;
  });
}

function isValidIPv6(ip) {
  const value = String(ip).trim();

  if (!value.includes(":")) {
    return false;
  }

  if (!/^[0-9a-fA-F:.]+$/.test(value)) {
    return false;
  }

  const parts = value.split(":");

  if (parts.length > 8) {
    return false;
  }

  let compressed = false;

  for (const part of parts) {
    if (part === "") {
      compressed = true;
      continue;
    }

    if (!/^[0-9a-fA-F]{1,4}$/.test(part)) {
      return false;
    }
  }

  return compressed || parts.length === 8;
}

function isValidIP(ip) {
  const value = String(ip || "").trim();

  return isValidIPv4(value) || isValidIPv6(value);
}

function formatEndpoint(ip) {
  const value = String(ip || "").trim();

  if (value.includes(":")) {
    return `[${value}]`;
  }

  return value;
}

function getOriginHost(request) {
  return new URL(request.url).hostname;
}

function getGlobalDO(env) {
  if (!env.RIXDO) {
    throw new Error("RIXDO binding is missing");
  }

  const id = env.RIXDO.idFromName("RIX-GLOBAL");
  return env.RIXDO.get(id);
}


/* =========================================================
   ADMIN AUTH
   ========================================================= */

function getBearerToken(request) {
  const value = request.headers.get("authorization") || "";

  if (!value.toLowerCase().startsWith("bearer ")) {
    return "";
  }

  return value.slice(7).trim();
}

function requireAdmin(request, env) {
  const expected = env[ADMIN_TOKEN_ENV];

  if (!expected) {
    return new Response(
      JSON.stringify({
        ok: false,
        error: "ADMIN_TOKEN is not configured"
      }),
      {
        status: 503,
        headers: JSON_HEADERS
      }
    );
  }

  const supplied = getBearerToken(request);

  if (!supplied || supplied !== expected) {
    return new Response(
      JSON.stringify({
        ok: false,
        error: "Unauthorized"
      }),
      {
        status: 401,
        headers: {
          ...JSON_HEADERS,
          "www-authenticate": "Bearer"
        }
      }
    );
  }

  return null;
}


/* =========================================================
   DO REQUEST
   ========================================================= */

async function doRequest(env, path, options = {}) {
  const stub = getGlobalDO(env);

  const request = new Request(
    "https://rixdo.internal" + path,
    {
      method: options.method || "GET",
      headers: {
        "content-type": "application/json"
      },
      body:
        options.body === undefined
          ? undefined
          : JSON.stringify(options.body)
    }
  );

  return stub.fetch(request);
}

async function doJson(env, path, options = {}) {
  const response = await doRequest(env, path, options);

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      data.error || "Durable Object error"
    );
  }

  return data;
}


/* =========================================================
   VLESS PARSER
   ========================================================= */

function uuidBytesFromString(uuid) {
  const clean = uuid.replaceAll("-", "");

  const bytes = new Uint8Array(16);

  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(
      clean.slice(i * 2, i * 2 + 2),
      16
    );
  }

  return bytes;
}

function uuidFromBytes(bytes) {
  const hex = [...bytes]
    .map((b) =>
      b.toString(16).padStart(2, "0")
    )
    .join("");

  return (
    hex.slice(0, 8) +
    "-" +
    hex.slice(8, 12) +
    "-" +
    hex.slice(12, 16) +
    "-" +
    hex.slice(16, 20) +
    "-" +
    hex.slice(20, 32)
  );
}

function readUint16(view, offset) {
  return (
    (view[offset] << 8) |
    view[offset + 1]
  );
}

function readAddress(view, offset) {
  const type = view[offset];
  let cursor = offset + 1;

  if (type === 1) {
    if (cursor + 4 > view.length) {
      throw new Error("Invalid IPv4");
    }

    const host = [
      view[cursor],
      view[cursor + 1],
      view[cursor + 2],
      view[cursor + 3]
    ].join(".");

    return {
      host,
      offset: cursor + 4
    };
  }

  if (type === 2) {
    const length = view[cursor];

    cursor++;

    if (
      cursor + length >
      view.length
    ) {
      throw new Error("Invalid domain");
    }

    const host = new TextDecoder().decode(
      view.slice(
        cursor,
        cursor + length
      )
    );

    return {
      host,
      offset: cursor + length
    };
  }

  if (type === 3) {
    if (cursor + 16 > view.length) {
      throw new Error("Invalid IPv6");
    }

    const chunks = [];

    for (let i = 0; i < 8; i++) {
      chunks.push(
        (
          (view[cursor + i * 2] << 8) |
          view[cursor + i * 2 + 1]
        ).toString(16)
      );
    }

    return {
      host: chunks.join(":"),
      offset: cursor + 16
    };
  }

  throw new Error(
    "Unsupported address type"
  );
}

function parseVlessRequest(buffer) {
  const view = new Uint8Array(buffer);

  if (view.length < 24) {
    throw new Error("VLESS request too short");
  }

  const version = view[0];

  if (version !== 0 && version !== 1) {
    throw new Error("Invalid VLESS version");
  }

  const uuid = uuidFromBytes(
    view.slice(1, 17)
  );

  const optionLength = view[17];

  let offset = 18 + optionLength;

  if (offset + 4 > view.length) {
    throw new Error("Invalid VLESS header");
  }

  const command = view[offset];

  offset++;

  if (command !== 1) {
    throw new Error(
      "Only TCP VLESS is supported"
    );
  }

  const port = readUint16(
    view,
    offset
  );

  offset += 2;

  const address = readAddress(
    view,
    offset
  );

  offset = address.offset;

  return {
    version,
    uuid,
    host: address.host,
    port,
    command,
    payload: view.slice(offset)
  };
}


/* =========================================================
   SOCKET RELAY
   ========================================================= */

async function relaySocket(
  socket,
  websocket,
  initialPayload,
  responseHeader
) {
  const writer =
    socket.writable.getWriter();

  const reader =
    socket.readable.getReader();

  let wsClosed = false;

  websocket.addEventListener(
    "close",
    () => {
      wsClosed = true;

      try {
        writer.close();
      } catch {}
    }
  );

  websocket.addEventListener(
    "error",
    () => {
      wsClosed = true;

      try {
        writer.close();
      } catch {}
    }
  );

  try {
    if (initialPayload?.length) {
      await writer.write(initialPayload);
    }

    writer.releaseLock();

    let first = true;

    while (!wsClosed) {
      const result =
        await reader.read();

      if (result.done) {
        break;
      }

      const chunk =
        new Uint8Array(result.value);

      if (first) {
        first = false;

        websocket.send(
          concatBytes(
            responseHeader,
            chunk
          )
        );
      } else {
        websocket.send(chunk);
      }
    }
  } catch {
    // connection closed
  } finally {
    try {
      reader.releaseLock();
    } catch {}

    try {
      websocket.close();
    } catch {}

    try {
      socket.close();
    } catch {}
  }
}

function concatBytes(a, b) {
  const result =
    new Uint8Array(
      a.length + b.length
    );

  result.set(a, 0);
  result.set(b, a.length);

  return result;
}


/* =========================================================
   VLESS WEBSOCKET
   ========================================================= */

async function handleVlessWebSocket(
  request,
  env
) {
  if (
    request.headers.get("Upgrade")
      ?.toLowerCase() !== "websocket"
  ) {
    return new Response(
      "WebSocket required",
      { status: 426 }
    );
  }

  const pair =
    new WebSocketPair();

  const client =
    pair[0];

  const server =
    pair[1];

  server.accept();

  let buffer = new Uint8Array(0);
  let connected = false;

  const timeout =
    setTimeout(() => {
      if (!connected) {
        try {
          server.close();
        } catch {}
      }
    }, 15000);

  server.addEventListener(
    "message",
    async (event) => {
      try {
        const incoming =
          typeof event.data === "string"
            ? new TextEncoder().encode(
                event.data
              )
            : new Uint8Array(
                event.data
              );

        if (connected) {
          return;
        }

        buffer = concatBytes(
          buffer,
          incoming
        );

        /*
          برای جلوگیری از پردازش ناقص،
          تا حداقل اندازه هدر صبر می‌کنیم.
        */
        if (buffer.length < 24) {
          return;
        }

        clearTimeout(timeout);

        const parsed =
          parseVlessRequest(buffer);

        /*
          UUID واقعی را از DO بررسی می‌کنیم.
        */
        const user =
          await doJson(
            env,
            "/internal/verify",
            {
              method: "POST",
              body: {
                uuid: parsed.uuid
              }
            }
          );

        if (
          !user.ok ||
          !user.enabled
        ) {
          throw new Error(
            "Invalid or disabled UUID"
          );
        }

        /*
          فقط TCP.
        */
        const socket =
          await connect({
            hostname: parsed.host,
            port: parsed.port
          });

        connected = true;

        const responseHeader =
          new Uint8Array([
            parsed.version,
            0
          ]);

        /*
          هر چیزی بعد از مقصد را به مقصد
          ارسال می‌کنیم.
        */
        await relaySocket(
          socket,
          server,
          parsed.payload,
          responseHeader
        );
      } catch (error) {
        try {
          server.send(
            JSON.stringify({
              error:
                error?.message ||
                "Connection failed"
            })
          );
        } catch {}

        try {
          server.close();
        } catch {}
      }
    }
  );

  server.addEventListener(
    "close",
    () => {
      clearTimeout(timeout);
    }
  );

  return new Response(null, {
    status: 101,
    webSocket: client
  });
}


/* =========================================================
   SUBSCRIPTION
   ========================================================= */

async function subscription(
  request,
  env,
  token
) {
  if (!token) {
    return text(
      "Subscription token required",
      400
    );
  }

  const data =
    await doJson(
      env,
      "/internal/sub/" +
        encodeURIComponent(token)
    );

  if (!data.ok) {
    return text(
      "Subscription not found",
      404
    );
  }

  return new Response(
    data.configs.join("\n"),
    {
      status: 200,
      headers: {
        "content-type":
          "text/plain; charset=utf-8",
        "cache-control":
          "no-store"
      }
    }
  );
}


/* =========================================================
   VLESS URL
   ========================================================= */

function buildVlessURL({
  uuid,
  endpoint,
  host,
  name
}) {
  const address =
    formatEndpoint(endpoint);

  const params =
    new URLSearchParams();

  params.set(
    "encryption",
    "none"
  );

  params.set(
    "security",
    "tls"
  );

  params.set(
    "type",
    "ws"
  );

  params.set(
    "host",
    host
  );

  params.set(
    "sni",
    host
  );

  params.set(
    "path",
    WS_PATH
  );

  return (
    "vless://" +
    uuid +
    "@" +
    address +
    ":443?" +
    params.toString() +
    "#" +
    encodeURIComponent(
      "RIX-" + name
    )
  );
}


/* =========================================================
   API ROUTES
   ========================================================= */

async function apiUsers(
  request,
  env
) {
  const auth =
    requireAdmin(request, env);

  if (auth) return auth;

  if (request.method === "GET") {
    return await doRequest(
      env,
      "/users"
    );
  }

  if (request.method === "POST") {
    const body =
      await request.json();

    const name =
      String(
        body.name || ""
      ).trim();

    if (!name) {
      return json(
        {
          ok: false,
          error:
            "User name required"
        },
        400
      );
    }

    return await doRequest(
      env,
      "/users",
      {
        method: "POST",
        body: { name }
      }
    );
  }

  return text(
    "Method Not Allowed",
    405
  );
}


async function apiUser(
  request,
  env,
  id
) {
  const auth =
    requireAdmin(request, env);

  if (auth) return auth;

  if (
    request.method === "DELETE"
  ) {
    return await doRequest(
      env,
      "/users/" +
        encodeURIComponent(id),
      {
        method: "DELETE"
      }
    );
  }

  return text(
    "Method Not Allowed",
    405
  );
}


async function apiConfigs(
  request,
  env
) {
  const auth =
    requireAdmin(request, env);

  if (auth) return auth;

  if (request.method === "GET") {
    const url =
      new URL(request.url);

    const userId =
      url.searchParams.get(
        "user_id"
      ) || "";

    return await doRequest(
      env,
      "/configs?user_id=" +
        encodeURIComponent(userId)
    );
  }

  if (request.method === "POST") {
    const body =
      await request.json();

    return await doRequest(
      env,
      "/configs",
      {
        method: "POST",
        body
      }
    );
  }

  return text(
    "Method Not Allowed",
    405
  );
}


async function apiConfig(
  request,
  env,
  id
) {
  const auth =
    requireAdmin(request, env);

  if (auth) return auth;

  if (
    request.method === "DELETE"
  ) {
    return await doRequest(
      env,
      "/configs/" +
        encodeURIComponent(id),
      {
        method: "DELETE"
      }
    );
  }

  return text(
    "Method Not Allowed",
    405
  );
}


async function apiIPs(
  request,
  env
) {
  const auth =
    requireAdmin(request, env);

  if (auth) return auth;

  if (request.method === "GET") {
    return await doRequest(
      env,
      "/ips"
    );
  }

  if (request.method === "POST") {
    const body =
      await request.json();

    return await doRequest(
      env,
      "/ips",
      {
        method: "POST",
        body
      }
    );
  }

  return text(
    "Method Not Allowed",
    405
  );
}


async function apiIP(
  request,
  env,
  id
) {
  const auth =
    requireAdmin(request, env);

  if (auth) return auth;

  if (
    request.method === "DELETE"
  ) {
    return await doRequest(
      env,
      "/ips/" +
        encodeURIComponent(id),
      {
        method: "DELETE"
      }
    );
  }

  if (
    request.method === "PATCH"
  ) {
    const body =
      await request.json();

    return await doRequest(
      env,
      "/ips/" +
        encodeURIComponent(id),
      {
        method: "PATCH",
        body
      }
    );
  }

  return text(
    "Method Not Allowed",
    405
  );
}


/* =========================================================
   HEALTH
   ========================================================= */

async function health(
  request,
  env
) {
  let storage = false;

  try {
    await doJson(
      env,
      "/internal/health"
    );

    storage = true;
  } catch {}

  return json({
    ok: true,
    service: "RIX PANEL",
    vless: true,
    websocket: true,
    storage,
    timestamp: now()
  });
}


/* =========================================================
   HTML
   ========================================================= */

const HTML = String.raw`<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width,
               initial-scale=1,
               maximum-scale=1">

<title>RIX PANEL</title>

<style>

* {
  box-sizing:border-box;
}

:root {
  --bg:#07080d;
  --panel:rgba(15,17,25,.88);
  --panel2:rgba(20,22,32,.94);
  --line:rgba(255,255,255,.08);
  --text:#f4f6fb;
  --muted:#858b9d;
  --purple:#7b4dff;
  --purple2:#5d35d8;
  --cyan:#19c7ef;
  --green:#19c77a;
  --red:#ff526f;
  --shadow:0 18px 55px rgba(0,0,0,.28);
  --bg-image:none;
}

html,
body {
  margin:0;
  width:100%;
  min-height:100%;
}

body {
  min-height:100vh;
  background:
    linear-gradient(
      135deg,
      rgba(5,6,10,.92),
      rgba(9,10,17,.86)
    ),
    var(--bg-image),
    var(--bg);

  background-size:cover;
  background-position:center;
  background-attachment:fixed;

  color:var(--text);
  font-family:
    Tahoma,
    Arial,
    sans-serif;

  overflow-x:hidden;
  transition:
    background .25s ease,
    color .25s ease;
}

body.light {
  --bg:#edf0f7;
  --panel:rgba(255,255,255,.80);
  --panel2:rgba(255,255,255,.94);
  --line:rgba(20,30,50,.10);
  --text:#151925;
  --muted:#687083;
  --shadow:0 18px 55px rgba(30,40,60,.12);

  background:
    linear-gradient(
      135deg,
      rgba(244,246,251,.78),
      rgba(238,241,247,.88)
    ),
    var(--bg-image),
    var(--bg);
}

button,
input,
select {
  font:inherit;
}

button {
  cursor:pointer;
}

::-webkit-scrollbar {
  width:7px;
  height:7px;
}

::-webkit-scrollbar-thumb {
  background:rgba(130,110,255,.35);
  border-radius:99px;
}

/* ===================================================== */

.app {
  display:flex;
  min-height:100vh;
}

/* SIDEBAR */

.sidebar {
  width:238px;
  flex:0 0 238px;
  position:fixed;
  top:0;
  bottom:0;
  right:0;
  z-index:30;

  background:
    linear-gradient(
      180deg,
      var(--panel2),
      var(--panel)
    );

  border-left:1px solid var(--line);
  backdrop-filter:blur(20px);

  padding:18px 14px;

  display:flex;
  flex-direction:column;
}

.brand {
  display:flex;
  align-items:center;
  gap:11px;
  padding:7px 8px 20px;
}

.logo {
  width:42px;
  height:42px;
  border-radius:13px;

  display:grid;
  place-items:center;

  background:
    linear-gradient(
      135deg,
      var(--purple),
      var(--cyan)
    );

  color:white;
  font-size:18px;
  font-weight:900;

  box-shadow:
    0 10px 28px
    rgba(123,77,255,.25);
}

.brand-title {
  font-size:16px;
  font-weight:900;
}

.brand-sub {
  font-size:10px;
  color:var(--muted);
  margin-top:3px;
}

.nav {
  display:flex;
  flex-direction:column;
  gap:6px;
}

.nav-btn {
  width:100%;
  border:1px solid transparent;
  background:transparent;
  color:var(--muted);

  padding:11px 12px;
  border-radius:12px;

  text-align:right;

  display:flex;
  align-items:center;
  gap:10px;

  transition:.18s;
}

.nav-btn:hover,
.nav-btn.active {
  color:var(--text);
  background:
    linear-gradient(
      135deg,
      rgba(123,77,255,.16),
      rgba(25,199,239,.06)
    );

  border-color:
    rgba(123,77,255,.16);
}

.nav-icon {
  width:25px;
  text-align:center;
  opacity:.9;
}

.sidebar-bottom {
  margin-top:auto;
  border-top:1px solid var(--line);
  padding-top:13px;
}

.theme-btn {
  width:100%;
  border:1px solid var(--line);
  background:var(--panel);
  color:var(--text);

  border-radius:11px;
  padding:10px;

  display:flex;
  justify-content:center;
  gap:8px;
}

/* MAIN */

.main {
  width:calc(100% - 238px);
  margin-right:238px;
  min-width:0;

  padding:
    18px
    22px
    70px;
}

.topbar {
  min-height:52px;

  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;

  margin-bottom:14px;
}

.page-title {
  font-size:20px;
  font-weight:900;
}

.page-subtitle {
  color:var(--muted);
  font-size:11px;
  margin-top:4px;
}

.status {
  display:flex;
  align-items:center;
  gap:8px;

  padding:8px 11px;
  border-radius:99px;

  background:var(--panel);
  border:1px solid var(--line);

  font-size:11px;
}

.dot {
  width:8px;
  height:8px;
  border-radius:50%;
  background:var(--green);
  box-shadow:
    0 0 12px
    rgba(25,199,122,.7);
}

/* HERO */

.hero {
  min-height:250px;
  border-radius:22px;

  padding:25px;

  position:relative;
  overflow:hidden;

  background:
    linear-gradient(
      115deg,
      rgba(17,18,28,.96),
      rgba(49,31,104,.78)
    );

  border:1px solid
    rgba(255,255,255,.08);

  box-shadow:var(--shadow);

  display:flex;
  align-items:center;
}

body.light .hero {
  background:
    linear-gradient(
      115deg,
      rgba(255,255,255,.94),
      rgba(235,229,255,.90)
    );
  border-color:var(--line);
}

.hero:after {
  content:"";
  position:absolute;
  width:300px;
  height:300px;
  border-radius:50%;

  left:-100px;
  top:-130px;

  background:
    radial-gradient(
      circle,
      rgba(25,199,239,.25),
      transparent 68%
    );
}

.hero-content {
  position:relative;
  z-index:2;
  max-width:650px;
}

.hero-kicker {
  color:var(--cyan);
  font-size:11px;
  font-weight:800;
  margin-bottom:9px;
}

.hero h1 {
  margin:0;
  font-size:
    clamp(28px,4vw,48px);
  line-height:1.05;
}

.hero p {
  color:var(--muted);
  max-width:570px;
  line-height:1.9;
  font-size:12px;
  margin:13px 0 18px;
}

.hero-actions {
  display:flex;
  flex-wrap:wrap;
  gap:8px;
}

.btn {
  border:1px solid var(--line);
  background:var(--panel);
  color:var(--text);

  border-radius:11px;
  padding:10px 14px;

  transition:.18s;
}

.btn:hover {
  transform:translateY(-1px);
}

.btn-primary {
  border:0;
  color:white;

  background:
    linear-gradient(
      135deg,
      var(--purple),
      var(--purple2)
    );

  box-shadow:
    0 10px 25px
    rgba(123,77,255,.22);
}

/* STATS */

.stats {
  display:grid;
  grid-template-columns:
    repeat(4,minmax(0,1fr));

  gap:11px;
  margin-top:12px;
}

.card {
  background:var(--panel);
  border:1px solid var(--line);
  border-radius:16px;
  box-shadow:var(--shadow);
}

.stat {
  padding:15px;
}

.stat-label {
  color:var(--muted);
  font-size:10px;
}

.stat-value {
  font-size:24px;
  font-weight:900;
  margin-top:8px;
}

.stat-note {
  color:var(--muted);
  font-size:9px;
  margin-top:4px;
}

/* CONTENT */

.content-grid {
  display:grid;
  grid-template-columns:
    minmax(0,1.5fr)
    minmax(280px,.7fr);

  gap:12px;
  margin-top:12px;
}

.section {
  padding:16px;
  min-width:0;
}

.section-title {
  font-size:14px;
  font-weight:900;
  margin-bottom:13px;
}

.section-head {
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:10px;
  margin-bottom:13px;
}

.table-wrap {
  overflow-x:auto;
}

table {
  width:100%;
  border-collapse:collapse;
  min-width:560px;
}

th,
td {
  padding:10px 8px;
  border-bottom:1px solid var(--line);
  font-size:11px;
  text-align:right;
}

th {
  color:var(--muted);
  font-size:9px;
}

.badge {
  display:inline-flex;
  align-items:center;
  gap:5px;

  padding:5px 8px;
  border-radius:99px;

  font-size:9px;

  background:
    rgba(25,199,122,.10);

  color:var(--green);
}

.badge.off {
  background:
    rgba(255,82,111,.10);
  color:var(--red);
}

/* FORMS */

.form-grid {
  display:grid;
  grid-template-columns:
    repeat(2,minmax(0,1fr));

  gap:10px;
}

.field {
  display:flex;
  flex-direction:column;
  gap:6px;
}

.field.full {
  grid-column:1/-1;
}

.field label {
  color:var(--muted);
  font-size:10px;
}

.field input,
.field select {
  width:100%;

  border:1px solid var(--line);
  background:var(--panel2);
  color:var(--text);

  border-radius:10px;
  padding:10px 11px;

  outline:none;
}

.field input:focus,
.field select:focus {
  border-color:
    rgba(123,77,255,.55);
}

/* VIEWS */

.view {
  display:none;
}

.view.active {
  display:block;
}

/* MODAL */

.modal {
  position:fixed;
  inset:0;
  z-index:100;

  display:none;
  align-items:center;
  justify-content:center;

  padding:15px;

  background:
    rgba(0,0,0,.60);

  backdrop-filter:blur(8px);
}

.modal.show {
  display:flex;
}

.modal-box {
  width:min(520px,100%);
  max-height:90vh;
  overflow:auto;

  background:var(--panel2);
  border:1px solid var(--line);

  border-radius:18px;
  padding:18px;

  box-shadow:
    0 30px 90px
    rgba(0,0,0,.35);
}

.modal-head {
  display:flex;
  align-items:center;
  justify-content:space-between;
  margin-bottom:15px;
}

.close {
  width:32px;
  height:32px;

  border:1px solid var(--line);
  background:transparent;
  color:var(--text);

  border-radius:9px;
}

/* MOBILE */

.mobile-nav {
  display:none;
}

@media(max-width:1050px) {

  .sidebar {
    width:210px;
    flex-basis:210px;
  }

  .main {
    width:calc(100% - 210px);
    margin-right:210px;
    padding:15px 16px 65px;
  }

  .stats {
    grid-template-columns:
      repeat(2,minmax(0,1fr));
  }

  .content-grid {
    grid-template-columns:1fr;
  }
}

@media(max-width:760px) {

  .sidebar {
    display:none;
  }

  .main {
    width:100%;
    margin-right:0;
    padding:
      12px
      11px
      78px;
  }

  .topbar {
    margin-bottom:10px;
  }

  .page-title {
    font-size:17px;
  }

  .hero {
    min-height:220px;
    padding:20px;
    border-radius:18px;
  }

  .hero h1 {
    font-size:30px;
  }

  .hero p {
    font-size:11px;
  }

  .stats {
    grid-template-columns:
      repeat(2,minmax(0,1fr));
    gap:8px;
  }

  .stat {
    padding:12px;
  }

  .stat-value {
    font-size:20px;
  }

  .form-grid {
    grid-template-columns:1fr;
  }

  .field.full {
    grid-column:auto;
  }

  .mobile-nav {
    display:grid;

    grid-template-columns:
      repeat(5,1fr);

    position:fixed;
    bottom:8px;
    left:8px;
    right:8px;

    z-index:50;

    padding:7px;

    background:
      rgba(15,17,25,.90);

    border:1px solid var(--line);
    border-radius:17px;

    backdrop-filter:blur(20px);
  }

  body.light .mobile-nav {
    background:
      rgba(255,255,255,.90);
  }

  .mobile-nav button {
    border:0;
    background:transparent;
    color:var(--muted);

    padding:7px 2px;

    font-size:9px;
  }

  .mobile-nav button.active {
    color:var(--purple);
    font-weight:900;
  }
}

@media(max-width:430px) {

  .hero-actions {
    display:grid;
    grid-template-columns:1fr;
  }

  .hero-actions .btn {
    width:100%;
  }

  .stats {
    gap:7px;
  }

  .stat-label {
    font-size:9px;
  }
}

</style>
</head>

<body>

<div class="app">

<aside class="sidebar">

  <div class="brand">
    <div class="logo">R</div>

    <div>
      <div class="brand-title">
        RIX PANEL
      </div>

      <div class="brand-sub">
        DIRECT VLESS
      </div>
    </div>
  </div>

  <nav class="nav">

    <button class="nav-btn active"
            data-view="dashboard">
      <span class="nav-icon">⌂</span>
      داشبورد
    </button>

    <button class="nav-btn"
            data-view="users">
      <span class="nav-icon">♙</span>
      کاربران
    </button>

    <button class="nav-btn"
            data-view="configs">
      <span class="nav-icon">⌁</span>
      کانفیگ‌ها
    </button>

    <button class="nav-btn"
            data-view="ips">
      <span class="nav-icon">◈</span>
      Clean IP
    </button>

    <button class="nav-btn"
            data-view="settings">
      <span class="nav-icon">⚙</span>
      تنظیمات
    </button>

    <button class="nav-btn"
            data-view="info">
      <span class="nav-icon">ⓘ</span>
      اطلاعات
    </button>

  </nav>

  <div class="sidebar-bottom">

    <button
      id="themeBtn"
      class="theme-btn">
      ◐ تغییر حالت
    </button>

  </div>

</aside>


<main class="main">

  <div class="topbar">

    <div>
      <div class="page-title">
        RIX PANEL
      </div>

      <div class="page-subtitle">
        مدیریت VLESS / WebSocket
      </div>
    </div>

    <div class="status">
      <span class="dot"></span>
      سرویس فعال
    </div>

  </div>


  <!-- =====================================================
       DASHBOARD
       ===================================================== -->

  <section
    id="view-dashboard"
    class="view active">

    <div class="hero">

      <div class="hero-content">

        <div class="hero-kicker">
          RIX DIRECT NETWORK
        </div>

        <h1>
          VLESS
          <br>
          مدیریت ساده و سریع
        </h1>

        <p>
          کاربران، کانفیگ‌ها و Clean IP های
          خودت را از یک پنل سبک و responsive
          مدیریت کن.
        </p>

        <div class="hero-actions">

          <button
            class="btn btn-primary"
            onclick="openUserModal()">
            + ساخت کاربر
          </button>

          <button
            class="btn"
            onclick="showView('configs')">
            کانفیگ‌ها
          </button>

          <button
            class="btn"
            onclick="showView('ips')">
            Clean IP
          </button>

        </div>

      </div>

    </div>


    <div class="stats">

      <div class="card stat">
        <div class="stat-label">
          کاربران
        </div>
        <div
          id="statUsers"
          class="stat-value">
          -
        </div>
        <div class="stat-note">
          ذخیره شده در RIXDO
        </div>
      </div>

      <div class="card stat">
        <div class="stat-label">
          کانفیگ‌ها
        </div>
        <div
          id="statConfigs"
          class="stat-value">
          -
        </div>
        <div class="stat-note">
          کانفیگ واقعی
        </div>
      </div>

      <div class="card stat">
        <div class="stat-label">
          Clean IP
        </div>
        <div
          id="statIPs"
          class="stat-value">
          -
        </div>
        <div class="stat-note">
          IP فعال
        </div>
      </div>

      <div class="card stat">
        <div class="stat-label">
          Worker
        </div>
        <div
          id="statLatency"
          class="stat-value">
          -
        </div>
        <div class="stat-note">
          latency واقعی
        </div>
      </div>

    </div>


    <div class="content-grid">

      <div class="card section">

        <div class="section-head">

          <div class="section-title">
            آخرین کاربران
          </div>

          <button
            class="btn"
            onclick="showView('users')">
            مشاهده همه
          </button>

        </div>

        <div
          id="dashboardUsers"
          class="table-wrap">
        </div>

      </div>


      <div class="card section">

        <div class="section-title">
          وضعیت سرویس
        </div>

        <div id="serviceStatus">

          <div class="badge">
            ● WebSocket فعال
          </div>

          <br><br>

          <div class="badge">
            ● VLESS فعال
          </div>

          <br><br>

          <div class="badge">
            ● SQLite فعال
          </div>

        </div>

      </div>

    </div>

  </section>


  <!-- =====================================================
       USERS
       ===================================================== -->

  <section
    id="view-users"
    class="view">

    <div class="card section">

      <div class="section-head">

        <div>
          <div class="section-title">
            کاربران
          </div>

          <div class="page-subtitle">
            برای هر کاربر UUID اختصاصی ساخته می‌شود.
          </div>
        </div>

        <button
          class="btn btn-primary"
          onclick="openUserModal()">
          + کاربر جدید
        </button>

      </div>

      <div
        id="usersTable"
        class="table-wrap">
      </div>

    </div>

  </section>


  <!-- =====================================================
       CONFIGS
       ===================================================== -->

  <section
    id="view-configs"
    class="view">

    <div class="card section">

      <div class="section-head">

        <div>
          <div class="section-title">
            کانفیگ‌ها
          </div>

          <div class="page-subtitle">
            هر کانفیگ متعلق به یک کاربر است.
          </div>
        </div>

        <button
          class="btn btn-primary"
          onclick="openConfigModal()">
          + کانفیگ جدید
        </button>

      </div>

      <div
        id="configsTable"
        class="table-wrap">
      </div>

    </div>

  </section>


  <!-- =====================================================
       CLEAN IP
       ===================================================== -->

  <section
    id="view-ips"
    class="view">

    <div class="card section">

      <div class="section-head">

        <div>
          <div class="section-title">
            Clean IP
          </div>

          <div class="page-subtitle">
            IP های قابل انتخاب برای کانفیگ‌ها.
          </div>
        </div>

        <button
          class="btn btn-primary"
          onclick="openIPModal()">
          + افزودن IP
        </button>

      </div>

      <div
        id="ipsTable"
        class="table-wrap">
      </div>

    </div>

  </section>


  <!-- =====================================================
       SETTINGS
       ===================================================== -->

  <section
    id="view-settings"
    class="view">

    <div class="card section">

      <div class="section-title">
        تنظیمات RIX
      </div>

      <div class="form-grid">

        <div class="field full">
          <label>
            Admin Token
          </label>

          <input
            id="adminToken"
            type="password"
            placeholder="ADMIN_TOKEN">
        </div>

        <div class="field">
          <label>
            Dark Background
          </label>

          <input
            id="darkBg"
            type="url"
            placeholder="https://...">
        </div>

        <div class="field">
          <label>
            Light Background
          </label>

          <input
            id="lightBg"
            type="url"
            placeholder="https://...">
        </div>

        <div class="field full">

          <button
            class="btn btn-primary"
            onclick="saveSettings()">
            ذخیره تنظیمات
          </button>

        </div>

      </div>

    </div>

  </section>


  <!-- =====================================================
       INFO
       ===================================================== -->

  <section
    id="view-info"
    class="view">

    <div class="card section">

      <div class="section-title">
        RIX PANEL
      </div>

      <p class="page-subtitle"
         style="line-height:2">

        RIX DIRECT VLESS PANEL

        <br><br>

        VLESS + WebSocket + TLS

        <br>

        Per User UUID

        <br>

        SQLite Durable Object

        <br>

        Clean IP Manager

        <br>

        Responsive UI

      </p>

    </div>

  </section>

</main>

</div>


<!-- MOBILE NAV -->

<div class="mobile-nav">

  <button
    data-view="dashboard"
    class="active">
    ⌂<br>خانه
  </button>

  <button data-view="users">
    ♙<br>کاربر
  </button>

  <button data-view="configs">
    ⌁<br>کانفیگ
  </button>

  <button data-view="ips">
    ◈<br>IP
  </button>

  <button data-view="settings">
    ⚙<br>تنظیمات
  </button>

</div>


<!-- USER MODAL -->

<div
  id="userModal"
  class="modal">

  <div class="modal-box">

    <div class="modal-head">

      <strong>
        ساخت کاربر
      </strong>

      <button
        class="close"
        onclick="closeModal('userModal')">
        ×
      </button>

    </div>

    <div class="form-grid">

      <div class="field full">

        <label>
          نام کاربر
        </label>

        <input
          id="userName"
          placeholder="مثلاً Ali">

      </div>

      <div class="field full">

        <button
          class="btn btn-primary"
          onclick="createUser()">
          ساخت کاربر
        </button>

      </div>

    </div>

  </div>

</div>


<!-- CONFIG MODAL -->

<div
  id="configModal"
  class="modal">

  <div class="modal-box">

    <div class="modal-head">

      <strong>
        ساخت کانفیگ
      </strong>

      <button
        class="close"
        onclick="closeModal('configModal')">
        ×
      </button>

    </div>

    <div class="form-grid">

      <div class="field full">

        <label>
          کاربر
        </label>

        <select id="configUser">
        </select>

      </div>

      <div class="field">

        <label>
          نام کانفیگ
        </label>

        <input
          id="configName"
          placeholder="مثلاً Main">

      </div>

      <div class="field">

        <label>
          Clean IP
        </label>

        <select id="configIP">
        </select>

      </div>

      <div class="field full">

        <button
          class="btn btn-primary"
          onclick="createConfig()">
          ساخت کانفیگ
        </button>

      </div>

    </div>

  </div>

</div>


<!-- IP MODAL -->

<div
  id="ipModal"
  class="modal">

  <div class="modal-box">

    <div class="modal-head">

      <strong>
        افزودن Clean IP
      </strong>

      <button
        class="close"
        onclick="closeModal('ipModal')">
        ×
      </button>

    </div>

    <div class="form-grid">

      <div class="field full">

        <label>
          IPv4 / IPv6
        </label>

        <input
          id="ipValue"
          placeholder="1.2.3.4">

      </div>

      <div class="field full">

        <button
          class="btn btn-primary"
          onclick="createIP()">
          افزودن
        </button>

      </div>

    </div>

  </div>

</div>


<script>

const DARK_DEFAULT =
  __DARK_BG__;

const LIGHT_DEFAULT =
  __LIGHT_BG__;

let users = [];
let configs = [];
let ips = [];


/* =====================================================
   AUTH
   ===================================================== */

function getToken() {

  return sessionStorage.getItem(
    "rix_admin_token"
  ) || "";

}

function saveToken(token) {

  sessionStorage.setItem(
    "rix_admin_token",
    token
  );

}

function authHeaders() {

  const token =
    getToken();

  return {
    "content-type":
      "application/json",

    "authorization":
      "Bearer " + token
  };

}


/* =====================================================
   API
   ===================================================== */

async function api(
  url,
  options = {}
) {

  if (
    options.body &&
    typeof options.body !== "string"
  ) {
    options.body =
      JSON.stringify(
        options.body
      );
  }

  options.headers = {
    ...authHeaders(),
    ...(options.headers || {})
  };

  const response =
    await fetch(
      url,
      options
    );

  const data =
    await response.json()
      .catch(() => ({
        ok:false,
        error:
          "Invalid server response"
      }));

  if (
    response.status === 401 ||
    response.status === 503
  ) {

    const token =
      prompt(
        "ADMIN_TOKEN را وارد کنید:"
      );

    if (!token) {
      throw new Error(
        "Admin token required"
      );
    }

    saveToken(token);

    return api(
      url,
      options
    );
  }

  if (!response.ok) {

    throw new Error(
      data.error ||
      "Request failed"
    );

  }

  return data;

}


/* =====================================================
   VIEWS
   ===================================================== */

function showView(name) {

  document
    .querySelectorAll(".view")
    .forEach(
      (view) => {
        view.classList.toggle(
          "active",
          view.id ===
            "view-" + name
        );
      }
    );

  document
    .querySelectorAll(
      ".nav-btn,.mobile-nav button"
    )
    .forEach(
      (button) => {
        button.classList.toggle(
          "active",
          button.dataset.view ===
            name
        );
      }
    );

  if (name === "users") {
    loadUsers();
  }

  if (name === "configs") {
    loadConfigs();
  }

  if (name === "ips") {
    loadIPs();
  }

}

document
  .querySelectorAll(
    ".nav-btn,.mobile-nav button"
  )
  .forEach(
    (button) => {

      button.addEventListener(
        "click",
        () => {
          showView(
            button.dataset.view
          );
        }
      );

    }
  );


/* =====================================================
   MODALS
   ===================================================== */

function openModal(id) {

  document
    .getElementById(id)
    .classList.add("show");

}

function closeModal(id) {

  document
    .getElementById(id)
    .classList.remove("show");

}

function openUserModal() {

  document
    .getElementById("userName")
    .value = "";

  openModal(
    "userModal"
  );

}

function openConfigModal() {

  document
    .getElementById("configName")
    .value = "";

  fillConfigUsers();
  fillConfigIPs();

  openModal(
    "configModal"
  );

}

function openIPModal() {

  document
    .getElementById("ipValue")
    .value = "";

  openModal(
    "ipModal"
  );

}


/* =====================================================
   USERS
   ===================================================== */

async function loadUsers() {

  try {

    const data =
      await api(
        "/api/users"
      );

    users =
      data.users || [];

    renderUsers();
    renderDashboardUsers();
    fillConfigUsers();

    updateStats();

  } catch (error) {

    showError(
      error.message
    );

  }

}

function renderUsers() {

  const box =
    document.getElementById(
      "usersTable"
    );

  if (!users.length) {

    box.innerHTML =
      "<p class='page-subtitle'>" +
      "هنوز کاربری ساخته نشده." +
      "</p>";

    return;

  }

  let html = `
    <table>
      <thead>
        <tr>
          <th>نام</th>
          <th>UUID</th>
          <th>کانفیگ</th>
          <th>وضعیت</th>
          <th>عملیات</th>
        </tr>
      </thead>
      <tbody>
  `;

  users.forEach(
    (user) => {

      html += `
        <tr>

          <td>
            ${escapeHtml(
              user.name
            )}
          </td>

          <td dir="ltr"
              style="font-size:9px">
            ${escapeHtml(
              user.uuid
            )}
          </td>

          <td>
            ${user.config_count || 0}
          </td>

          <td>
            ${
              user.enabled
              ? "<span class='badge'>فعال</span>"
              : "<span class='badge off'>غیرفعال</span>"
            }
          </td>

          <td>

            <button
              class="btn"
              onclick="copyText('${user.uuid}')">
              UUID
            </button>

            <button
              class="btn"
              onclick="copySubscription('${user.sub_token}')">
              Sub
            </button>

            <button
              class="btn"
              onclick="deleteUser('${user.id}')">
              حذف
            </button>

          </td>

        </tr>
      `;

    }
  );

  html += `
      </tbody>
    </table>
  `;

  box.innerHTML = html;

}

function renderDashboardUsers() {

  const box =
    document.getElementById(
      "dashboardUsers"
    );

  const list =
    users.slice(0,5);

  if (!list.length) {

    box.innerHTML =
      "<p class='page-subtitle'>" +
      "هنوز کاربری وجود ندارد." +
      "</p>";

    return;

  }

  let html = `
    <table>
      <thead>
        <tr>
          <th>نام</th>
          <th>کانفیگ</th>
          <th>وضعیت</th>
        </tr>
      </thead>
      <tbody>
  `;

  list.forEach(
    (user) => {

      html += `
        <tr>
          <td>
            ${escapeHtml(
              user.name
            )}
          </td>

          <td>
            ${user.config_count || 0}
          </td>

          <td>
            ${
              user.enabled
              ? "<span class='badge'>فعال</span>"
              : "<span class='badge off'>خاموش</span>"
            }
          </td>
        </tr>
      `;

    }
  );

  html += `
      </tbody>
    </table>
  `;

  box.innerHTML = html;

}


async function createUser() {

  const name =
    document
      .getElementById(
        "userName"
      )
      .value
      .trim();

  if (!name) {

    alert(
      "نام کاربر را وارد کنید."
    );

    return;

  }

  try {

    const data =
      await api(
        "/api/users",
        {
          method:"POST",
          body:{ name }
        }
      );

    closeModal(
      "userModal"
    );

    await loadUsers();

    alert(
      "کاربر ساخته شد.\n\n" +
      "UUID:\n" +
      data.user.uuid
    );

  } catch (error) {

    showError(
      error.message
    );

  }

}


async function deleteUser(id) {

  if (
    !confirm(
      "این کاربر و کانفیگ‌هایش حذف شود؟"
    )
  ) {
    return;
  }

  try {

    await api(
      "/api/users/" +
      encodeURIComponent(id),
      {
        method:"DELETE"
      }
    );

    await loadUsers();

    await loadConfigs();

  } catch (error) {

    showError(
      error.message
    );

  }

}


/* =====================================================
   CONFIGS
   ===================================================== */

async function loadConfigs() {

  try {

    const data =
      await api(
        "/api/configs"
      );

    configs =
      data.configs || [];

    renderConfigs();
    updateStats();

  } catch (error) {

    showError(
      error.message
    );

  }

}

function renderConfigs() {

  const box =
    document.getElementById(
      "configsTable"
    );

  if (!configs.length) {

    box.innerHTML =
      "<p class='page-subtitle'>" +
      "هنوز کانفیگی ساخته نشده." +
      "</p>";

    return;

  }

  let html = `
    <table>
      <thead>
        <tr>
          <th>نام</th>
          <th>کاربر</th>
          <th>Endpoint</th>
          <th>Clean IP</th>
          <th>عملیات</th>
        </tr>
      </thead>
      <tbody>
  `;

  configs.forEach(
    (config) => {

      html += `
        <tr>

          <td>
            ${escapeHtml(
              config.name
            )}
          </td>

          <td>
            ${escapeHtml(
              config.user_name
            )}
          </td>

          <td dir="ltr">
            ${escapeHtml(
              config.endpoint
            )}
          </td>

          <td>
            ${
              config.clean_ip
              ? escapeHtml(
                  config.clean_ip
                )
              : "Worker Host"
            }
          </td>

          <td>

            <button
              class="btn"
              onclick="copyText(${escapeJsString(config.url)})">
              کپی
            </button>

            <button
              class="btn"
              onclick="deleteConfig('${config.id}')">
              حذف
            </button>

          </td>

        </tr>
      `;

    }
  );

  html += `
      </tbody>
    </table>
  `;

  box.innerHTML = html;

}

function fillConfigUsers() {

  const select =
    document.getElementById(
      "configUser"
    );

  select.innerHTML =
    "";

  users.forEach(
    (user) => {

      const option =
        document.createElement(
          "option"
        );

      option.value =
        user.id;

      option.textContent =
        user.name;

      select.appendChild(
        option
      );

    }
  );

}

function fillConfigIPs() {

  const select =
    document.getElementById(
      "configIP"
    );

  select.innerHTML =
    "";

  const none =
    document.createElement(
      "option"
    );

  none.value = "";
  none.textContent =
    "بدون Clean IP";

  select.appendChild(
    none
  );

  ips
    .filter(
      (ip) => ip.enabled
    )
    .forEach(
      (ip) => {

        const option =
          document.createElement(
            "option"
          );

        option.value =
          ip.id;

        option.textContent =
          ip.ip;

        select.appendChild(
          option
        );

      }
    );

}

async function createConfig() {

  const user_id =
    document
      .getElementById(
        "configUser"
      )
      .value;

  const name =
    document
      .getElementById(
        "configName"
      )
      .value
      .trim();

  const clean_ip_id =
    document
      .getElementById(
        "configIP"
      )
      .value;

  if (!user_id) {

    alert(
      "کاربر انتخاب نشده."
    );

    return;

  }

  if (!name) {

    alert(
      "نام کانفیگ را وارد کنید."
    );

    return;

  }

  try {

    const data =
      await api(
        "/api/configs",
        {
          method:"POST",
          body:{
            user_id,
            name,
            clean_ip_id:
              clean_ip_id || null
          }
        }
      );

    closeModal(
      "configModal"
    );

    await loadConfigs();
    await loadUsers();

    await copyText(
      data.config.url
    );

    alert(
      "کانفیگ ساخته شد و کپی شد."
    );

  } catch (error) {

    showError(
      error.message
    );

  }

}

async function deleteConfig(id) {

  if (
    !confirm(
      "این کانفیگ حذف شود؟"
    )
  ) {
    return;
  }

  try {

    await api(
      "/api/configs/" +
      encodeURIComponent(id),
      {
        method:"DELETE"
      }
    );

    await loadConfigs();
    await loadUsers();

  } catch (error) {

    showError(
      error.message
    );

  }

}


/* =====================================================
   IPS
   ===================================================== */

async function loadIPs() {

  try {

    const data =
      await api(
        "/api/ips"
      );

    ips =
      data.ips || [];

    renderIPs();
    fillConfigIPs();
    updateStats();

  } catch (error) {

    showError(
      error.message
    );

  }

}

function renderIPs() {

  const box =
    document.getElementById(
      "ipsTable"
    );

  if (!ips.length) {

    box.innerHTML =
      "<p class='page-subtitle'>" +
      "هنوز Clean IP اضافه نشده." +
      "</p>";

    return;

  }

  let html = `
    <table>
      <thead>
        <tr>
          <th>IP</th>
          <th>وضعیت</th>
          <th>عملیات</th>
        </tr>
      </thead>
      <tbody>
  `;

  ips.forEach(
    (ip) => {

      html += `
        <tr>

          <td dir="ltr">
            ${escapeHtml(
              ip.ip
            )}
          </td>

          <td>
            ${
              ip.enabled
              ? "<span class='badge'>فعال</span>"
              : "<span class='badge off'>غیرفعال</span>"
            }
          </td>

          <td>

            <button
              class="btn"
              onclick="toggleIP('${ip.id}',${!ip.enabled})">
              ${
                ip.enabled
                ? "غیرفعال"
                : "فعال"
              }
            </button>

            <button
              class="btn"
              onclick="deleteIP('${ip.id}')">
              حذف
            </button>

          </td>

        </tr>
      `;

    }
  );

  html += `
      </tbody>
    </table>
  `;

  box.innerHTML = html;

}

async function createIP() {

  const ip =
    document
      .getElementById(
        "ipValue"
      )
      .value
      .trim();

  if (!ip) {

    alert(
      "IP را وارد کنید."
    );

    return;

  }

  try {

    await api(
      "/api/ips",
      {
        method:"POST",
        body:{ ip }
      }
    );

    closeModal(
      "ipModal"
    );

    await loadIPs();

  } catch (error) {

    showError(
      error.message
    );

  }

}

async function toggleIP(
  id,
  enabled
) {

  try {

    await api(
      "/api/ips/" +
      encodeURIComponent(id),
      {
        method:"PATCH",
        body:{ enabled }
      }
    );

    await loadIPs();

  } catch (error) {

    showError(
      error.message
    );

  }

}

async function deleteIP(id) {

  if (
    !confirm(
      "این IP حذف شود؟"
    )
  ) {
    return;
  }

  try {

    await api(
      "/api/ips/" +
      encodeURIComponent(id),
      {
        method:"DELETE"
      }
    );

    await loadIPs();

  } catch (error) {

    showError(
      error.message
    );

  }

}


/* =====================================================
   SUBSCRIPTION
   ===================================================== */

async function copySubscription(
  token
) {

  const url =
    location.origin +
    "/sub/" +
    token;

  await copyText(
    url
  );

  alert(
    "Subscription URL کپی شد."
  );

}


/* =====================================================
   COPY
   ===================================================== */

async function copyText(
  value
) {

  try {

    await navigator
      .clipboard
      .writeText(
        String(value)
      );

  } catch {

    const area =
      document.createElement(
        "textarea"
      );

    area.value =
      String(value);

    document.body.appendChild(
      area
    );

    area.select();

    document.execCommand(
      "copy"
    );

    area.remove();

  }

}


/* =====================================================
   THEME
   ===================================================== */

function applyBackground(
  theme
) {

  const saved =
    localStorage.getItem(
      theme === "light"
        ? "rix_light_bg"
        : "rix_dark_bg"
    );

  const url =
    saved ||
    (
      theme === "light"
        ? LIGHT_DEFAULT
        : DARK_DEFAULT
    );

  if (!url) {

    document
      .documentElement
      .style
      .removeProperty(
        "--bg-image"
      );

    return;

  }

  document
    .documentElement
    .style
    .setProperty(
      "--bg-image",
      'url("' +
      url.replaceAll(
        '"',
        "%22"
      ) +
      '")'
    );

}

function setTheme(
  theme
) {

  document.body
    .classList
    .toggle(
      "light",
      theme === "light"
    );

  localStorage.setItem(
    "rix_theme",
    theme
  );

  applyBackground(
    theme
  );

}

document
  .getElementById(
    "themeBtn"
  )
  .addEventListener(
    "click",
    () => {

      const next =
        document.body
          .classList
          .contains("light")
          ? "dark"
          : "light";

      setTheme(next);

    }
  );


/* =====================================================
   SETTINGS
   ===================================================== */

function loadSettings() {

  document
    .getElementById(
      "darkBg"
    )
    .value =
      localStorage.getItem(
        "rix_dark_bg"
      ) ||
      DARK_DEFAULT;

  document
    .getElementById(
      "lightBg"
    )
    .value =
      localStorage.getItem(
        "rix_light_bg"
      ) ||
      LIGHT_DEFAULT;

}

function saveSettings() {

  const token =
    document
      .getElementById(
        "adminToken"
      )
      .value
      .trim();

  const dark =
    document
      .getElementById(
        "darkBg"
      )
      .value
      .trim();

  const light =
    document
      .getElementById(
        "lightBg"
      )
      .value
      .trim();

  if (token) {
    saveToken(token);
  }

  localStorage.setItem(
    "rix_dark_bg",
    dark
  );

  localStorage.setItem(
    "rix_light_bg",
    light
  );

  const theme =
    localStorage.getItem(
      "rix_theme"
    ) || "dark";

  applyBackground(
    theme
  );

  alert(
    "تنظیمات ذخیره شد."
  );

}


/* =====================================================
   STATS
   ===================================================== */

function updateStats() {

  document
    .getElementById(
      "statUsers"
    )
    .textContent =
      users.length || 0;

  document
    .getElementById(
      "statConfigs"
    )
    .textContent =
      configs.length || 0;

  document
    .getElementById(
      "statIPs"
    )
    .textContent =
      ips.filter(
        (x) => x.enabled
      ).length || 0;

}


/* =====================================================
   REAL LATENCY
   ===================================================== */

async function measureLatency() {

  const element =
    document.getElementById(
      "statLatency"
    );

  const start =
    performance.now();

  try {

    await fetch(
      "/health",
      {
        cache:"no-store"
      }
    );

    const ms =
      Math.round(
        performance.now() -
        start
      );

    element.textContent =
      ms + "ms";

  } catch {

    element.textContent =
      "-";

  }

}


/* =====================================================
   ERROR
   ===================================================== */

function showError(
  message
) {

  alert(
    "RIX ERROR\n\n" +
    String(message)
  );

}


/* =====================================================
   INITIALIZE
   ===================================================== */

async function init() {

  loadSettings();

  const theme =
    localStorage.getItem(
      "rix_theme"
    ) || "dark";

  setTheme(theme);

  await Promise.allSettled([
    loadUsers(),
    loadConfigs(),
    loadIPs()
  ]);

  measureLatency();

}

init();

</script>

</body>
</html>`;


/* =========================================================
   DURABLE OBJECT
   ========================================================= */

export class RIXDO {

  constructor(ctx, env) {

    this.ctx = ctx;
    this.env = env;
    this.sql = ctx.storage.sql;

    /*
      ساخت جداول هنگام اولین اجرا.
    */
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        uuid TEXT NOT NULL UNIQUE,
        sub_token TEXT NOT NULL UNIQUE,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS configs (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        name TEXT NOT NULL,
        clean_ip_id TEXT,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS clean_ips (
        id TEXT PRIMARY KEY,
        ip TEXT NOT NULL UNIQUE,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS
        idx_users_uuid
        ON users(uuid);

      CREATE INDEX IF NOT EXISTS
        idx_users_sub_token
        ON users(sub_token);

      CREATE INDEX IF NOT EXISTS
        idx_configs_user
        ON configs(user_id);

      CREATE INDEX IF NOT EXISTS
        idx_configs_ip
        ON configs(clean_ip_id);
    `);
  }


  async fetch(request) {

    const url =
      new URL(request.url);

    const path =
      url.pathname;


    /* =====================================================
       HEALTH
       ===================================================== */

    if (
      path ===
      "/internal/health"
    ) {

      return json({
        ok:true
      });

    }


    /* =====================================================
       VERIFY UUID
       ===================================================== */

    if (
      path ===
      "/internal/verify"
      &&
      request.method === "POST"
    ) {

      const body =
        await request.json();

      const uuid =
        String(
          body.uuid || ""
        ).toLowerCase();

      if (!isValidUUID(uuid)) {

        return json({
          ok:false,
          enabled:false
        });

      }

      const cursor =
        this.sql.exec(
          `
          SELECT
            id,
            name,
            uuid,
            enabled
          FROM users
          WHERE lower(uuid)=?
          LIMIT 1
          `,
          uuid
        );

      const rows =
        [...cursor];

      if (!rows.length) {

        return json({
          ok:false,
          enabled:false
        });

      }

      return json({
        ok:true,
        ...rows[0],
        enabled:
          Boolean(
            rows[0].enabled
          )
      });

    }


    /* =====================================================
       USERS
       ===================================================== */

    if (
      path === "/users"
    ) {

      if (
        request.method === "GET"
      ) {

        const cursor =
          this.sql.exec(`
            SELECT
              u.id,
              u.name,
              u.uuid,
              u.sub_token,
              u.enabled,
              u.created_at,
              COUNT(c.id)
                AS config_count
            FROM users u
            LEFT JOIN configs c
              ON c.user_id=u.id
            GROUP BY u.id
            ORDER BY
              u.created_at DESC
          `);

        const users =
          [...cursor].map(
            (user) => ({
              ...user,
              enabled:
                Boolean(
                  user.enabled
                )
            })
          );

        return json({
          ok:true,
          users
        });

      }


      if (
        request.method === "POST"
      ) {

        const body =
          await request.json();

        const name =
          String(
            body.name || ""
          ).trim();

        if (!name) {

          return json(
            {
              ok:false,
              error:
                "User name required"
            },
            400
          );

        }

        const id =
          randomId();

        const uuid =
          crypto.randomUUID();

        const subToken =
          randomToken();

        this.sql.exec(
          `
          INSERT INTO users
          (
            id,
            name,
            uuid,
            sub_token,
            enabled,
            created_at
          )
          VALUES
          (?, ?, ?, ?, 1, ?)
          `,
          id,
          name,
          uuid,
          subToken,
          now()
        );

        return json({
          ok:true,
          user:{
            id,
            name,
            uuid,
            sub_token:subToken,
            enabled:true,
            config_count:0
          }
        });

      }

      return text(
        "Method Not Allowed",
        405
      );
    }


    /* =====================================================
       USER DELETE
       ===================================================== */

    if (
      path.startsWith(
        "/users/"
      )
      &&
      request.method === "DELETE"
    ) {

      const id =
        decodeURIComponent(
          path.slice(
            "/users/".length
          )
        );

      const existing =
        [
          ...this.sql.exec(
            `
            SELECT id
            FROM users
            WHERE id=?
            LIMIT 1
            `,
            id
          )
        ];

      if (!existing.length) {

        return json(
          {
            ok:false,
            error:
              "User not found"
          },
          404
        );

      }

      this.sql.exec(
        `
        DELETE FROM configs
        WHERE user_id=?
        `,
        id
      );

      this.sql.exec(
        `
        DELETE FROM users
        WHERE id=?
        `,
        id
      );

      return json({
        ok:true
      });

    }


    /* =====================================================
       CONFIGS
       ===================================================== */

    if (
      path === "/configs"
    ) {

      if (
        request.method === "GET"
      ) {

        const userId =
          url.searchParams.get(
            "user_id"
          );

        let cursor;

        if (userId) {

          cursor =
            this.sql.exec(
              `
              SELECT
                c.id,
                c.user_id,
                c.name,
                c.clean_ip_id,
                c.created_at,
                u.name AS user_name,
                u.uuid AS uuid,
                u.sub_token AS sub_token,
                i.ip AS clean_ip,
                i.enabled AS clean_ip_enabled
              FROM configs c
              JOIN users u
                ON u.id=c.user_id
              LEFT JOIN clean_ips i
                ON i.id=c.clean_ip_id
              WHERE c.user_id=?
              ORDER BY
                c.created_at DESC
              `,
              userId
            );

        } else {

          cursor =
            this.sql.exec(`
              SELECT
                c.id,
                c.user_id,
                c.name,
                c.clean_ip_id,
                c.created_at,
                u.name AS user_name,
                u.uuid AS uuid,
                u.sub_token AS sub_token,
                i.ip AS clean_ip,
                i.enabled AS clean_ip_enabled
              FROM configs c
              JOIN users u
                ON u.id=c.user_id
              LEFT JOIN clean_ips i
                ON i.id=c.clean_ip_id
              ORDER BY
                c.created_at DESC
            `);

        }

        const rows =
          [...cursor];

        const host =
          this.env.__RIX_HOST ||
          "";

        /*
          host واقعی از Worker در API
          پایین‌تر در fetch اصلی تزریق می‌شود.
        */

        const configs =
          rows.map(
            (row) => {

              const endpoint =
                row.clean_ip &&
                row.clean_ip_enabled
                  ? row.clean_ip
                  : host;

              return {
                ...row,
                clean_ip_enabled:
                  Boolean(
                    row.clean_ip_enabled
                  ),
                endpoint,
                url:
                  buildVlessURL({
                    uuid:
                      row.uuid,
                    endpoint,
                    host,
                    name:
                      row.name
                  })
              };

            }
          );

        return json({
          ok:true,
          configs
        });

      }


      if (
        request.method === "POST"
      ) {

        const body =
          await request.json();

        const userId =
          String(
            body.user_id || ""
          );

        const name =
          String(
            body.name || ""
          ).trim();

        const cleanIpId =
          body.clean_ip_id
            ? String(
                body.clean_ip_id
              )
            : null;

        if (
          !userId ||
          !name
        ) {

          return json(
            {
              ok:false,
              error:
                "user_id and name required"
            },
            400
          );

        }

        const userRows =
          [
            ...this.sql.exec(
              `
              SELECT
                id,
                name,
                uuid,
                sub_token,
                enabled
              FROM users
              WHERE id=?
              LIMIT 1
              `,
              userId
            )
          ];

        if (!userRows.length) {

          return json(
            {
              ok:false,
              error:
                "User not found"
            },
            404
          );

        }

        const user =
          userRows[0];

        if (!user.enabled) {

          return json(
            {
              ok:false,
              error:
                "User is disabled"
            },
            400
          );

        }

        let cleanIP = null;

        if (cleanIpId) {

          const rows =
            [
              ...this.sql.exec(
                `
                SELECT
                  id,
                  ip,
                  enabled
                FROM clean_ips
                WHERE id=?
                LIMIT 1
                `,
                cleanIpId
              )
            ];

          if (!rows.length) {

            return json(
              {
                ok:false,
                error:
                  "Clean IP not found"
              },
              404
            );

          }

          if (!rows[0].enabled) {

            return json(
              {
                ok:false,
                error:
                  "Clean IP is disabled"
              },
              400
            );

          }

          cleanIP =
            rows[0];

        }

        const id =
          randomId();

        this.sql.exec(
          `
          INSERT INTO configs
          (
            id,
            user_id,
            name,
            clean_ip_id,
            created_at
          )
          VALUES
          (?, ?, ?, ?, ?)
          `,
          id,
          userId,
          name,
          cleanIpId,
          now()
        );

        const host =
          this.env.__RIX_HOST ||
          "";

        const endpoint =
          cleanIP
            ? cleanIP.ip
            : host;

        const vless =
          buildVlessURL({
            uuid:
              user.uuid,
            endpoint,
            host,
            name
          });

        return json({
          ok:true,
          config:{
            id,
            name,
            user_id:
              userId,
            user_name:
              user.name,
            uuid:
              user.uuid,
            clean_ip:
              cleanIP
                ? cleanIP.ip
                : null,
            endpoint,
            url:vless
          }
        });

      }

      return text(
        "Method Not Allowed",
        405
      );
    }


    /* =====================================================
       CONFIG DELETE
       ===================================================== */

    if (
      path.startsWith(
        "/configs/"
      )
      &&
      request.method === "DELETE"
    ) {

      const id =
        decodeURIComponent(
          path.slice(
            "/configs/".length
          )
        );

      this.sql.exec(
        `
        DELETE FROM configs
        WHERE id=?
        `,
        id
      );

      return json({
        ok:true
      });

    }


    /* =====================================================
       CLEAN IPS
       ===================================================== */

    if (
      path === "/ips"
    ) {

      if (
        request.method === "GET"
      ) {

        const cursor =
          this.sql.exec(`
            SELECT
              id,
              ip,
              enabled,
              created_at
            FROM clean_ips
            ORDER BY
              created_at DESC
          `);

        const ips =
          [...cursor].map(
            (ip) => ({
              ...ip,
              enabled:
                Boolean(
                  ip.enabled
                )
            })
          );

        return json({
          ok:true,
          ips
        });

      }


      if (
        request.method === "POST"
      ) {

        const body =
          await request.json();

        const ip =
          String(
            body.ip || ""
          ).trim();

        if (!isValidIP(ip)) {

          return json(
            {
              ok:false,
              error:
                "Invalid IP address"
            },
            400
          );

        }

        const existing =
          [
            ...this.sql.exec(
              `
              SELECT id
              FROM clean_ips
              WHERE ip=?
              LIMIT 1
              `,
              ip
            )
          ];

        if (existing.length) {

          return json(
            {
              ok:false,
              error:
                "IP already exists"
            },
            409
          );

        }

        const id =
          randomId();

        this.sql.exec(
          `
          INSERT INTO clean_ips
          (
            id,
            ip,
            enabled,
            created_at
          )
          VALUES
          (?, ?, 1, ?)
          `,
          id,
          ip,
          now()
        );

        return json({
          ok:true,
          ip:{
            id,
            ip,
            enabled:true
          }
        });

      }

      return text(
        "Method Not Allowed",
        405
      );
    }


    /* =====================================================
       CLEAN IP ACTION
       ===================================================== */

    if (
      path.startsWith(
        "/ips/"
      )
    ) {

      const id =
        decodeURIComponent(
          path.slice(
            "/ips/".length
          )
        );


      if (
        request.method === "DELETE"
      ) {

        this.sql.exec(
          `
          DELETE FROM configs
          WHERE clean_ip_id=?
          `,
          id
        );

        this.sql.exec(
          `
          DELETE FROM clean_ips
          WHERE id=?
          `,
          id
        );

        return json({
          ok:true
        });

      }


      if (
        request.method === "PATCH"
      ) {

        const body =
          await request.json();

        const enabled =
          Boolean(
            body.enabled
          );

        this.sql.exec(
          `
          UPDATE clean_ips
          SET enabled=?
          WHERE id=?
          `,
          enabled ? 1 : 0,
          id
        );

        return json({
          ok:true,
          enabled
        });

      }

    }


    /* =====================================================
       SUBSCRIPTION
       ===================================================== */

    if (
      path.startsWith(
        "/internal/sub/"
      )
    ) {

      const token =
        decodeURIComponent(
          path.slice(
            "/internal/sub/".length
          )
        );

      const users =
        [
          ...this.sql.exec(
            `
            SELECT
              id,
              uuid,
              name,
              enabled
            FROM users
            WHERE sub_token=?
            LIMIT 1
            `,
            token
          )
        ];

      if (!users.length) {

        return json({
          ok:false,
          error:
            "Subscription not found"
        });

      }

      const user =
        users[0];

      if (!user.enabled) {

        return json({
          ok:false,
          error:
            "User disabled"
        });

      }

      const configs =
        [
          ...this.sql.exec(
            `
            SELECT
              c.name,
              i.ip AS clean_ip,
              i.enabled AS clean_ip_enabled
            FROM configs c
            LEFT JOIN clean_ips i
              ON i.id=c.clean_ip_id
            WHERE c.user_id=?
            ORDER BY
              c.created_at DESC
            `,
            user.id
          )
        ];

      const host =
        this.env.__RIX_HOST ||
        "";

      const urls =
        configs.map(
          (config) => {

            const endpoint =
              config.clean_ip &&
              config.clean_ip_enabled
                ? config.clean_ip
                : host;

            return buildVlessURL({
              uuid:
                user.uuid,
              endpoint,
              host,
              name:
                config.name
            });

          }
        );

      return json({
        ok:true,
        configs:urls
      });

    }


    return text(
      "Not Found",
      404
    );

  }

}


/* =========================================================
   WORKER FETCH
   ========================================================= */

export default {

  async fetch(
    request,
    env,
    ctx
  ) {

    const url =
      new URL(request.url);

    const path =
      url.pathname;


    /* -----------------------------------------------------
       Inject actual Worker hostname into DO
       ----------------------------------------------------- */

    /*
      DO درخواست‌ها را از طریق stub دریافت می‌کند.
      برای تولید VLESS URL باید hostname واقعی Worker
      را بداند.
    */

    env.__RIX_HOST =
      url.hostname;


    /* -----------------------------------------------------
       WebSocket
       ----------------------------------------------------- */

    if (
      path === WS_PATH
    ) {

      return handleVlessWebSocket(
        request,
        env
      );

    }


    /* -----------------------------------------------------
       Subscription
       ----------------------------------------------------- */

    if (
      path.startsWith(
        "/sub/"
      )
    ) {

      const token =
        path.slice(
          "/sub/".length
        );

      return subscription(
        request,
        env,
        token
      );

    }


    /* -----------------------------------------------------
       Health
       ----------------------------------------------------- */

    if (
      path === "/health"
    ) {

      return health(
        request,
        env
      );

    }


    /* -----------------------------------------------------
       API USERS
       ----------------------------------------------------- */

    if (
      path === "/api/users"
    ) {

      return apiUsers(
        request,
        env
      );

    }

    if (
      path.startsWith(
        "/api/users/"
      )
    ) {

      return apiUser(
        request,
        env,
        path.slice(
          "/api/users/".length
        )
      );

    }


    /* -----------------------------------------------------
       API CONFIGS
       ----------------------------------------------------- */

    if (
      path === "/api/configs"
    ) {

      return apiConfigs(
        request,
        env
      );

    }

    if (
      path.startsWith(
        "/api/configs/"
      )
    ) {

      return apiConfig(
        request,
        env,
        path.slice(
          "/api/configs/".length
        )
      );

    }


    /* -----------------------------------------------------
       API IPS
       ----------------------------------------------------- */

    if (
      path === "/api/ips"
    ) {

      return apiIPs(
        request,
        env
      );

    }

    if (
      path.startsWith(
        "/api/ips/"
      )
    ) {

      return apiIP(
        request,
        env,
        path.slice(
          "/api/ips/".length
        )
      );

    }


    /* -----------------------------------------------------
       PANEL
       ----------------------------------------------------- */

    if (
      path === "/" ||
      path === "/panel"
    ) {

      const html =
        HTML
          .replace(
            "__DARK_BG__",
            escapeJsString(
              DARK_BACKGROUND_URL
            )
          )
          .replace(
            "__LIGHT_BG__",
            escapeJsString(
              LIGHT_BACKGROUND_URL
            )
          );

      return new Response(
        html,
        {
          status:200,
          headers:{
            "content-type":
              "text/html; charset=utf-8",
            "cache-control":
              "no-store"
          }
        }
      );

    }


    return new Response(
      "RIX PANEL - Not Found",
      {
        status:404,
        headers:{
          "content-type":
            "text/plain; charset=utf-8"
        }
      }
    );

  }

};
