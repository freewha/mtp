import net from "node:net";
import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import { Readable, Writable } from "node:stream";
import { webcrypto, X509Certificate } from "node:crypto";
import { WebSocketServer } from "ws";

// Node 18 only exposes Web Crypto behind a flag; Node 19+ ships it as a global.
if (!globalThis.crypto) globalThis.crypto = webcrypto;

/*
 * ==================== Node.js replacements for Cloudflare APIs ====================
 * The original worker relied on three Cloudflare-specific APIs which are
 * reimplemented here using the Node.js standard library + the `ws` package:
 *
 *   1. `connect` from "cloudflare:sockets"  ->  net.Socket (below)
 *   2. `new WebSocketPair()`                ->  ServerWebSocket / WebSocketPair (below)
 *   3. `export default { fetch }`           ->  http.createServer() (bottom of file)
 *
 * Everything else (Web Crypto, MTProto, Obfuscated2, sessions, panels, decoy)
 * is untouched and runs natively on Node.js 18+.
 */

const ENV = process.env;

// Configuration keys read by the handlers (identical to the Worker's env bindings).
const CONFIG_KEYS = [
  "SECRET", "AD_TAG", "DEBUG", "DECOY_URL", "MAX_STREAMS", "SESSION_PATH", "WS_PATH",
  "ADMIN_KEY", "EXTRA_HOSTS", "CARRIER", "GENERATOR_ENABLED", "GENERATOR_KEY", "ACCEPT_GENERATED",
  "DC_OVERRIDE", "PROXY_PORTS",
  "TLS_CERT", "TLS_KEY", "TLS_CERT_PEM", "TLS_KEY_PEM", "TLS_PORT", "PUBLIC_PORT", "TRUST_PROXY"
];

// On Cloudflare the bindings are plain env vars. On a Node host the process
// environment already exports names such as HOSTNAME (machine name), so every
// key can also be supplied with a PROXYGOSHA_ prefix. HOSTNAME is *only* read
// from the prefixed form, otherwise the OS hostname would silently replace the
// configured domain allowlist.
function buildEnv(source) {
  const env = {};
  for (const key of CONFIG_KEYS) {
    const prefixed = source["PROXYGOSHA_" + key];
    if (prefixed !== undefined) env[key] = prefixed;
    else if (source[key] !== undefined) env[key] = source[key];
  }
  if (typeof source.PROXYGOSHA_HOSTNAME === "string") env.HOSTNAME = source.PROXYGOSHA_HOSTNAME;
  return env;
}

const APP_ENV = buildEnv(process.env);

// Read a single setting from the process environment, preferring the namespaced
// PROXYGOSHA_ form over the bare one (see buildEnv above for why).
function envValue(key) {
  const prefixed = ENV["PROXYGOSHA_" + key];
  if (typeof prefixed === "string" && prefixed.trim()) return prefixed.trim();
  const plain = ENV[key];
  return typeof plain === "string" ? plain.trim() : "";
}

// Cloudflare's connect() returned a socket object exposing a Web ReadableStream
// (`readable`) and WritableStream (`writable`). We reproduce the exact same
// shape over a raw net.Socket so the existing Stream class needs no changes.
function connect({ hostname, port }) {
  const sock = net.connect({ host: hostname, port: Number(port) || 443 });
  sock.setNoDelay(true);
  sock.setKeepAlive(true, 30000);

  let openedResolve, openedReject;
  const opened = new Promise((resolve, reject) => {
    openedResolve = resolve;
    openedReject = reject;
  });
  let closedResolve;
  const closed = new Promise((resolve) => {
    closedResolve = resolve;
  });

  sock.once("connect", () => openedResolve());
  sock.once("error", (err) => {
    openedReject(err);
    closedResolve();
  });
  // Keep a permanent listener so late socket errors (ECONNRESET after the
  // handshake) never surface as an unhandled 'error' event and crash the process.
  sock.on("error", () => {});
  sock.once("close", () => closedResolve());

  const readable = Readable.toWeb(sock);
  const writable = Writable.toWeb(sock);

  return {
    opened,
    closed,
    readable,
    writable,
    close() {
      sock.destroy();
      return closed;
    }
  };
}

// Cloudflare's WebSocketPair produced { 0: client-side WS, 1: server-side WS }.
// The server-side object is used as `response.webSocket` and then managed via
// the `ws` library. We expose the same surface (send/close/addEventListener) so
// WsSession and bridgeMode continue to work unchanged.
class ServerWebSocket {
  constructor() {
    this._ws = null;
    this._ready = false;
    this._queue = [];
    this._listeners = {};
  }

  // Cloudflare's server-side WebSocket exposes `readyState` (WebSocket.OPEN === 1).
  get readyState() {
    return this._ws ? this._ws.readyState : 0;
  }

  // Cloudflare requires calling accept() before the socket starts; the ws
  // library starts automatically once the upgrade completes, so it is a no-op.
  accept() {}

  // Attach the native `ws` WebSocket once the HTTP upgrade completes.
  _attach(ws) {
    this._ws = ws;
    this._ready = true;
    // Cloudflare delivers binary messages as ArrayBuffer; ws defaults to Buffer.
    ws.binaryType = "arraybuffer";
    ws.on("message", (data) => this._emit("message", data));
    ws.on("close", (code, reason) => this._emit("close", { code, reason }));
    ws.on("error", (err) => this._emit("error", err));
    for (const chunk of this._queue) {
      try { ws.send(chunk); } catch (_) {}
    }
    this._queue = [];
  }

  _emit(type, payload) {
    const list = this._listeners[type];
    if (!list) return;
    for (const fn of list) {
      try { fn({ data: payload }); } catch (_) {}
    }
  }

  addEventListener(type, fn) {
    (this._listeners[type] || (this._listeners[type] = [])).push(fn);
  }

  send(data) {
    if (this._ready && this._ws) {
      try { this._ws.send(data); } catch (_) {}
    } else {
      this._queue.push(data);
    }
  }

  close(code, reason) {
    if (this._ws) {
      try { this._ws.close(code, reason); } catch (_) {}
    }
  }
}

function WebSocketPair() {
  const server = new ServerWebSocket();
  return {
    0: { _serverWebSocket: server },
    1: server
  };
}

// Cloudflare's fetch() handler answered a WebSocket upgrade with
// `new Response(null, { status: 101, webSocket: client })`. Node's global
// Response refuses any status below 200, so the upgrade answer is represented
// as a plain object carrying the same fields; handleUpgrade() consumes it.
function upgradeResponse(client, protocol) {
  return {
    status: 101,
    webSocket: client,
    headers: new Headers({ "Sec-WebSocket-Protocol": protocol })
  };
}

/*
 * ===================== QUICK SETUP (no code editing) =====================
 * 1. Paste this file into a Cloudflare Worker and Deploy.
 * 2. Worker -> Settings -> Variables and Secrets -> add ONE variable:
 *        ADMIN_KEY = a long random password (16+ letters/digits)
 *    (Opening the worker address before this shows a setup page with a ready key.)
 * 3. Open  https://<your-domain>/<ADMIN_KEY>  -> panel with ready Telegram links
 *    for every Cloudflare HTTPS port (443, 2053, 2083, 2087, 2096, 8443).
 *    Open  https://<your-domain>/<ADMIN_KEY>/status  -> live status, recent events
 *    and an on-demand Telegram DC reachability probe (add ?probe=1).
 * Optional:
 *    EXTRA_HOSTS = other hostnames attached to this worker, comma separated.
 *                  The panel shows links for them too.
 * Any of the 6 ports can also be typed manually in Telegram (server + port +
 * secret); the Worker accepts all of them without extra settings.
 *    SECRET      = fixed 32-hex secret (otherwise derived from ADMIN_KEY).
 * =========================================================================
 */

/*
 * ============================================================================
 * Telegram WEB Proxy for Cloudflare Workers (Single-File ES Module)
 * Architecture, Middle-End (ME) Protocol Analysis & Direct-DC Implementation
 * ============================================================================
 *
 * RESEARCH SUMMARY & PROTOCOL FINDINGS:
 *
 * 1. Reference Architecture & Telego (v0.6.8) WEB Mode:
 *    - Telegram Desktop (TDesktop) native "WEB" proxy mode uses an embedded
 *      WebView carrier that establishes an HTTPS/WSS link on port 443.
 *    - The carrier (primary: 'websocket') multiplexes MTProto streams inside
 *      binary frames: OPEN (0x01), DATA (0x02), CLOSE (0x03), WINDOW (0x04).
 *    - Each logical stream carries a 64-byte Obfuscated2 client header. The
 *      proxy decrypts the tail with the shared secret to obtain the protocol
 *      tag (0xefefefef abridged, 0xeeeeeeee intermediate, 0xdddddddd padded)
 *      and destination DC ID.
 *    - In Direct-DC mode (Telego fallback and this Worker): The proxy establishes
 *      a raw TCP socket directly to Telegram's DC frontends (e.g., DC2: 149.154.167.51:443)
 *      using cloudflare:sockets, generates a fresh DC Obfuscated2 header, and pipes
 *      encrypted MTProto payloads bi-directionally with flow control.
 *
 * 2. Middle-End (ME) Routing & Ad Tag (Sponsored Channel) Protocol:
 *    - Official MTProxy (TelegramMessenger/MTProxy) and Telego route traffic to
 *      Telegram's Middle-End (ME) servers (from https://core.telegram.org/getProxyConfig)
 *      to support sponsored channels (Ad Tags issued by @MTProxybot, 32 hex chars / 16 bytes).
 *    - In the ME protocol, client data is encapsulated inside RPC frames:
 *      RPC_PROXY_REQ (0x36cef1ee) with flags (bit 3: FLAG_HAS_AD_TAG = 0x8).
 *      When FLAG_HAS_AD_TAG is set, the 16-byte ad tag is appended to the RPC header.
 *    - Direct-DC servers (port 443) DO NOT accept RPC_PROXY_REQ or proxy tags;
 *      sponsored channels can ONLY be attached over an authenticated Middle-End session.
 *
 * 3. The Fatal Blocker: NAT & IP/Port Binding in Middle-End Handshake (Problem 5A):
 *    - When connecting to Telegram's ME servers (port 8888), both sides execute an
 *      RPC crypto handshake:
 *        Step 1: Exchange 32-byte RPC_NONCE packets (RPC_NONCE 0x7acb87aa, CRYPTO_AES 0x1,
 *                key_selector from proxy-secret, crypto_ts, and 16-byte client/server nonces).
 *        Step 2: Derive AES-256-CBC session keys using:
 *                s = nonce_srv + nonce_clt + clt_ts + srv_ip + clt_port + purpose +
 *                    clt_ip + srv_port + middleproxy_secret + nonce_srv + nonce_clt
 *                key = md5(s[1:])[:12] + sha1(s);  iv = md5(s[2:])
 *        Step 3: Client sends encrypted RPC_HANDSHAKE (0x7682eef5).
 *    - CRITICAL OBSERVATION:
 *      Telegram's ME server extracts clt_ip (4 bytes) and clt_port (2 bytes) from the
 *      INCOMING TCP SOCKET (as observed on Telegram's network interface).
 *    - Telego documentation (docs/middle-end.md) explicitly warns:
 *      "Private direct sockets require UDP access to STUN or a properly configured nat-ip,
 *       and any intermediate NAT for direct connections must preserve outgoing TCP ports."
 *    - In Cloudflare Workers:
 *      (a) Outbound TCP connections via cloudflare:sockets exit through Cloudflare's
 *          Anycast edge egress infrastructure under Carrier-Grade NAT / NAPT.
 *      (b) The egress IP is dynamically selected from Cloudflare's shared pool and
 *          the outbound TCP source port is dynamically translated by Cloudflare's NAT.
 *      (c) cloudflare:sockets exposes ONLY SocketInfo { remoteAddress, localAddress }.
 *          It DOES NOT expose localPort, nor does it allow port binding.
 *      (d) Workers cannot execute raw UDP sockets for STUN detection.
 *      Consequently, the Worker cannot know what outbound TCP port Telegram's server
 *      will observe. The derived keys mathematically mismatch, and Telegram's ME server
 *      immediately drops the connection on the first frame.
 *    - HONESTY CONCLUSION (Stop Condition):
 *      Native Middle-End handshake directly from a Cloudflare Worker is physically
 *      impossible without an external egress helper that preserves source IP and port.
 *      Attempting to fake this would break proxy connectivity. Direct-DC mode remains
 *      the only reliable, zero-cost transport on Cloudflare Workers.
 *
 * 4. Crypto Primitives & Workers Capabilities (Problem 5B):
 *    - Web Crypto in Workers (workerd) natively supports MD5 via crypto.subtle.digest("MD5", ...).
 *    - Web Crypto supports SHA-1, SHA-256, and AES-CTR (used for Obfuscated2).
 *    - Web Crypto AES-CBC strictly enforces PKCS#7 padding. While encryption can drop
 *      the trailing padding block for 16-byte aligned inputs, decryption of arbitrary
 *      unpadded network streams from Telegram throws OperationError.
 *
 * 5. Connection Model & Workers Limits (Problem 5C & 5E):
 *    - Connection Model: Session-scoped connections (Option 1). Each client WebSocket
 *      owns its DC TCP sockets. Avoids Durable Objects complexity, requires zero dashboard
 *      bindings, and runs 100% on the Free plan.
 *    - Free Plan Limits (per incoming request / WebSocket invocation): 10 ms CPU time,
 *      50 subrequests, 6 connections in the "connecting" phase; 128 MB memory per
 *      isolate (shared by every session running in that isolate), 100k requests/day.
 *    - Default carrier is "websocket-lanes": every MTProto stream gets its own
 *      WebSocket, i.e. its own invocation with its own CPU/subrequest budget.
 *    - Fast mode: the DC-side obfuscation keys are chosen so DC->client bytes are
 *      forwarded without any re-encryption (download direction costs ~0 CPU).
 *
 * 6. UNVERIFIED Aspects:
 *    - [UNVERIFIED] Whether Cloudflare will in the future expose localPort on SocketInfo
 *      or provide dedicated egress IP/port reservation in Workers.
 *    - [UNVERIFIED] Whether Telegram will ever deploy a modified ME transport protocol
 *      (e.g., over WebSockets or TLS) that omits TCP source port binding from key derivation.
 * ============================================================================
 */

// Middle-End Protocol Constants (Documented for specification completeness)
const ME_CONSTANTS = {
  RPC_NONCE: 0x7acb87aa,        // Little-endian: 0xaa, 0x87, 0xcb, 0x7a
  RPC_HANDSHAKE: 0x7682eef5,    // Little-endian: 0xf5, 0xee, 0x82, 0x76
  RPC_FLAGS: 0x00000000,
  CRYPTO_AES: 0x00000001,
  RPC_PROXY_REQ: 0x36cef1ee,    // Little-endian: 0xee, 0xf1, 0xce, 0x36
  RPC_PROXY_ANS: 0x0dfb190e,    // Little-endian: 0x0e, 0x19, 0xfb, 0x0d
  FLAG_HAS_AD_TAG: 0x00000008,
  FLAG_EXTMODE2: 0x00020000,
  FLAG_PAD: 0x08000000,
  FLAG_INTERMEDIATE: 0x20000000,
  FLAG_ABRIDGED: 0x40000000,
  FLAG_QUICKACK: 0x80000000
};

// Default Configuration fallback (overridden by dashboard environment variables)
const HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];

// Release version of this worker build (shown on the admin status page).
const VERSION = "1.2.3";

const CONFIG = {
  secretHex: "",                // Overridden by env.SECRET (32 hex or dd+32 hex)
  adTagHex: "",                 // Overridden by env.AD_TAG (32 hex)
  hostnames: ["*"],             // Overridden by env.HOSTNAME (comma-separated or '*')
  debug: false,                 // Overridden by env.DEBUG ("true" or "1")

  generatorEnabled: false,      // Secret page is OFF by default (it used to leak SECRET publicly)
  generatorKey: "",             // Optional custom seed for secret derivation
  acceptGenerated: false,

  dc: {
    1: ["149.154.175.50", "149.154.175.53", "149.154.175.54"],
    2: ["149.154.167.51", "149.154.167.50", "149.154.167.40", "149.154.167.41"],
    3: ["149.154.175.100", "149.154.175.101"],
    4: ["149.154.167.91", "149.154.167.92", "149.154.167.90"],
    5: ["91.108.56.156", "91.108.56.165", "91.108.56.170"],
    203: ["91.105.192.110"]
  },
  dcPort: 443,
  dcPorts: [443, 80, 5222],
  carrier: "websocket-lanes",   // "websocket-lanes" (one WS per stream) or "websocket" (all streams in one WS)
  sessionPath: "/api/v1/session",
  wsPath: "/api/v1/ws",
  batchBytes: 2097152,
  bootstrapTtl: 3600,           // 1 hour (resilient against session renegotiation and client reconnects)
  sessionTtl: 86400,
  maxStreams: 6,                // Safe default for Cloudflare Workers Free plan socket limits
  maxQueued: 16777216,
  streamWindow: 4194304,
  dataChunk: 65536
};

const te = new TextEncoder();
const TOKEN_DOMAIN = te.encode("tgweb-token-v1\0");
const BUILD_SEAL = "Pt54F2/pkjqM1YnQmZRs3Xvqd54U1iZVSYCfYAOgf5wIRzjyeruT";
const TOKEN_KIND_BOOTSTRAP = 1;
const TOKEN_KIND_SESSION = 2;
const PORT_MODE_BASE = 10;
const REQUEST_LIMIT = 16777216;

// ---- Lightweight in-memory telemetry (per isolate, best effort) ----
// No external calls, no dependencies, bounded memory. It powers the admin
// status page so the operator can answer "is the proxy actually working?".
// Counters reset whenever Cloudflare recycles the isolate. No client IPs,
// tokens or secrets are ever recorded.
const ISOLATE_START = Date.now();
const STATS = {
  sessions: 0,        // WebSocket proxy sessions created in this isolate
  sessionsActive: 0,  // currently open in this isolate
  streams: 0,         // MTProto streams opened in this isolate
  dcAttempts: 0,      // outbound TCP connects to Telegram DCs
  dcFails: 0,         // failed DC connects
  bytesUp: 0,         // client -> Telegram bytes (approximate)
  bytesDown: 0,       // Telegram -> client bytes (approximate)
  wsRejects: 0,       // WebSocket handshakes rejected (bad/expired token)
  tlsErrors: 0,       // failed TLS handshakes (bad cert / wrong port / SNI mismatch)
  panelViews: 0,
  statusViews: 0
};
const LOG = [];
const LOG_LIMIT = 240;
function logEvent(event, detail) {
  try {
    LOG.push({ t: Date.now(), event: String(event).slice(0, 24), detail: String(detail || "").slice(0, 120) });
    if (LOG.length > LOG_LIMIT) LOG.splice(0, LOG.length - LOG_LIMIT);
  } catch (_) {}
}

// Debug trace switch, mirrored from env.DEBUG by getRuntime(). Kept module-global
// so low-level helpers (Stream, connect wrapper) can log without a cfg reference.
let DEBUG_ON = ENV.DEBUG === "true" || ENV.DEBUG === "1";

// Single structured diagnostic line. Always mirrored into the in-memory LOG ring
// (so the admin /status page shows it) and additionally printed to stdout when
// DEBUG is enabled. Secrets, tokens and full IPs are never emitted verbatim:
// IPs are truncated to the first two octets.
function diag(scope, message, extra) {
  const detail = extra === undefined ? String(message) : String(message) + " " + String(extra);
  logEvent(scope, detail);
  if (DEBUG_ON) {
    try { console.log(`[${new Date().toISOString()}] ${scope.padEnd(10)} ${detail}`); } catch (_) {}
  }
}

// Verbose per-request trace. Unlike logEvent() (a 240-entry ring with 120-char
// details), this keeps the full request line, every request header, a body
// preview and the resulting status, so a failed Telegram handshake can be
// reconstructed step by step. Secrets are redacted before anything is stored.
const REQLOG = [];
const REQLOG_LIMIT = 200;

function redactHeader(name, value) {
  const lower = String(name).toLowerCase();
  if (lower === "authorization" || lower === "proxy-authorization" || lower === "cookie" || lower === "set-cookie") {
    const text = String(value);
    return text.length > 24 ? text.slice(0, 12) + "…" + text.slice(-6) + " (len=" + text.length + ")" : "***";
  }
  return String(value);
}

function hexPreview(bytes, limit) {
  const take = Math.min(bytes.length, limit);
  let hex = "";
  for (let i = 0; i < take; i++) hex += (i ? " " : "") + bytes[i].toString(16).padStart(2, "0");
  return hex + (bytes.length > take ? " …+" + (bytes.length - take) + "B" : "");
}

function logRequest(entry) {
  try {
    entry.t = Date.now();
    REQLOG.push(entry);
    if (REQLOG.length > REQLOG_LIMIT) REQLOG.splice(0, REQLOG.length - REQLOG_LIMIT);
  } catch (_) {}
  if (DEBUG_ON) {
    try {
      const headers = Object.keys(entry.headers).map((k) => k + ": " + entry.headers[k]).join(" | ");
      console.log(`[${new Date(entry.t).toISOString()}] req        ${entry.method} ${entry.path} status=${entry.status || "-"} dur=${entry.ms === undefined ? "-" : entry.ms + "ms"} body=${entry.body || "-"}\n    headers ${headers}`);
    } catch (_) {}
  }
}

function maskIp(ip) {
  const text = String(ip || "");
  if (!text) return "-";
  if (text.includes(":")) {
    const parts = text.split(":");
    return parts.slice(0, 2).join(":") + ":…";
  }
  const parts = text.split(".");
  return parts.length === 4 ? parts[0] + "." + parts[1] + ".x.x" : text;
}

const PERMISSIONS_POLICY = "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-create=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), web-share=(), xr-spatial-tracking=()";

// Realistic premium fashion e-commerce storefront for anti-censorship camouflage
// (resists GFW / TSPU / DPI active probing — looks like a legitimate clothing brand)
const DECOY_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="LUXVEIL — Premium contemporary fashion. Curated collections of designer apparel, outerwear, and accessories for the modern wardrobe.">
<meta name="robots" content="index, follow">
<meta property="og:title" content="LUXVEIL — Contemporary Fashion House">
<meta property="og:type" content="website">
<title>LUXVEIL &mdash; Contemporary Fashion House</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#faf9f7;--surface:#fff;--text:#1a1a1a;--muted:#71717a;--accent:#92400e;--accent-light:#fef3c7;--border:#e4e4e7;--hover:#f4f4f5;--gold:#b8860b;--shadow:0 1px 3px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);--shadow-lg:0 10px 25px rgba(0,0,0,.07),0 4px 10px rgba(0,0,0,.04)}
@keyframes fadeUp{from{opacity:0;transform:translateY(28px)}to{opacity:1;transform:translateY(0)}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes shimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
@keyframes marquee{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,-apple-system,Helvetica,Arial,sans-serif;line-height:1.6;-webkit-font-smoothing:antialiased;overflow-x:hidden}
a{color:inherit;text-decoration:none}
.announce{background:var(--text);color:#fff;text-align:center;padding:.55rem 1rem;font-size:.8rem;letter-spacing:.08em;text-transform:uppercase;overflow:hidden}
.announce-inner{display:inline-flex;gap:3rem;animation:marquee 25s linear infinite;white-space:nowrap}
nav{background:var(--surface);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100;backdrop-filter:blur(12px);background:rgba(255,255,255,.92)}
.nav-inner{max-width:1280px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;padding:.85rem 2rem}
.nav-logo{font-size:1.4rem;font-weight:800;letter-spacing:.22em;text-transform:uppercase}
.nav-links{display:flex;gap:2rem;list-style:none;font-size:.88rem;font-weight:500;letter-spacing:.03em;text-transform:uppercase}
.nav-links a{position:relative;padding:.25rem 0;transition:color .2s}
.nav-links a::after{content:'';position:absolute;bottom:0;left:0;width:0;height:1.5px;background:var(--accent);transition:width .3s ease}
.nav-links a:hover::after{width:100%}
.nav-links a:hover{color:var(--accent)}
.nav-icons{display:flex;align-items:center;gap:1.25rem}
.nav-icons svg{width:20px;height:20px;stroke:var(--text);stroke-width:1.5;fill:none;cursor:pointer;transition:stroke .2s}
.nav-icons svg:hover{stroke:var(--accent)}
.cart-badge{position:relative}
.cart-badge::after{content:'2';position:absolute;top:-6px;right:-8px;background:var(--accent);color:#fff;font-size:.6rem;width:16px;height:16px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700}
.hamburger{display:none;flex-direction:column;gap:4px;cursor:pointer;padding:4px}
.hamburger span{width:20px;height:1.5px;background:var(--text);border-radius:1px}
.hero{max-width:1280px;margin:0 auto;padding:0 2rem;display:grid;grid-template-columns:1fr 1fr;gap:3rem;align-items:center;min-height:75vh;animation:fadeIn .8s ease}
.hero-text{animation:fadeUp .9s ease .1s both}
.hero-tag{display:inline-block;font-size:.72rem;letter-spacing:.15em;text-transform:uppercase;color:var(--accent);background:var(--accent-light);padding:.35rem .9rem;border-radius:2rem;font-weight:600;margin-bottom:1.5rem}
.hero h1{font-size:3.5rem;font-weight:800;line-height:1.08;letter-spacing:-.02em;margin-bottom:1.25rem}
.hero h1 em{font-style:normal;color:var(--accent)}
.hero p{font-size:1.1rem;color:var(--muted);max-width:460px;margin-bottom:2rem;line-height:1.7}
.hero-btns{display:flex;gap:1rem;flex-wrap:wrap}
.btn{display:inline-flex;align-items:center;gap:.5rem;padding:.85rem 2rem;border-radius:.4rem;font-size:.88rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;transition:all .25s ease;cursor:pointer;border:none}
.btn-primary{background:var(--text);color:#fff}
.btn-primary:hover{background:var(--accent);transform:translateY(-1px);box-shadow:var(--shadow-lg)}
.btn-outline{background:transparent;color:var(--text);border:1.5px solid var(--border)}
.btn-outline:hover{border-color:var(--text);background:var(--hover)}
.hero-visual{position:relative;animation:fadeUp .9s ease .3s both}
.hero-img{width:100%;aspect-ratio:3/4;background:linear-gradient(135deg,#e8e0d6 0%,#d4c8b8 30%,#c9b99a 60%,#b8a88a 100%);border-radius:1rem;overflow:hidden;position:relative}
.hero-img::before{content:'';position:absolute;inset:0;background:linear-gradient(45deg,transparent 40%,rgba(255,255,255,.15) 50%,transparent 60%);background-size:200% 200%;animation:shimmer 4s ease-in-out infinite}
.hero-img::after{content:'LUXVEIL';position:absolute;bottom:2rem;left:2rem;font-size:1.1rem;letter-spacing:.3em;text-transform:uppercase;color:rgba(255,255,255,.7);font-weight:300}
.hero-float{position:absolute;right:-1rem;top:25%;background:var(--surface);border-radius:.75rem;padding:1rem 1.25rem;box-shadow:var(--shadow-lg);animation:float 4s ease-in-out infinite;z-index:2}
.hero-float .hf-label{font-size:.65rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:.25rem}
.hero-float .hf-value{font-size:1.3rem;font-weight:700;color:var(--accent)}
.banner{background:var(--text);padding:1rem 0;overflow:hidden}
.banner-track{display:flex;gap:3rem;animation:marquee 20s linear infinite;white-space:nowrap}
.banner-track span{color:rgba(255,255,255,.6);font-size:.78rem;letter-spacing:.2em;text-transform:uppercase;font-weight:500}
.section{max-width:1280px;margin:0 auto;padding:5rem 2rem}
.section-head{text-align:center;margin-bottom:3.5rem}
.section-head h2{font-size:2.2rem;font-weight:800;letter-spacing:-.01em;margin-bottom:.75rem}
.section-head p{color:var(--muted);font-size:1rem;max-width:480px;margin:0 auto}
.products{display:grid;grid-template-columns:repeat(4,1fr);gap:1.5rem}
.product{cursor:pointer}
.product-img{aspect-ratio:3/4;border-radius:.75rem;overflow:hidden;position:relative;margin-bottom:1rem}
.product-img .img-fill{width:100%;height:100%;transition:transform .6s ease}
.product:hover .img-fill{transform:scale(1.06)}
.p1 .img-fill{background:linear-gradient(160deg,#c4b5a3,#a89279)}
.p2 .img-fill{background:linear-gradient(160deg,#2c2c2c,#555)}
.p3 .img-fill{background:linear-gradient(160deg,#8b7355,#c4a97d)}
.p4 .img-fill{background:linear-gradient(160deg,#d6cfc4,#a89888)}
.product-img .quick{position:absolute;bottom:0;left:0;right:0;background:rgba(26,26,26,.88);color:#fff;text-align:center;padding:.7rem;font-size:.78rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;transform:translateY(100%);transition:transform .35s ease;backdrop-filter:blur(4px)}
.product:hover .quick{transform:translateY(0)}
.product-info h3{font-size:.92rem;font-weight:600;margin-bottom:.3rem}
.product-info .cat{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:.4rem}
.product-info .price{font-size:.95rem;font-weight:700}
.product-info .price .old{text-decoration:line-through;color:var(--muted);font-weight:400;margin-left:.4rem;font-size:.85rem}
.product-colors{display:flex;gap:.35rem;margin-top:.5rem}
.product-colors span{width:14px;height:14px;border-radius:50%;border:1.5px solid var(--border);transition:transform .2s}
.product-colors span:hover{transform:scale(1.3)}
.features{display:grid;grid-template-columns:repeat(4,1fr);gap:2rem;margin-top:4rem}
.feature{text-align:center;padding:2rem 1.25rem;border-radius:.75rem;transition:all .3s ease}
.feature:hover{background:var(--surface);box-shadow:var(--shadow-lg);transform:translateY(-4px)}
.feature svg{width:32px;height:32px;stroke:var(--accent);stroke-width:1.5;fill:none;margin:0 auto 1rem}
.feature h4{font-size:.92rem;font-weight:700;margin-bottom:.4rem;text-transform:uppercase;letter-spacing:.04em}
.feature p{font-size:.82rem;color:var(--muted);line-height:1.6}
.lookbook{display:grid;grid-template-columns:1fr 1fr;gap:0;min-height:65vh;margin:5rem 0}
.lookbook-img{background:linear-gradient(160deg,#d4c4b0,#baa78c);position:relative;overflow:hidden}
.lookbook-img::before{content:'';position:absolute;inset:0;background:linear-gradient(180deg,transparent 60%,rgba(0,0,0,.2) 100%)}
.lookbook-content{display:flex;flex-direction:column;justify-content:center;padding:5rem 4rem;background:var(--surface)}
.lookbook-content .lb-tag{font-size:.7rem;letter-spacing:.2em;text-transform:uppercase;color:var(--accent);margin-bottom:1rem}
.lookbook-content h2{font-size:2.8rem;font-weight:800;line-height:1.1;margin-bottom:1.25rem}
.lookbook-content p{color:var(--muted);font-size:1rem;line-height:1.8;margin-bottom:2rem;max-width:400px}
.reviews{display:grid;grid-template-columns:repeat(3,1fr);gap:1.5rem}
.review{background:var(--surface);border:1px solid var(--border);border-radius:.75rem;padding:2rem;transition:box-shadow .3s,transform .3s}
.review:hover{box-shadow:var(--shadow-lg);transform:translateY(-3px)}
.review-stars{color:var(--gold);font-size:.85rem;margin-bottom:.75rem;letter-spacing:2px}
.review p{font-size:.9rem;color:var(--text);line-height:1.7;margin-bottom:1rem;font-style:italic}
.review-author{font-size:.8rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.newsletter{text-align:center;background:var(--text);color:#fff;padding:5rem 2rem}
.newsletter h2{font-size:2rem;font-weight:800;margin-bottom:.75rem}
.newsletter p{color:rgba(255,255,255,.55);margin-bottom:2rem;font-size:.95rem}
.newsletter-form{display:flex;max-width:460px;margin:0 auto;border-radius:.4rem;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.2)}
.newsletter-form input{flex:1;padding:.9rem 1.25rem;border:none;font-size:.88rem;outline:none;background:#fff;color:var(--text)}
.newsletter-form button{padding:.9rem 1.8rem;background:var(--accent);color:#fff;border:none;font-size:.82rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;cursor:pointer;transition:background .2s;white-space:nowrap}
.newsletter-form button:hover{background:#7c3309}
footer{background:var(--surface);border-top:1px solid var(--border);padding:4rem 2rem 2rem}
.footer-inner{max-width:1280px;margin:0 auto}
.footer-grid{display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:3rem;margin-bottom:3rem}
.footer-brand .f-logo{font-size:1.2rem;font-weight:800;letter-spacing:.2em;text-transform:uppercase;margin-bottom:.75rem}
.footer-brand p{color:var(--muted);font-size:.85rem;line-height:1.7;max-width:280px}
.footer-col h5{font-size:.75rem;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin-bottom:1rem}
.footer-col ul{list-style:none}
.footer-col li{margin-bottom:.5rem}
.footer-col a{font-size:.88rem;color:var(--text);transition:color .2s}
.footer-col a:hover{color:var(--accent)}
.footer-bottom{display:flex;justify-content:space-between;align-items:center;padding-top:2rem;border-top:1px solid var(--border);font-size:.78rem;color:var(--muted)}
.footer-social{display:flex;gap:1rem}
.footer-social svg{width:18px;height:18px;stroke:var(--muted);stroke-width:1.5;fill:none;transition:stroke .2s;cursor:pointer}
.footer-social svg:hover{stroke:var(--accent)}
@media(max-width:1024px){
.hero{grid-template-columns:1fr;text-align:center;min-height:auto;padding-top:3rem}
.hero h1{font-size:2.6rem}
.hero p{margin:0 auto 2rem}
.hero-btns{justify-content:center}
.hero-visual{max-width:400px;margin:0 auto}
.hero-float{display:none}
.products{grid-template-columns:repeat(2,1fr)}
.features{grid-template-columns:repeat(2,1fr)}
.lookbook{grid-template-columns:1fr}
.lookbook-content{padding:3rem 2rem}
.footer-grid{grid-template-columns:1fr 1fr}
.reviews{grid-template-columns:1fr}
}
@media(max-width:640px){
.nav-links{display:none}
.hamburger{display:flex}
.hero h1{font-size:2rem}
.products,.features,.footer-grid{grid-template-columns:1fr}
.newsletter-form{flex-direction:column}
.newsletter-form input,.newsletter-form button{width:100%}
.lookbook-content h2{font-size:2rem}
}
</style>
</head>
<body>
<div class="announce"><div class="announce-inner"><span>Free express shipping on orders over \\$150</span><span>&bull;</span><span>New Season &mdash; Autumn/Winter 2026 Collection now live</span><span>&bull;</span><span>Complimentary gift wrapping on all orders</span><span>&bull;</span><span>Free express shipping on orders over \\$150</span><span>&bull;</span><span>New Season &mdash; Autumn/Winter 2026 Collection now live</span><span>&bull;</span><span>Complimentary gift wrapping on all orders</span></div></div>
<nav><div class="nav-inner"><a href="/" class="nav-logo">LUXVEIL</a><ul class="nav-links"><li><a href="/">New Arrivals</a></li><li><a href="/">Women</a></li><li><a href="/">Men</a></li><li><a href="/">Outerwear</a></li><li><a href="/">Accessories</a></li><li><a href="/">Sale</a></li></ul><div class="nav-icons"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.35-4.35"/></svg><svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg><div class="cart-badge"><svg viewBox="0 0 24 24"><path d="M6 2L3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z"/><line x1="3" y1="6" x2="21" y2="6"/><path d="M16 10a4 4 0 0 1-8 0"/></svg></div><div class="hamburger"><span></span><span></span><span></span></div></div></div></nav>
<section class="hero"><div class="hero-text"><div class="hero-tag">Autumn/Winter 2026</div><h1>Redefine Your<br><em>Everyday</em> Elegance</h1><p>Discover our latest collection of meticulously crafted garments, designed with premium fabrics and contemporary silhouettes for the modern wardrobe.</p><div class="hero-btns"><a href="/" class="btn btn-primary">Shop Collection <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg></a><a href="/" class="btn btn-outline">Lookbook</a></div></div><div class="hero-visual"><div class="hero-img"></div><div class="hero-float"><div class="hf-label">Best Seller</div><div class="hf-value">Cashmere Overcoat</div></div></div></section>
<div class="banner"><div class="banner-track"><span>Premium Quality</span><span>&#10022;</span><span>Sustainable Materials</span><span>&#10022;</span><span>Handcrafted Details</span><span>&#10022;</span><span>Worldwide Delivery</span><span>&#10022;</span><span>30-Day Returns</span><span>&#10022;</span><span>Premium Quality</span><span>&#10022;</span><span>Sustainable Materials</span><span>&#10022;</span><span>Handcrafted Details</span><span>&#10022;</span><span>Worldwide Delivery</span><span>&#10022;</span><span>30-Day Returns</span></div></div>
<section class="section"><div class="section-head"><h2>Curated Essentials</h2><p>Timeless pieces designed to transition seamlessly from season to season.</p></div><div class="products"><div class="product"><div class="product-img p1"><div class="img-fill"></div><div class="quick">Quick View</div></div><div class="product-info"><div class="cat">Outerwear</div><h3>Wool Blend Overcoat</h3><div class="price">\\$385.00</div><div class="product-colors"><span style="background:#c4b5a3"></span><span style="background:#2c2c2c"></span><span style="background:#8b7355"></span></div></div></div><div class="product"><div class="product-img p2"><div class="img-fill"></div><div class="quick">Quick View</div></div><div class="product-info"><div class="cat">Tailoring</div><h3>Relaxed Fit Blazer</h3><div class="price">\\$265.00</div><div class="product-colors"><span style="background:#2c2c2c"></span><span style="background:#3d4f5f"></span></div></div></div><div class="product"><div class="product-img p3"><div class="img-fill"></div><div class="quick">Quick View</div></div><div class="product-info"><div class="cat">Knitwear</div><h3>Merino Turtleneck</h3><div class="price">\\$145.00 <span class="old">\\$195.00</span></div><div class="product-colors"><span style="background:#8b7355"></span><span style="background:#f5f0eb"></span><span style="background:#4a3728"></span></div></div></div><div class="product"><div class="product-img p4"><div class="img-fill"></div><div class="quick">Quick View</div></div><div class="product-info"><div class="cat">Accessories</div><h3>Leather Crossbody Bag</h3><div class="price">\\$220.00</div><div class="product-colors"><span style="background:#d6cfc4"></span><span style="background:#2c2c2c"></span></div></div></div></div></section>
<section class="section" style="padding-top:0"><div class="features"><div class="feature"><svg viewBox="0 0 24 24"><rect x="1" y="3" width="15" height="13" rx="2"/><path d="M16 8l4 2v4l-4 2"/></svg><h4>Free Shipping</h4><p>Complimentary express delivery on all orders over \\$150. Worldwide tracked shipping.</p></div><div class="feature"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><h4>Secure Checkout</h4><p>256-bit SSL encryption with trusted payment partners. Your data is always protected.</p></div><div class="feature"><svg viewBox="0 0 24 24"><path d="M21 12a9 9 0 1 1-9-9c2.5 0 4.8 1 6.5 2.6"/><path d="M22 4L12 14.01l-3-3"/></svg><h4>Quality Guarantee</h4><p>Every garment is inspected for quality. 30-day hassle-free returns and exchanges.</p></div><div class="feature"><svg viewBox="0 0 24 24"><path d="M12 3L2 12h3v8h6v-6h2v6h6v-8h3L12 3z"/></svg><h4>Sustainable Fashion</h4><p>Ethically sourced materials with carbon-neutral shipping. Fashion with a conscience.</p></div></div></section>
<section class="lookbook"><div class="lookbook-img"></div><div class="lookbook-content"><div class="lb-tag">The Lookbook</div><h2>Autumn<br>Silhouettes</h2><p>Explore our editorial collection featuring rich tonal palettes, luxurious textures, and the defining shapes of the season. Each piece tells a story of understated refinement.</p><a href="/" class="btn btn-primary">View Lookbook</a></div></section>
<section class="section"><div class="section-head"><h2>What Our Clients Say</h2><p>Trusted by thousands of discerning customers worldwide.</p></div><div class="reviews"><div class="review"><div class="review-stars">&starf;&starf;&starf;&starf;&starf;</div><p>&ldquo;The quality of the cashmere overcoat exceeded my expectations. Impeccable tailoring and the fabric feels absolutely luxurious.&rdquo;</p><div class="review-author">&mdash; Sarah M., London</div></div><div class="review"><div class="review-stars">&starf;&starf;&starf;&starf;&starf;</div><p>&ldquo;Fast shipping to Dubai and the packaging was beautiful. The merino turtleneck is now my go-to piece for every occasion.&rdquo;</p><div class="review-author">&mdash; Ahmed K., Dubai</div></div><div class="review"><div class="review-stars">&starf;&starf;&starf;&starf;&starf;</div><p>&ldquo;Finally found a brand that combines minimalist design with real craftsmanship. The blazer fits perfectly &mdash; no alterations needed.&rdquo;</p><div class="review-author">&mdash; Elena V., Paris</div></div></div></section>
<section class="newsletter"><h2>Join the LUXVEIL World</h2><p>Subscribe for exclusive access to new collections, private sales, and style inspiration.</p><div class="newsletter-form"><input type="email" placeholder="Enter your email address" autocomplete="off"><button type="button">Subscribe</button></div></section>
<footer><div class="footer-inner"><div class="footer-grid"><div class="footer-brand"><div class="f-logo">LUXVEIL</div><p>Contemporary fashion house crafting timeless garments with modern sensibility. Established 2019, shipping worldwide from our ateliers in Milan and London.</p></div><div class="footer-col"><h5>Shop</h5><ul><li><a href="/">New Arrivals</a></li><li><a href="/">Women</a></li><li><a href="/">Men</a></li><li><a href="/">Outerwear</a></li><li><a href="/">Accessories</a></li><li><a href="/">Sale</a></li></ul></div><div class="footer-col"><h5>Company</h5><ul><li><a href="/">About Us</a></li><li><a href="/">Sustainability</a></li><li><a href="/">Careers</a></li><li><a href="/">Press</a></li><li><a href="/">Store Locator</a></li></ul></div><div class="footer-col"><h5>Support</h5><ul><li><a href="/">Contact Us</a></li><li><a href="/">Shipping &amp; Returns</a></li><li><a href="/">Size Guide</a></li><li><a href="/">FAQ</a></li><li><a href="/">Privacy Policy</a></li></ul></div></div><div class="footer-bottom"><span>&copy; 2026 LUXVEIL Ltd. All rights reserved.</span><div class="footer-social"><svg viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="20" rx="5"/><circle cx="12" cy="12" r="5"/><circle cx="17.5" cy="6.5" r="1.5" fill="currentColor" stroke="none"/></svg><svg viewBox="0 0 24 24"><path d="M22 4s-.7 2.1-2 3.4c1.6 10-9.4 17.3-18 11.6 2.2.1 4.4-.6 6-2C3 15.5.5 9.6 3 5c2.2 2.6 5.6 4.1 9 4-.9-4.2 4-6.6 7-3.8 1.1 0 3-1.2 3-1.2z"/></svg><svg viewBox="0 0 24 24"><path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-4 0v7h-4v-7a6 6 0 0 1 6-6z"/><rect x="2" y="9" width="4" height="12"/><circle cx="4" cy="4" r="2"/></svg></div></div></div></footer>
</body>
</html>`;

const WELCOME = new Uint8Array([0x11, 0, 0, 0, 0, 0, 0, 0]);
const EMPTY = new Uint8Array(0);

const BRIDGE_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connection</title>
</head>
<body>
<script nonce="__NONCE__">
(()=>{
'use strict';
const relayBase=location.origin+'/',bootstrap=__BOOTSTRAP__,carrierMode=__CARRIER_MODE__,sessionPath=__SESSION_PATH__,wsPath=__WS_PATH__;
const fragment=location.hash,androidNonce=/^#android=([A-Za-z0-9_-]{43})$/.exec(fragment)?.[1]||'';
history.replaceState(null,'',location.pathname);
let initialized=false,closed=false,port=null,sessionToken='',createStarted=false;
let queuedBytes=0,queuedItems=0,pollController=null,webSocket=null,webSocketTimer=0;
const pending=[],upPending=[],lanes=new Map(),closedLanes=new Set(),closedLaneOrder=[];
const queueLimit=33554432,queueItemLimit=16384,closedLaneLimit=4096;
const laneQueueLimit=8388608,laneItemLimit=1024,batchLimit=__BATCH_LIMIT__;
let upSequence=1,downCursor='0',upRunning=false;
let pingTimer=0,reconnectAttempts=0,reconnecting=false;
const openStreams=new Set();
function trackFrames(value,up){
 const view=new DataView(value);let offset=0;
 while(value.byteLength-offset>=8){
  const type=view.getUint8(offset),id=(view.getUint8(offset+1)<<16)|(view.getUint8(offset+2)<<8)|view.getUint8(offset+3);
  if(id){if(up&&type===1)openStreams.add(id);else if(type===3)openStreams.delete(id)}
  offset+=8+view.getUint32(offset+4);
 }
}
function startHeartbeat(){
 if(pingTimer)clearInterval(pingTimer);
 pingTimer=setInterval(()=>{
  if(closed||!webSocket||webSocket.readyState!==WebSocket.OPEN)return;
  try{
   const ping=new Uint8Array(12);
   ping[0]=5;
   const v=new DataView(ping.buffer);
   v.setUint32(4,4);
   v.setUint32(8,Math.floor(Date.now()/1000));
   webSocket.send(ping.buffer);
  }catch(_){}
 },20000);
}
function stopHeartbeat(){
 if(pingTimer){clearInterval(pingTimer);pingTimer=0}
}
const status=state=>{if(port&&!closed)port.postMessage({t:'status',state})};
const pause=milliseconds=>new Promise(resolve=>setTimeout(resolve,milliseconds));
const options=(method,token,body,headers,signal,keepalive)=>({
 method,body,signal,keepalive:!!keepalive,mode:'same-origin',credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',
 headers:Object.assign(token?{Authorization:'Bearer '+token}:{},body?{'Content-Type':'application/octet-stream'}:{},headers||{})
});
const bufferedBytes=()=>{
 let total=webSocket&&webSocket.readyState===WebSocket.OPEN?webSocket.bufferedAmount:0;
 if(carrierMode==='websocket-lanes')for(const lane of lanes.values())if(lane.socket&&lane.socket.readyState===WebSocket.OPEN)total+=lane.socket.bufferedAmount;
 return total;
};
function reserve(data,lane){
 if(!data.byteLength||queuedBytes+bufferedBytes()>queueLimit-data.byteLength||queuedItems>=queueItemLimit)return false;
 if(lane&&(lane.bytes>laneQueueLimit-data.byteLength||lane.items>=laneItemLimit))return false;
 queuedBytes+=data.byteLength;queuedItems++;
 if(lane){lane.bytes+=data.byteLength;lane.items++}
 return true;
}
function release(bytes,items,lane){
 queuedBytes-=bytes;queuedItems-=items;
 if(lane){lane.bytes-=bytes;lane.items-=items}
}
function splitFrames(value){
 const view=new DataView(value),result=[];let offset=0;
 while(offset<value.byteLength){
  if(value.byteLength-offset<8||result.length>=4096)throw new Error('invalid frame batch');
  const type=view.getUint8(offset),id=(view.getUint8(offset+1)<<16)|(view.getUint8(offset+2)<<8)|view.getUint8(offset+3);
  const size=view.getUint32(offset+4),end=offset+8+size;
  if((type===2&&!size)||size>1048576||end>value.byteLength)throw new Error('invalid frame');
  result.push({type,id,data:offset===0&&end===value.byteLength?value:value.slice(offset,end)});offset=end;
 }
 if(!result.length)throw new Error('empty frame batch');
 return result;
}
function frameBound(value,maxFrames,maxBytes){
 const view=new DataView(value);let offset=0,frames=0;
 while(offset<value.byteLength){
  if(value.byteLength-offset<8)throw new Error('invalid frame batch');
  const size=view.getUint32(offset+4),end=offset+8+size;
  if(end>value.byteLength)throw new Error('invalid frame');
  if(frames>0&&(frames>=maxFrames||end>maxBytes))break;
  frames++;offset=end;
 }
 return {frames,bytes:offset};
}
function joinPending(values,lane){
 let total=0,count=0,frames=0;
 while(count<values.length){
  const bound=frameBound(values[count],4096,batchLimit);
  const whole=bound.bytes===values[count].byteLength;
  if(count===0&&!whole){
   const head=new Uint8Array(values[0],0,bound.bytes).slice();
   values[0]=values[0].slice(bound.bytes);
   queuedItems++;if(lane)lane.items++;
   return {body:head.buffer,total:bound.bytes,count:1};
  }
  if(count!==0&&(total+values[count].byteLength>batchLimit||frames+bound.frames>4096))break;
  total+=values[count].byteLength;frames+=bound.frames;count++;
 }
 const joined=new Uint8Array(total);let offset=0;
 for(const data of values.splice(0,count)){joined.set(new Uint8Array(data),offset);offset+=data.byteLength}
 return {body:joined.buffer,total,count};
}
function retryAfterMs(response){
 const header=response.headers.get('Retry-After');
 if(!header)return 0;
 const seconds=Number(header);
 if(Number.isFinite(seconds)&&seconds>=0)return Math.min(seconds*1000,30000);
 const when=Date.parse(header);
 if(Number.isFinite(when)){const delta=when-Date.now();return delta>0?Math.min(delta,30000):0}
 return 0;
}
async function request(path,makeOptions){
 let delay=250,attempt=0;const deadline=Date.now()+90000;
 while(true){
  const requestOptions=makeOptions(),controller=new AbortController();
  const external=requestOptions.signal,abort=()=>controller.abort();
  if(external)external.addEventListener('abort',abort,{once:true});
  requestOptions.signal=controller.signal;
  const timer=setTimeout(abort,90000);
  let wait=0,serviceUnavailable=false;
  try{
   const response=await fetch(relayBase+path,requestOptions);
   if(response.status!==503)return response;
   serviceUnavailable=true;wait=retryAfterMs(response);
   await response.arrayBuffer();
  }catch(error){if(closed||(external&&external.aborted))throw error;attempt++;if(attempt===9)throw new Error('carrier retry limit reached')}
  finally{clearTimeout(timer);if(external)external.removeEventListener('abort',abort)}
  if(serviceUnavailable&&Date.now()>=deadline)throw new Error('carrier retry limit reached');
  status('reconnecting');
  const backoff=wait||(delay+Math.floor(Math.random()*Math.max(1,delay/4)));
  await pause(backoff);
  if(!serviceUnavailable)delay=Math.min(delay*2,5000);
 }
}
function fail(){
 if(closed)return;
 status('failed');
 if(port)port.postMessage({t:'close'});
 close(true);
}
async function createSession(first){
 try{
  status('connecting');
  const response=await request(sessionPath,()=>options('POST',bootstrap,first));
  if(response.status!==200||response.headers.get('X-Carrier-Mode')!==carrierMode)throw new Error('session creation rejected');
  sessionToken=response.headers.get('X-Session-Token')||'';
  downCursor=response.headers.get('X-Down-Cursor')||'0';
  if(!sessionToken)throw new Error('missing session token');
  if(closed){fetch(relayBase+sessionPath,options('DELETE',sessionToken,null,null,undefined,true)).catch(()=>{});return}
  const welcome=await response.arrayBuffer();
  if(carrierMode==='websocket')await openWebSocket();
  if(closed){fetch(relayBase+sessionPath,options('DELETE',sessionToken,null,null,undefined,true)).catch(()=>{});return}
  port.postMessage(welcome,[welcome]);
  status('connected');
  for(const data of pending.splice(0)){release(data.byteLength,1,null);queueCarrier(data)}
  if(carrierMode==='https')poll();
  else if(carrierMode==='https-lanes')pollLane(ensureLane(0));
 }catch(error){fail()}
}
function queueCarrier(data){
 try{
  if(carrierMode==='https')queueUp(data);
  else if(carrierMode==='https-lanes')for(const value of splitFrames(data))queueLane(value);
  else if(carrierMode==='websocket')queueWebSocket(data);
  else for(const value of splitFrames(data))queueWebSocketLane(value);
 }catch(error){fail()}
}
function queueUp(data){
 if(!reserve(data,null)){fail();return}
 upPending.push(data);runUp();
}
async function runUp(){
 if(upRunning)return;
 upRunning=true;
 try{
  while(!closed&&sessionToken&&upPending.length){
   const batch=joinPending(upPending,null),sequence=String(upSequence);
   const response=await request('api/v1/up',()=>options('POST',sessionToken,batch.body,{'X-Up-Seq':sequence}));
   if(response.status!==204||response.headers.get('X-Up-Ack')!==sequence)throw new Error('uplink rejected');
   release(batch.total,batch.count,null);port.postMessage({t:'traffic',up:batch.total,down:0});upSequence++;
  }
 }catch(error){fail()}
 finally{upRunning=false;if(!closed&&sessionToken&&upPending.length)runUp()}
}
async function poll(){
 while(!closed&&sessionToken){
  try{
   pollController=new AbortController();
   const response=await request('api/v1/down',()=>options('POST',sessionToken,null,{'X-Down-Cursor':downCursor},pollController.signal));
   if(response.status===204){status('connected');continue}
   if(response.status!==200)throw new Error('downlink rejected');
   const next=response.headers.get('X-Down-Cursor')||'',data=await response.arrayBuffer();
   if(!next||!data.byteLength)throw new Error('invalid downlink response');
   if(closed)return;
   port.postMessage({t:'traffic',up:0,down:data.byteLength});port.postMessage(data,[data]);downCursor=next;status('connected');
  }catch(error){if(!closed)fail();return}
 }
}
function ensureLane(id){
 let lane=lanes.get(id);
 if(!lane){lane={id,sequence:1,cursor:'0',pending:[],bytes:0,items:0,running:false,polling:false,socket:null,timer:0,opened:false,localClosed:false,remoteClosed:false,finished:false};lanes.set(id,lane)}
 return lane;
}
function rememberLaneClosed(id){
 if(!id||closedLanes.has(id))return;
 if(closedLaneOrder.length===closedLaneLimit)closedLanes.delete(closedLaneOrder.shift());
 closedLanes.add(id);closedLaneOrder.push(id);
}
function queueLane(value){
 let lane=lanes.get(value.id);
 if(!lane&&(value.type===2||value.type===3||value.type===4))return;
 if(!lane&&closedLanes.has(value.id))throw new Error('closed lane was reused');
 if(!lane&&value.type!==1)throw new Error('lane did not begin with OPEN');
 lane=lane||ensureLane(value.id);
 if(!reserve(value.data,lane)){fail();return}
 lane.pending.push(value.data);runLaneUp(lane);
}
async function runLaneUp(lane){
 if(lane.running)return;
 lane.running=true;
 try{
  while(!closed&&sessionToken&&lane.pending.length){
   const batch=joinPending(lane.pending,lane),sequence=String(lane.sequence),laneID=String(lane.id);
   const response=await request('api/v1/up',()=>options('POST',sessionToken,batch.body,{'X-Up-Seq':sequence,'X-Lane-ID':laneID}));
   if(response.status!==204||response.headers.get('X-Up-Ack')!==sequence)throw new Error('lane uplink rejected');
   release(batch.total,batch.count,lane);port.postMessage({t:'traffic',up:batch.total,down:0});lane.sequence++;
   if(!lane.polling)pollLane(lane);
  }
 }catch(error){fail()}
 finally{lane.running=false;if(!closed&&sessionToken&&lane.pending.length)runLaneUp(lane)}
}
async function pollLane(lane){
 if(lane.polling)return;
 lane.polling=true;
 try{
  while(!closed&&sessionToken&&lanes.get(lane.id)===lane){
   const controller=new AbortController(),laneID=String(lane.id);
   lane.controller=controller;
   const response=await request('api/v1/down',()=>options('POST',sessionToken,null,{'X-Down-Cursor':lane.cursor,'X-Lane-ID':laneID},controller.signal));
   if(response.status===204){
    if(response.headers.get('X-Lane-Closed')==='1'){lanes.delete(lane.id);rememberLaneClosed(lane.id);return}
    status('connected');continue;
   }
   if(response.status!==200)throw new Error('lane downlink rejected');
   const next=response.headers.get('X-Down-Cursor')||'',data=await response.arrayBuffer();
   if(!next||!data.byteLength)throw new Error('invalid lane downlink response');
   for(const value of splitFrames(data))if(value.id!==lane.id)throw new Error('cross-lane frame');
   if(closed)return;
   port.postMessage({t:'traffic',up:0,down:data.byteLength});port.postMessage(data,[data]);lane.cursor=next;status('connected');
  }
 }catch(error){if(!closed)fail()}
 finally{lane.polling=false;lane.controller=null}
}
function openWebSocket(){
 return new Promise((resolve,reject)=>{
  const target=relayBase.replace(/^https:/,'wss:')+wsPath,socket=new WebSocket(target,'tproxy-v1.'+sessionToken);
  webSocket=socket;socket.binaryType='arraybuffer';
  let opened=false;
  socket.onopen=()=>{
   opened=true;
   startHeartbeat();
   resolve();
  };
  socket.onmessage=event=>{
   if(!(event.data instanceof ArrayBuffer)||!event.data.byteLength){fail();return}
   if(event.data.byteLength>=8){
    const view=new DataView(event.data);
    const type=view.getUint8(0);
    const id=(view.getUint8(1)<<16)|(view.getUint8(2)<<8)|view.getUint8(3);
    if(id===0){
     if(type===5){
      const pong=new Uint8Array(event.data.slice(0));
      pong[0]=6;
      if(socket.readyState===WebSocket.OPEN)try{socket.send(pong.buffer)}catch(_){}
      return;
     }
     if(type===6)return;
    }
   }
   try{trackFrames(event.data,false)}catch(_){}
   port.postMessage({t:'traffic',up:0,down:event.data.byteLength});port.postMessage(event.data,[event.data]);status('connected');
  };
  socket.onerror=()=>reject(new Error('websocket failed'));
  socket.onclose=()=>{
   if(closed||webSocket!==socket||!opened)return;
   scheduleReconnect();
  };
 });
}
function scheduleReconnect(){
 if(closed||reconnecting)return;
 reconnecting=true;stopHeartbeat();status('reconnecting');
 // The server-side session (DC sockets + cipher state) died with the old socket.
 // Close those streams towards Telegram so it reopens them at once instead of hanging,
 // and drop uplink bytes that belong to the dead streams.
 for(const id of openStreams){const frame=closeFrame(id);port.postMessage(frame,[frame])}
 openStreams.clear();
 if(upPending.length){let bytes=0;for(const data of upPending)bytes+=data.byteLength;release(bytes,upPending.length,null);upPending.length=0}
 const attempt=()=>{
  if(closed)return;
  if(reconnectAttempts>=12){fail();return}
  const delay=Math.min(1000*Math.pow(1.5,Math.min(reconnectAttempts,8)),10000);
  reconnectAttempts++;
  setTimeout(()=>{
   if(closed)return;
   openWebSocket().then(()=>{reconnecting=false;reconnectAttempts=0;status('connected');runWebSocketUp()}).catch(attempt);
  },delay);
 };
 attempt();
}
function queueWebSocket(data){
 trackFrames(data,true);
 if(!reserve(data,null)){fail();return}
 upPending.push(data);runWebSocketUp();
}
function runWebSocketUp(){
 if(closed||!webSocket||webSocket.readyState!==WebSocket.OPEN||!upPending.length)return;
 if(webSocket.bufferedAmount+queuedBytes>queueLimit||webSocket.bufferedAmount>=batchLimit){
  if(!webSocketTimer)webSocketTimer=setTimeout(()=>{webSocketTimer=0;runWebSocketUp()},10);
  return;
 }
 try{
  const batch=joinPending(upPending,null);webSocket.send(batch.body);release(batch.total,batch.count,null);
  port.postMessage({t:'traffic',up:batch.total,down:0});
  if(upPending.length)queueMicrotask(runWebSocketUp);
 }catch(error){fail()}
}
function closeFrame(id){
 const data=new ArrayBuffer(8),view=new DataView(data);
 view.setUint8(0,3);view.setUint8(1,id>>>16);view.setUint8(2,id>>>8);view.setUint8(3,id);view.setUint32(4,0);
 return data;
}
function finishWebSocketLane(lane,notify){
 if(lane.finished||lanes.get(lane.id)!==lane)return;
 lane.finished=true;if(lane.timer)clearTimeout(lane.timer);
 if(lane.bytes||lane.items)release(lane.bytes,lane.items,lane);
 lane.pending.length=0;lanes.delete(lane.id);rememberLaneClosed(lane.id);
 if(lane.socket&&(lane.socket.readyState===WebSocket.OPEN||lane.socket.readyState===WebSocket.CONNECTING))try{lane.socket.close()}catch(error){}
 if(notify&&port&&!closed){const frame=closeFrame(lane.id);port.postMessage(frame,[frame])}
}
function openWebSocketLane(lane){
 const target=relayBase.replace(/^https:/,'wss:')+wsPath;
 const socket=new WebSocket(target,'tproxy-lane-v1.'+sessionToken+'.'+lane.id);
 lane.socket=socket;socket.binaryType='arraybuffer';
 socket.onopen=()=>{if(closed||lane.finished){socket.close();return}lane.opened=true;status('connected');runWebSocketLaneUp(lane)};
 socket.onmessage=event=>{
  if(!(event.data instanceof ArrayBuffer)||!event.data.byteLength){fail();return}
  let values;try{values=splitFrames(event.data)}catch(error){fail();return}
  if(values.some(value=>value.id!==lane.id)){fail();return}
  if(values.some(value=>value.type===3))lane.remoteClosed=true;
  port.postMessage({t:'traffic',up:0,down:event.data.byteLength});port.postMessage(event.data,[event.data]);status('connected');
 };
 socket.onerror=()=>{};
 socket.onclose=()=>{
  if(closed||lane.finished)return;
  if(!lane.opened){fail();return}
  finishWebSocketLane(lane,!lane.localClosed&&!lane.remoteClosed);
 };
}
function queueWebSocketLane(value){
 let lane=lanes.get(value.id);
 if(!lane&&(value.type===2||value.type===3||value.type===4))return;
 if(!value.id||(!lane&&closedLanes.has(value.id)))throw new Error('closed lane was reused');
 if(!lane&&value.type!==1)throw new Error('lane did not begin with OPEN');
 lane=lane||ensureLane(value.id);
 if(value.type===3&&!lane.opened){finishWebSocketLane(lane,false);return}
 if(!reserve(value.data,lane)){fail();return}
 lane.pending.push(value.data);if(value.type===3)lane.localClosed=true;
 if(!lane.socket)openWebSocketLane(lane);else runWebSocketLaneUp(lane);
}
function runWebSocketLaneUp(lane){
 const socket=lane.socket;
 if(closed||lane.finished||!socket||socket.readyState!==WebSocket.OPEN||!lane.pending.length)return;
 if(socket.bufferedAmount>=batchLimit){
  if(!lane.timer)lane.timer=setTimeout(()=>{lane.timer=0;runWebSocketLaneUp(lane)},10);
  return;
 }
 try{
  const batch=joinPending(lane.pending,lane);socket.send(batch.body);release(batch.total,batch.count,lane);
  port.postMessage({t:'traffic',up:batch.total,down:0});
  if(lane.pending.length)queueMicrotask(()=>runWebSocketLaneUp(lane));
 }catch(error){fail()}
}
function close(notifyServer){
 if(closed)return;
 closed=true;
 stopHeartbeat();
 if(pollController)pollController.abort();
 for(const lane of lanes.values()){
  if(lane.controller)lane.controller.abort();
  if(lane.timer)clearTimeout(lane.timer);
  if(lane.socket)try{lane.socket.close()}catch(error){}
 }
 if(webSocketTimer)clearTimeout(webSocketTimer);
 if(webSocket)webSocket.close();
 if(notifyServer&&sessionToken)fetch(relayBase+sessionPath,options('DELETE',sessionToken,null,null,undefined,true)).catch(()=>{});
 if(port)port.close();
}
function activatePort(nextPort){
 initialized=true;port=nextPort;
 port.onmessage=message=>{
  if(message.data instanceof ArrayBuffer){
   if(!createStarted){createStarted=true;createSession(message.data)}
   else if(!sessionToken){if(!reserve(message.data,null)){fail();return}pending.push(message.data)}
   else queueCarrier(message.data);
  }else if(message.data&&message.data.t==='close')close(true);
 };
 port.start();status('connecting');
}
addEventListener('message',event=>{
 if(initialized||event.source!==parent||event.data===null||typeof event.data!=='object')return;
 const keys=Object.keys(event.data).sort();
 if(keys.length!==2||keys[0]!=='t'||keys[1]!=='v'||event.data.t!=='tproxy-init'||event.data.v!==1||event.ports.length!==1)return;
 let source;try{source=new URL(event.origin)}catch(error){return}
 if(source.protocol!=='http:'||source.hostname!=='127.0.0.1'||!source.port||source.origin!==event.origin)return;
 activatePort(event.ports[0]);
},{once:false});
const androidBridge=globalThis.TelegramWebProxy;
if(!initialized&&androidNonce&&androidBridge&&typeof androidBridge.postMessage==='function'){
 const androidPort={onmessage:null,start(){},close(){androidBridge.onmessage=null},postMessage(value){
  if(value instanceof ArrayBuffer){
   let frames;try{frames=splitFrames(value)}catch(error){fail();return}
   for(const frame of frames)androidBridge.postMessage(frame.data);
  }else androidBridge.postMessage(JSON.stringify(value));
 }};
 androidBridge.onmessage=event=>{
  let data=event.data;if(typeof data==='string'){try{data=JSON.parse(data)}catch(error){return}}
  if(androidPort.onmessage)androidPort.onmessage({data});
 };
 activatePort(androidPort);androidBridge.postMessage(JSON.stringify({t:'tproxy-android-init',v:1,nonce:androidNonce}));
}
addEventListener('pagehide',()=>close(true),{once:true});
})();
</script>
</body>
</html>
`;

function concat(...parts) {
  let size = 0;
  for (const part of parts) size += part.length;
  const out = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function reverse(bytes) {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = bytes[bytes.length - 1 - i];
  return out;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes) {
  let text = "";
  for (let i = 0; i < bytes.length; i++) text += bytes[i].toString(16).padStart(2, "0");
  return text;
}

function b64uEncode(bytes) {
  let text = "";
  for (let i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64uDecodeStrict(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const remainder = value.length % 4;
  if (remainder === 1) return null;
  try {
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - remainder) % 4));
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return b64uEncode(out) === value ? out : null;
  } catch (_) {
    return null;
  }
}

let sealCache = null;
// Decodes BUILD_SEAL. Its bytes are also mixed into key derivation (see buildRuntime).
async function unseal() {
  if (sealCache) return sealCache;
  const raw = atob(BUILD_SEAL);
  const data = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) data[i] = raw.charCodeAt(i);
  const salt = concat(TOKEN_DOMAIN, Uint8Array.of(0x50, 0x47, 0x01));
  const out = new Uint8Array(data.length);
  let stream = new Uint8Array(0);
  for (let block = 0; stream.length < data.length; block++) {
    stream = concat(stream, await sha256(concat(salt, Uint8Array.of(block))));
  }
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ stream[i];
  const text = new TextDecoder().decode(out);
  const bar = text.indexOf(" | ");
  sealCache = {
    bytes: out,
    name: bar > 0 ? text.slice(0, bar) : text,
    mail: bar > 0 ? text.slice(bar + 3) : ""
  };
  return sealCache;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function importHmac(raw, usages) {
  return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, usages);
}

function importAes(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "AES-CTR" }, false, ["encrypt"]);
}

function add128(iv, amount) {
  const out = new Uint8Array(iv);
  let carry = amount >>> 0;
  for (let i = 15; i >= 0 && carry !== 0; i--) {
    const sum = out[i] + (carry & 0xff);
    out[i] = sum & 0xff;
    carry = (carry >>> 8) + (sum >>> 8);
  }
  return out;
}

async function ctrAt(key, iv, position, data) {
  const block = Math.floor(position / 16);
  const skip = position % 16;
  const counter = add128(iv, block);
  if (skip === 0) {
    return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CTR", counter, length: 64 }, key, data));
  }
  const input = new Uint8Array(skip + data.length);
  input.set(data, skip);
  const out = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CTR", counter, length: 64 }, key, input));
  return out.subarray(skip);
}

function parseSecret(hexValue) {
  if (!hexValue) return null;
  let hex = String(hexValue).trim().toLowerCase();
  if (hex.startsWith("0x")) hex = hex.substring(2);
  if (!/^[0-9a-f]+$/.test(hex)) return null;
  // Telegram uses the secret exactly as typed into the link (17 bytes when the
  // "dd" prefix is present, 16 bytes otherwise), so the value is never trimmed.
  if (hex.length === 32 || hex.length === 34) return hexToBytes(hex);
  return null;
}

function parseAdTag(hexValue) {
  const hex = String(hexValue || "").trim().toLowerCase();
  if (/^[0-9a-f]{32}$/.test(hex)) return hexToBytes(hex);
  return null;
}

function resolveConfig(env) {
  const secretHex = (typeof env?.SECRET === "string" ? env.SECRET : CONFIG.secretHex || "").trim();
  const adTagHex = (typeof env?.AD_TAG === "string" ? env.AD_TAG : CONFIG.adTagHex || "").trim();
  const debug = env?.DEBUG === "true" || env?.DEBUG === "1" || CONFIG.debug === true;
  const decoyUrl = (typeof env?.DECOY_URL === "string" ? env.DECOY_URL : "").trim();

  let hostnames = [];
  if (typeof env?.HOSTNAME === "string" && env.HOSTNAME.trim()) {
    hostnames = env.HOSTNAME.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  } else if (Array.isArray(CONFIG.hostnames)) {
    hostnames = CONFIG.hostnames.map((s) => String(s).trim().toLowerCase()).filter(Boolean);
  }

  const maxStreams = env?.MAX_STREAMS && !isNaN(parseInt(env.MAX_STREAMS, 10))
    ? Math.min(32, Math.max(1, parseInt(env.MAX_STREAMS, 10)))
    : CONFIG.maxStreams;

  const sessionPath = (typeof env?.SESSION_PATH === "string" && env.SESSION_PATH.trim())
    ? (env.SESSION_PATH.trim().startsWith("/") ? env.SESSION_PATH.trim() : "/" + env.SESSION_PATH.trim())
    : CONFIG.sessionPath;

  const wsPath = (typeof env?.WS_PATH === "string" && env.WS_PATH.trim())
    ? (env.WS_PATH.trim().startsWith("/") ? env.WS_PATH.trim() : "/" + env.WS_PATH.trim())
    : CONFIG.wsPath;

  const adminKey = (typeof env?.ADMIN_KEY === "string" ? env.ADMIN_KEY.trim() : "");
  const extraHosts = (typeof env?.EXTRA_HOSTS === "string" ? env.EXTRA_HOSTS : "")
    .split(/[,\s]+/)
    .map((value) => value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/[:/].*$/, "").replace(/\.$/, ""))
    .filter((value) => /^[a-z0-9.-]+$/.test(value) && !value.includes(".."));
  // PROXY_PORTS overrides the Telegram-facing ports (default: Cloudflare's
  // 6 allowed HTTPS ports). For a self-hosted Node setup you can point it at
  // your own public port, e.g. "9090" or "443,8443". The first entry carries
  // the base SECRET; every other entry gets its own derived secret.
  const ports = [];
  if (typeof env?.PROXY_PORTS === "string" && env.PROXY_PORTS.trim()) {
    for (const token of env.PROXY_PORTS.split(/[,\s]+/)) {
      const p = parseInt(token, 10);
      if (Number.isFinite(p) && p > 0 && p <= 65535 && !ports.includes(p)) ports.push(p);
    }
  }
  // A public TLS port (PUBLIC_PORT, default 443) is what Telegram actually dials,
  // so it always leads the list. Without it the panel would advertise Cloudflare's
  // 2053/2083/2087/2096 ports, which do not exist on a self-hosted box.
  const publicPortRaw = parseInt(env?.PUBLIC_PORT, 10);
  const publicPort = Number.isFinite(publicPortRaw) && publicPortRaw > 0 && publicPortRaw <= 65535
    ? publicPortRaw
    : 443;
  if (ports.length === 0) ports.push(publicPort);
  else if (ports[0] !== publicPort) ports.unshift(publicPort);

  const carrierEnv = (typeof env?.CARRIER === "string" ? env.CARRIER.trim().toLowerCase() : "");
  const carrier = carrierEnv === "websocket" || carrierEnv === "websocket-lanes" ? carrierEnv : CONFIG.carrier;

  // DC_OVERRIDE lets an operator point a DC at a private mirror (or a local
  // mock for testing): "2=127.0.0.1:8443,3=10.0.0.5:443". Entries are merged
  // over the built-in DC table; absent entries keep their default addresses.
  const dc = Object.assign({}, CONFIG.dc);
  let dcPortsOverride = null;
  if (typeof env?.DC_OVERRIDE === "string" && env.DC_OVERRIDE.trim()) {
    for (const entry of env.DC_OVERRIDE.split(",")) {
      const m = /^(\d+)=([a-z0-9.\-\[\]:]+):(\d{1,5})$/.exec(entry.trim().toLowerCase());
      if (!m) continue;
      const id = parseInt(m[1], 10);
      const host = m[2];
      const p = parseInt(m[3], 10);
      if (!Number.isFinite(id) || id <= 0 || !host || !(p > 0 && p <= 65535)) continue;
      dc[id] = host;
      if (!dcPortsOverride) dcPortsOverride = [];
      if (!dcPortsOverride.includes(p)) dcPortsOverride.push(p);
    }
  }

  return {
    secretHex,
    adminKey,
    extraHosts,
    adTagHex,
    debug,
    hostnames,
    ports,
    decoyUrl,
    maxStreams,
    sessionPath,
    wsPath,
    generatorEnabled: env?.GENERATOR_ENABLED !== undefined ? (env.GENERATOR_ENABLED === "true" || env.GENERATOR_ENABLED === "1") : CONFIG.generatorEnabled,
    generatorKey: (typeof env?.GENERATOR_KEY === "string" ? env.GENERATOR_KEY : CONFIG.generatorKey || "").trim(),
    acceptGenerated: env?.ACCEPT_GENERATED !== undefined ? (env.ACCEPT_GENERATED === "true" || env.ACCEPT_GENERATED === "1") : CONFIG.acceptGenerated,
    dc,
    dcPort: dcPortsOverride ? dcPortsOverride[0] : CONFIG.dcPort,
    dcPorts: dcPortsOverride || CONFIG.dcPorts,
    carrier,
    tlsCertPath: (typeof env?.TLS_CERT === "string" ? env.TLS_CERT : "").trim(),
    tlsKeyPath: (typeof env?.TLS_KEY === "string" ? env.TLS_KEY : "").trim(),
    tlsPort: (() => {
      const raw = parseInt(env?.TLS_PORT, 10);
      return Number.isFinite(raw) && raw > 0 && raw <= 65535 ? raw : 8443;
    })(),
    publicPort,
    trustProxy: env?.TRUST_PROXY === "true" || env?.TRUST_PROXY === "1",
    batchBytes: CONFIG.batchBytes,
    bootstrapTtl: CONFIG.bootstrapTtl,
    sessionTtl: CONFIG.sessionTtl,
    maxQueued: CONFIG.maxQueued,
    streamWindow: CONFIG.streamWindow,
    dataChunk: CONFIG.dataChunk
  };
}

let cachedRuntime = null;
let cachedKey = null;

async function getRuntime(env) {
  const resolved = resolveConfig(env);
  DEBUG_ON = resolved.debug === true || DEBUG_ON;
  const cacheKey = `${resolved.secretHex}:${resolved.generatorKey}:${resolved.hostnames.join(",")}:${resolved.adTagHex}:${resolved.decoyUrl}:${resolved.maxStreams}:${resolved.sessionPath}:${resolved.wsPath}:${resolved.debug}:${resolved.carrier}:${resolved.acceptGenerated}:${resolved.generatorEnabled}:${resolved.adminKey}:${resolved.extraHosts.join(",")}:${resolved.ports.join(",")}`;
  if (cachedRuntime && cachedKey === cacheKey) {
    return cachedRuntime;
  }
  const runtime = await buildRuntime(resolved);
  if (runtime) {
    cachedRuntime = runtime;
    cachedKey = cacheKey;
  }
  return runtime;
}

async function buildRuntime(cfg) {
  const adminKey = cfg.adminKey && cfg.adminKey.length >= 16 ? cfg.adminKey : "";
  const seal = await unseal();
  let base = parseSecret(cfg.secretHex);
  const secretDerived = !base && !!adminKey;
  if (secretDerived) {
    // One-variable setup: the proxy secret is derived from ADMIN_KEY.
    base = (await sha256(concat(te.encode("proxygosha-secret-from-admin-v2\n"), seal.bytes, te.encode("\n" + adminKey)))).slice(0, 16);
  }
  const generatorText = String(cfg.generatorKey || "").trim();
  if (!base && !generatorText) return null;

  const fallback = base || new Uint8Array(await sha256(concat(te.encode("tgweb-fallback-v1\0"), te.encode(generatorText))));
  const generatorRaw = generatorText
    ? new Uint8Array(await sha256(concat(te.encode("tgweb-generator-v1\0"), te.encode(generatorText))))
    : base;

  const bridgeKeys = [];
  if (base) {
    bridgeKeys.push(await importHmac(base, ["verify"]));
    bridgeKeys.push(await importHmac(concat(Uint8Array.of(0xdd), base), ["verify"]));
  }

  const portSecrets = {};
  if (base) {
    for (const p of cfg.ports) {
      let sBytes;
      if (p === cfg.ports[0]) {
        sBytes = base;
      } else {
        sBytes = (await sha256(concat(te.encode("proxygosha-port-secret-v1\n"), base, te.encode("\n" + p)))).slice(0, 16);
      }
      const hex = bytesToHex(sBytes);
      portSecrets[p] = {
        secret: sBytes,
        secretHex: hex.startsWith("dd") ? hex : "dd" + hex,
        keys: [
          await importHmac(sBytes, ["verify"]),
          await importHmac(concat(Uint8Array.of(0xdd), sBytes), ["verify"])
        ]
      };
    }
  }

  const tokenKey = await importHmac(
    await sha256(concat(te.encode("tgweb-token-key-v1\0"), seal.bytes, fallback)),
    ["sign", "verify"]
  );

  const hosts = Array.isArray(cfg.hostnames)
    ? cfg.hostnames.map((value) => String(value).trim().toLowerCase()).filter(Boolean)
    : [];

  const adTag = parseAdTag(cfg.adTagHex);

  return {
    base,
    portSecrets,
    adminKey,
    secretDerived,
    extraHosts: cfg.extraHosts || [],
    bridgeKeys,
    generatorHmac: generatorRaw ? await importHmac(generatorRaw, ["sign", "verify"]) : null,
    tokenKey,
    hosts,
    ports: cfg.ports,
    dc: cfg.dc,
    dcPort: cfg.dcPort,
    dcPorts: cfg.dcPorts,
    adTag,
    adTagHex: cfg.adTagHex,
    debug: cfg.debug,
    tlsCertPath: cfg.tlsCertPath,
    tlsKeyPath: cfg.tlsKeyPath,
    tlsPort: cfg.tlsPort,
    publicPort: cfg.publicPort,
    trustProxy: cfg.trustProxy,
    decoyUrl: cfg.decoyUrl,
    sessionPath: cfg.sessionPath,
    wsPath: cfg.wsPath,
    acceptGenerated: cfg.acceptGenerated,
    generatorEnabled: cfg.generatorEnabled,
    streamWindow: cfg.streamWindow,
    maxQueued: cfg.maxQueued,
    maxStreams: cfg.maxStreams,
    dataChunk: cfg.dataChunk,
    bootstrapTtl: cfg.bootstrapTtl,
    sessionTtl: cfg.sessionTtl,
    carrier: cfg.carrier,
    batchBytes: cfg.batchBytes
  };
}

function requestHost(request, url) {
  let host = String(request.headers.get("host") || url.host || "").toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (host.startsWith("[")) return host;
  const colon = host.lastIndexOf(":");
  if (colon > 0 && host.indexOf(":") === colon) host = host.slice(0, colon);
  return host;
}

function isLocalHost(host) {
  return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]" || host.startsWith("127.");
}

function hostAllowed(cfg, host) {
  if (!/^[a-z0-9.-]+$/.test(host) || host.includes("..")) return false;
  if (cfg.hosts.length === 0 || cfg.hosts.includes("*") || (cfg.hosts.length === 1 && cfg.hosts[0] === "proxy.example.com")) {
    return true;
  }
  // Reverse proxies and NAT tunnels often rewrite the Host header to a loopback
  // address. Those requests are authenticated by the capability secret, not by
  // the Host allowlist, so let local hosts through.
  if (isLocalHost(host)) return true;
  return cfg.hosts.includes(host) || (cfg.extraHosts || []).includes(host);
}

// The domain Telegram sees. When a tunnel rewrites the Host header to a
// loopback address, fall back to the first configured hostname so the bridge
// page tells the client to connect back to the public domain, not 127.0.0.1.
function publicHost(cfg, host) {
  if (isLocalHost(host)) {
    const configured = (cfg.hosts || []).filter((h) => h !== "*" && h !== "proxy.example.com");
    if (configured.length > 0) return configured[0];
  }
  return host;
}

async function deriveSecret(cfg, label) {
  if (!cfg.generatorHmac) return null;
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", cfg.generatorHmac, te.encode("tgweb-secret-v1\n" + label)));
  return mac.subarray(0, 16);
}

async function bridgeMode(cfg, host, capability, port) {
  const provided = b64uDecodeStrict(capability);
  if (!provided || provided.length !== 32) return -1;

  const incomingPort = port ? parseInt(port, 10) : 443;
  const isKnownPort = cfg.ports.includes(incomingPort);

  // Telegram signs the capability with the public domain, but a reverse proxy or
  // tunnel may rewrite the Host header to a loopback address. Verify against the
  // request host plus every configured hostname so both setups work.
  const verifyHosts = [host];
  for (const h of cfg.hosts || []) {
    if (h && h !== "*" && h !== "proxy.example.com" && !verifyHosts.includes(h)) verifyHosts.push(h);
  }
  for (const h of cfg.extraHosts || []) {
    if (h && !verifyHosts.includes(h)) verifyHosts.push(h);
  }

  if (isKnownPort && cfg.portSecrets?.[incomingPort]) {
    const pKeys = cfg.portSecrets[incomingPort].keys;
    for (const vh of verifyHosts) {
      const contexts = incomingPort === 443
        ? [te.encode("tdesktop-web-proxy-bridge-v1\n" + vh)]
        : [
            te.encode(`tdesktop-web-proxy-bridge-v1\n${vh}:${incomingPort}`),
            te.encode("tdesktop-web-proxy-bridge-v1\n" + vh)
          ];
      for (const ctx of contexts) {
        for (const key of pKeys) {
          if (await crypto.subtle.verify("HMAC", key, provided, ctx)) {
            return PORT_MODE_BASE + cfg.ports.indexOf(incomingPort);
          }
        }
      }
    }
  }

  const candidateHosts = [];
  const candidatePorts = [];
  if (port && port !== "443" && port !== "80") candidatePorts.push(port);
  for (const p of cfg.ports) if (p !== cfg.ports[0] && !candidatePorts.includes(String(p))) candidatePorts.push(String(p));
  for (const vh of verifyHosts) if (!candidateHosts.includes(vh)) candidateHosts.push(vh);
  for (const p of candidatePorts) for (const vh of verifyHosts) {
    const ch = `${vh}:${p}`;
    if (!candidateHosts.includes(ch)) candidateHosts.push(ch);
  }

  for (const h of candidateHosts) {
    const context = te.encode("tdesktop-web-proxy-bridge-v1\n" + h);
    for (const key of cfg.bridgeKeys) {
      if (await crypto.subtle.verify("HMAC", key, provided, context)) {
        return PORT_MODE_BASE;
      }
    }
  }

  if (cfg.portSecrets) {
    for (let idx = 0; idx < cfg.ports.length; idx++) {
      const p = cfg.ports[idx];
      if (p === incomingPort) continue;
      const pKeys = cfg.portSecrets[p].keys;
      for (const vh of verifyHosts) {
        const contexts = [
          te.encode(`tdesktop-web-proxy-bridge-v1\n${vh}:${p}`),
          te.encode("tdesktop-web-proxy-bridge-v1\n" + vh)
        ];
        for (const ctx of contexts) {
          for (const key of pKeys) {
            if (await crypto.subtle.verify("HMAC", key, provided, ctx)) {
              if (!port || !isKnownPort || port === String(cfg.ports[0]) || port === String(p)) {
                return PORT_MODE_BASE + idx;
              }
            }
          }
        }
      }
    }
  }

  if (cfg.acceptGenerated) {
    for (let index = 0; index < candidateHosts.length; index++) {
      const h = candidateHosts[index];
      const context = te.encode("tdesktop-web-proxy-bridge-v1\n" + h);
      const secret = await deriveSecret(cfg, h);
      if (secret) {
        const key = await importHmac(secret, ["verify"]);
        if (await crypto.subtle.verify("HMAC", key, provided, context)) return index === 0 ? 1 : 2;
      }
    }
  }
  return -1;
}

function safeEqual(a, b) {
  const x = te.encode(String(a));
  const y = te.encode(String(b));
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}

function generatorLabel(url) {
  for (const key of ["--create-secret", "create-secret", "create_secret"]) {
    if (url.searchParams.has(key)) return url.searchParams.get(key) || "";
  }
  return null;
}

async function serveSecret(cfg, host, label, port) {
  const cleanLabel = String(label || "").replace(/^https?:\/\//i, "").replace(/\/.*$/, "").replace(/[\u0000-\u001f\u007f]/g, "").trim().toLowerCase().slice(0, 128);
  const isCustomDomain = cleanLabel.length > 0;

  let hex = "";
  let domainHex = "";
  let isExisting = false;

  if (isCustomDomain) {
    // Generate ASCII hex representation of domain
    for (let i = 0; i < cleanLabel.length; i++) {
      domainHex += cleanLabel.charCodeAt(i).toString(16).padStart(2, "0");
    }

    // Deterministically derive a 16-byte (32-hex) secret based on the address
    if (cfg && cfg.generatorHmac) {
      const derived = await deriveSecret(cfg, cleanLabel);
      if (derived) hex = bytesToHex(derived);
    }
    if (!hex) {
      // No server-side key: an unkeyed hash of a public domain name would be guessable by anyone.
      hex = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    }
  } else if (cfg && cfg.base) {
    hex = bytesToHex(cfg.base);
    isExisting = true;
  } else {
    // Fresh deployment without configured SECRET in env: generate strong random secret
    const randomBytes = crypto.getRandomValues(new Uint8Array(16));
    hex = bytesToHex(randomBytes);
  }

  const portSuffix = (port && port !== "443" && port !== "80") ? "&port=" + port : "";
  const link = "tg://webproxy?server=" + encodeURIComponent(host) + portSuffix + "&secret=" + hex;
  const paddedSecret = "dd" + hex;
  const paddedLink = "tg://webproxy?server=" + encodeURIComponent(host) + portSuffix + "&secret=" + paddedSecret;

  const lines = [
    "=== ProxyGosha Secret Generator ===",
    isCustomDomain
      ? `[Mode: DOMAIN-DERIVED SECRET for "${cleanLabel}"]`
      : (isExisting ? "[Status: ACTIVE CONFIGURATION]" : "[Status: NEW SECRET GENERATED]"),
    "",
    "Server:        " + host + (port && port !== "443" && port !== "80" ? ":" + port : ""),
  ];

  if (isCustomDomain) {
    lines.push("Target Domain: " + cleanLabel);
    lines.push("Domain Hex:    " + domainHex);
  }

  lines.push("Secret:        " + hex);
  lines.push("Telegram Link: " + link);
  lines.push("");
  lines.push("Padded Secret: " + paddedSecret + " (Random padding mode - recommended)");
  lines.push("Padded Link:   " + paddedLink);
  lines.push("");

  if (isExisting && !isCustomDomain) {
    lines.push("Your proxy is running with this secret. Use the link above in Telegram to connect.");
  } else {
    lines.push("Next Steps to Activate:");
    lines.push("1. Copy the 32-character secret (or dd-padded secret) above.");
    lines.push("2. In Cloudflare Dashboard -> Workers & Pages -> your worker -> Settings -> Variables and Secrets.");
    lines.push("3. Add/Update Environment Variable: SECRET with the value above and click Deploy.");
    lines.push("4. Connect in Telegram using the link above!");
  }
  lines.push("");

  return new Response(lines.join("\n"), {
    status: 200,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Robots-Tag": "noindex",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// Resolves which admin surface (if any) a request targets:
//   "panel"  -> the link panel at /<ADMIN_KEY> (or legacy ?create-secret&key=<ADMIN_KEY>)
//   "status" -> the status & logs page at /<ADMIN_KEY>/status
// Anything else returns null and the request falls through to the decoy site.
function panelRoute(url, cfg) {
  if (!cfg.adminKey) return null;
  let path = "";
  try { path = decodeURIComponent(url.pathname.slice(1)); } catch (_) { return null; }
  if (path.endsWith("/")) path = path.slice(0, -1);
  if (path && safeEqual(path, cfg.adminKey)) return "panel";
  if (path && safeEqual(path, cfg.adminKey + "/status")) return "status";
  if (generatorLabel(url) === "" && safeEqual(url.searchParams.get("key") || "", cfg.adminKey)) return "panel";
  return null;
}

function pageHeaders() {
  return {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Robots-Tag": "noindex, nofollow",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Strict-Transport-Security": "max-age=31536000",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
  };
}

const PAGE_STYLE = "body{font-family:system-ui,-apple-system,'Segoe UI',Tahoma,sans-serif;max-width:760px;margin:0 auto;padding:16px;background:#f6f7f9;color:#1d2330;line-height:1.8}h1{font-size:21px;margin:8px 0 4px}h2{font-size:16px;margin-top:28px}.card{background:#fff;border-radius:12px;padding:12px 16px;margin:10px 0;box-shadow:0 1px 3px rgba(0,0,0,.08)}a.btn{display:block;text-align:center;background:#2a9df4;color:#fff;text-decoration:none;padding:10px;border-radius:10px;margin:6px 0;font-weight:bold}code,textarea{direction:ltr;text-align:left;font-family:ui-monospace,Consolas,monospace;font-size:12px}textarea{width:100%;height:58px;box-sizing:border-box;border:1px solid #ccd;border-radius:8px;padding:6px}textarea.one{height:34px}.muted{color:#667;font-size:13px}.warn{background:#fff4e5;border-inline-start:4px solid #f0a020}footer.credit{margin:32px 0 8px;text-align:center;font-size:12px;color:#889;direction:ltr}footer.credit a{color:#667}ol{padding-inline-start:22px;margin:4px 0}nav.lang{text-align:end;font-size:14px}nav.lang label{cursor:pointer;padding:4px 10px;border-radius:8px;color:#2a6fd6}"
  + ".fa{display:none}#l-fa:checked~main{direction:rtl;font-family:Tahoma,system-ui,sans-serif}#l-fa:checked~main .en{display:none}#l-fa:checked~main span.fa{display:inline}#l-fa:checked~main div.fa,#l-fa:checked~main p.fa,#l-fa:checked~main ol.fa,#l-fa:checked~main h1.fa,#l-fa:checked~main h2.fa{display:block}#l-en:checked~main nav label[for=l-en],#l-fa:checked~main nav label[for=l-fa]{background:#e3eefc;font-weight:bold}"
  + "pre{background:#f0f2f5;padding:8px;border-radius:8px;overflow-x:auto;font-size:11px}pre.req-pre{margin:0;max-width:360px;max-height:180px;overflow:auto;white-space:pre-wrap;word-break:break-all;font-size:11px;background:transparent;padding:0;direction:ltr;text-align:left}table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:4px 8px;border-bottom:1px solid #e5e7eb;text-align:start;vertical-align:top}th{font-weight:600;white-space:nowrap}.ok{color:#177245}.bad{color:#b33}a.plain{color:#2a6fd6}";

// Inline text in both languages; CSS shows one of them (no JavaScript needed).
function bi(en, fa) {
  return `<span class="en">${en}</span><span class="fa">${fa}</span>`;
}

// English is the default; ?lang=fa pre-selects Persian. Switching needs no reload.
function bilingualPage(title, lang, body, seal) {
  const fa = lang === "fa";
  const credit = `<footer class="credit">ProxyGosha &middot; ${escapeHtml(seal.name)} &middot; <a href="mailto:${escapeHtml(seal.mail)}">${escapeHtml(seal.mail)}</a></footer>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${title}</title><style>${PAGE_STYLE}</style></head><body>
<input type="radio" name="l" id="l-en" hidden${fa ? "" : " checked"}><input type="radio" name="l" id="l-fa" hidden${fa ? " checked" : ""}>
<main><nav class="lang"><label for="l-en">English</label> <label for="l-fa">فارسی</label></nav>
${body}
${credit}
</main></body></html>`;
}

async function servePanel(cfg, host, port, lang) {
  STATS.panelViews++;
  logEvent("panel_view", host);
  const statusHref = "/" + encodeURIComponent(cfg.adminKey) + "/status";
  const baseHex = bytesToHex(cfg.base);
  const secret = baseHex.startsWith("dd") ? baseHex : "dd" + baseHex;
  const hosts = [];
  for (const h of [host, ...(cfg.extraHosts || [])]) if (h && !hosts.includes(h)) hosts.push(h);
  const sections = hosts.map((h) => {
    const workersDev = h.endsWith(".workers.dev");
    const items = cfg.ports.map((p) => {
      const pSecret = cfg.portSecrets?.[p]?.secretHex || secret;
      const link = "tg://webproxy?server=" + encodeURIComponent(h) + (p !== 443 ? "&port=" + p : "") + "&secret=" + pSecret;
      return `<div class="card"><b>${bi("Port", "پورت")} ${p}</b>${p === cfg.ports[0] ? " " + bi("(default)", "(پیش‌فرض)") : ""}<a class="btn" href="${escapeHtml(link)}">${bi("Connect in Telegram", "اتصال در تلگرام")}</a><textarea readonly>${escapeHtml(link)}</textarea></div>`;
    }).join("");
    const note = workersDev
      ? `<p class="muted">${bi(
          "workers.dev addresses are often filtered in Iran, and some ports may not open on them. Attach a custom domain to this Worker for the best results.",
          "آدرس workers.dev معمولاً در ایران فیلتر است و ممکن است بعضی پورت‌ها رویش باز نباشند. بهتر است یک دامنه شخصی (Custom Domain) به ورکر وصل کنید."
        )}</p>`
      : "";
    const manualItems = cfg.ports.map((p) => {
      const s = cfg.portSecrets?.[p]?.secretHex || secret;
      return `<div style="margin:6px 0"><b>${bi("Port", "پورت")} ${p}</b>${p === cfg.ports[0] ? " " + bi("(default)", "(پیش‌فرض)") : ""}:<textarea class="one" readonly>${escapeHtml(s)}</textarea></div>`;
    }).join("");
    const manual = `<div class="card"><b>${bi("Manual entry", "ورود دستی")}</b> — ${bi(
        "in Telegram's proxy settings, add a new proxy of type <b>WEB</b>. Each port has its own unique secret:",
        "در تنظیمات پروکسی تلگرام یک پروکسی جدید از نوع <b>WEB</b> اضافه کنید. هر پورت سکرت اختصاصی خود را دارد:"
      )}<br>
${bi("Server", "سرور")}:<textarea class="one" readonly>${escapeHtml(h)}</textarea>
<div style="margin-top:8px"><b>${bi("Ports &amp; Secrets", "پورت‌ها و سکرت‌ها")}:</b></div>
${manualItems}</div>`;
    return `<h2>${escapeHtml(h)}</h2>${note}${manual}${items}`;
  }).join("");
  const derivedNote = cfg.secretDerived
    ? `<div class="card warn">${bi(
        "Your proxy secrets are derived from ADMIN_KEY. Changing ADMIN_KEY changes the secrets and breaks every link you have shared. To avoid this, also set a fixed SECRET variable.",
        "سکرت‌های پروکسی از ADMIN_KEY ساخته شده‌اند. اگر ADMIN_KEY را عوض کنید، سکرت‌ها هم عوض می‌شوند و همه لینک‌هایی که فرستاده‌اید از کار می‌افتند. برای جلوگیری، یک متغیر SECRET ثابت هم تنظیم کنید."
      )}</div>`
    : "";
  const body = `<h1>${bi("Proxy panel", "پنل پروکسی")}</h1>
<div class="card">${bi(
    "Tap <b>Connect in Telegram</b> to add the proxy. Each port has its own secret. If a port does not connect, try another one. You can add several ports at once and switch between them in Telegram.",
    "روی «اتصال در تلگرام» بزنید تا پروکسی اضافه شود. هر پورت سکرت اختصاصی خود را دارد. اگر یک پورت وصل نشد، پورت دیگری را امتحان کنید. می‌توانید چند پورت را با هم اضافه کنید و در تلگرام بینشان جابه‌جا شوید."
  )}</div>
<div class="card warn">${bi(
    "Do not share this page. Share only the links, or the server, port and matching secret.",
    "این صفحه را با کسی به اشتراک نگذارید. فقط لینک‌ها یا سرور، پورت و سکرت مربوطه را بفرستید."
  )}</div>
<div class="card"><a class="plain" href="${escapeHtml(statusHref)}">${bi("Status &amp; logs", "وضعیت و لاگ‌ها")}</a> <span class="muted">${bi("— live statistics, recent events and a Telegram DC reachability probe.", "— آمار زنده، رویدادهای اخیر و تست دسترسی به دیتاسنترهای تلگرام.")}</span></div>
${derivedNote}
${sections}`;
  return new Response(bilingualPage("Panel", lang, body, await unseal()), { status: 200, headers: pageHeaders() });
}

async function serveSetup(host, env, lang, method) {
  // The setup page is documentation for the operator's browser only; every
  // other method gets a plain 404 so the worker does not answer API-style
  // probes with a page that identifies the software.
  if (method !== "GET" && method !== "HEAD") return notFound();
  const suggested = b64uEncode(crypto.getRandomValues(new Uint8Array(18))).replace(/[-_]/g, "x");
  const current = typeof env?.ADMIN_KEY === "string" ? env.ADMIN_KEY.trim() : "";
  const problem = current && current.length < 16
    ? `<div class="card warn">${bi(
        "Your current ADMIN_KEY is too short. It must be at least 16 characters.",
        "ADMIN_KEY فعلی کوتاه است. حداقل ۱۶ کاراکتر لازم است."
      )}</div>`
    : "";
  const body = `<h1>${bi("Proxy setup", "راه‌اندازی پروکسی")}</h1>${problem}
<div class="card">
<ol class="en"><li>In the Cloudflare dashboard, open <b>Workers &amp; Pages</b> → this Worker → <b>Settings</b> → <b>Variables and Secrets</b>.</li>
<li>Click <b>Add</b>. Name: <code>ADMIN_KEY</code>. Value: the key below (or any password of 16+ English letters and digits).</li>
<li>Click <b>Deploy</b>.</li>
<li>Open the address below to reach your panel with ready Telegram links.</li></ol>
<ol class="fa"><li>در داشبورد کلودفلر: <b>Workers &amp; Pages</b> ← این ورکر ← <b>Settings</b> ← <b>Variables and Secrets</b></li>
<li>روی <b>Add</b> بزنید. نام: <code>ADMIN_KEY</code> ، مقدار: رمز زیر (یا هر رمز ۱۶+ حرفی از حروف و اعداد انگلیسی)</li>
<li><b>Deploy</b> را بزنید.</li>
<li>آدرس زیر را باز کنید تا پنل و لینک‌های آماده تلگرام را ببینید.</li></ol>
${bi("Suggested key", "رمز پیشنهادی")}:<textarea class="one" readonly>${escapeHtml(suggested)}</textarea>
${bi("Panel address", "آدرس پنل")}:<textarea class="one" readonly>https://${escapeHtml(host)}/${escapeHtml(suggested)}</textarea></div>
<p class="muted">${bi(
    "Keep this key private. Anyone who has it can open your panel. If you reload this page, a new key is suggested; use the one you actually saved in Cloudflare.",
    "این رمز را جایی امن نگه دارید. هر کس آن را داشته باشد به پنل دسترسی دارد. با رفرش صفحه رمز جدیدی پیشنهاد می‌شود؛ همان رمزی را استفاده کنید که در کلودفلر ذخیره کرده‌اید."
  )}</p>`;
  return new Response(bilingualPage("Setup", lang, body, await unseal()), { status: 200, headers: pageHeaders() });
}

function fmtBytes(value) {
  const n = Number(value) || 0;
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
  return (n / 1073741824).toFixed(2) + " GB";
}

function fmtDuration(milliseconds) {
  const total = Math.max(0, Math.floor(milliseconds / 1000));
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  if (days) return days + "d " + hours + "h";
  if (hours) return hours + "h " + minutes + "m";
  return minutes + "m " + (total % 60) + "s";
}

// On-demand reachability probe of the Telegram DC front-ends used by this
// worker. Admin-only, runs only when explicitly requested (?probe=1), keeps
// at most three TCP sockets in the "connecting" phase and closes them right
// away. It never leaves the Cloudflare network and stores no results.
async function probeDcs(cfg) {
  const keys = Object.keys(cfg.dc).map(Number).sort((a, b) => a - b);
  const results = [];
  const probeOne = async (key) => {
    const ips = Array.isArray(cfg.dc[key]) ? cfg.dc[key] : [cfg.dc[key]];
    const ip = ips[Math.floor(Math.random() * ips.length)];
    const started = Date.now();
    let socket = null;
    try {
      socket = connect({ hostname: ip, port: cfg.dcPort || 443 }, { secureTransport: "off" });
      socket.closed.catch(() => {});
      await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 2500))]);
      try { await socket.close(); } catch (_) {}
      results.push({ dc: key, ip, ok: true, ms: Date.now() - started });
    } catch (_) {
      if (socket) { try { socket.close().catch(() => {}); } catch (_) {} }
      results.push({ dc: key, ip, ok: false, ms: Date.now() - started });
    }
  };
  for (let i = 0; i < keys.length; i += 3) {
    await Promise.all(keys.slice(i, i + 3).map(probeOne));
  }
  logEvent("dc_probe", results.map((r) => "DC" + r.dc + (r.ok ? ":ok" : ":fail")).join(" "));
  return results;
}

// Admin status & logs page: /<ADMIN_KEY>/status  (add ?probe=1 for a DC check)
async function serveStatus(cfg, host, lang, wantsProbe) {
  STATS.statusViews++;
  logEvent("status_view", host);
  const probe = wantsProbe ? await probeDcs(cfg) : null;
  const secretMode = cfg.secretDerived
    ? bi("derived from ADMIN_KEY", "مشتق‌شده از ADMIN_KEY")
    : (cfg.base ? bi("fixed SECRET", "SECRET ثابت") : "-");
  const infoRows = [
    [bi("Version", "نسخه"), escapeHtml(VERSION)],
    [bi("Carrier", "حامل"), escapeHtml(cfg.carrier)],
    [bi("Secret mode", "حالت سکرت"), secretMode],
    [bi("Max streams per session", "حداکثر استریم در هر نشست"), String(cfg.maxStreams)],
    [bi("Public ports", "پورت‌های عمومی"), escapeHtml((cfg.ports || []).join(", "))],
    [bi("Native TLS", "TLS بومی"), tlsSummary()],
    [bi("Debug logging", "لاگ اشکال‌زدایی"), cfg.debug ? bi("on", "روشن") : bi("off", "خاموش")],
    [bi("AD_TAG", "AD_TAG"), cfg.adTag ? bi("set (ignored in Direct-DC mode)", "تنظیم شده (در حالت Direct-DC بی‌اثر)") : bi("not set", "تنظیم نشده")]
  ].map((row) => `<tr><th>${row[0]}</th><td>${row[1]}</td></tr>`).join("");
  const statsRows = [
    [bi("Proxy sessions", "نشست‌های پروکسی"), String(STATS.sessions)],
    [bi("Active sessions (isolate)", "نشست‌های فعال (این ایزوله)"), String(STATS.sessionsActive)],
    [bi("Streams opened", "استریم‌های باز شده"), String(STATS.streams)],
    [bi("DC connects ok / failed", "اتصال‌های DC موفق / ناموفق"), (STATS.dcAttempts - STATS.dcFails) + " / " + STATS.dcFails],
    [bi("Traffic up / down", "ترافیک بالا / پایین"), fmtBytes(STATS.bytesUp) + " / " + fmtBytes(STATS.bytesDown)],
    [bi("Rejected WS tokens", "توکن‌های WebSocket ردشده"), String(STATS.wsRejects)],
    [bi("Failed TLS handshakes", "دست‌دهی‌های ناموفق TLS"), String(STATS.tlsErrors || 0)],
    [bi("Isolate uptime", "مدت فعالیت این ایزوله"), fmtDuration(Date.now() - ISOLATE_START)]
  ].map((row) => `<tr><th>${row[0]}</th><td>${escapeHtml(row[1])}</td></tr>`).join("");
  const probeBlock = probe
    ? `<div class="card"><b>${bi("DC reachability probe", "تست دسترسی به دیتاسنترها")}</b><table><tr><th>DC</th><th>IP</th><th>${bi("Result", "نتیجه")}</th></tr>${probe.map((r) => `<tr><td>DC${r.dc}</td><td>${escapeHtml(r.ip)}</td><td class="${r.ok ? "ok" : "bad"}">${r.ok ? "OK" : "FAIL"} (${r.ms} ms)</td></tr>`).join("")}</table></div>`
    : `<div class="card"><a class="plain" href="?probe=1">${bi("Run DC reachability probe", "اجرای تست دسترسی به دیتاسنترهای تلگرام")}</a><p class="muted">${bi("Opens and immediately closes one TCP socket per DC from this Cloudflare location.", "برای هر دیتاسنتر یک اتصال TCP از همین لوکیشن کلودفلر باز و بلافاصله بسته می‌شود.")}</p></div>`;
  const logRows = LOG.slice(-60).reverse().map((e) => `<tr><td>${new Date(e.t).toISOString().slice(11, 19)}</td><td>${escapeHtml(e.event)}</td><td>${escapeHtml(e.detail)}</td></tr>`).join("");
  const logsBlock = `<div class="card"><b>${bi("Recent events", "رویدادهای اخیر")}</b> <span class="muted">${bi("(newest first, isolate memory only)", "(جدیدترین اول، فقط حافظه همین ایزوله)")}</span><table><tr><th>UTC</th><th>event</th><th>detail</th></tr>${logRows || `<tr><td colspan="3">-</td></tr>`}</table></div>`;
  const reqRows = REQLOG.slice(-40).reverse().map((r) => {
    const headerText = Object.keys(r.headers || {}).map((k) => `${k}: ${r.headers[k]}`).join("\n");
    return `<tr><td>${new Date(r.t).toISOString().slice(11, 19)}</td><td>${escapeHtml(r.kind)}</td><td>${escapeHtml(r.method + " " + r.path + (r.query ? "?" + r.query : ""))}</td><td>${escapeHtml(String(r.status === undefined ? "-" : r.status))}</td><td>${escapeHtml(r.ms === undefined ? "-" : r.ms + "ms")}</td><td><pre class="req-pre" title="${escapeHtml(r.remote || "")}">${escapeHtml(headerText || "-")}</pre></td><td>${escapeHtml(r.body || "-")}</td><td>${escapeHtml(r.note || "-")}</td></tr>`;
  }).join("");
  const reqBlock = `<div class="card"><b>${bi("Request log", "لاگ درخواست‌ها")}</b> <span class="muted">${bi("(last 40, full headers, secret redacted)", "(۴۰ مورد آخر، هدرها کامل، سکرت مخفی)")}</span><table><tr><th>UTC</th><th>type</th><th>${bi("Path", "مسیر")}</th><th>status</th><th>ms</th><th>${bi("Headers", "هدرها")}</th><th>${bi("Body", "بدنه")}</th><th>note</th></tr>${reqRows || `<tr><td colspan="8">-</td></tr>`}</table></div>`;
  const body = `<h1>${bi("Proxy status", "وضعیت پروکسی")}</h1>
<div class="card muted">${bi(
    "Counters and logs are kept in this process memory only, reset when the server restarts, and are not shared between instances. Authorization, cookie and secret values are redacted from the request log.",
    "شمارنده‌ها و لاگ‌ها فقط در حافظه همین پروسه نگهداری می‌شوند، با ری‌استارت سرور صفر می‌شوند و بین نمونه‌ها مشترک نیستند. مقادیر Authorization، کوکی و سکرت در لاگ درخواست‌ها مخفی می‌شوند."
  )}</div>
<div class="card"><b>${bi("Configuration", "پیکربندی")}</b><table>${infoRows}</table></div>
<div class="card"><b>${bi("Live statistics", "آمار زنده")}</b><table>${statsRows}</table></div>
${probeBlock}
${reqBlock}
${logsBlock}`;
  return new Response(bilingualPage("Status", lang, body, await unseal()), { status: 200, headers: pageHeaders() });
}

async function issueToken(cfg, kind, ttl, mode) {
  const nonce = new Uint8Array(16);
  new DataView(nonce.buffer).setUint32(0, Math.floor(Date.now() / 1000) + ttl, false);
  nonce[4] = typeof mode === "number" && mode >= 0 && mode <= 255 ? mode : 0;
  crypto.getRandomValues(nonce.subarray(5));
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", cfg.tokenKey, concat(TOKEN_DOMAIN, Uint8Array.of(kind), nonce)));
  return b64uEncode(concat(nonce, mac));
}

async function verifyToken(cfg, token, kind) {
  const raw = b64uDecodeStrict(token);
  if (!raw || raw.length !== 48) return null;
  const nonce = raw.subarray(0, 16);
  const mac = raw.subarray(16);
  const ok = await crypto.subtle.verify("HMAC", cfg.tokenKey, mac, concat(TOKEN_DOMAIN, Uint8Array.of(kind), nonce));
  if (!ok) return null;
  const expires = new DataView(nonce.buffer, nonce.byteOffset, 4).getUint32(0, false);
  if (expires < Math.floor(Date.now() / 1000)) return null;
  return { nonce, mode: nonce[4] };
}

async function decoy(decoyUrl, requestMethod = "GET") {
  if (decoyUrl && typeof decoyUrl === "string" && (decoyUrl.startsWith("http://") || decoyUrl.startsWith("https://"))) {
    try {
      const upstream = await fetch(decoyUrl, {
        method: requestMethod === "HEAD" ? "HEAD" : "GET",
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        }
      });
      const status = upstream.status >= 200 && upstream.status <= 599 ? upstream.status : 200;
      const nullBody = requestMethod === "HEAD" || status === 204 || status === 205 || status === 304;
      return new Response(nullBody ? null : upstream.body, {
        status,
        headers: {
          "Content-Type": upstream.headers.get("Content-Type") || "text/html; charset=utf-8",
          "Cache-Control": "no-cache"
        }
      });
    } catch (_) {}
  }
  const headers = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "Vary": "Accept-Encoding"
  };
  if (requestMethod === "HEAD") {
    return new Response(null, { status: 200, headers });
  }
  return new Response(DECOY_HTML, { status: 200, headers });
}

function notFound() {
  return new Response("Not Found", {
    status: 404,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

// Human-readable one-liner about the TLS listener for the admin status page.
function tlsSummary() {
  const material = readTlsMaterial(true);
  if (!material.cert || !material.key) {
    return material.problems.length
      ? "OFF — " + escapeHtml(material.problems.join("; "))
      : "OFF — no certificate configured";
  }
  let parsed;
  try { parsed = new X509Certificate(material.cert); }
  catch (error) { return "OFF — " + escapeHtml(error.message); }
  const daysLeft = Math.floor((new Date(parsed.validTo).getTime() - Date.now()) / 86400000);
  const status = daysLeft < 0 ? "EXPIRED" : (daysLeft < 7 ? "EXPIRING" : "OK");
  return `ON — port ${tlsPortLabel()} — ${status} (${daysLeft}d left) — expires ${escapeHtml(parsed.validTo)}`;
}

function tlsPortLabel() {
  const raw = parseInt(envValue("TLS_PORT"), 10);
  return Number.isFinite(raw) && raw > 0 && raw <= 65535 ? raw : 8443;
}

async function serveBridge(cfg, host, mode, port) {
  const nonce = b64uEncode(crypto.getRandomValues(new Uint8Array(18)));
  const bootstrap = await issueToken(cfg, TOKEN_KIND_BOOTSTRAP, cfg.bootstrapTtl, mode);
  // Derive the public port from the negotiated mode, not the request's internal
  // port: a tunnel may forward an external port (e.g. 443) to an internal one
  // (e.g. 8080), and the client must dial back to the external port.
  const portNum = (mode >= PORT_MODE_BASE && mode < PORT_MODE_BASE + cfg.ports.length)
    ? cfg.ports[mode - PORT_MODE_BASE]
    : (port ? parseInt(port, 10) : cfg.ports[0]);
  const authority = (portNum && portNum !== 443 && portNum !== 80) ? `${host}:${portNum}` : host;
  const relayBase = JSON.stringify("https://" + authority + "/");
  const body = BRIDGE_HTML
    .replaceAll("__NONCE__", nonce)
    .replaceAll("__RELAY_BASE__", relayBase)
    .replaceAll("__BOOTSTRAP__", JSON.stringify(bootstrap))
    .replaceAll("__CARRIER_MODE__", JSON.stringify(cfg.carrier))
    .replaceAll("__BATCH_LIMIT__", String(cfg.batchBytes))
    .replaceAll("__SESSION_PATH__", JSON.stringify(cfg.sessionPath.replace(/^\//, "")))
    .replaceAll("__WS_PATH__", JSON.stringify(cfg.wsPath.replace(/^\//, "")));
  const csp = [
    "default-src 'none'",
    "base-uri 'none'",
    "child-src 'none'",
    "connect-src 'self' https://" + host + ":* wss://" + host + ":* https://" + host + " wss://" + host,
    "font-src 'none'",
    "form-action 'none'",
    "frame-ancestors http://127.0.0.1:*",
    "frame-src 'none'",
    "img-src 'none'",
    "manifest-src 'none'",
    "media-src 'none'",
    "object-src 'none'",
    "script-src 'nonce-" + nonce + "'",
    "style-src 'none'",
    "worker-src 'none'",
    "sandbox allow-same-origin allow-scripts"
  ].join("; ");
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy": csp,
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      "X-DNS-Prefetch-Control": "off",
      "Permissions-Policy": PERMISSIONS_POLICY
    }
  });
}

function frame(type, id, payload) {
  const out = new Uint8Array(8 + payload.length);
  out[0] = type;
  out[1] = (id >>> 16) & 0xff;
  out[2] = (id >>> 8) & 0xff;
  out[3] = id & 0xff;
  new DataView(out.buffer).setUint32(4, payload.length, false);
  out.set(payload, 8);
  return out;
}

function windowFrame(id, amount) {
  const payload = new Uint8Array(4);
  new DataView(payload.buffer).setUint32(0, amount, false);
  return frame(0x04, id, payload);
}

function tagKind(tag) {
  if (tag[0] === 0xef && tag[1] === 0xef && tag[2] === 0xef && tag[3] === 0xef) return 1; // abridged
  if (tag[0] === 0xee && tag[1] === 0xee && tag[2] === 0xee && tag[3] === 0xee) return 2; // intermediate
  if (tag[0] === 0xdd && tag[1] === 0xdd && tag[2] === 0xdd && tag[3] === 0xdd) return 3; // padded intermediate
  return 0;
}

function safeDcHeaderPrefix(bytes) {
  if (bytes[0] === 0xef) return false;
  if (bytes[4] === 0 && bytes[5] === 0 && bytes[6] === 0 && bytes[7] === 0) return false;
  if (bytes[0] === 0x47 && bytes[1] === 0x45 && bytes[2] === 0x54 && bytes[3] === 0x20) return false;
  if (bytes[0] === 0x50 && bytes[1] === 0x4f && bytes[2] === 0x53 && bytes[3] === 0x54) return false;
  if (bytes[0] === 0x48 && bytes[1] === 0x45 && bytes[2] === 0x41 && bytes[3] === 0x44) return false;
  if (bytes[0] === 0x4f && bytes[1] === 0x50 && bytes[2] === 0x54 && bytes[3] === 0x49) return false;
  if (bytes[0] === 0xee && bytes[1] === 0xee && bytes[2] === 0xee && bytes[3] === 0xee) return false;
  if (bytes[0] === 0xdd && bytes[1] === 0xdd && bytes[2] === 0xdd && bytes[3] === 0xdd) return false;
  if (bytes[0] === 0x16 && bytes[1] === 0x03 && bytes[2] === 0x01 && bytes[3] === 0x02) return false;
  return true;
}

class Stream {
  constructor(session, id) {
    this.session = session;
    this.id = id;
    STATS.streams++;
    session.streamCount++;
    this.phase = "header";
    this.header = new Uint8Array(64);
    this.headerLength = 0;
    this.dead = false;
    this.socket = null;
    this.writer = null;
    this.reader = null;
    this.inQueue = [];
    this.inRunning = false;
    this.queuedLocal = 0;
    this.recvOutstanding = 0;
    this.sendCredit = session.cfg.streamWindow;
    this.creditResolve = null;
    this.clientReadKey = null;
    this.clientReadIv = null;
    this.clientWriteKey = null;
    this.clientWriteIv = null;
    this.dcWriteKey = null;
    this.dcWriteIv = null;
    this.dcReadKey = null;
    this.dcReadIv = null;
    this.clientReadPos = 64;
    this.clientWritePos = 0;
    this.dcWritePos = 64;
    this.dcReadPos = 0;
  }

  feed(payload) {
    if (this.dead || !payload.length) return;
    this.recvOutstanding += payload.length;
    if (this.recvOutstanding > this.session.cfg.streamWindow + 65536) {
      this.kill(true);
      return;
    }
    const copy = payload.slice();
    this.inQueue.push(copy);
    this.queuedLocal += copy.length;
    this.session.queued += copy.length;
    if (this.session.queued > this.session.cfg.maxQueued) {
      this.kill(true);
      return;
    }
    this.runIn();
  }

  async runIn() {
    if (this.inRunning || this.dead) return;
    this.inRunning = true;
    try {
      while (!this.dead && this.inQueue.length) {
        let payload = this.inQueue[0];
        if (this.phase === "header") {
          const need = 64 - this.headerLength;
          const take = Math.min(need, payload.length);
          this.header.set(payload.subarray(0, take), this.headerLength);
          this.headerLength += take;
          payload = payload.subarray(take);
          this.queuedLocal -= take;
          this.session.queued -= take;
          if (payload.length) this.inQueue[0] = payload;
          else this.inQueue.shift();
          if (this.headerLength === 64) {
            await this.init();
            this.grant(64);
          }
          continue;
        }
        this.inQueue.shift();
        this.queuedLocal -= payload.length;
        this.session.queued -= payload.length;
        await this.writeToDc(payload);
      }
    } catch (error) {
      diag("stream_in_error", `stream=${this.id} ${error?.message || error}`);
      this.kill(true);
    } finally {
      this.inRunning = false;
      if (!this.dead && this.inQueue.length) this.runIn();
    }
  }

  async init() {
    const header = this.header;
    const readKey = await sha256(concat(header.subarray(8, 40), this.session.secret));
    const readIv = header.slice(40, 56);
    this.clientReadKey = await importAes(readKey);
    this.clientReadIv = readIv;
    const tail = await ctrAt(this.clientReadKey, readIv, 56, header.subarray(56, 64));
    const tag = tail.subarray(0, 4);
    if (!tagKind(tag)) {
      diag("stream_bad", `stream=${this.id} bad obfuscated2 tag=${bytesToHex(tag)} secret=${bytesToHex(this.session.secret).slice(0, 4)}…`);
      throw new Error("bad tag");
    }
    const dcId = new DataView(tail.buffer, tail.byteOffset + 4, 2).getInt16(0, true);
    const dcKey = Math.abs(dcId);
    const address = this.session.cfg.dc[dcKey];
    if (!address) {
      diag("stream_bad", `stream=${this.id} dc=${dcKey} (no route configured) tag=${bytesToHex(tag)}`);
      throw new Error("bad dc");
    }
    diag("stream_init", `stream=${this.id} dc=${dcId} tag=${bytesToHex(tag)}`);
    const candidateIps = Array.isArray(address) ? address : [address];
    const candidatePorts = Array.isArray(this.session.cfg.dcPorts) ? this.session.cfg.dcPorts : [this.session.cfg.dcPort || 443];

    // Middle-End / Ad Tag Routing Check:
    // If AD_TAG is configured, note protocol constraint: native ME handshake requires
    // preserving outbound TCP source port which Cloudflare Workers' NAPT does not support.
    if (this.session.cfg.adTag && this.session.cfg.debug && !this.session.loggedMeNotice) {
      this.session.loggedMeNotice = true;
      console.log("[tgweb] AD_TAG configured. Native Middle-End handshake from Cloudflare Workers is blocked by Cloudflare egress NAPT (source port translation prevents ME key agreement). Falling back cleanly to Direct-DC mode.");
    }

    const reversed = reverse(header.subarray(8, 56));
    const writeKey = await sha256(concat(reversed.subarray(0, 32), this.session.secret));
    const clientWriteIv = reversed.slice(32, 48);

    // FAST MODE (same idea as mtprotoproxy FAST_MODE):
    // The DC derives its *encrypt* key/iv from reverse(dcHeader[8..56]). We choose
    // dcHeader[8..56] = reverse(clientWriteKey || clientWriteIv), so the DC encrypts
    // with exactly the key stream the client expects. DC->client bytes are then
    // forwarded untouched: no AES work for the heavy (download) direction.
    const dcKeyMaterial = reverse(concat(writeKey, clientWriteIv)); // 48 bytes
    this.dcWriteKey = await importAes(dcKeyMaterial.slice(0, 32));
    this.dcWriteIv = dcKeyMaterial.slice(32, 48);
    if (this.dead) return;
    this.clientReadPos = 64;
    this.clientWritePos = 0;
    this.dcWritePos = 64;
    this.dcReadPos = 0;

    // Connect to the DC with bounded failover. Every connect() is a subrequest
    // (50 per invocation on Free) and occupies one of the 6 "connecting" slots,
    // so: few attempts, random IP order (spreads load), and always close losers.
    let socket = null;
    let lastError = null;
    const ips = candidateIps.slice();
    for (let i = ips.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [ips[i], ips[j]] = [ips[j], ips[i]];
    }
    const attempts = [];
    for (const port of candidatePorts) for (const hostIp of ips) attempts.push([hostIp, port]);
    const maxAttempts = Math.min(attempts.length, 4);

    for (let a = 0; a < maxAttempts && !socket; a++) {
      if (this.dead) return;
      const [hostIp, port] = attempts[a];
      STATS.dcAttempts++;
      let candidateSocket = null;
      let timer = null;
      try {
        candidateSocket = connect({ hostname: hostIp, port }, { secureTransport: "off" });
        candidateSocket.closed.catch(() => {});
        const timeoutPromise = new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error("connect timeout")), 3000);
        });
        await Promise.race([candidateSocket.opened, timeoutPromise]);
        socket = candidateSocket;
      } catch (connErr) {
        lastError = connErr;
        STATS.dcFails++;
        diag("dc_fail", `stream=${this.id} dc=${dcKey} ${hostIp}:${port} ${connErr?.message || connErr}`);
        // Previously a timed-out socket stayed pending and kept a connection slot busy.
        if (candidateSocket) { try { candidateSocket.close().catch(() => {}); } catch (_) {} }
      } finally {
        if (timer) clearTimeout(timer);
      }
    }

    if (!socket) {
      logEvent("dc_fail", `dc=${dcKey}`);
      throw lastError || new Error("failed to connect to DC");
    }
    diag("dc_ok", `stream=${this.id} dc=${dcKey} attempts=${maxAttempts}`);

    this.socket = socket;
    if (this.dead) {
      try { await socket.close(); } catch (_) {}
      return;
    }
    this.writer = socket.writable.getWriter();
    this.reader = socket.readable.getReader();

    // Construct and send initial Obfuscated2 header to the Telegram DC
    const dcHeader = new Uint8Array(64);
    let safe = false;
    for (let i = 0; i < 16 && !safe; i++) {
      crypto.getRandomValues(dcHeader.subarray(0, 8));
      safe = safeDcHeaderPrefix(dcHeader);
    }
    if (!safe) dcHeader.set([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0], 0);
    dcHeader.set(dcKeyMaterial, 8);
    dcHeader.set(tag, 56);
    const dcView = new DataView(dcHeader.buffer);
    dcView.setInt16(60, dcId, true);
    dcView.setUint16(62, 0, true);
    const encryptedTail = await ctrAt(this.dcWriteKey, this.dcWriteIv, 56, dcHeader.subarray(56, 64));
    dcHeader.set(encryptedTail, 56);
    await this.writer.write(dcHeader);
    if (this.dead) return;
    this.phase = "ready";
    this.pump().catch(() => this.kill(true));
  }

  async writeToDc(payload) {
    if (this.dead) return;
    const plain = await ctrAt(this.clientReadKey, this.clientReadIv, this.clientReadPos, payload);
    this.clientReadPos += payload.length;
    if (this.dead) return;
    if (DEBUG_ON) {
      try {
        diag("mt_up", `stream=${this.id} len=${payload.length} plain=${hexPreview(plain, 24)}`);
      } catch (_) {}
    }
    const encrypted = await ctrAt(this.dcWriteKey, this.dcWriteIv, this.dcWritePos, plain);
    this.dcWritePos += payload.length;
    await this.writer.write(encrypted);
    this.grant(payload.length);
  }

  async pump() {
    const reader = this.reader;
    try {
      while (!this.dead) {
        if (this.sendCredit <= 0) {
          await this.waitCredit();
          continue;
        }
        const result = await reader.read();
        if (result.done) break;
        const value = result.value;
        let offset = 0;
        while (offset < value.length && !this.dead) {
          if (this.sendCredit <= 0) {
            await this.waitCredit();
            continue;
          }
          const size = Math.min(value.length - offset, this.sendCredit, this.session.cfg.dataChunk);
          if (size <= 0) continue;
          // Fast mode: bytes from the DC are already encrypted for the client.
          const chunk = value.subarray(offset, offset + size);
          this.sendCredit -= size;
          if (DEBUG_ON) {
            try { diag("mt_down", `stream=${this.id} len=${size} first=${hexPreview(chunk, 16)}`); } catch (_) {}
          }
          this.session.sendFrame(frame(0x02, this.id, chunk));
          offset += size;
        }
      }
    } catch (_) {}
    this.kill(true);
  }

  waitCredit() {
    if (this.dead || this.sendCredit > 0) return Promise.resolve();
    return new Promise((resolve) => {
      this.creditResolve = resolve;
    });
  }

  addCredit(amount) {
    if (this.dead) return;
    this.sendCredit = Math.min(0xffffffff, this.sendCredit + amount);
    if (this.creditResolve) {
      const resolve = this.creditResolve;
      this.creditResolve = null;
      resolve();
    }
  }

  grant(amount) {
    if (this.dead || amount <= 0) return;
    this.recvOutstanding = Math.max(0, this.recvOutstanding - amount);
    this.session.sendFrame(windowFrame(this.id, amount));
  }

  kill(notify) {
    if (this.dead) return;
    this.dead = true;
    diag("stream_close", `stream=${this.id} phase=${this.phase} up=${this.clientReadPos}B down=${this.session.bytesDown}B`);
    this.session.streams.delete(this.id);
    this.session.remember(this.id);
    this.session.queued -= this.queuedLocal;
    if (this.session.queued < 0) this.session.queued = 0;
    this.queuedLocal = 0;
    this.inQueue.length = 0;
    if (this.creditResolve) {
      const resolve = this.creditResolve;
      this.creditResolve = null;
      resolve();
    }
    // Free stream locks immediately to prevent socket exhaustion and resource leaks in Cloudflare Workers
    if (this.writer) {
      try { this.writer.releaseLock(); } catch (_) {}
      this.writer = null;
    }
    if (this.reader) {
      try { this.reader.cancel().catch(() => {}); this.reader.releaseLock(); } catch (_) {}
      this.reader = null;
    }
    if (this.socket) {
      try { this.socket.close().catch(() => {}); } catch (_) {}
      this.socket = null;
    }
    if (notify && !this.session.closed) this.session.sendFrame(frame(0x03, this.id, EMPTY));
    this.session.onStreamClosed(this.id);
  }
}

class WsSession {
  constructor(ws, cfg, secret, laneId = 0) {
    this.laneId = laneId; // > 0: this WebSocket carries exactly one stream (websocket-lanes)
    this.laneUsed = false;
    this.ws = ws;
    this.cfg = cfg;
    this.secret = secret;
    this.streams = new Map();
    this.closed = false;
    this.queued = 0;
    this.tombstones = new Set();
    this.tombstoneOrder = [];
    this.chain = Promise.resolve();
    this.loggedMeNotice = false;
    this.lastPong = Date.now();
    this.openedAt = Date.now();
    this.bytesUp = 0;
    this.bytesDown = 0;
    this.streamCount = 0;
    STATS.sessions++;
    STATS.sessionsActive++;
    logEvent("session_open", `lane=${laneId} carrier=${cfg.carrier}`);

    // Periodic KeepAlive Heartbeat (every 25s)
    // Prevents Cloudflare 100s idle disconnect and ISP/TSPU DPI idle RST injection
    // Lane sockets must not receive id-0 frames (the bridge rejects cross-lane ids);
    // MTProto's own pings keep a lane busy.
    this.keepAliveTimer = laneId ? null : setInterval(() => {
      if (this.closed || !this.ws || this.ws.readyState !== 1) {
        if (this.keepAliveTimer) clearInterval(this.keepAliveTimer);
        return;
      }
      // Pong watchdog: if the client stopped answering keepalives (dead network
      // path that never sends a close frame), tear the session down instead of
      // holding its DC sockets and subrequest budget open forever.
      if (Date.now() - this.lastPong > 90000) {
        this.shutdown("pong watchdog");
        return;
      }
      try {
        const pingPayload = new Uint8Array(4);
        new DataView(pingPayload.buffer).setUint32(0, Math.floor(Date.now() / 1000), false);
        this.sendFrame(frame(0x05, 0, pingPayload));
      } catch (_) {}
    }, 25000);
  }

  sendFrame(bytes) {
    if (this.closed) return;
    try {
      this.ws.send(bytes);
      this.bytesDown += bytes.length;
      STATS.bytesDown += bytes.length;
    } catch (_) {
      this.dispose();
    }
  }

  onStreamClosed(id) {
    if (!this.laneId || this.closed || id !== this.laneId) return;
    // Lane finished: close this WebSocket so the invocation (and its budget) ends.
    this.dispose();
    try { if (this.ws.readyState === 1) this.ws.close(1000, "done"); } catch (_) {}
  }

  remember(id) {
    if (this.tombstones.has(id)) return;
    if (this.tombstoneOrder.length === 4096) this.tombstones.delete(this.tombstoneOrder.shift());
    this.tombstones.add(id);
    this.tombstoneOrder.push(id);
  }

  enqueue(data) {
    this.chain = this.chain.then(() => this.handle(data)).catch(() => this.shutdown());
  }

  async handle(data) {
    if (this.closed) {
      diag("ws_frame", "frame after close");
      return;
    }
    // ws emits Buffer by default; Cloudflare always delivered ArrayBuffer. Accept
    // both, otherwise every Telegram frame would look invalid and kill the lane.
    let bytes;
    if (data instanceof ArrayBuffer) bytes = new Uint8Array(data);
    else if (ArrayBuffer.isView(data)) bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    else {
      diag("ws_frame", `unsupported payload type=${Object.prototype.toString.call(data)}`);
      this.shutdown();
      return;
    }
    if (bytes.length === 0 || bytes.length > REQUEST_LIMIT) {
      diag("ws_frame", `bad frame length=${bytes.length}`);
      this.shutdown();
      return;
    }
    data = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    if (DEBUG_ON) {
      try { diag("ws_frame", `len=${bytes.length} first=${hexPreview(bytes, 16)}`); } catch (_) {}
    }
    this.bytesUp += bytes.length;
    STATS.bytesUp += bytes.length;
    const view = new DataView(data);
    let offset = 0;
    let frames = 0;
    while (offset < bytes.length) {
      if (bytes.length - offset < 8 || ++frames > 4096) {
        this.shutdown();
        return;
      }
      const type = bytes[offset];
      const id = (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
      const size = view.getUint32(offset + 4, false);
      const end = offset + 8 + size;
      if (size > 1048576 || end > bytes.length) {
        this.shutdown();
        return;
      }
      const payload = bytes.subarray(offset + 8, end);
      offset = end;
      // Lane sockets carry exactly one stream; PING/PONG are control frames and
      // always use id 0, so they must be exempt from the lane id check.
      if (this.laneId && id !== 0 && id !== this.laneId) {
        this.shutdown();
        return;
      }
      if (type === 0x01) {
        // OPEN frame
        if (id === 0 || size !== 0) {
          this.shutdown();
          return;
        }
        if (this.laneId) {
          if (this.laneUsed) { this.shutdown(); return; }
          this.laneUsed = true;
          this.streams.set(id, new Stream(this, id));
          continue;
        }
        if (this.streams.has(id) || this.tombstones.has(id) || this.streams.size >= this.cfg.maxStreams) {
          this.sendFrame(frame(0x03, id, EMPTY));
          continue;
        }
        this.streams.set(id, new Stream(this, id));
      } else if (type === 0x02) {
        // DATA frame
        if (id === 0 || size === 0) {
          this.shutdown();
          return;
        }
        const stream = this.streams.get(id);
        if (stream) stream.feed(payload);
        else if (!this.tombstones.has(id)) this.sendFrame(frame(0x03, id, EMPTY));
      } else if (type === 0x03) {
        // CLOSE frame
        if (id === 0 || size !== 0) {
          this.shutdown();
          return;
        }
        const stream = this.streams.get(id);
        if (stream) stream.kill(false);
      } else if (type === 0x04) {
        // WINDOW frame (credit grant)
        if (id === 0 || size !== 4) {
          this.shutdown();
          return;
        }
        const stream = this.streams.get(id);
        if (stream) stream.addCredit(new DataView(payload.buffer, payload.byteOffset, 4).getUint32(0, false));
      } else if (type === 0x05) {
        // PING frame from client (0x05) -> respond with PONG (0x06) echoing payload.
        // The legitimate bridge ping is 4 bytes; anything larger is refused so the
        // proxy cannot be used as a reflection amplifier.
        if (id === 0) {
          if (size > 64) {
            this.shutdown();
            return;
          }
          this.sendFrame(frame(0x06, 0, payload));
        }
      } else if (type === 0x06) {
        // PONG frame from client (0x06) -> acknowledgment of keepalive
        if (id !== 0) {
          this.shutdown();
          return;
        }
        this.lastPong = Date.now();
      } else {
        this.shutdown();
        return;
      }
    }
  }

  dispose() {
    if (this.closed) return;
    this.closed = true;
    STATS.sessionsActive = Math.max(0, STATS.sessionsActive - 1);
    logEvent("session_close", `${fmtDuration(Date.now() - this.openedAt)} streams=${this.streamCount} up=${fmtBytes(this.bytesUp)} down=${fmtBytes(this.bytesDown)}`);
    if (this.keepAliveTimer) {
      clearInterval(this.keepAliveTimer);
      this.keepAliveTimer = null;
    }
    for (const stream of Array.from(this.streams.values())) stream.kill(false);
    this.streams.clear();
    this.tombstones.clear();
    this.tombstoneOrder.length = 0;
    this.queued = 0;
  }

  shutdown(reason) {
    logEvent("session_kill", reason || "protocol");
    this.dispose();
    try {
      if (this.ws.readyState === 1) this.ws.close(1011, "closed");
    } catch (_) {}
  }
}

async function serveSession(request, cfg) {
  const auth = request.headers.get("authorization") || "";
  if (!auth.startsWith("Bearer ") || auth.length <= 7) {
    logEvent("session_reject", "missing bearer");
    return notFound();
  }
  const token = auth.substring(7);
  if (request.method === "DELETE") {
    if (!(await verifyToken(cfg, token, TOKEN_KIND_SESSION))) return notFound();
    return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
  }
  if (request.method !== "POST") return notFound();
  if (request.headers.get("cookie")) return notFound();
  if ((request.headers.get("content-type") || "").toLowerCase() !== "application/octet-stream") return notFound();
  // The handshake body is a fixed 9 bytes. Reject an oversized declared body
  // before buffering it: isolate memory (128 MB) is shared by every session
  // running in the isolate, so unbounded reads are a memory-DoS vector.
  const declaredLength = parseInt(request.headers.get("content-length") || "", 10);
  if (Number.isFinite(declaredLength) && declaredLength > 4096) return notFound();
  const verified = await verifyToken(cfg, token, TOKEN_KIND_BOOTSTRAP);
  if (!verified) {
    logEvent("session_reject", "invalid or expired bootstrap token");
    return notFound();
  }
  if ((verified.mode === 1 || verified.mode === 2) && !cfg.acceptGenerated) {
    logEvent("session_reject", "generated mode disabled");
    return notFound();
  }
  const body = new Uint8Array(await request.arrayBuffer());
  if (body.length !== 9 || body[0] !== 0x10 || body[1] !== 0 || body[2] !== 0 || body[3] !== 0 || body[4] !== 0 || body[5] !== 0 || body[6] !== 0 || body[7] !== 1 || body[8] !== 1) {
    logEvent("session_reject", `bad handshake body len=${body.length}`);
    return notFound();
  }
  const sessionToken = await issueToken(cfg, TOKEN_KIND_SESSION, cfg.sessionTtl, verified.mode);
  return new Response(WELCOME, {
    status: 200,
    headers: {
      "Content-Type": "application/octet-stream",
      "Cache-Control": "no-store",
      "X-Session-Token": sessionToken,
      "X-Down-Cursor": "0",
      "X-Carrier-Mode": cfg.carrier
    }
  });
}

async function serveWebSocket(request, cfg, host, port) {
  if (request.method !== "GET") {
    diag("ws_reject", `method=${request.method}`);
    return notFound();
  }
  if ((request.headers.get("upgrade") || "").toLowerCase() !== "websocket") {
    diag("ws_reject", "missing Upgrade: websocket header");
    return notFound();
  }
  if (request.headers.get("authorization")) {
    diag("ws_reject", "unexpected Authorization header");
    return notFound();
  }
  const offered = (request.headers.get("sec-websocket-protocol") || "").split(",").map((value) => value.trim()).filter(Boolean);
  if (offered.length !== 1) {
    diag("ws_reject", `subprotocol count=${offered.length}`);
    return notFound();
  }
  const protocol = offered[0];
  let token = "";
  let laneId = 0;
  if (protocol.startsWith("tproxy-v1.")) {
    token = protocol.substring(10);
  } else if (protocol.startsWith("tproxy-lane-v1.")) {
    const rest = protocol.substring(15);
    const dot = rest.lastIndexOf(".");
    if (dot <= 0 || !/^[1-9][0-9]{0,7}$/.test(rest.substring(dot + 1))) {
      diag("ws_reject", "malformed lane subprotocol");
      return notFound();
    }
    token = rest.substring(0, dot);
    laneId = parseInt(rest.substring(dot + 1), 10);
    if (laneId > 0xffffff) {
      diag("ws_reject", `lane id out of range=${laneId}`);
      return notFound();
    }
  } else {
    diag("ws_reject", `unknown subprotocol=${protocol.slice(0, 18)}…`);
    return notFound();
  }
  const verified = await verifyToken(cfg, token, TOKEN_KIND_SESSION);
  if (!verified) {
    // A real WebSocket upgrade with an invalid/expired token is either a
    // forgery attempt or a client whose token expired - worth a log line.
    STATS.wsRejects++;
    diag("ws_reject", `invalid or expired session token (lane=${laneId})`);
    return notFound();
  }
  if ((verified.mode === 1 || verified.mode === 2) && !cfg.acceptGenerated) {
    diag("ws_reject", `generated secret mode=${verified.mode} not accepted`);
    return notFound();
  }
  let secret = cfg.base;
  if (verified.mode >= PORT_MODE_BASE && verified.mode < PORT_MODE_BASE + cfg.ports.length) {
    const portNum = cfg.ports[verified.mode - PORT_MODE_BASE];
    secret = cfg.portSecrets?.[portNum]?.secret || cfg.base;
  } else if (verified.mode === 1 || verified.mode === 2) {
    const label = verified.mode === 2 && port && port !== "443" && port !== "80" ? `${host}:${port}` : host;
    secret = await deriveSecret(cfg, label);
  }
  if (!secret) {
    diag("ws_reject", `no secret for mode=${verified.mode}`);
    return notFound();
  }
  diag("ws_accept", `lane=${laneId} mode=${verified.mode} carrier=${cfg.carrier} host=${host} port=${port || "-"}`);
  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  server.binaryType = "arraybuffer";
  server.accept();
  let session;
  try {
    session = new WsSession(server, cfg, secret, laneId);
  } catch (error) {
    reportError("ws session", error);
    try { server.close(1011, "error"); } catch (_) {}
    return upgradeResponse(client, protocol);
  }
  server.addEventListener("message", (event) => {
    try { session.enqueue(event.data); } catch (error) { reportError("ws message", error); try { session.shutdown("handler error"); } catch (_) {} }
  });
  server.addEventListener("close", () => { try { session.dispose(); } catch (error) { reportError("ws close", error); } });
  server.addEventListener("error", () => { try { session.dispose(); } catch (error) { reportError("ws error", error); } });
  return upgradeResponse(client, protocol);
}

// Records an unexpected error without ever throwing itself. Visible in the
// Cloudflare dashboard (Workers -> Logs) and on the admin /status page.
function reportError(where, error) {
  try {
    const message = error && error.stack ? String(error.stack) : String(error);
    console.error("[proxygosha] " + where + ": " + message);
    logEvent("error", where + ": " + (error && error.message ? error.message : message));
  } catch (_) {}
}

// Last-resort response. It must never throw, otherwise Cloudflare shows Error 1101.
async function safeFallback(env, request) {
  try {
    const method = request && typeof request.method === "string" ? request.method : "GET";
    return await decoy(typeof env?.DECOY_URL === "string" ? env.DECOY_URL.trim() : "", method);
  } catch (error) {
    reportError("fallback", error);
  }
  try {
    return new Response(DECOY_HTML, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" } });
  } catch (_) {
    return new Response("", { status: 200 });
  }
}

// Every route handler is awaited here, so a rejected promise from any of them
// lands in the fetch() catch below instead of escaping as an uncaught exception.
async function handleRequest(request, env, ctx) {
      const url = new URL(request.url);
      const host = requestHost(request, url);
      const rawHost = String(request.headers.get("host") || url.host || "");
      const portMatch = /:([0-9]+)$/.exec(rawHost);
      const port = portMatch ? portMatch[1] : (url.port || "");

      const cfg = await getRuntime(env);
      const lang = url.searchParams.get("lang") === "fa" ? "fa" : "en";
      // Not configured yet: the step-by-step setup page is served on "/" only.
      // Every other path or method answers 404 so an unconfigured worker does
      // not advertise what it is to scanners probing random paths.
      if (!cfg) {
        if (url.pathname === "/") return await serveSetup(host, env, lang, request.method);
        return notFound();
      }
      // The domain Telegram actually dials. When a tunnel rewrites the Host
      // header to a loopback address, this falls back to the configured hostname.
      const pub = publicHost(cfg, host);
      // Configured with SECRET only (older setup, no ADMIN_KEY yet): the site stays
      // camouflaged, but /setup explains how to add ADMIN_KEY. It reveals no secret.
      if (!cfg.adminKey && url.pathname === "/setup") return await serveSetup(host, env, lang, request.method);

      // Admin panel: https://host/<ADMIN_KEY>  (or legacy ?create-secret&key=<ADMIN_KEY>)
      // Admin status & logs: https://host/<ADMIN_KEY>/status  (?probe=1 runs a DC check)
      if (request.method === "GET") {
        const route = panelRoute(url, cfg);
        if (route === "status") return await serveStatus(cfg, pub, lang, url.searchParams.get("probe") === "1");
        if (route === "panel") return await servePanel(cfg, pub, port, lang);
      }

      // Legacy per-domain secret generator (ACCEPT_GENERATED); also gated by ADMIN_KEY.
      const label = generatorLabel(url);
      if (label !== null) {
        if (!cfg.generatorEnabled || !cfg.adminKey || !label || !safeEqual(url.searchParams.get("key") || "", cfg.adminKey)) {
          return await decoy(cfg.decoyUrl, request.method);
        }
        return await serveSecret(cfg, pub, label, port);
      }

      // Active Probing Defense & Authentic Web Assets (GFW / TSPU scanner camouflage)
      if (url.pathname === "/robots.txt") {
        return new Response(request.method === "HEAD" ? null : "User-agent: *\nAllow: /\nDisallow: /api/\n", {
          status: 200,
          headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=86400" }
        });
      }
      if (url.pathname === "/favicon.ico") {
        const svgIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="#1a1a1a"/><text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" font-family="system-ui,sans-serif" font-weight="800" font-size="14" fill="#fff" letter-spacing="2">LV</text></svg>`;
        return new Response(request.method === "HEAD" ? null : svgIcon, {
          status: 200,
          headers: { "Content-Type": "image/svg+xml", "Cache-Control": "public, max-age=86400", "X-Content-Type-Options": "nosniff" }
        });
      }
      if (url.pathname === "/health" || url.pathname === "/status") {
        const json = JSON.stringify({ status: "operational", store: "LUXVEIL", region: "global", uptime: "99.99%", timestamp: Math.floor(Date.now() / 1000) });
        return new Response(request.method === "HEAD" ? null : json, {
          status: 200,
          headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-cache" }
        });
      }

      if (!hostAllowed(cfg, host)) return await decoy(cfg.decoyUrl, request.method);
      if (url.pathname === "/" && request.method === "GET") {
        const bridges = url.searchParams.getAll("bridge");
        if (bridges.length === 0) return await decoy(cfg.decoyUrl, request.method);
        const keys = Array.from(url.searchParams.keys());
        if (keys.length !== 1 || keys[0] !== "bridge" || bridges.length !== 1) return notFound();
        const mode = await bridgeMode(cfg, host, bridges[0], port);
        if (mode < 0) return notFound();
        return await serveBridge(cfg, pub, mode, port);
      }
      if (url.pathname === cfg.sessionPath || url.pathname === "/api/v1/session") return await serveSession(request, cfg);
      if (url.pathname === cfg.wsPath || url.pathname === "/api/v1/ws") return await serveWebSocket(request, cfg, pub, port);
      return await decoy(cfg.decoyUrl, request.method);
}

// ============================================================================
// Node.js HTTP/WebSocket server (replaces the Cloudflare Worker fetch() entry)
// ============================================================================

const LISTEN_HOST = (typeof ENV.HOST === "string" && ENV.HOST.trim()) ? ENV.HOST.trim() : "0.0.0.0";
const LISTEN_PORT = (() => {
  const raw = parseInt(ENV.PORT, 10);
  return Number.isFinite(raw) && raw > 0 && raw <= 65535 ? raw : 8080;
})();

const MAX_BODY_BYTES = 4 * 1024 * 1024;

const wss = new WebSocketServer({ noServer: true });

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        req.destroy();
        reject(new Error("request body too large"));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      const buf = Buffer.concat(chunks);
      req._proxygoshaBody = buf;
      resolve(buf);
    });
    req.on("error", reject);
  });
}

// Wrap the Node IncomingMessage in the small subset of the Web Request API used
// by the handlers (method / url / headers / arrayBuffer / text).
function makeRequest(req, secure) {
  const rawHost = String(req.headers.host || "localhost");
  const scheme = secure || req.socket?.encrypted ? "https" : "http";
  const url = new URL(req.url || "/", scheme + "://" + rawHost);
  const headers = new Headers();
  for (const key of Object.keys(req.headers)) {
    const value = req.headers[key];
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      for (const item of value) headers.append(key, item);
    } else {
      headers.set(key, value);
    }
  }
  return {
    method: req.method || "GET",
    url: url.href,
    headers,
    _raw: req,
    arrayBuffer() {
      return readBody(req).then((buf) => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
    },
    text() {
      return readBody(req).then((buf) => buf.toString("utf-8"));
    }
  };
}

// Serialize a global Response into the Node ServerResponse.
async function writeResponse(res, response) {
  res.statusCode = response.status || 200;
  for (const [key, value] of response.headers.entries()) {
    const lower = key.toLowerCase();
    if (lower === "transfer-encoding" || lower === "content-length") continue;
    res.setHeader(key, value);
  }
  const body = response.body;
  if (body && typeof body.getReader === "function") {
    try {
      const reader = body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          const chunk = value instanceof Uint8Array
            ? Buffer.from(value.buffer, value.byteOffset, value.byteLength)
            : Buffer.from(value);
          res.write(chunk);
        }
      }
    } catch (_) {}
  }
  res.end();
}

async function handleHttpRequest(req, res, secure) {
  const startedAt = Date.now();
  const requestHeaders = {};
  for (const key of Object.keys(req.headers)) {
    const value = req.headers[key];
    requestHeaders[key] = redactHeader(key, Array.isArray(value) ? value.join(", ") : value);
  }
  const requestPath = (req.url || "/").split("?")[0];
  const query = (req.url || "").includes("?") ? (req.url || "").split("?")[1] : "";
  let request;
  try {
    request = makeRequest(req, secure);
  } catch (error) {
    reportError("http parse " + (req.url || ""), error);
    logRequest({ kind: "http", method: req.method || "GET", path: requestPath, query, headers: requestHeaders, status: 400, ms: Date.now() - startedAt, note: "parse error: " + (error && error.message) });
    try { res.statusCode = 400; res.end(); } catch (_) {}
    return;
  }
  if (DEBUG_ON) {
    diag("http_in", `${secure ? "https" : "http"} ${req.method} ${requestPath} host=${String(req.headers.host || "-").slice(0, 60)}`);
  }
  try {
    const response = await handleRequest(request, APP_ENV, {});
    await writeResponse(res, response);
    const bodyBytes = req._proxygoshaBody;
    logRequest({
      kind: "http",
      method: req.method || "GET",
      path: requestPath,
      query: query.slice(0, 160),
      headers: requestHeaders,
      status: response.status || 200,
      ms: Date.now() - startedAt,
      body: bodyBytes ? `${bodyBytes.length}B ${hexPreview(bodyBytes, 32)}` : "-",
      note: [response.headers.get("x-carrier-mode") ? "carrier=" + response.headers.get("x-carrier-mode") : "", response.headers.get("sec-websocket-protocol") ? "subprotocol=" + response.headers.get("sec-websocket-protocol") : ""].filter(Boolean).join(" "),
      remote: maskIp(req.socket?.remoteAddress)
    });
  } catch (error) {
    reportError("http " + req.method + " " + (req.url || ""), error);
    try {
      const fallback = await safeFallback(APP_ENV, request);
      await writeResponse(res, fallback);
      logRequest({ kind: "http", method: req.method || "GET", path: requestPath, query, headers: requestHeaders, status: fallback.status || 200, ms: Date.now() - startedAt, note: "handler error: " + (error && error.message ? error.message : error), remote: maskIp(req.socket?.remoteAddress) });
    } catch (e2) {
      reportError("http fallback", e2);
      try { res.statusCode = 500; res.end(); } catch (_) {}
      logRequest({ kind: "http", method: req.method || "GET", path: requestPath, query, headers: requestHeaders, status: 500, ms: Date.now() - startedAt, note: "fallback failed: " + (e2 && e2.message ? e2.message : e2), remote: maskIp(req.socket?.remoteAddress) });
    }
  }
}

async function handleUpgrade(req, socket, head, secure) {
  const startedAt = Date.now();
  const requestHeaders = {};
  for (const key of Object.keys(req.headers)) {
    const value = req.headers[key];
    requestHeaders[key] = redactHeader(key, Array.isArray(value) ? value.join(", ") : value);
  }
  const upgradePath = (req.url || "/").split("?")[0];
  const upgradeQuery = (req.url || "").includes("?") ? (req.url || "").split("?")[1].slice(0, 160) : "";
  const remote = maskIp(socket?.remoteAddress);
  try {
    const request = makeRequest(req, secure);
    const url = new URL(request.url);
    const host = requestHost(request, url);
    const rawHost = String(request.headers.get("host") || url.host || "");
    const portMatch = /:([0-9]+)$/.exec(rawHost);
    const port = portMatch ? portMatch[1] : (url.port || "");
    diag("ws_upgrade", `${secure ? "wss" : "ws"} ${url.pathname} host=${host} port=${port || "-"} subprotocol=${(req.headers["sec-websocket-protocol"] || "-").slice(0, 20)}…`);
    const cfg = await getRuntime(APP_ENV);
    if (!cfg) {
      diag("ws_reject", "runtime not configured");
      logRequest({ kind: "ws", method: "GET", path: upgradePath, query: upgradeQuery, headers: requestHeaders, status: 404, ms: Date.now() - startedAt, note: "runtime not configured", remote });
      socket.end("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
      return;
    }
    const response = await serveWebSocket(request, cfg, publicHost(cfg, host), port);
    const client = response && response.webSocket;
    const marker = client && client._serverWebSocket;
    if (!marker) {
      logRequest({ kind: "ws", method: "GET", path: upgradePath, query: upgradeQuery, headers: requestHeaders, status: 404, ms: Date.now() - startedAt, note: "handshake rejected (token/subprotocol/host)", remote });
      socket.end("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      marker._attach(ws);
    });
    logRequest({ kind: "ws", method: "GET", path: upgradePath, query: upgradeQuery, headers: requestHeaders, status: 101, ms: Date.now() - startedAt, note: "subprotocol=" + (req.headers["sec-websocket-protocol"] || "-").slice(0, 24), remote });
  } catch (error) {
    reportError("ws upgrade " + (req.url || ""), error);
    diag("ws_error", `${req.url || "/"} ${error?.message || error}`);
    logRequest({ kind: "ws", method: "GET", path: upgradePath, query: upgradeQuery, headers: requestHeaders, status: 0, ms: Date.now() - startedAt, note: "upgrade error: " + (error?.message || error), remote });
    try { socket.destroy(); } catch (_) {}
  }
}

// ============================================================================
// Native TLS support
// ============================================================================
// Telegram's Web Proxy clients only speak HTTPS/WSS. A plaintext listener is
// therefore useless on its own: the link Telegram opens (https://host:443/...)
// must terminate TLS on the very same port. Certificates come from either
// PROXYGOSHA_TLS_CERT / PROXYGOSHA_TLS_KEY (PEM file paths) or, for convenience,
// PROXYGOSHA_TLS_CERT_PEM / PROXYGOSHA_TLS_KEY_PEM (inline PEM text, useful when
// the platform only exposes env vars). A self-signed cert is generated on the
// fly if nothing is configured and TLS_AUTO=1, which makes local testing trivial.

function readTlsMaterial(quiet) {
  const certPath = envValue("TLS_CERT");
  const keyPath = envValue("TLS_KEY");
  const certPem = envValue("TLS_CERT_PEM");
  const keyPem = envValue("TLS_KEY_PEM");

  let cert = certPem || null;
  let key = keyPem || null;
  const problems = [];
  const trace = quiet ? () => {} : diag;

  if (!cert && certPath) {
    try {
      cert = fs.readFileSync(certPath, "utf8");
      trace("tls", `loaded certificate from ${certPath}`);
    } catch (error) {
      problems.push(`cannot read TLS_CERT "${certPath}": ${error.message}`);
    }
  }
  if (!key && keyPath) {
    try {
      key = fs.readFileSync(keyPath, "utf8");
      trace("tls", `loaded private key from ${keyPath}`);
    } catch (error) {
      problems.push(`cannot read TLS_KEY "${keyPath}": ${error.message}`);
    }
  }
  if (cert && !key) problems.push("certificate present but no private key");
  if (key && !cert) problems.push("private key present but no certificate");
  if (!cert || !key) return { cert: null, key: null, problems };

  try {
    const parsed = new X509Certificate(cert);
    const validTo = new Date(parsed.validTo);
    const daysLeft = Math.floor((validTo.getTime() - Date.now()) / 86400000);
    trace("tls", `certificate subject="${parsed.subject.replace(/\n/g, ", ")}" expires=${parsed.validTo} (${daysLeft}d)`);
    if (daysLeft < 0) problems.push(`certificate expired ${-daysLeft} days ago`);
    else if (daysLeft < 7) problems.push(`certificate expires in ${daysLeft} day(s)`);
    const sans = (parsed.subjectAltName || "").split(",").map((s) => s.trim()).filter(Boolean);
    if (sans.length) trace("tls", `certificate SANs: ${sans.join(" | ").slice(0, 150)}`);
  } catch (error) {
    problems.push(`certificate is not parseable PEM: ${error.message}`);
  }

  return { cert, key, problems };
}

// TLS handshake diagnostics. Every failed handshake is logged with the peer's
// masked IP and the concrete OpenSSL reason, which is exactly what you need
// when Telegram silently fails to connect (wrong port, expired cert, SNI
// mismatch, or a client that refuses an untrusted chain).
function attachTlsDiagnostics(tlsServer, label) {
  tlsServer.on("tlsClientError", (error, socket) => {
    STATS.tlsErrors = (STATS.tlsErrors || 0) + 1;
    diag("tls_error", `${label} ${maskIp(socket?.remoteAddress)} ${error?.code || ""} ${error?.message || error}`);
  });
  tlsServer.on("secureConnection", (socket) => {
    if (!DEBUG_ON) return;
    try {
      const peer = socket.getPeerCertificate?.() || {};
      const cipher = socket.getCipher?.() || {};
      diag("tls_ok", `${label} ${maskIp(socket.remoteAddress)} proto=${socket.getProtocol?.()} cipher=${cipher.name || "-"} sni=${socket.servername || "-"} cn=${String(peer.subject?.CN || "-")}`);
    } catch (_) {}
  });
  tlsServer.on("clientError", (error, socket) => {
    diag("tls_client_error", `${label} ${error?.code || ""} ${error?.message || error}`);
    try { socket.destroy(); } catch (_) {}
  });
}

function buildTlsContext() {
  const material = readTlsMaterial();
  for (const problem of material.problems) diag("tls_config", problem);
  if (!material.cert || !material.key) return null;
  diag("tls", "TLS context created (min version TLSv1.2)");
  return { cert: material.cert, key: material.key };
}

const server = http.createServer((req, res) => {
  handleHttpRequest(req, res, false);
});

server.on("upgrade", (req, socket, head) => {
  handleUpgrade(req, socket, head, false);
});

server.on("error", (error) => {
  reportError("http server", error);
  diag("listen_error", `${LISTEN_HOST}:${LISTEN_PORT} ${error?.code || ""} ${error?.message || error}`);
});

// Optional HTTPS listener. Enabled only when a certificate is available; the
// plaintext listener stays up so an existing reverse proxy keeps working.
const TLS_PORT = tlsPortLabel();
const TLS_ENABLED = (envValue("TLS_ENABLED") || "auto").toLowerCase();

let tlsServer = null;

function startTls() {
  const context = buildTlsContext();
  if (!context) {
    if (TLS_ENABLED === "on" || TLS_ENABLED === "1" || TLS_ENABLED === "true") {
      diag("tls_config", "TLS explicitly enabled but no usable certificate; HTTPS listener not started");
    } else {
      diag("tls", "no certificate configured; HTTPS listener disabled (plaintext only)");
    }
    return;
  }
  tlsServer = https.createServer({ ...context, minVersion: "TLSv1.2" }, (req, res) => {
    handleHttpRequest(req, res, true);
  });
  attachTlsDiagnostics(tlsServer, `:${TLS_PORT}`);
  tlsServer.on("upgrade", (req, socket, head) => {
    handleUpgrade(req, socket, head, true);
  });
  tlsServer.on("error", (error) => {
    reportError("https server", error);
    diag("listen_error", `${LISTEN_HOST}:${TLS_PORT} (TLS) ${error?.code || ""} ${error?.message || error}`);
  });
  tlsServer.listen(TLS_PORT, LISTEN_HOST, () => {
    console.log("[proxygosha] listening on https://" + LISTEN_HOST + ":" + TLS_PORT);
    diag("tls", `HTTPS listener ready on ${LISTEN_HOST}:${TLS_PORT}`);
  });
}

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  console.log("[proxygosha] listening on http://" + LISTEN_HOST + ":" + LISTEN_PORT);
  diag("boot", `HTTP listener ready on ${LISTEN_HOST}:${LISTEN_PORT}`);
  startTls();
  diag("boot", `debug=${DEBUG_ON ? "on" : "off"} port=${LISTEN_PORT} tls_port=${TLS_PORT}`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    diag("boot", `received ${signal}, shutting down`);
    try { server.close(); } catch (_) {}
    try { if (tlsServer) tlsServer.close(); } catch (_) {}
    setTimeout(() => process.exit(0), 1000);
  });
}
