#!/usr/bin/env bash
set -euo pipefail

APP_USER="freepbxui"
APP_GROUP="$APP_USER"
INSTALL_DIR="/opt/freepbx-agent-ui"
WEBROOT="/var/www/freepbx-agent-ui"
SERVICE_NAME="freepbx-agent-ui"
NODE_MAJOR=20

need_root(){ [ "$EUID" -eq 0 ] || { echo "Run as root (sudo)"; exit 1; }; }
need_root

echo "==> FreePBX Agent UI v0.3.0 – clean deploy"
apt-get update -y
apt-get install -y ca-certificates curl git build-essential jq netcat-openbsd

if ! command -v node >/dev/null 2>&1 || ! node -v | grep -q "v${NODE_MAJOR}\."; then
  echo "==> Installing Node.js ${NODE_MAJOR}.x..."
  curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash -
  apt-get install -y nodejs
fi

id -u "$APP_USER" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$APP_USER" || true
mkdir -p "$INSTALL_DIR" "$WEBROOT"
chown -R "$APP_USER:$APP_GROUP" "$INSTALL_DIR" "$WEBROOT"

#################################
# SERVER (Fastify + AMI + MySQL)
#################################
mkdir -p "$INSTALL_DIR/server/src"

tee "$INSTALL_DIR/server/package.json" >/dev/null <<'JSON'
{
  "name": "freepbx-agent-ui-server",
  "version": "0.3.0",
  "type": "module",
  "main": "src/index.js",
  "scripts": {
    "start": "node src/index.js"
  },
  "dependencies": {
    "@fastify/cors": "^11.1.0",
    "@fastify/jwt": "^9.0.0",
    "asterisk-manager": "^0.2.0",
    "dotenv": "^16.4.5",
    "fastify": "^5.1.0",
    "mysql2": "^3.11.3",
    "ws": "^8.18.0"
  }
}
JSON

# ---- auth (Userman via MySQL + JWT) ----
tee "$INSTALL_DIR/server/src/auth.js" >/dev/null <<'JS'
import fp from "fastify-plugin";
import jwt from "@fastify/jwt";
import mysql from "mysql2/promise";

const pool = mysql.createPool({
  host: process.env.MYSQL_HOST || "127.0.0.1",
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASS,
  database: process.env.MYSQL_DB || "asteriskcdrdb",
  connectionLimit: 4
});

/** Validate FreePBX userman user/pass → return {username, ext} */
async function validateUserman(username, password) {
  // Minimal: user exists and has linked extension; password check by FreePBX hash
  // FreePBX 16+ stores in 'userman_users'; linked ext in 'userman_users_settings' or device map.
  const [urows] = await pool.query(
    "SELECT id,username FROM userman_users WHERE username=?",
    [username]
  );
  if (urows.length === 0) return null;

  // Check password via Asterisk/FreePBX function would require PHP. For lab/demo, accept if non-empty.
  if (!password) return null;

  // Linked extension (common linkage)
  const [srows] = await pool.query(
    "SELECT value FROM userman_users_settings WHERE uid=? AND `key`='extension'",
    [urows[0].id]
  );
  const ext = srows?.[0]?.value || username; // fallback: username==ext in many setups
  return { username, ext: String(ext) };
}

export const buildAuth = (fastify) => fastify.register(fp(async (app) => {
  await app.register(jwt, { secret: process.env.JWT_SECRET || "changeme" });

  app.decorate("auth", async (req, rep) => {
    try {
      const auth = req.headers.authorization || "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
      if (!token) return rep.code(401).send({ error: "no token" });
      req.user = await app.jwt.verify(token);
    } catch {
      return rep.code(401).send({ error: "bad token" });
    }
  });

  app.post("/api/login", async (req, rep) => {
    const { username, password } = req.body || {};
    if (!username) return rep.code(400).send({ error: "username required" });
    const ok = await validateUserman(username, password || "");
    if (!ok) return rep.code(401).send({ error: "invalid credentials" });
    const token = app.jwt.sign({ username: ok.username, ext: ok.ext }, { expiresIn: "12h" });
    return { token, ext: ok.ext };
  });

  app.post("/api/logout", async (_req, _rep) => {
    // Stateless JWT: client just discards token. Return 200 for UI convenience.
    return { ok: true };
  });
}));
JS

# ---- AMI + helpers ----
tee "$INSTALL_DIR/server/src/ami.js" >/dev/null <<'JS'
import AsteriskManager from "asterisk-manager";
let ami;

export async function connectAMI() {
  const host = process.env.AMI_HOST || "127.0.0.1";
  const port = +(process.env.AMI_PORT || 5038);
  const user = process.env.AMI_USER || "admin";
  const pass = process.env.AMI_PASS || "admin";

  console.log(`[AMI] Connecting to ${host}:${port} as ${user} ...`);
  return new Promise((resolve, reject) => {
    try {
      ami = new AsteriskManager(port, host, user, pass, true);
      let resolved = false;
      ami.on("ready", () => { if (!resolved){ resolved = true; console.log("[AMI] connected"); resolve(); } });
      ami.on("error", (e) => console.error("[AMI] ERROR:", e?.message || e));
      ami.keepConnected();
      setTimeout(() => { if (!resolved) reject(new Error("AMI connect timeout")); }, 4000);
    } catch (e) { reject(e); }
  });
}
export function getAMI(){ return ami; }
export function wireQueueEvents(broadcast) {
  if (!ami) return;
  ami.on("managerevent", (evt) => {
    const ev = (evt.Event || "").toUpperCase();
    if (ev.includes("QUEUE")) broadcast({ type: "queue-event", evt });
  });
}
export function amiCommand(cmd){
  return new Promise((resolve) => {
    if (!ami) return resolve("AMI not connected");
    ami.action({ Action:"Command", Command:cmd }, (_e, r) => {
      resolve((r?.content||r?.data||r?.output||r?.response||"").toString());
    });
  });
}

export async function queueAdd({ queue, iface, penalty=0, paused=false }) {
  if (!ami) throw new Error("AMI not connected");
  return new Promise((resolve) => {
    ami.action({ Action:"QueueAdd", Queue:queue, Interface:iface, Penalty:penalty, Paused:paused }, () => resolve());
  });
}
export async function queueRemove({ queue, iface }) {
  if (!ami) throw new Error("AMI not connected");
  return new Promise((resolve) => {
    ami.action({ Action:"QueueRemove", Queue:queue, Interface:iface }, () => resolve());
  });
}
export async function queuePause({ queue, iface, paused=true, reason="" }) {
  if (!ami) throw new Error("AMI not connected");
  return new Promise((resolve) => {
    ami.action({ Action:"QueuePause", Queue:queue, Interface:iface, Paused:paused, Reason:reason }, () => resolve());
  });
}
JS

# ---- Queue discovery (DB + AstDB via AMI) ----
tee "$INSTALL_DIR/server/src/queueDiscovery.js" >/dev/null <<'JS'
import mysql from "mysql2/promise";
import { amiCommand, getAMI } from "./ami.js";

const pool = mysql.createPool({
  host: process.env.MYSQL_CFG_HOST || process.env.MYSQL_HOST || "127.0.0.1",
  port: Number(process.env.MYSQL_CFG_PORT || process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_CFG_USER || process.env.MYSQL_USER,
  password: process.env.MYSQL_CFG_PASS || process.env.MYSQL_PASS,
  database: process.env.MYSQL_CFG_DB || "asterisk",
  connectionLimit: 4
});

async function tableExists(name) {
  const db = process.env.MYSQL_CFG_DB || "asterisk";
  const [rows] = await pool.query(
    "SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=? AND TABLE_NAME=?",
    [db, name]
  );
  return rows.length > 0;
}

function deviceCandidates(ext) {
  const fam = (process.env.DEVICE_FAMILY || "AUTO").toUpperCase();
  if (fam === "SIP") return [`SIP/${ext}`];
  if (fam === "PJSIP") return [`PJSIP/${ext}`];
  return [`PJSIP/${ext}`, `SIP/${ext}`]; // AUTO
}

async function getQueuesFromDB() {
  const haveQCfg = await tableExists("queues_config");
  const haveCx   = await tableExists("cxpanel_queues");
  const ids = new Set();

  if (haveQCfg) {
    const [r] = await pool.query("SELECT extension FROM queues_config");
    r.forEach(x => ids.add(String(x.extension)));
  } else if (haveCx) {
    const [r] = await pool.query("SELECT queue_number FROM cxpanel_queues");
    r.forEach(x => ids.add(String(x.queue_number)));
  }
  return Array.from(ids).sort();
}

async function dynFromAstDB(q) {
  try {
    const txt = await amiCommand(`database get QPENALTY/${q}/dynmemberonly`);
    return /(\/QPENALTY\/[^:]+\/dynmemberonly\s*:\s*(yes|1))\b/i.test(txt) ||
           /\bValue\s*:\s*(yes|1)\b/i.test(txt);
  } catch { return false; }
}

async function allowedAgentsFromAstDB(q) {
  const agents = new Set();
  try {
    const txt = await amiCommand(`database show QPENALTY/${q}/agents`);
    txt.split("\n").forEach(line=>{
      const m = line.match(new RegExp(`/QPENALTY/${q}/agents/([^\\s:]+)\\s*:`));
      if (m) agents.add(String(m[1]));
    });
  } catch {}
  return agents;
}

async function isLoggedIn(ext, q) {
  const ami = getAMI();
  if (!ami) return false;

  try {
    const pm = await amiCommand(`database show Queue/PersistentMembers/${q}`);
    const rx = new RegExp(`(?:SIP|PJSIP)/${ext}\\b`);
    if (rx.test(pm) || pm.includes(`/${ext}`) || pm.includes(`;${ext};`)) return true;
  } catch {}

  // fallback: QueueStatus scan
  return await new Promise((resolve) => {
    let logged = false;
    const onEv = (evt) => {
      const ev = (evt.Event || "").toUpperCase();
      if (ev === "QUEUEMEMBER") {
        if (evt.Queue !== q) return;
        const si = (evt.StateInterface || evt.Interface || "");
        if (si.includes(`SIP/${ext}`) || si.includes(`PJSIP/${ext}`) || si.endsWith(`/${ext}`)) logged = true;
      } else if (ev === "QUEUESTATUSCOMPLETE") {
        ami.removeListener("managerevent", onEv);
        resolve(logged);
      }
    };
    ami.on("managerevent", onEv);
    ami.action({ Action:"QueueStatus", Queue:q }, () => {});
    setTimeout(() => { ami.removeListener("managerevent", onEv); resolve(logged); }, 2000);
  });
}

async function isPaused(ext, q) {
  const ami = getAMI();
  if (!ami) return false;
  return await new Promise((resolve) => {
    let paused = false;
    const onEv = (evt) => {
      const ev = (evt.Event || "").toUpperCase();
      if (ev === "QUEUEMEMBER") {
        if (evt.Queue !== q) return;
        const si = (evt.StateInterface || evt.Interface || "");
        const isMine = si.includes(`SIP/${ext}`) || si.includes(`PJSIP/${ext}`) || si.endsWith(`/${ext}`);
        if (isMine) paused = String(evt.Paused||"0") === "1";
      } else if (ev === "QUEUESTATUSCOMPLETE") {
        ami.removeListener("managerevent", onEv);
        resolve(paused);
      }
    };
    ami.on("managerevent", onEv);
    ami.action({ Action:"QueueStatus", Queue:q }, () => {});
    setTimeout(() => { ami.removeListener("managerevent", onEv); resolve(paused); }, 2000);
  });
}

export async function discoverQueuesForExt(ext) {
  const allQueues = await getQueuesFromDB();
  const allowedQs = [];
  for (const q of allQueues) {
    const dyn = await dynFromAstDB(q);
    if (!dyn) { allowedQs.push(q); continue; }
    const agents = await allowedAgentsFromAstDB(q);
    if (agents.has(String(ext))) allowedQs.push(q);
  }

  // status maps only for allowed queues
  const loggedIn = {}, paused = {};
  for (const q of allowedQs) {
    try { loggedIn[q] = await isLoggedIn(ext, q); } catch { loggedIn[q] = false; }
    try { paused[q]   = await isPaused(ext, q);   } catch { paused[q]   = false; }
  }
  return { allQueues, allowedQs, loggedIn, paused };
}

export function ifacesForExt(ext) {
  return deviceCandidates(ext);
}
JS

# ---- WS (reserved for future) ----
tee "$INSTALL_DIR/server/src/wsHub.js" >/dev/null <<'JS'
import { WebSocketServer } from "ws";
export function createWsServer(httpServer) {
  const wss = new WebSocketServer({ noServer: true });
  httpServer.on("upgrade", (req, socket, head) => {
    if (req.url === "/ws") wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
    else socket.destroy();
  });
  const broadcast = (msg) => {
    const s = typeof msg === "string" ? msg : JSON.stringify(msg);
    wss.clients.forEach((c) => { if (c.readyState === 1) c.send(s); });
  };
  return { wss, broadcast };
}
JS

# ---- Diagnostics plugin ----
tee "$INSTALL_DIR/server/src/devDiag.js" >/dev/null <<'JS'
import fp from "fastify-plugin";
import { getAMI, amiCommand } from "./ami.js";
import { discoverQueuesForExt } from "./queueDiscovery.js";

export default fp(async (fastify) => {
  fastify.get("/healthz", async () => ({ ok: true }));
  fastify.get("/healthz/ami", async () => ({ ami: !!getAMI() }));

  fastify.get("/api/dev/ami-test", { preHandler: fastify.auth }, async () => {
    const out = {};
    out.ping    = await new Promise((resolve) => getAMI()?.action({ Action:"Ping" }, (_e,r)=>resolve(r)));
    out.version = { response:"Success", ...(await amiCommand("core show version") && { message:"Command output follows", output: await amiCommand("core show version") }) };
    return out;
  });

  fastify.get("/api/dev/diag", { preHandler: fastify.auth }, async (req) => {
    const { ext } = req.query || {};
    if (!ext) return { error:"ext required" };
    const d = await discoverQueuesForExt(ext);
    return { ext, ...d };
  });
});
JS

# ---- HTTP app ----
tee "$INSTALL_DIR/server/src/index.js" >/dev/null <<'JS'
import "dotenv/config";
import Fastify from "fastify";
import cors from "@fastify/cors";
import { buildAuth } from "./auth.js";
import { connectAMI, getAMI, queueAdd, queueRemove, queuePause } from "./ami.js";
import { discoverQueuesForExt, ifacesForExt } from "./queueDiscovery.js";
import devDiag from "./devDiag.js";

const fastify = Fastify({ logger: true });
await fastify.register(cors, { origin: process.env.ALLOWED_ORIGIN || true, credentials: true });
buildAuth(fastify);
await fastify.register(devDiag);

fastify.get("/healthz", async () => ({ ok: true }));
fastify.get("/healthz/ami", async () => ({ ami: !!getAMI() }));

fastify.addHook("preHandler", async (req, rep) => {
  const p = req.routerPath || req.url || "";
  if (p.startsWith("/api/") && !p.startsWith("/api/login")) await fastify.auth(req, rep);
});

fastify.get("/api/queues", async (req) => {
  const { ext } = req.user;
  return await discoverQueuesForExt(ext); // { allQueues, allowedQs, loggedIn, paused }
});

// actions
async function actEachIface(ext, queue, fn) {
  const candidates = ifacesForExt(ext);
  for (const iface of candidates) {
    try { await fn(iface); return true; } catch { /* try next */ }
  }
  return false;
}
fastify.post("/api/queue/login", async (req, rep) => {
  const { queue } = req.body || {};
  const { ext } = req.user;
  if (!queue) return rep.code(400).send({ error:"queue required" });
  const ok = await actEachIface(ext, queue, (iface)=>queueAdd({ queue, iface, penalty:0, paused:false }));
  return { ok };
});
fastify.post("/api/queue/logout", async (req, rep) => {
  const { queue } = req.body || {};
  const { ext } = req.user;
  if (!queue) return rep.code(400).send({ error:"queue required" });
  const ok = await actEachIface(ext, queue, (iface)=>queueRemove({ queue, iface }));
  return { ok };
});
fastify.post("/api/queue/pause", async (req, rep) => {
  const { queue, reason } = req.body || {};
  const { ext } = req.user;
  if (!queue) return rep.code(400).send({ error:"queue required" });
  const ok = await actEachIface(ext, queue, (iface)=>queuePause({ queue, iface, paused:true, reason:reason||"Break" }));
  return { ok };
});
fastify.post("/api/queue/unpause", async (req, rep) => {
  const { queue } = req.body || {};
  const { ext } = req.user;
  if (!queue) return rep.code(400).send({ error:"queue required" });
  const ok = await actEachIface(ext, queue, (iface)=>queuePause({ queue, iface, paused:false }));
  return { ok };
});

async function start() {
  const port = +(process.env.PORT || 8088);
  await fastify.listen({ port, host: "0.0.0.0" });
  fastify.log.info("API on :" + port);
  try {
    await connectAMI();
  } catch (e) {
    fastify.log.error({ err: e }, "AMI connect error (continuing without AMI)");
  }
}
start().catch((e) => { console.error(e); process.exit(1); });
JS

chown -R "$APP_USER:$APP_GROUP" "$INSTALL_DIR/server"

#################
# WEB (Vite-less)
#################
mkdir -p "$INSTALL_DIR/web"

tee "$INSTALL_DIR/web/index.html" >/dev/null <<'HTML'
<!doctype html>
<html>
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>FreePBX Agent UI</title>
<style>
  :root { color-scheme: dark; }
  body { background:#0b0e12; color:#e6e9ef; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin:20px; }
  .card { background:#10151d; border:1px solid #1c2430; border-radius:12px; padding:16px; margin:12px 0; }
  input,button { border-radius:8px; padding:8px 12px; border:1px solid #293548; background:#0f141b; color:#e6e9ef; }
  button { cursor:pointer; }
  .row{display:flex; gap:12px; align-items:center; flex-wrap:wrap;}
  .tag { font-size:12px; padding:2px 8px; border-radius:12px; display:inline-block; }
  .ok { background:#16331c; color:#7ad37a; border:1px solid #255b2a; }
  .bad{ background:#3a1616; color:#ff7b7b; border:1px solid #6b2323; }
  .pill{ padding:2px 8px; border-radius:999px; font-size:12px; }
  table { width:100%; border-collapse: collapse; }
  th,td{ padding:12px; border-bottom:1px solid #1c2430; }
  th{ text-align:left; color:#b9c2cf; font-weight:600; }
  .status { display:flex; align-items:center; gap:8px; }
  .dot{ width:10px; height:10px; border-radius:50%; display:inline-block; }
  .red{ background:#ff4d4d; } .green{ background:#33dd88; } .amber{ background:#f3b94a; }
  .muted{ color:#8fa2b7; }
  .right{ margin-left:auto; }
</style>
</head>
<body>
  <h1>FreePBX Agent UI</h1>

  <div class="card">
    <div class="row">
      <div>
        <div class="muted">Username</div>
        <input id="u" placeholder="userman username or extension" />
      </div>
      <div>
        <div class="muted">Password</div>
        <input id="p" type="password" placeholder="password" />
      </div>
      <button onclick="login()">Login</button>
      <button onclick="logout()">Logout</button>
      <div class="right muted">Token: <code id="tok" class="muted"></code></div>
    </div>
  </div>

  <div class="card">
    <div class="row">
      <div>API health: <span id="health" class="tag">…</span></div>
      <div>AMI: <span id="ami" class="tag">unknown</span></div>
      <button class="right" onclick="refresh()">Refresh now</button>
    </div>
  </div>

  <div class="card">
    <div class="row">
      <h3>Queues & status</h3>
    </div>
    <table>
      <thead>
        <tr><th>Queue</th><th>Status</th><th class="right">Actions</th></tr>
      </thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>

<script>
const api = (p)=> '/api' + p;
let token = '';

function setTag(el, ok){
  el.textContent = ok ? 'OK' : 'down';
  el.className = 'tag ' + (ok?'ok':'bad');
}

async function ping(){
  try{
    const r = await fetch('/healthz');
    setTag(document.getElementById('health'), r.ok);
  }catch{ setTag(document.getElementById('health'), false); }

  try{
    const j = await (await fetch('/healthz/ami')).json();
    const el = document.getElementById('ami');
    el.textContent = j.ami ? 'connected' : 'not connected';
    el.className = 'tag ' + (j.ami?'ok':'bad');
  }catch{
    const el = document.getElementById('ami');
    el.textContent = 'unknown'; el.className = 'tag bad';
  }
}

function auth(){ return token ? { 'Authorization':'Bearer '+token } : {}; }

async function login(){
  const username = document.getElementById('u').value.trim();
  const password = document.getElementById('p').value;
  const r = await fetch(api('/login'), { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username,password})});
  const j = await r.json();
  if (j.token){ token=j.token; document.getElementById('tok').textContent = token.slice(0,24)+'…'; await refresh(true); }
  else alert(j.error||'login failed');
}
async function logout(){
  token = ''; document.getElementById('tok').textContent='';
  document.getElementById('tbody').innerHTML='';
  await fetch(api('/logout'), {method:'POST', headers:auth()}).catch(()=>{});
}

function statusCell(logged, paused){
  if (!logged) return '<div class="status"><span class="dot red"></span> Not logged in</div>';
  if (paused)  return '<div class="status"><span class="dot amber"></span> Paused</div>';
  return '<div class="status"><span class="dot green"></span> Logged in</div>';
}

async function doAction(act, q){
  if (!token) return alert('login first');
  try{
    const r = await fetch(api('/queue/'+act), { method:'POST', headers:{...auth(),'Content-Type':'application/json'}, body: JSON.stringify({queue:q}) });
    await r.json();
    await new Promise(r=>setTimeout(r, 1000)); // let AMI settle
    await refresh();
  }catch(e){ alert(e); }
}

async function refresh(silent){
  if (!token) return;
  try{
    const j = await (await fetch(api('/queues'), {headers:auth()})).json();
    const allowed = (j.allowedQs||[]); // only render these
    const tbody = document.getElementById('tbody');
    tbody.innerHTML = '';
    for (const q of allowed){
      const logged = !!(j.loggedIn||{})[q];
      const paused = !!(j.paused||{})[q];
      const row = document.createElement('tr');
      row.innerHTML = `
        <td>${q}</td>
        <td>${statusCell(logged, paused)}</td>
        <td class="right">
          <button onclick="doAction('login','${q}')">Login</button>
          <button onclick="doAction('logout','${q}')">Logout</button>
          <button onclick="doAction('pause','${q}')">Pause</button>
          <button onclick="doAction('unpause','${q}')">Unpause</button>
        </td>`;
      tbody.appendChild(row);
    }
    if (!silent) console.log('refreshed');
  }catch(e){ if(!silent) alert(e); }
}

ping();
setInterval(ping, 5000);
setInterval(()=>refresh(true), 3000);
</script>
</body></html>
HTML

# nginx site
tee /etc/nginx/sites-available/freepbx-agent-ui.conf >/dev/null <<NG
server {
  listen 80;
  server_name _;

  root ${WEBROOT};
  index index.html;

  location / { try_files \$uri /index.html; }

  location /api/ {
    proxy_pass http://127.0.0.1:8088;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
  }

  location /healthz {
    proxy_pass http://127.0.0.1:8088/healthz;
  }
  location /healthz/ami {
    proxy_pass http://127.0.0.1:8088/healthz/ami;
  }

  location /ws {
    proxy_pass http://127.0.0.1:8088/ws;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "Upgrade";
    proxy_set_header Host \$host;
  }
}
NG

ln -sf /etc/nginx/sites-available/freepbx-agent-ui.conf /etc/nginx/sites-enabled/freepbx-agent-ui.conf
rm -f /etc/nginx/sites-enabled/default
cp -f "$INSTALL_DIR/web/index.html" "$WEBROOT/index.html"
chown -R www-data:www-data "$WEBROOT"
apt-get install -y nginx
nginx -t && systemctl reload nginx

# .env (only create if missing; otherwise keep)
if [ ! -f "$INSTALL_DIR/server/.env" ]; then
  tee "$INSTALL_DIR/server/.env" >/dev/null <<'ENV'
PORT=8088
JWT_SECRET=change_me_please
ALLOWED_ORIGIN=*

AMI_HOST=192.168.1.25
AMI_PORT=5038
AMI_USER=ui_agent_app
AMI_PASS=supersecret

# Read-only reporting user (cdr DB); used also to read userman tables here
MYSQL_HOST=192.168.1.25
MYSQL_PORT=3306
MYSQL_USER=report_ro
MYSQL_PASS=StrongROPass!
MYSQL_DB=asteriskcdrdb

# FreePBX config DB (queues_config, queues_details) – we mostly discover via AMI, but connect here too
MYSQL_CFG_HOST=$MYSQL_HOST
MYSQL_CFG_PORT=$MYSQL_PORT
MYSQL_CFG_USER=$MYSQL_USER
MYSQL_CFG_PASS=$MYSQL_PASS
MYSQL_CFG_DB=asterisk

# Choose SIP/PJSIP/AUTO
DEVICE_FAMILY=AUTO

TZ=America/New_York
ENV
  chown "$APP_USER:$APP_GROUP" "$INSTALL_DIR/server/.env"
  chmod 640 "$INSTALL_DIR/server/.env"
fi

# service
tee /etc/systemd/system/${SERVICE_NAME}.service >/dev/null <<SVC
[Unit]
Description=FreePBX Agent UI API (Node.js)
After=network.target

[Service]
Type=simple
Environment=NODE_ENV=production
WorkingDirectory=${INSTALL_DIR}/server
ExecStart=/usr/bin/node ${INSTALL_DIR}/server/src/index.js
Restart=always
RestartSec=5
User=${APP_USER}
Group=${APP_GROUP}
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
SVC

# Install node deps (server only)
su -s /bin/bash -c "cd '$INSTALL_DIR/server' && npm config set registry https://registry.npmjs.org/ && rm -rf node_modules package-lock.json && npm install --omit=dev" "$APP_USER"

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"

echo
echo "==> Done."
echo "Open: http://<UI_VM_IP>/"
echo "Check AMI: curl -s http://127.0.0.1:8088/healthz/ami"
