#!/usr/bin/env bash
set -euo pipefail

# ===============================
# FreePBX Agent UI – Full Installer
# ===============================

APP_USER="freepbxui"
APP_GROUP="$APP_USER"
INSTALL_DIR="/opt/freepbx-agent-ui"
WEBROOT="/var/www/freepbx-agent-ui"
SERVICE_NAME="freepbx-agent-ui"
NODE_MAJOR=20

need_root(){ [ "$EUID" -eq 0 ] || { echo "Run as root (sudo)"; exit 1; }; }
prompt(){ local p="$1"; local d="${2:-}"; read -rp "$p${d:+ [$d]}: " v; echo "${v:-$d}"; }
yn(){ local p="$1"; local d="${2:-Y}"; read -rp "$p [$d]: " a; a="${a:-$d}"; [[ "$a" =~ ^[Yy]$ ]]; }

need_root
echo "==> FreePBX Agent UI installer starting..."

# --- OS prereqs ---
echo "==> Installing prerequisites..."
apt-get update -y
apt-get install -y ca-certificates curl git build-essential jq netcat-openbsd

# Node.js
if ! command -v node >/dev/null 2>&1 || ! node -v | grep -q "v${NODE_MAJOR}\."; then
  echo "==> Installing Node.js ${NODE_MAJOR}.x..."
  curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash -
  apt-get install -y nodejs
fi

# --- Service user & dirs ---
echo "==> Creating service user and directories..."
id -u "$APP_USER" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$APP_USER" || true
mkdir -p "/home/$APP_USER" "$INSTALL_DIR"
chown -R "$APP_USER:$APP_GROUP" "/home/$APP_USER" "$INSTALL_DIR"

# =========================
# Scaffold/patch SERVER
# =========================
echo "==> Scaffolding server..."
mkdir -p "$INSTALL_DIR/server/src"

cat > "$INSTALL_DIR/server/package.json" <<'JSON'
{
  "name": "freepbx-agent-ui-server",
  "version": "0.2.0",
  "type": "module",
  "main": "src/index.js",
  "scripts": { "start": "node src/index.js" },
  "dependencies": {
    "fastify": "^5.1.0",
    "@fastify/cors": "^11.1.0",
    "@fastify/jwt": "^9.0.0",
    "dotenv": "^16.4.5",
    "asterisk-manager": "^0.2.0",
    "mysql2": "^3.11.3",
    "ws": "^8.18.0"
  }
}
JSON

# ---- auth (JWT + /api/login) ----
cat > "$INSTALL_DIR/server/src/auth.js" <<'JS'
import fp from "fastify-plugin";
import jwt from "@fastify/jwt";

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

  // minimal login: client posts {ext:"1010"}; we sign it
  app.post("/api/login", async (req, rep) => {
    const { ext } = req.body || {};
    if (!ext) return rep.code(400).send({ error: "ext required" });
    const token = app.jwt.sign({ ext }, { expiresIn: "12h" });
    return { token };
  });
}));
JS

# ---- ws hub ----
cat > "$INSTALL_DIR/server/src/wsHub.js" <<'JS'
import { WebSocketServer } from "ws";
export function createWsServer(httpServer) {
  const wss = new WebSocketServer({ noServer: true });
  httpServer.on("upgrade", (req, socket, head) => {
    if (req.url === "/ws") {
      wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
    } else socket.destroy();
  });
  const broadcast = (msg) => {
    const txt = typeof msg === "string" ? msg : JSON.stringify(msg);
    wss.clients.forEach((c) => { if (c.readyState === 1) c.send(txt); });
  };
  return { wss, broadcast };
}
JS

# ---- config (queues ACL + device family) ----
cat > "$INSTALL_DIR/server/src/config.js" <<'JS'
export const USER_ACCESS = {
  // "1010": { queues: ["001","support"], ext: "1010" },
};
export const DEVICE_TEMPLATE = (ext) => {
  const family = (process.env.DEVICE_FAMILY || "SIP").toUpperCase(); // or PJSIP
  return `${family}/${ext}`;
};
JS

# ---- AMI helpers (connect + queue actions + queue status dump) ----
cat > "$INSTALL_DIR/server/src/ami.js" <<'JS'
import AsteriskManager from "asterisk-manager";
let ami;

export async function connectAMI() {
  const host = process.env.AMI_HOST || "127.0.0.1";
  const port = +(process.env.AMI_PORT || 5038);
  const user = process.env.AMI_USER || "admin";
  const pass = process.env.AMI_PASS || "admin";
  return new Promise((resolve, reject) => {
    try {
      ami = new AsteriskManager(port, host, user, pass, true);
      ami.on("ready", () => resolve());
      ami.on("error", (e) => console.error("AMI error:", e?.message || e));
      ami.keepConnected();
    } catch (e) { reject(e); }
  });
}
export function wireQueueEvents(broadcast) {
  if (!ami) return;
  ami.on("managerevent", (evt) => {
    const ev = (evt.Event || "").toUpperCase();
    if (ev.includes("QUEUE")) broadcast({ type: "queue-event", evt });
  });
}
export async function queueAdd({ queue, iface, penalty=0, paused=false }) {
  if (!ami) throw new Error("AMI not connected");
  ami.action({ Action:"QueueAdd", Queue:queue, Interface:iface, Penalty:penalty, Paused:paused }, () => {});
}
export async function queueRemove({ queue, iface }) {
  if (!ami) throw new Error("AMI not connected");
  ami.action({ Action:"QueueRemove", Queue:queue, Interface:iface }, () => {});
}
export async function queuePause({ queue, iface, paused=true, reason="" }) {
  if (!ami) throw new Error("AMI not connected");
  ami.action({ Action:"QueuePause", Queue:queue, Interface:iface, Paused:paused, Reason:reason }, () => {});
}

/** Return { members:[], calls:[] } for a given queue (or all if null) */
export async function queueStatus(targetQueue = null) {
  if (!ami) throw new Error("AMI not connected");
  return new Promise((resolve) => {
    const members = [], calls = [];
    const onEvent = (evt) => {
      const ev = (evt.Event || "").toUpperCase();
      if (ev === "QUEUEMEMBER") {
        if (targetQueue && evt.Queue !== targetQueue) return;
        members.push({
          queue: evt.Queue,
          name: evt.Name || evt.MemberName,
          iface: evt.StateInterface || evt.Interface,
          paused: evt.Paused === "1",
          status: Number(evt.Status || 0),
          callsTaken: Number(evt.CallsTaken || 0),
          lastCall: Number(evt.LastCall || 0)
        });
      } else if (ev === "QUEUEENTRY") {
        if (targetQueue && evt.Queue !== targetQueue) return;
        calls.push({
          queue: evt.Queue,
          position: Number(evt.Position || 0),
          wait: Number(evt.Wait || 0),
          caller: evt.CallerIDNum || evt.CallerIDName
        });
      } else if (ev === "QUEUESTATUSCOMPLETE") {
        ami.removeListener("managerevent", onEvent);
        resolve({ members, calls });
      }
    };
    ami.on("managerevent", onEvent);
    ami.action({ Action:"QueueStatus" }, () => {});
    setTimeout(() => { ami.removeListener("managerevent", onEvent); resolve({ members, calls }); }, 2000);
  });
}
JS

# ---- SLA & agent stats (MySQL) ----
cat > "$INSTALL_DIR/server/src/sla.js" <<'JS'
import mysql from "mysql2/promise";
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST || "127.0.0.1",
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASS,
  database: process.env.MYSQL_DB,
  connectionLimit: 4
});

// Configure queue thresholds here
const SLA_RULES = {
  // "001": { answerTargetSec: 60, shortAbandonSec: 6 },
  // "support": { answerTargetSec: 20, shortAbandonSec: 10 },
};

export async function getSLA({ queue, from, to }) {
  const { answerTargetSec, shortAbandonSec } =
    SLA_RULES[queue] || { answerTargetSec: 60, shortAbandonSec: 6 };
  const sql = `
    WITH
    enterq AS (
      SELECT callid FROM queue_log
      WHERE queuename = ? AND event = 'ENTERQUEUE'
        AND time BETWEEN ? AND ?
      GROUP BY callid
    ),
    answered_under AS (
      SELECT ql.callid
      FROM queue_log ql JOIN enterq e USING (callid)
      WHERE ql.queuename = ? AND ql.event = 'CONNECT'
        AND CAST(ql.data1 AS UNSIGNED) <= ?
      GROUP BY ql.callid
    ),
    short_abandons AS (
      SELECT ql.callid
      FROM queue_log ql JOIN enterq e USING (callid)
      WHERE ql.queuename = ? AND ql.event = 'ABANDON'
        AND CAST(ql.data2 AS UNSIGNED) <= ?
      GROUP BY ql.callid
    )
    SELECT
      (SELECT COUNT(*) FROM answered_under) AS answered_under_target,
      (SELECT COUNT(*) FROM enterq) AS inbound_total,
      (SELECT COUNT(*) FROM short_abandons) AS aband_short
  `;
  const params = [queue, from, to, queue, answerTargetSec, queue, shortAbandonSec];
  const [rows] = await pool.query(sql, params);
  const r = rows[0] || { answered_under_target: 0, inbound_total: 0, aband_short: 0 };
  const denom = Math.max(0, r.inbound_total - r.aband_short);
  const sla = denom === 0 ? 0 : r.answered_under_target / denom;
  return { queue, from, to, answerTargetSec, shortAbandonSec,
           answeredUnderTarget: r.answered_under_target,
           inbound: r.inbound_total,
           shortAbandons: r.aband_short,
           sla };
}
JS

cat > "$INSTALL_DIR/server/src/agentStats.js" <<'JS'
import mysql from "mysql2/promise";
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST || "127.0.0.1",
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASS,
  database: process.env.MYSQL_DB,
  connectionLimit: 4
});

export function dayWindow(dateStr) {
  const d = dateStr ? new Date(dateStr) : new Date();
  const y = d.getFullYear(), m = String(d.getMonth()+1).padStart(2,"0"), day = String(d.getDate()).padStart(2,"0");
  const from = `${y}-${m}-${day} 00:00:00`; const to = `${y}-${m}-${day} 23:59:59`;
  return { from, end: to };
}

export async function getAgentToday({ ext, from, to }) {
  const family = (process.env.DEVICE_FAMILY || "SIP").toUpperCase();
  const agentDev = `${family}/${ext}`;

  const [[inb]] = await pool.query(
    "SELECT COUNT(*) AS inbound FROM queue_log WHERE event='CONNECT' AND agent=? AND time BETWEEN ? AND ?",
    [agentDev, from, to]
  );

  const [[att]] = await pool.query(
    "SELECT COALESCE(SUM(CAST(data2 AS UNSIGNED)),0) AS talk FROM queue_log WHERE event IN ('COMPLETEAGENT','COMPLETECALLER') AND agent=? AND time BETWEEN ? AND ?",
    [agentDev, from, to]
  );

  const [[ob]] = await pool.query(
    "SELECT COUNT(*) AS outbound FROM cdr WHERE calldate BETWEEN ? AND ? AND src=? AND disposition='ANSWERED'",
    [from, to, ext]
  );

  return {
    inbound: Number(inb.inbound || 0),
    outbound: Number(ob.outbound || 0),
    att: Number(att.talk || 0),
    availableSec: 0
  };
}
JS

# ---- HTTP app (HTTP-first, routes, WS wire, AMI after listen) ----
cat > "$INSTALL_DIR/server/src/index.js" <<'JS'
import "dotenv/config";
import Fastify from "fastify";
import cors from "@fastify/cors";
import { connectAMI, wireQueueEvents, queueAdd, queueRemove, queuePause, queueStatus } from "./ami.js";
import { buildAuth } from "./auth.js";
import { createWsServer } from "./wsHub.js";
import { DEVICE_TEMPLATE, USER_ACCESS } from "./config.js";
import { getSLA } from "./sla.js";
import { getAgentToday, dayWindow } from "./agentStats.js";

const fastify = Fastify({ logger: true });
await fastify.register(cors, { origin: process.env.ALLOWED_ORIGIN || true, credentials: true });
buildAuth(fastify);

fastify.get("/healthz", async () => ({ ok: true }));

fastify.addHook("preHandler", async (req, rep) => {
  const p = req.routerPath || req.url || "";
  if (p.startsWith("/api/") && p !== "/api/login") await fastify.auth(req, rep);
});

// ACL → queues for this extension
fastify.get("/api/queues", async (req, rep) => {
  const { ext } = req.user || {};
  if (!ext) return rep.code(401).send({ error: "unauthorized" });
  const acl = USER_ACCESS[ext] || { queues: [], ext };
  return acl.queues;
});

// queue actions
fastify.post("/api/queue/login", async (req) => {
  const { queue } = req.body || {};
  const { ext } = req.user; const iface = DEVICE_TEMPLATE(ext);
  await queueAdd({ queue, iface, penalty: 0, paused: false });
  return { ok: true };
});
fastify.post("/api/queue/logout", async (req) => {
  const { queue } = req.body || {};
  const { ext } = req.user; const iface = DEVICE_TEMPLATE(ext);
  await queueRemove({ queue, iface }); return { ok: true };
});
fastify.post("/api/queue/pause", async (req) => {
  const { queue, reason } = req.body || {};
  const { ext } = req.user; const iface = DEVICE_TEMPLATE(ext);
  await queuePause({ queue, iface, paused: true, reason: reason || "Break" });
  return { ok: true };
});
fastify.post("/api/queue/unpause", async (req) => {
  const { queue } = req.body || {};
  const { ext } = req.user; const iface = DEVICE_TEMPLATE(ext);
  await queuePause({ queue, iface, paused: false }); return { ok: true };
});

// members + callers in a queue
fastify.get("/api/queue/members", async (req, rep) => {
  const { queue } = req.query || {};
  if (!queue) return rep.code(400).send({ error: "queue required" });
  return queueStatus(queue);
});

// SLA + agent stats
fastify.get("/api/stats/sla", async (req, rep) => {
  const { queue, from, to } = req.query || {};
  if (!queue || !from || !to) return rep.code(400).send({ error: "queue, from, to required" });
  return getSLA({ queue, from, to });
});
fastify.get("/api/stats/agentToday", async (req) => {
  const { date } = req.query || {};
  const { ext } = req.user; const { from, end } = dayWindow(date);
  return getAgentToday({ ext, from, to: end });
});

async function start() {
  const port = +(process.env.PORT || 8088);
  await fastify.listen({ port, host: "0.0.0.0" });
  console.log("API on :" + port);

  const ws = createWsServer(fastify.server);
  try {
    await connectAMI();
    wireQueueEvents(ws.broadcast);
    try { await queueStatus(); } catch (e) { fastify.log.error({ err: e }, "QueueStatus error"); }
  } catch (e) {
    fastify.log.error({ err: e }, "AMI connect error");
  }
}
start().catch((e) => { console.error(e); process.exit(1); });
JS

chown -R "$APP_USER:$APP_GROUP" "$INSTALL_DIR/server"

# =========================
# Scaffold WEB (vite static SPA)
# =========================
echo "==> Scaffolding web..."
mkdir -p "$INSTALL_DIR/web"

cat > "$INSTALL_DIR/web/package.json" <<'JSON'
{
  "name": "freepbx-agent-ui-web",
  "version": "0.2.0",
  "private": true,
  "scripts": { "dev": "vite", "build": "vite build", "preview": "vite preview" },
  "devDependencies": { "vite": "^5.4.10" }
}
JSON

cat > "$INSTALL_DIR/web/index.html" <<'HTML'
<!doctype html>
<html>
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>FreePBX Agent UI</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 24px; line-height:1.45; }
    .card { border:1px solid #ddd; border-radius:12px; padding:16px; margin:12px 0; }
    button { padding:8px 12px; border-radius:8px; border:1px solid #999; background:#fff; cursor:pointer; }
    input { padding:8px; border:1px solid #ccc; border-radius:8px; }
    code { background:#f7f7f7; padding:2px 6px; border-radius:6px; }
  </style>
</head>
<body>
  <h1>FreePBX Agent UI</h1>
  <div class="card">
    API health: <code id="health">checking...</code>
  </div>

  <div class="card">
    <div>
      <label>Extension:</label>
      <input id="ext" placeholder="1010" />
      <button onclick="login()">Get Token</button>
      <code id="tok"></code>
    </div>
  </div>

  <div class="card">
    <div>
      <label>Queue:</label>
      <input id="qname" placeholder="001" />
      <button onclick="fetchQueues()">My Queues</button>
      <button onclick="joinQ()">Login</button>
      <button onclick="pauseQ()">Pause</button>
      <button onclick="unpauseQ()">Unpause</button>
      <button onclick="leaveQ()">Logout</button>
    </div>
    <pre id="out"></pre>
  </div>

  <div class="card">
    <div>
      <label>Members of queue:</label>
      <input id="qmem" placeholder="001" />
      <button onclick="members()">Refresh</button>
    </div>
    <pre id="members"></pre>
  </div>

  <script>
    const api = (p) => '/api' + p;
    let token = '';
    fetch(api('/queues')).then(r=>{document.getElementById('health').textContent = r.status===401?'API OK':'API '+r.status}).catch(()=>document.getElementById('health').textContent='API down');

    function auth(){ return token ? { 'Authorization':'Bearer '+token } : {}; }
    function login(){
      const ext = document.getElementById('ext').value.trim();
      fetch(api('/login'), {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ext})})
        .then(r=>r.json()).then(j=>{ token=j.token||''; document.getElementById('tok').textContent = token? token.slice(0,24)+'…':''; });
    }
    function fetchQueues(){
      fetch(api('/queues'), {headers:auth()}).then(r=>r.json()).then(j=>{ document.getElementById('out').textContent = JSON.stringify(j,null,2); });
    }
    function joinQ(){
      const queue = document.getElementById('qname').value.trim();
      fetch(api('/queue/login'), {method:'POST', headers:{'Content-Type':'application/json',...auth()}, body:JSON.stringify({queue})}).then(r=>r.json()).then(j=>alert(JSON.stringify(j)));
    }
    function pauseQ(){
      const queue = document.getElementById('qname').value.trim();
      fetch(api('/queue/pause'), {method:'POST', headers:{'Content-Type':'application/json',...auth()}, body:JSON.stringify({queue,reason:'Break'})}).then(r=>r.json()).then(j=>alert(JSON.stringify(j)));
    }
    function unpauseQ(){
      const queue = document.getElementById('qname').value.trim();
      fetch(api('/queue/unpause'), {method:'POST', headers:{'Content-Type':'application/json',...auth()}, body:JSON.stringify({queue})}).then(r=>r.json()).then(j=>alert(JSON.stringify(j)));
    }
    function leaveQ(){
      const queue = document.getElementById('qname').value.trim();
      fetch(api('/queue/logout'), {method:'POST', headers:{'Content-Type':'application/json',...auth()}, body:JSON.stringify({queue})}).then(r=>r.json()).then(j=>alert(JSON.stringify(j)));
    }
    function members(){
      const queue = document.getElementById('qmem').value.trim();
      fetch(api('/queue/members?queue='+encodeURIComponent(queue)), {headers:auth()})
        .then(r=>r.json()).then(j=>{ document.getElementById('members').textContent = JSON.stringify(j,null,2); });
    }
  </script>
</body>
</html>
HTML

chown -R "$APP_USER:$APP_GROUP" "$INSTALL_DIR/web"

# =========================
# Install deps + build
# =========================
echo "==> Installing dependencies & building..."
su -s /bin/bash -c "cd '$INSTALL_DIR/server' && npm config set registry https://registry.npmjs.org/ && rm -rf node_modules package-lock.json && npm install --omit=dev" "$APP_USER"
su -s /bin/bash -c "cd '$INSTALL_DIR/web' && npm install && npm run build" "$APP_USER"

# =========================
# Create .env by prompting
# =========================
echo "==> Creating .env ..."
PORT=$(prompt "API port" "8088")
ALLOWED_ORIGIN=$(prompt "Allowed CORS origin (* or http://host)" "*")
JWT_SECRET=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 28)

AMI_HOST=$(prompt "FreePBX AMI host/IP" "127.0.0.1")
AMI_PORT=$(prompt "FreePBX AMI port" "5038")
AMI_USER=$(prompt "FreePBX AMI username" "ui_agent_app")
AMI_PASS=$(prompt "FreePBX AMI password" "")
[ -n "$AMI_PASS" ] || { echo "AMI password cannot be empty"; exit 1; }

DEVICE_FAMILY=$(prompt "Device family (SIP or PJSIP)" "SIP")

MYSQL_HOST=$(prompt "MySQL host (PBX)" "127.0.0.1")
MYSQL_PORT=$(prompt "MySQL port" "3306")
MYSQL_USER=$(prompt "MySQL user (RO)" "report_ro")
MYSQL_PASS=$(prompt "MySQL password" "")
[ -n "$MYSQL_PASS" ] || { echo "MySQL password cannot be empty"; exit 1; }
MYSQL_DB=$(prompt "MySQL database" "asteriskcdrdb")

TZV=$(prompt "Timezone (IANA)" "America/New_York")

cat >"$INSTALL_DIR/server/.env" <<ENV
PORT=$PORT
JWT_SECRET=$JWT_SECRET
ALLOWED_ORIGIN=$ALLOWED_ORIGIN

AMI_HOST=$AMI_HOST
AMI_PORT=$AMI_PORT
AMI_USER=$AMI_USER
AMI_PASS=$AMI_PASS
DEVICE_FAMILY=$DEVICE_FAMILY

MYSQL_HOST=$MYSQL_HOST
MYSQL_PORT=$MYSQL_PORT
MYSQL_USER=$MYSQL_USER
MYSQL_PASS=$MYSQL_PASS
MYSQL_DB=$MYSQL_DB

TZ=$TZV
ENV
chown "$APP_USER:$APP_GROUP" "$INSTALL_DIR/server/.env"
chmod 640 "$INSTALL_DIR/server/.env"

# =========================
# systemd service
# =========================
echo "==> Installing systemd service..."
cat >/etc/systemd/system/${SERVICE_NAME}.service <<SVC
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

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"

# =========================
# Nginx site
# =========================
if yn "Install and configure Nginx to serve the web UI and proxy /api & /ws?" "Y"; then
  apt-get install -y nginx
  rm -rf "$WEBROOT"
  mkdir -p "$WEBROOT"
  cp -r "$INSTALL_DIR/web/dist/"* "$WEBROOT/"
  chown -R www-data:www-data "$WEBROOT"

  cat >/etc/nginx/sites-available/freepbx-agent-ui.conf <<NG
server {
    listen 80;
    server_name _;

    root ${WEBROOT};
    index index.html;

    location / { try_files \$uri /index.html; }

    location /api/ {
        proxy_pass http://127.0.0.1:${PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location /ws {
        proxy_pass http://127.0.0.1:${PORT}/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }
}
NG

  ln -sf /etc/nginx/sites-available/freepbx-agent-ui.conf /etc/nginx/sites-enabled/freepbx-agent-ui.conf
  rm -f /etc/nginx/sites-enabled/default
  nginx -t && systemctl reload nginx
fi

echo
echo "==> Sanity checks:"
echo "  Health: curl -s http://127.0.0.1:${PORT}/healthz"
echo "  Queues (401 expected w/o token): curl -i http://127.0.0.1:${PORT}/api/queues"
echo "  Service: systemctl status ${SERVICE_NAME} --no-pager"
echo
echo "Next steps:"
echo "  1) Edit ${INSTALL_DIR}/server/src/config.js and add USER_ACCESS mappings."
echo "  2) (PBX) Ensure AMI permits the UI VM IP and bindaddr=0.0.0.0 (or use an SSH tunnel)."
echo "  3) (PBX DB) Grant SELECT on asteriskcdrdb to ${MYSQL_USER}@<UI_VM_IP>."
echo
echo "Done."
