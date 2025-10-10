#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# FreePBX Agent UI (FOP2-lite) — Interactive Installer
# Target: Debian/Ubuntu (apt based). Should also work on most systemd distros.
# This script:
#  - Prompts for AMI/MySQL/JWT/app settings
#  - Lays down Node.js app (server + React web) from templates
#  - Installs Node.js (Node 20 LTS via NodeSource) and builds everything
#  - Creates a systemd service for the API (WebSocket included)
#  - Optionally installs Nginx reverse proxy for web + /api + /ws
# ==============================================================================

red()   { printf "\033[31m%s\033[0m\n" "$*"; }
green() { printf "\033[32m%s\033[0m\n" "$*"; }
yellow(){ printf "\033[33m%s\033[0m\n" "$*"; }
cyan()  { printf "\033[36m%s\033[0m\n" "$*"; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    red "Please run as root (sudo)."
    exit 1
  fi
}

detect_distro() {
  if command -v apt >/dev/null 2>&1; then
    PKG=apt
  elif command -v dnf >/dev/null 2>&1; then
    PKG=dnf
  elif command -v yum >/dev/null 2>&1; then
    PKG=yum
  else
    red "Unsupported distro: need apt, dnf or yum."
    exit 1
  fi
}

ask() {
  local prompt default var
  prompt="$1"; default="${2:-}"; var=""
  if [[ -n "$default" ]]; then
    read -r -p "$prompt [$default]: " var || true
    echo "${var:-$default}"
  else
    while true; do
      read -r -p "$prompt: " var || true
      [[ -n "$var" ]] && { echo "$var"; return; }
      echo "Value required."
    done
  fi
}

ask_secret() {
  local prompt var
  prompt="$1"
  while true; do
    read -r -s -p "$prompt: " var || true
    echo
    [[ -n "$var" ]] && { echo "$var"; return; }
    echo "Value required."
  done
}

confirm() {
  local prompt="$1"
  read -r -p "$prompt [y/N]: " yn || true
  [[ "$yn" =~ ^[Yy]$ ]]
}

# ---------- Prereqs ----------
need_root
detect_distro

cyan "==> Installing prerequisites..."
if [[ "$PKG" == "apt" ]]; then
  apt update -y
  apt install -y curl git build-essential ca-certificates
elif [[ "$PKG" == "dnf" ]]; then
  dnf install -y curl git @development-tools ca-certificates
else
  yum install -y curl git @development-tools ca-certificates
fi

# ---------- Gather config ----------
cyan "==> Answer a few questions to configure the app."

INSTALL_DIR=$(ask "Install directory" "/opt/freepbx-agent-ui")
APP_USER=$(ask "Run-as system user" "freepbxui")
APP_GROUP="$APP_USER"

APP_PORT=$(ask "API port (Node server)" "8088")
ALLOWED_ORIGIN=$(ask "Allowed web origin (for CORS; e.g., http://ui.example.com or http://localhost:5173)" "http://localhost:5173")
JWT_SECRET=$(ask_secret "JWT secret (for issuing/validating tokens)")
SERVER_TZ=$(ask "Server timezone (for queries)" "America/New_York")

AMI_HOST=$(ask "Asterisk AMI host/IP" "127.0.0.1")
AMI_PORT=$(ask "Asterisk AMI port" "5038")
AMI_USER=$(ask "Asterisk AMI username" "ui_agent_app")
AMI_PASS=$(ask_secret "Asterisk AMI password")

MYSQL_HOST=$(ask "MySQL host" "127.0.0.1")
MYSQL_PORT=$(ask "MySQL port" "3306")
MYSQL_DB=$(ask "MySQL database (FreePBX CDR/QXact)" "asteriskcdrdb")
MYSQL_USER=$(ask "MySQL read-only user" "report_ro")
MYSQL_PASS=$(ask_secret "MySQL read-only password")

DEVICE_TEMPLATE=$(ask "Member interface template (use {ext} placeholder)" "PJSIP/{ext}")

cyan "==> Configure per-queue SLA rules"
read -r -p "How many queues to configure? [2]: " QN || true
QN="${QN:-2}"

QUEUE_JSON="{"$'\n'
for ((i=1;i<=QN;i++)); do
  qname=$(ask "  Queue #$i name (e.g., support_main)")
  thr=$(ask "    Answer threshold seconds (e.g., 60 or 20)" "60")
  abx=$(ask "    Abandon exempt seconds (e.g., 6 or 10)" "6")
  QUEUE_JSON+="  \"${qname}\": { \"thresholdSecs\": ${thr}, \"abandonExemptSecs\": ${abx} }"
  if [[ $i -lt $QN ]]; then QUEUE_JSON+=","$'\n'; else QUEUE_JSON+=$'\n'; fi
done
QUEUE_JSON+="}"

INSTALL_NGINX=false
if confirm "Install and configure Nginx reverse proxy (serve web + proxy /api and /ws)?"; then
  INSTALL_NGINX=true
  NGINX_SERVER_NAME=$(ask "  Public hostname for UI (server_name)" "agent-ui.local")
  NGINX_LISTEN_PORT=$(ask "  Nginx HTTP listen port" "80")
  PUBLIC_SCHEME=$(ask "  Public scheme for VITE_API (http/https)" "http")
  PUBLIC_PORT=$(ask "  Public port for VITE_API" "$NGINX_LISTEN_PORT")
  VITE_API="${PUBLIC_SCHEME}://${NGINX_SERVER_NAME}"
  if [[ "$PUBLIC_PORT" != "80" && "$PUBLIC_PORT" != "443" ]]; then
    VITE_API="${VITE_API}:${PUBLIC_PORT}"
  fi
  VITE_API+="/api"
else
  VITE_API="http://localhost:${APP_PORT}"
fi

# ---------- Create user & directories ----------
cyan "==> Creating user and directories..."
id -u "$APP_USER" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$APP_USER"
mkdir -p "$INSTALL_DIR"
chown -R "$APP_USER:$APP_GROUP" "$INSTALL_DIR"

# ---------- Install Node.js 20 LTS ----------
cyan "==> Installing Node.js 20 LTS..."
if [[ "$PKG" == "apt" ]]; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt install -y nodejs
elif [[ "$PKG" == "dnf" ]]; then
  curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -
  dnf install -y nodejs
else
  curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -
  yum install -y nodejs
fi

# ---------- Scaffold project ----------
cyan "==> Scaffolding project files..."
mkdir -p "$INSTALL_DIR/server/src" "$INSTALL_DIR/web/src/components"

# server/package.json
cat > "$INSTALL_DIR/server/package.json" <<'JSON'
{
  "name": "freepbx-agent-ui-server",
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "node --watch src/index.js",
    "start": "node src/index.js"
  },
  "dependencies": {
    "asterisk-ami-client": "^0.5.2",
    "dotenv": "^16.4.5",
    "fastify": "^4.28.1",
    "fastify-cors": "^8.4.2",
    "fastify-jwt": "^6.7.1",
    "mysql2": "^3.10.2",
    "ws": "^8.18.0"
  }
}
JSON

# server/.env
cat > "$INSTALL_DIR/server/.env" <<ENV
PORT=${APP_PORT}
JWT_SECRET=${JWT_SECRET}
ALLOWED_ORIGIN=${ALLOWED_ORIGIN}

AMI_HOST=${AMI_HOST}
AMI_PORT=${AMI_PORT}
AMI_USER=${AMI_USER}
AMI_PASS=${AMI_PASS}

MYSQL_HOST=${MYSQL_HOST}
MYSQL_PORT=${MYSQL_PORT}
MYSQL_USER=${MYSQL_USER}
MYSQL_PASS=${MYSQL_PASS}
MYSQL_DB=${MYSQL_DB}

TZ=${SERVER_TZ}
ENV

# server/src/config.js
cat > "$INSTALL_DIR/server/src/config.js" <<CFG
export const DEVICE_TEMPLATE = (ext) => \`${DEVICE_TEMPLATE}\`.replace('{ext}', ext);

export const QUEUE_RULES = ${QUEUE_JSON};

// MVP user access: allow any ext to see all queues; tighten later or replace with DB/UserMan.
export const USER_ACCESS = new Proxy({}, {
  get: (_, ext) => ({ queues: Object.keys(QUEUE_RULES), ext })
});
CFG

# server/src/db.js
cat > "$INSTALL_DIR/server/src/db.js" <<'JS'
import mysql from 'mysql2/promise';

let pool;
export function getPool() {
  if (!pool) {
    pool = mysql.createPool({
      host: process.env.MYSQL_HOST,
      port: +process.env.MYSQL_PORT,
      user: process.env.MYSQL_USER,
      password: process.env.MYSQL_PASS,
      database: process.env.MYSQL_DB,
      connectionLimit: 10,
      timezone: 'Z'
    });
  }
  return pool;
}
JS

# server/src/ami.js
cat > "$INSTALL_DIR/server/src/ami.js" <<'JS'
import AsteriskAmi from 'asterisk-ami-client';

const client = new AsteriskAmi({ reconnect: true, keepAlive: true });
let connected = false;

export async function connectAMI() {
  if (connected) return client;
  await client.connect(process.env.AMI_USER, process.env.AMI_PASS, {
    host: process.env.AMI_HOST,
    port: +process.env.AMI_PORT,
    keepAlive: true
  });
  connected = true;
  return client;
}

export function onAMI(event, handler) {
  client.on(event, handler);
}

export async function queueAdd({ queue, iface, penalty = 0, paused = false }) {
  return client.action({ action: 'QueueAdd', queue, interface: iface, penalty, paused });
}
export async function queueRemove({ queue, iface }) {
  return client.action({ action: 'QueueRemove', queue, interface: iface });
}
export async function queuePause({ queue, iface, paused, reason }) {
  return client.action({ action: 'QueuePause', queue, interface: iface, paused, reason });
}
export async function queueStatus() {
  return client.action({ action: 'QueueStatus' });
}

export const state = {
  queues: new Map(),
};

function ensureQueue(name) {
  if (!state.queues.has(name)) state.queues.set(name, { entries: new Map(), members: new Map() });
  return state.queues.get(name);
}

export function wireQueueEvents(broadcast) {
  client.on('event', (e) => {
    const type = e.Event;
    if (!type) return;

    if (type === 'QueueParams') {
      ensureQueue(e.Queue);
    }
    if (type === 'QueueEntry') {
      const q = ensureQueue(e.Queue);
      q.entries.set(e.Uniqueid || `${e.Position}-${e.CallerIDNum}`, {
        callerid: e.CallerIDNum,
        position: +e.Position,
        wait: +e.Wait,
        queue: e.Queue
      });
      broadcast({ t: 'queue_entry', data: { queue: e.Queue } });
    }
    if (type === 'QueueEntryRemove' || type === 'QueueCallerAbandon') {
      const q = ensureQueue(e.Queue);
      q.entries.delete(e.Uniqueid || `${e.Position}-${e.CallerIDNum}`);
      broadcast({ t: 'queue_entry', data: { queue: e.Queue } });
    }
    if (type === 'QueueMember' || type === 'QueueMemberAdded' || type === 'QueueMemberRemoved') {
      const q = ensureQueue(e.Queue);
      if (type === 'QueueMemberRemoved') {
        q.members.delete(e.Interface);
      } else {
        q.members.set(e.Interface, {
          iface: e.Interface,
          status: e.Status,
          paused: e.Paused === '1',
          name: e.MemberName,
          penalty: e.Penalty
        });
      }
      broadcast({ t: 'queue_member', data: { queue: e.Queue } });
    }
  });
}
JS

# server/src/sla.js
cat > "$INSTALL_DIR/server/src/sla.js" <<'JS'
import { getPool } from './db.js';
import { QUEUE_RULES } from './config.js';

// SLA = answered_under_threshold / (total_inbound - abandoned_within_exempt)
export async function getSLA({ queue, from, to }) {
  const rule = QUEUE_RULES[queue];
  if (!rule) throw new Error(`No SLA rule configured for queue ${queue}`);
  const { thresholdSecs, abandonExemptSecs } = rule;
  const pool = getPool();

  // Adjust table/column names to your Q-Xact schema if needed
  const [rows] = await pool.query(
    `WITH calls AS (
       SELECT queue,
              enqueued_time,
              answered_time,
              (answered_time IS NOT NULL) AS answered,
              (abandoned = 1) AS abandoned,
              TIMESTAMPDIFF(SECOND, enqueued_time, answered_time) AS answer_secs,
              TIMESTAMPDIFF(SECOND, enqueued_time, COALESCE(answered_time, NOW())) AS wait_secs
       FROM qxact_calls
       WHERE queue = ? AND enqueued_time >= ? AND enqueued_time < ?
     )
     SELECT
       COUNT(*) AS total_inbound,
       SUM(answered) AS answered_total,
       SUM(CASE WHEN answered = 1 AND answer_secs <= ? THEN 1 ELSE 0 END) AS answered_under_threshold,
       SUM(CASE WHEN abandoned = 1 AND wait_secs <= ? THEN 1 ELSE 0 END) AS abandoned_within_exempt
     FROM calls`,
    [queue, from, to, thresholdSecs, abandonExemptSecs]
  );

  const r = rows[0] || { total_inbound: 0, answered_total: 0, answered_under_threshold: 0, abandoned_within_exempt: 0 };
  const denom = Math.max(0, (r.total_inbound || 0) - (r.abandoned_within_exempt || 0));
  const sla = denom === 0 ? null : Number(((r.answered_under_threshold || 0) * 100 / denom).toFixed(2));

  return { queue, from, to, thresholdSecs, abandonExemptSecs, ...r, sla_pct: sla };
}
JS

# server/src/agentStats.js
cat > "$INSTALL_DIR/server/src/agentStats.js" <<'JS'
import { getPool } from './db.js';

export function dayWindow(dateStr) {
  const d = dateStr ? new Date(dateStr) : new Date();
  const start = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const end = new Date(start.getTime() + 24*3600*1000);
  return { from: start.toISOString().slice(0,19).replace('T',' '), end: end.toISOString().slice(0,19).replace('T',' ') };
}

export async function getAgentToday({ ext, from, to }) {
  const pool = getPool();

  // NOTE: You may want to refine inbound detection depending on dialplan
  const [cdr] = await pool.query(
    `SELECT 
       SUM(CASE WHEN dcontext LIKE 'from-internal%' THEN (disposition='ANSWERED') ELSE 0 END) AS outbound_answered,
       SUM(CASE WHEN dcontext NOT LIKE 'from-internal%' AND dstchannel LIKE ? AND disposition='ANSWERED' THEN 1 ELSE 0 END) AS inbound_answered,
       AVG(CASE WHEN dstchannel LIKE ? AND disposition='ANSWERED' THEN billsec END) AS att_secs
     FROM cdr
     WHERE calldate >= ? AND calldate < ? AND (src = ? OR dstchannel LIKE ?)`,
    [`%/${ext}%`, `%/${ext}%`, from, to, ext, `%/${ext}%`]
  );

  const [actions] = await pool.query(
    `SELECT action, ts
       FROM qxact_agent_actions
      WHERE agent = ? AND ts >= ? AND ts < ?
      ORDER BY ts ASC`,
    [ext, from, to]
  );

  let loggedIn = false, paused = false, lastTs = new Date(from), acc = 0;
  for (const a of actions) {
    const t = new Date(a.ts);
    if (loggedIn && !paused) acc += Math.max(0, (t - lastTs) / 1000);
    if (a.action === 'LOGIN') loggedIn = true;
    if (a.action === 'LOGOUT') loggedIn = false;
    if (a.action === 'PAUSE') paused = true;
    if (a.action === 'UNPAUSE') paused = false;
    lastTs = t;
  }
  const endTs = new Date(to);
  if (loggedIn && !paused) acc += Math.max(0, (endTs - lastTs) / 1000);

  const row = cdr[0] || {};
  return {
    ext,
    from,
    to,
    outbound_answered: Number(row.outbound_answered || 0),
    inbound_answered: Number(row.inbound_answered || 0),
    att_secs: row.att_secs ? Math.round(row.att_secs) : 0,
    available_secs: Math.round(acc)
  };
}
JS

# server/src/auth.js
cat > "$INSTALL_DIR/server/src/auth.js" <<'JS'
export function buildAuth(fastify) {
  fastify.register(import('fastify-jwt'), { secret: process.env.JWT_SECRET });

  fastify.decorate('auth', async (request, reply) => {
    try {
      await request.jwtVerify();
    } catch (err) {
      return reply.code(401).send({ error: 'unauthorized' });
    }
  });

  // MVP: login by extension only (swap for FreePBX userman/LDAP later)
  fastify.post('/api/login', async (req, reply) => {
    const { ext } = req.body || {};
    if (!ext) return reply.code(400).send({ error: 'ext required' });
    const token = fastify.jwt.sign({ sub: ext, ext });
    return { token };
  });
}
JS

# server/src/wsHub.js
cat > "$INSTALL_DIR/server/src/wsHub.js" <<'JS'
import { WebSocketServer } from 'ws';
import { state } from './ami.js';

export function createWsServer(server) {
  const wss = new WebSocketServer({ server, path: '/ws' });

  function snapshot() {
    const out = {};
    for (const [qName, q] of state.queues.entries()) {
      out[qName] = {
        entries: Array.from(q.entries.values()),
        members: Array.from(q.members.values()),
      };
    }
    return out;
  }

  function broadcast(msg) {
    const data = JSON.stringify(msg);
    for (const c of wss.clients) if (c.readyState === 1) c.send(data);
  }

  wss.on('connection', (ws) => {
    ws.send(JSON.stringify({ t: 'snapshot', data: snapshot() }));
    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw.toString());
        if (msg.t === 'resync') {
          ws.send(JSON.stringify({ t: 'snapshot', data: snapshot() }));
        }
      } catch { /* ignore */ }
    });
  });

  return { broadcast };
}
JS

# server/src/index.js
cat > "$INSTALL_DIR/server/src/index.js" <<'JS'
import 'dotenv/config';
import Fastify from 'fastify';
import cors from 'fastify-cors';
import { connectAMI, wireQueueEvents, queueAdd, queueRemove, queuePause, queueStatus } from './ami.js';
import { buildAuth } from './auth.js';
import { createServer } from 'http';
import { createWsServer } from './wsHub.js';
import { DEVICE_TEMPLATE, USER_ACCESS } from './config.js';
import { getSLA } from './sla.js';
import { getAgentToday, dayWindow } from './agentStats.js';

const fastify = Fastify({ logger: true });
fastify.register(cors, { origin: process.env.ALLOWED_ORIGIN || true, credentials: true });
buildAuth(fastify);

fastify.addHook('preHandler', async (req, reply) => {
  if (req.routerPath?.startsWith('/api/') && req.routerPath !== '/api/login') {
    await fastify.auth(req, reply);
  }
});

fastify.get('/api/queues', async (req, reply) => {
  const { ext } = req.user;
  const acl = USER_ACCESS[ext] || { queues: [], ext };
  return acl.queues;
});

fastify.post('/api/queue/login', async (req, reply) => {
  const { queue } = req.body;
  const { ext } = req.user;
  const iface = DEVICE_TEMPLATE(ext);
  await queueAdd({ queue, iface, penalty: 0, paused: false });
  return { ok: true };
});

fastify.post('/api/queue/logout', async (req, reply) => {
  const { queue } = req.body;
  const { ext } = req.user;
  const iface = DEVICE_TEMPLATE(ext);
  await queueRemove({ queue, iface });
  return { ok: true };
});

fastify.post('/api/queue/pause', async (req, reply) => {
  const { queue, reason } = req.body;
  const { ext } = req.user;
  const iface = DEVICE_TEMPLATE(ext);
  await queuePause({ queue, iface, paused: true, reason: reason || 'Break' });
  return { ok: true };
});

fastify.post('/api/queue/unpause', async (req, reply) => {
  const { queue } = req.body;
  const { ext } = req.user;
  const iface = DEVICE_TEMPLATE(ext);
  await queuePause({ queue, iface, paused: false });
  return { ok: true };
});

fastify.get('/api/stats/sla', async (req, reply) => {
  const { queue, from, to } = req.query;
  if (!queue || !from || !to) return reply.code(400).send({ error: 'queue, from, to required' });
  return getSLA({ queue, from, to });
});

fastify.get('/api/stats/agentToday', async (req, reply) => {
  const { date } = req.query;
  const { ext } = req.user;
  const { from, end } = dayWindow(date);
  return getAgentToday({ ext, from, to: end });
});

const httpServer = createServer(fastify);
const ws = createWsServer(httpServer);

async function start() {
  await connectAMI();
  wireQueueEvents(ws.broadcast);
  await queueStatus();
  const port = +process.env.PORT || 8088;
  httpServer.listen(port, '0.0.0.0', () => console.log(`API+WS on :${port}`));
}

start().catch((e) => {
  console.error(e);
  process.exit(1);
});
JS

# web/package.json
cat > "$INSTALL_DIR/web/package.json" <<'JSON'
{
  "name": "freepbx-agent-ui-web",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.3.1",
    "vite": "^5.4.8"
  }
}
JSON

# web/vite.config.js
cat > "$INSTALL_DIR/web/vite.config.js" <<'JS'
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({
  plugins: [react()],
  server: { port: 5173 }
});
JS

# web/.env (for Vite)
cat > "$INSTALL_DIR/web/.env" <<ENV
VITE_API=${VITE_API}
ENV

# web/src files
cat > "$INSTALL_DIR/web/index.html" <<'HTML'
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Agent UI</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
  </body>
</html>
HTML

cat > "$INSTALL_DIR/web/src/api.js" <<'JS'
const API = import.meta.env.VITE_API || 'http://localhost:8088';
let token = localStorage.getItem('token') || '';
export function setToken(t){ token=t; localStorage.setItem('token', t); }

async function req(path, opts={}){
  const headers = { 'Content-Type': 'application/json', ...(token?{Authorization:`Bearer ${token}`}:{}) };
  const res = await fetch(`${API}${path}`, { ...opts, headers });
  if(!res.ok) throw new Error(await res.text());
  return res.json();
}

export const api = {
  login: (ext)=> req('/api/login', { method:'POST', body: JSON.stringify({ ext }) }),
  myQueues: ()=> req('/api/queues'),
  qLogin: (queue)=> req('/api/queue/login', { method:'POST', body: JSON.stringify({ queue }) }),
  qLogout: (queue)=> req('/api/queue/logout', { method:'POST', body: JSON.stringify({ queue }) }),
  qPause: (queue, reason)=> req('/api/queue/pause', { method:'POST', body: JSON.stringify({ queue, reason }) }),
  qUnpause: (queue)=> req('/api/queue/unpause', { method:'POST', body: JSON.stringify({ queue }) }),
  sla: (queue, from, to)=> req(`/api/stats/sla?queue=${encodeURIComponent(queue)}&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`),
  agentToday: (date)=> req(`/api/stats/agentToday?date=${encodeURIComponent(date||'')}`)
};

export function wsURL(){ return `${API.replace('http','ws').replace('/api','')}/ws`; }
JS

cat > "$INSTALL_DIR/web/src/useWS.js" <<'JS'
import { useEffect, useRef, useState } from 'react';
import { wsURL } from './api';
export function useWS(){
  const wsRef = useRef();
  const [snapshot, setSnapshot] = useState({});
  useEffect(()=>{
    wsRef.current = new WebSocket(wsURL());
    wsRef.current.onmessage = (ev)=>{
      const msg = JSON.parse(ev.data);
      if(msg.t==='snapshot') setSnapshot(msg.data);
      if(msg.t==='queue_entry' || msg.t==='queue_member'){
        wsRef.current.send?.(JSON.stringify({t:'resync'}));
      }
    };
    return ()=> wsRef.current?.close();
  },[]);
  return snapshot;
}
JS

cat > "$INSTALL_DIR/web/src/components/LoginBar.jsx" <<'JSX'
import { useState } from 'react';
import { api, setToken } from '../api';

export default function LoginBar(){
  const [ext, setExt] = useState(localStorage.getItem('ext')||'');
  const [ok, setOk] = useState(!!localStorage.getItem('token'));
  async function doLogin(){
    const { token } = await api.login(ext);
    setToken(token); localStorage.setItem('ext', ext); setOk(true);
  }
  if(ok) return <div>Logged in as <b>{ext}</b></div>;
  return (
    <div style={{display:'flex', gap:8}}>
      <input value={ext} onChange={e=>setExt(e.target.value)} placeholder="Extension" />
      <button onClick={doLogin}>Login</button>
    </div>
  );
}
JSX

cat > "$INSTALL_DIR/web/src/components/QueueCard.jsx" <<'JSX'
import { useState } from 'react';
import { api } from '../api';

export default function QueueCard({ name, snapshot }){
  const [busy, setBusy] = useState(false);
  const entries = snapshot?.[name]?.entries || [];
  async function act(fn){ setBusy(true); try { await fn(); } finally { setBusy(false); } }
  return (
    <div style={{border:'1px solid #ddd', borderRadius:8, padding:12, marginBottom:12}}>
      <div style={{display:'flex', justifyContent:'space-between', alignItems:'center'}}>
        <h3 style={{margin:0}}>{name}</h3>
        <div style={{display:'flex', gap:8}}>
          <button disabled={busy} onClick={()=>act(()=>api.qLogin(name))}>Login</button>
          <button disabled={busy} onClick={()=>act(()=>api.qLogout(name))}>Logout</button>
          <button disabled={busy} onClick={()=>act(()=>api.qPause(name,'Break'))}>Pause</button>
          <button disabled={busy} onClick={()=>act(()=>api.qUnpause(name))}>Unpause</button>
        </div>
      </div>
      <div style={{marginTop:8, fontSize:12, opacity:0.7}}>Calls waiting: {entries.length}</div>
      <table style={{width:'100%', marginTop:8}}>
        <thead><tr><th align="left">CallerID</th><th align="right">Pos</th><th align="right">Wait (s)</th></tr></thead>
        <tbody>
          {entries.sort((a,b)=>a.position-b.position).map((e,i)=> (
            <tr key={i}><td>{e.callerid}</td><td align="right">{e.position}</td><td align="right">{e.wait}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
JSX

cat > "$INSTALL_DIR/web/src/components/MyStats.jsx" <<'JSX'
import { useEffect, useState } from 'react';
import { api } from '../api';

function fmtSec(s){
  const h=Math.floor(s/3600), m=Math.floor((s%3600)/60), ss=Math.floor(s%60);
  return [h,m,ss].map(x=>String(x).padStart(2,'0')).join(':');
}

export default function MyStats({ queues }){
  const [today, setToday] = useState(null);
  const [sla, setSla] = useState({});
  const [from, setFrom] = useState(new Date(new Date().setHours(0,0,0,0)).toISOString().slice(0,19).replace('T',' '));
  const [to, setTo] = useState(new Date(new Date().setHours(24,0,0,0)).toISOString().slice(0,19).replace('T',' '));

  useEffect(()=>{ api.agentToday().then(setToday); },[]);
  useEffect(()=>{
    (async()=>{
      const out={};
      for(const q of queues){ out[q]= await api.sla(q, from, to); }
      setSla(out);
    })();
  },[queues, from, to]);

  if(!today) return null;
  return (
    <div style={{border:'1px solid #ddd', borderRadius:8, padding:12}}>
      <h3 style={{marginTop:0}}>Today</h3>
      <div>Inbound Answered: <b>{today.inbound_answered}</b></div>
      <div>Outbound Answered: <b>{today.outbound_answered}</b></div>
      <div>Avg Talk Time (ATT): <b>{today.att_secs}s</b></div>
      <div>Available: <b>{fmtSec(today.available_secs)}</b></div>

      <h4>Queue SLA</h4>
      <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fit,minmax(220px,1fr))', gap:12}}>
        {queues.map(q=> (
          <div key={q} style={{background:'#fafafa', border:'1px solid #eee', borderRadius:8, padding:8}}>
            <div><b>{q}</b></div>
            <div>SLA: <b>{sla[q]?.sla_pct ?? '—'}%</b></div>
            <div>Answered ≤{sla[q]?.thresholdSecs}s: {sla[q]?.answered_under_threshold}</div>
            <div>Inbound: {sla[q]?.total_inbound}</div>
            <div>Abandoned ≤{sla[q]?.abandonExemptSecs}s (excluded): {sla[q]?.abandoned_within_exempt}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
JSX

cat > "$INSTALL_DIR/web/src/App.jsx" <<'JSX'
import { useEffect, useState } from 'react';
import LoginBar from './components/LoginBar';
import QueueCard from './components/QueueCard';
import MyStats from './components/MyStats';
import { api } from './api';
import { useWS } from './useWS';

export default function App(){
  const [queues, setQueues] = useState([]);
  const snapshot = useWS();
  useEffect(()=>{ api.myQueues().then(setQueues).catch(()=>{}); },[]);
  return (
    <div style={{maxWidth:1000, margin:'24px auto', padding:'0 16px'}}>
      <h2>Agent Controls</h2>
      <LoginBar/>
      <div style={{display:'grid', gridTemplateColumns:'1fr', gap:12, marginTop:12}}>
        {queues.map(q=> <QueueCard key={q} name={q} snapshot={snapshot}/>) }
      </div>
      <div style={{marginTop:16}}>
        <MyStats queues={queues}/>
      </div>
    </div>
  );
}
JSX

cat > "$INSTALL_DIR/web/src/main.jsx" <<'JSX'
import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
createRoot(document.getElementById('root')).render(<App/>);
JSX

# ---------- Install dependencies & build ----------
cyan "==> Installing Node dependencies & building..."
cd "$INSTALL_DIR/server"
sudo -u "$APP_USER" npm install --omit=dev

cd "$INSTALL_DIR/web"
sudo -u "$APP_USER" npm install
sudo -u "$APP_USER" npm run build

# Optionally serve the built web with Nginx (recommended)
if $INSTALL_NGINX; then
  cyan "==> Installing & configuring Nginx..."
  if [[ "$PKG" == "apt" ]]; then
    apt install -y nginx
  elif [[ "$PKG" == "dnf" ]]; then
    dnf install -y nginx
    systemctl enable nginx
    systemctl start nginx
  else
    yum install -y nginx
    systemctl enable nginx
    systemctl start nginx
  fi

  # Create a static site root
  WEBROOT="/var/www/freepbx-agent-ui"
  rm -rf "$WEBROOT"
  mkdir -p "$WEBROOT"
  cp -r "$INSTALL_DIR/web/dist/"* "$WEBROOT/"
  chown -R "$APP_USER:$APP_GROUP" "$WEBROOT"

  # Nginx site
  NCONF="/etc/nginx/sites-available/freepbx-agent-ui.conf"
  if [[ -d /etc/nginx/sites-available ]]; then
    cat > "$NCONF" <<NG
server {
    listen ${NGINX_LISTEN_PORT};
    server_name ${NGINX_SERVER_NAME};

    root ${WEBROOT};
    index index.html;

    # Serve app
    location / {
        try_files \$uri /index.html;
    }

    # Proxy API
    location /api/ {
        proxy_pass http://127.0.0.1:${APP_PORT}/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Proxy WS
    location /ws {
        proxy_pass http://127.0.0.1:${APP_PORT}/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }
}
NG
    ln -sf "$NCONF" /etc/nginx/sites-enabled/freepbx-agent-ui.conf
    if [[ -f /etc/nginx/sites-enabled/default ]]; then rm -f /etc/nginx/sites-enabled/default; fi
  else
    # RHEL-style single nginx.conf include
    cat > /etc/nginx/conf.d/freepbx-agent-ui.conf <<NG
server {
    listen ${NGINX_LISTEN_PORT};
    server_name ${NGINX_SERVER_NAME};
    root ${WEBROOT};
    index index.html;

    location / {
        try_files \$uri /index.html;
    }
    location /api/ {
        proxy_pass http://127.0.0.1:${APP_PORT}/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    location /ws {
        proxy_pass http://127.0.0.1:${APP_PORT}/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }
}
NG
  fi
  nginx -t
  systemctl reload nginx
fi

# ---------- systemd service ----------
cyan "==> Creating systemd service..."
cat > /etc/systemd/system/freepbx-agent-ui.service <<SVC
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
# Harden a bit
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
systemctl enable --now freepbx-agent-ui.service

# ---------- UFW (optional) ----------
if command -v ufw >/dev/null 2>&1; then
  if confirm "Open firewall for HTTP (${NGINX_LISTEN_PORT:-80})?"; then
    ufw allow "${NGINX_LISTEN_PORT:-80}"/tcp || true
  fi
fi

green "==> Done!"
echo
echo "Install dir:         ${INSTALL_DIR}"
echo "API port:            ${APP_PORT}"
echo "Web URL:"
if $INSTALL_NGINX; then
  echo "  http://${NGINX_SERVER_NAME}:${NGINX_LISTEN_PORT}"
  echo "  (VITE_API pointing to ${VITE_API})"
else
  echo "  Build is in: ${INSTALL_DIR}/web/dist"
  echo "  Serve it via Nginx/your proxy; point VITE_API to http://<server>:${APP_PORT}/api"
fi
echo
echo "Systemd service:     freepbx-agent-ui  (logs: journalctl -u freepbx-agent-ui -f)"
echo "If AMI/MySQL schemas differ from the defaults, adjust queries in:"
echo "  - ${INSTALL_DIR}/server/src/sla.js"
echo "  - ${INSTALL_DIR}/server/src/agentStats.js"
