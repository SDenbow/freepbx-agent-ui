#!/usr/bin/env bash
set -euo pipefail

# ===============================
# FreePBX Agent UI – Installer
# ===============================

APP_USER="freepbxui"
APP_GROUP="$APP_USER"
INSTALL_DIR="/opt/freepbx-agent-ui"
WEBROOT="/var/www/freepbx-agent-ui"
SERVICE_NAME="freepbx-agent-ui"
NODE_MAJOR=20
REPO_URL_DEFAULT="https://github.com/SDenbow/freepbx-agent-ui.git"

# --- utilities ---
die(){ echo "ERROR: $*" >&2; exit 1; }
need_root(){ [ "$EUID" -eq 0 ] || die "Run as root (sudo)"; }
yn(){ local p="$1"; local d="${2:-N}"; read -rp "$p [$d]: " ans; ans="${ans:-$d}"; [[ "$ans" =~ ^[Yy]$ ]]; }
prompt(){ local p="$1"; local d="${2:-}"; read -rp "$p${d:+ [$d]}: " v; echo "${v:-$d}"; }

need_root
echo "==> FreePBX Agent UI installer starting..."

# --- OS prereqs ---
if command -v apt-get >/dev/null 2>&1; then
  PKG="apt"
else
  die "This script currently supports Debian/Ubuntu (apt)."
fi

echo "==> Installing prerequisites..."
apt-get update -y
apt-get install -y ca-certificates curl git build-essential jq netcat-openbsd

# Node.js LTS
if ! command -v node >/dev/null 2>&1 || ! node -v | grep -q "v${NODE_MAJOR}\."; then
  echo "==> Installing Node.js ${NODE_MAJOR}.x..."
  curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash -
  apt-get install -y nodejs
fi

# --- Repo setup ---
REPO_URL="${REPO_URL_DEFAULT}"
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  # convert https://github.com/Owner/Repo.git -> token form
  REPO_URL="$(echo "$REPO_URL" | sed -E "s#https://github.com/#https://${GITHUB_TOKEN}@github.com/#")"
fi

mkdir -p "$INSTALL_DIR"
if [ ! -d "$INSTALL_DIR/.git" ]; then
  echo "==> Cloning repository..."
  git clone "$REPO_URL_DEFAULT" "$INSTALL_DIR" || git clone "$REPO_URL" "$INSTALL_DIR"
else
  echo "==> Repository exists. Pulling latest..."
  git -C "$INSTALL_DIR" fetch --all --prune || true
  git -C "$INSTALL_DIR" reset --hard origin/main || true
fi

# --- Service user ---
echo "==> Creating service user and setting permissions..."
id -u "$APP_USER" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$APP_USER"
mkdir -p "/home/$APP_USER"
chown -R "$APP_USER:$APP_GROUP" "/home/$APP_USER" "$INSTALL_DIR"

# --- Patch dependencies (server) ---
echo "==> Patching server dependencies (cors/jwt/ami)..."
SERVER_PKG="$INSTALL_DIR/server/package.json"
[ -f "$SERVER_PKG" ] || die "Missing $SERVER_PKG"

# replace deprecated fastify plugins & AMI client
sed -i -E 's/"fastify-cors"[[:space:]]*:[[:space:]]*"[^"]+"/"@fastify\/cors": "^11.1.0"/' "$SERVER_PKG" || true
sed -i -E 's/"fastify-jwt"[[:space:]]*:[[:space:]]*"[^"]+"/"@fastify\/jwt": "^9.0.0"/' "$SERVER_PKG" || true
sed -i -E 's/"asterisk-ami-client"[[:space:]]*:[[:space:]]*"[^"]+"/"asterisk-manager": "^0.2.0"/' "$SERVER_PKG" || true

# --- Patch server code (start HTTP first, fix imports, add /healthz) ---
echo "==> Updating server code (HTTP-first, imports, healthz)..."
IDX="$INSTALL_DIR/server/src/index.js"
AUTH="$INSTALL_DIR/server/src/auth.js"
[ -f "$IDX" ] || die "Missing $IDX"
[ -f "$AUTH" ] || touch "$AUTH"

# fix CORS import if needed
sed -i "s|from 'fastify-cors'|from '@fastify/cors'|" "$IDX" || true

# ensure fastify.listen & /healthz and AMI connect after HTTP
if ! grep -q "fastify.listen" "$IDX"; then
  cat >"$IDX" <<'JS'
import 'dotenv/config';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import { connectAMI, wireQueueEvents, queueAdd, queueRemove, queuePause, queueStatus } from './ami.js';
import { buildAuth } from './auth.js';
import { createWsServer } from './wsHub.js';
import { DEVICE_TEMPLATE, USER_ACCESS } from './config.js';
import { getSLA } from './sla.js';
import { getAgentToday, dayWindow } from './agentStats.js';

const fastify = Fastify({ logger: true });

// CORS + auth
await fastify.register(cors, { origin: process.env.ALLOWED_ORIGIN || true, credentials: true });
buildAuth(fastify);

// Health (no auth)
fastify.get('/healthz', async () => ({ ok: true }));

// Protect /api/* except /api/login
fastify.addHook('preHandler', async (request, reply) => {
  const p = request.routerPath || request.url || '';
  if (p.startsWith('/api/') && p !== '/api/login') {
    await fastify.auth(request, reply);
  }
});

// Minimal routes to keep UI functional
fastify.get('/api/queues', async (req, reply) => {
  const { ext } = req.user || {};
  if (!ext) return reply.code(401).send({ error: 'unauthorized' });
  const acl = USER_ACCESS[ext] || { queues: [], ext };
  return acl.queues;
});

fastify.post('/api/queue/login', async (req) => {
  const { queue } = req.body || {};
  const { ext } = req.user;
  const iface = DEVICE_TEMPLATE(ext);
  await queueAdd({ queue, iface, penalty: 0, paused: false });
  return { ok: true };
});
fastify.post('/api/queue/logout', async (req) => {
  const { queue } = req.body || {};
  const { ext } = req.user;
  const iface = DEVICE_TEMPLATE(ext);
  await queueRemove({ queue, iface });
  return { ok: true };
});
fastify.post('/api/queue/pause', async (req) => {
  const { queue, reason } = req.body || {};
  const { ext } = req.user;
  const iface = DEVICE_TEMPLATE(ext);
  await queuePause({ queue, iface, paused: true, reason: reason || 'Break' });
  return { ok: true };
});
fastify.post('/api/queue/unpause', async (req) => {
  const { queue } = req.body || {};
  const { ext } = req.user;
  const iface = DEVICE_TEMPLATE(ext);
  await queuePause({ queue, iface, paused: false });
  return { ok: true };
});

fastify.get('/api/stats/sla', async (req, reply) => {
  const { queue, from, to } = req.query || {};
  if (!queue || !from || !to) return reply.code(400).send({ error: 'queue, from, to required' });
  return getSLA({ queue, from, to });
});

fastify.get('/api/stats/agentToday', async (req) => {
  const { date } = req.query || {};
  const { ext } = req.user;
  const { from, end } = dayWindow(date);
  return getAgentToday({ ext, from, to: end });
});

async function start() {
  const port = +process.env.PORT || 8088;
  await fastify.listen({ port, host: '0.0.0.0' });
  console.log(`API on :${port}`);

  // WebSocket on the Fastify server
  const ws = createWsServer(fastify.server);

  // Connect AMI after HTTP is up
  try {
    await connectAMI();
    wireQueueEvents(ws.broadcast);
    try { await queueStatus(); } catch (e) { fastify.log.error({ err: e }, 'QueueStatus error'); }
  } catch (e) {
    fastify.log.error({ err: e }, 'AMI connect error');
  }
}

start().catch((e) => { console.error(e); process.exit(1); });
JS
fi

# fix JWT import in auth.js if needed
if grep -q "fastify-jwt" "$AUTH" 2>/dev/null; then
  sed -i "s|fastify-jwt|@fastify/jwt|g" "$AUTH"
fi

# --- Install deps & build ---
echo "==> Installing Node dependencies..."
su -s /bin/bash -c "cd '$INSTALL_DIR/server' && npm config set registry https://registry.npmjs.org/ && rm -rf node_modules package-lock.json && npm install --omit=dev" "$APP_USER"

echo "==> Building web..."
su -s /bin/bash -c "cd '$INSTALL_DIR/web' && npm install && npm run build" "$APP_USER"

# --- Create .env ---
echo "==> Creating server .env ..."
PORT_DEFAULT="8088"
ALLOWED_ORIGIN_DEFAULT="*"
JWT_SECRET_DEFAULT="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 24)"

AMI_HOST=$(prompt "FreePBX/Asterisk AMI host" "127.0.0.1")
AMI_PORT=$(prompt "FreePBX AMI port" "5038")
AMI_USER=$(prompt "FreePBX AMI username" "ui_agent_app")
AMI_PASS=$(prompt "FreePBX AMI password" "")
[ -n "$AMI_PASS" ] || die "AMI password cannot be empty."

MYSQL_HOST=$(prompt "MySQL host (FreePBX DB host)" "127.0.0.1")
MYSQL_PORT=$(prompt "MySQL port" "3306")
MYSQL_USER=$(prompt "MySQL user (read-only)" "report_ro")
MYSQL_PASS=$(prompt "MySQL password" "")
[ -n "$MYSQL_PASS" ] || die "MySQL password cannot be empty."
MYSQL_DB=$(prompt "MySQL database" "asteriskcdrdb")

TZV=$(prompt "Timezone (IANA, e.g. America/New_York)" "America/New_York")
JWT_SECRET=$(prompt "JWT secret" "$JWT_SECRET_DEFAULT")
PORT=$(prompt "API port" "$PORT_DEFAULT")
ALLOWED_ORIGIN=$(prompt "Allowed CORS origin (* or http://host)" "$ALLOWED_ORIGIN_DEFAULT")

cat >"$INSTALL_DIR/server/.env" <<ENV
PORT=$PORT
JWT_SECRET=$JWT_SECRET
ALLOWED_ORIGIN=$ALLOWED_ORIGIN

AMI_HOST=$AMI_HOST
AMI_PORT=$AMI_PORT
AMI_USER=$AMI_USER
AMI_PASS=$AMI_PASS

MYSQL_HOST=$MYSQL_HOST
MYSQL_PORT=$MYSQL_PORT
MYSQL_USER=$MYSQL_USER
MYSQL_PASS=$MYSQL_PASS
MYSQL_DB=$MYSQL_DB

TZ=$TZV
ENV
chown "$APP_USER:$APP_GROUP" "$INSTALL_DIR/server/.env"
chmod 640 "$INSTALL_DIR/server/.env"

# --- Systemd service ---
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

# --- Optional Nginx ---
if yn "Install and configure Nginx to serve the web UI and proxy /api and /ws?" "Y"; then
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
        proxy_pass http://127.0.0.1:${PORT}/;
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

echo "==> Checking service status..."
sleep 1
systemctl --no-pager --full status "${SERVICE_NAME}" || true

echo
echo "==> Sanity checks:"
echo "   Health:   curl -s http://127.0.0.1:${PORT}/healthz"
echo "   Queues:   curl -i http://127.0.0.1:${PORT}/api/queues   # 401 means API is up"
echo
echo "==> AMI socket check (from this host):"
echo "   nc -vz ${AMI_HOST} ${AMI_PORT}"
echo
echo "Done."
