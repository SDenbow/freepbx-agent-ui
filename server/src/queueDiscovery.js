import mysql from "mysql2/promise";
import { amiCommand, getAMI, isAMIConnected } from "./ami.js";

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

async function collectQueueStatus(ext, allowedQs) {
  const ami = getAMI();
  const loggedIn = {}, paused = {};
  allowedQs.forEach((q) => { loggedIn[q] = false; paused[q] = false; });

  if (!ami) return { loggedIn, paused };

  return await new Promise((resolve) => {
    const allowedSet = new Set(allowedQs);
    const pending = new Set(allowedQs);
    const onEv = (evt) => {
      const ev = (evt.Event || "").toUpperCase();
      if (ev === "QUEUEMEMBER") {
        const q = evt.Queue;
        if (!allowedSet.has(q)) return;
        const si = (evt.StateInterface || evt.Interface || "");
        const matchesExt = si.includes(`SIP/${ext}`) || si.includes(`PJSIP/${ext}`) || si.endsWith(`/${ext}`);
        if (matchesExt) {
          loggedIn[q] = true;
          paused[q] = String(evt.Paused || "0") === "1";
        }
      } else if (ev === "QUEUESTATUSCOMPLETE") {
        const q = evt.Queue || "";
        pending.delete(q);
        if (pending.size === 0) cleanup();
      }
    };
    const cleanup = () => {
      ami.removeListener("managerevent", onEv);
      resolve({ loggedIn, paused });
    };

    ami.on("managerevent", onEv);
    allowedQs.forEach((q) => ami.action({ Action: "QueueStatus", Queue: q }, () => {}));
    setTimeout(cleanup, 2000);
  });
}

export async function discoverQueuesForExt(ext) {
  const allQueues = await getQueuesFromDB();
  const results = await Promise.all(allQueues.map(async (q) => {
    const dyn = await dynFromAstDB(q);
    if (!dyn) return { q, allowed: true };
    const agents = await allowedAgentsFromAstDB(q);
    return { q, allowed: agents.has(String(ext)) };
  }));

  const allowedQs = results.filter((r) => r.allowed).map((r) => r.q);
  const status = isAMIConnected() ? await collectQueueStatus(ext, allowedQs) : { loggedIn: {}, paused: {} };
  const loggedIn = status.loggedIn || {};
  const paused = status.paused || {};

  allowedQs.forEach((q) => {
    if (!(q in loggedIn)) loggedIn[q] = false;
    if (!(q in paused)) paused[q] = false;
  });

  return { allQueues, allowedQs, loggedIn, paused };
}

export function ifacesForExt(ext) {
  return deviceCandidates(ext);
}
