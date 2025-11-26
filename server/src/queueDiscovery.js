import mysql from "mysql2/promise";
import { amiCommand, getAMI } from "./ami.js";

const pool = mysql.createPool({
  host: process.env.MYSQL_CFG_HOST || process.env.MYSQL_HOST || "127.0.0.1",
  port: Number(process.env.MYSQL_CFG_PORT || process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_CFG_USER || process.env.MYSQL_USER,
  password: process.env.MYSQL_CFG_PASS || process.env.MYSQL_PASS,
  database: process.env.MYSQL_CFG_DB || "asterisk",
  connectionLimit: 4,
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
  const haveCx = await tableExists("cxpanel_queues");
  const ids = new Set();

  if (haveQCfg) {
    const [r] = await pool.query("SELECT extension FROM queues_config");
    r.forEach((x) => ids.add(String(x.extension)));
  } else if (haveCx) {
    const [r] = await pool.query("SELECT queue_number FROM cxpanel_queues");
    r.forEach((x) => ids.add(String(x.queue_number)));
  }
  return Array.from(ids).sort();
}

async function dynFromAstDB(q) {
  try {
    const txt = await amiCommand(`database get QPENALTY/${q}/dynmemberonly`);
    return (
      /(\/QPENALTY\/[^:]+\/dynmemberonly\s*:\s*(yes|1))\b/i.test(txt) ||
      /\bValue\s*:\s*(yes|1)\b/i.test(txt)
    );
  } catch {
    return false;
  }
}

async function allowedAgentsFromAstDB(q) {
  const agents = new Set();
  try {
    const txt = await amiCommand(`database show QPENALTY/${q}/agents`);
    txt.split("\n").forEach((line) => {
      const m = line.match(
        new RegExp(`/QPENALTY/${q}/agents/([^\\s:]+)\\s*:`)
      );
      if (m) agents.add(String(m[1]));
    });
  } catch {}
  return agents;
}

// NEW: static members from MySQL queue_members
async function staticMembersFromDB(q) {
  const agents = new Set();
  try {
    const haveQM = await tableExists("queue_members");
    if (!haveQM) return agents;

    const [rows] = await pool.query(
      "SELECT interface FROM queue_members WHERE queue_name = ?",
      [q]
    );

    rows.forEach((r) => {
      const iface = r.interface || "";
      // Typical formats: SIP/1010, PJSIP/1010, Local/1010@from-queue/n
      const m =
        iface.match(/^(?:SIP|PJSIP)\/(\d+)/) ||
        iface.match(/Local\/(\d+)@/);
      if (m) agents.add(String(m[1]));
    });
  } catch {
    // ignore errors; return whatever we collected
  }
  return agents;
}

async function isLoggedIn(ext, q) {
  const ami = getAMI();
  if (!ami) return false;

  try {
    const pm = await amiCommand(`database show Queue/PersistentMembers/${q}`);
    const rx = new RegExp(`(?:SIP|PJSIP)/${ext}\\b`);
    if (rx.test(pm) || pm.includes(`/${ext}`) || pm.includes(`;${ext};`))
      return true;
  } catch {}

  // fallback: QueueStatus scan
  return await new Promise((resolve) => {
    let logged = false;
    const onEv = (evt) => {
      const ev = (evt.Event || "").toUpperCase();
      if (ev === "QUEUEMEMBER") {
        if (evt.Queue !== q) return;
        const si = (evt.StateInterface || evt.Interface || "");
        if (
          si.includes(`SIP/${ext}`) ||
          si.includes(`PJSIP/${ext}`) ||
          si.endsWith(`/${ext}`)
        )
          logged = true;
      } else if (ev === "QUEUESTATUSCOMPLETE") {
        ami.removeListener("managerevent", onEv);
        resolve(logged);
      }
    };
    ami.on("managerevent", onEv);
    ami.action({ Action: "QueueStatus", Queue: q }, () => {});
    setTimeout(() => {
      ami.removeListener("managerevent", onEv);
      resolve(logged);
    }, 2000);
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
        const isMine =
          si.includes(`SIP/${ext}`) ||
          si.includes(`PJSIP/${ext}`) ||
          si.endsWith(`/${ext}`);
        if (isMine) paused = String(evt.Paused || "0") === "1";
      } else if (ev === "QUEUESTATUSCOMPLETE") {
        ami.removeListener("managerevent", onEv);
        resolve(paused);
      }
    };
    ami.on("managerevent", onEv);
    ami.action({ Action: "QueueStatus", Queue: q }, () => {});
    setTimeout(() => {
      ami.removeListener("managerevent", onEv);
      resolve(paused);
    }, 2000);
  });
}

export async function discoverQueuesForExt(ext) {
  const allQueues = await getQueuesFromDB();
  const allowedQs = [];
  const extStr = String(ext);

  for (const q of allQueues) {
    const dynOnly = await dynFromAstDB(q);
    const staticAgents = await staticMembersFromDB(q);
    const dynAgents = await allowedAgentsFromAstDB(q);

    if (dynOnly) {
      // Queue is dynamic-member-only: must be in AstDB agents to be allowed
      if (dynAgents.has(extStr)) allowedQs.push(q);
    } else {
      // Queue may have static and/or dynamic members:
      // only allow if ext is static OR dynamic member
      if (staticAgents.has(extStr) || dynAgents.has(extStr)) {
        allowedQs.push(q);
      }
    }
  }

  // status maps only for allowed queues
  const loggedIn = {};
  const paused = {};
  for (const q of allowedQs) {
    try {
      loggedIn[q] = await isLoggedIn(ext, q);
    } catch {
      loggedIn[q] = false;
    }
    try {
      paused[q] = await isPaused(ext, q);
    } catch {
      paused[q] = false;
    }
  }
  return { allQueues, allowedQs, loggedIn, paused };
}

export function ifacesForExt(ext) {
  return deviceCandidates(ext);
}
