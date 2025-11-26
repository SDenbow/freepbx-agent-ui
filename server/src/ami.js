import AsteriskManager from "asterisk-manager";

let ami;
let amiReady = false;
let lastAmiError = null;
let connectPromise = null;

function attachEventLogging(instance) {
  instance.on("ready", () => {
    amiReady = true;
    lastAmiError = null;
    console.log("[AMI] connected");
  });
  instance.on("error", (e) => {
    lastAmiError = e;
    amiReady = false;
    console.error("[AMI] ERROR:", e?.message || e);
  });
  instance.on("close", () => {
    amiReady = false;
    console.warn("[AMI] connection closed; reconnecting");
  });
  instance.on("end", () => {
    amiReady = false;
    console.warn("[AMI] connection ended; reconnecting");
  });
}

export async function connectAMI() {
  if (amiReady && ami) return ami;
  if (connectPromise) return connectPromise;

  const host = process.env.AMI_HOST || "127.0.0.1";
  const port = +(process.env.AMI_PORT || 5038);
  const user = process.env.AMI_USER || "admin";
  const pass = process.env.AMI_PASS || "admin";

  console.log(`[AMI] Connecting to ${host}:${port} as ${user} ...`);
  connectPromise = new Promise((resolve, reject) => {
    try {
      const inst = new AsteriskManager(port, host, user, pass, true);
      amiReady = false;
      ami = inst;
      attachEventLogging(inst);
      inst.keepConnected();

      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          connectPromise = null;
          reject(new Error("AMI connect timeout"));
        }
      }, 5000);

      inst.once("ready", () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        connectPromise = null;
        resolve(inst);
      });

      inst.once("error", (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        connectPromise = null;
        reject(err);
      });
    } catch (e) {
      connectPromise = null;
      reject(e);
    }
  });
  return connectPromise;
}

export function isAMIConnected() {
  return !!ami && amiReady;
}

export function amiStatus() {
  return { connected: isAMIConnected(), lastError: lastAmiError?.message || null };
}

export function getAMI() { return ami; }

export function wireQueueEvents(broadcast) {
  if (!ami) return;
  ami.on("managerevent", (evt) => {
    const ev = (evt.Event || "").toUpperCase();
    if (ev.includes("QUEUE")) broadcast({ type: "queue-event", evt });
  });
}

export function amiCommand(cmd) {
  return new Promise((resolve, reject) => {
    if (!ami) return reject(new Error("AMI not connected"));
    ami.action({ Action: "Command", Command: cmd }, (_e, r) => {
      resolve((r?.content || r?.data || r?.output || r?.response || "").toString());
    });
  });
}

export async function queueAdd({ queue, iface, penalty = 0, paused = false }) {
  if (!ami) throw new Error("AMI not connected");
  return new Promise((resolve) => {
    ami.action({ Action: "QueueAdd", Queue: queue, Interface: iface, Penalty: penalty, Paused: paused }, () => resolve());
  });
}
export async function queueRemove({ queue, iface }) {
  if (!ami) throw new Error("AMI not connected");
  return new Promise((resolve) => {
    ami.action({ Action: "QueueRemove", Queue: queue, Interface: iface }, () => resolve());
  });
}
export async function queuePause({ queue, iface, paused = true, reason = "" }) {
  if (!ami) throw new Error("AMI not connected");
  return new Promise((resolve) => {
    ami.action({ Action: "QueuePause", Queue: queue, Interface: iface, Paused: paused, Reason: reason }, () => resolve());
  });
}
