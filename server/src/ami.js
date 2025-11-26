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
