import "dotenv/config";
import Fastify from "fastify";
import cors from "@fastify/cors";
import { buildAuth } from "./auth.js";
import { connectAMI, amiStatus, queueAdd, queueRemove, queuePause } from "./ami.js";
import { discoverQueuesForExt, ifacesForExt } from "./queueDiscovery.js";
import devDiag from "./devDiag.js";

const fastify = Fastify({ logger: true });
await fastify.register(cors, { origin: process.env.ALLOWED_ORIGIN || true, credentials: true });
buildAuth(fastify);
await fastify.register(devDiag);

fastify.get("/healthz", async () => ({ ok: true }));
fastify.get("/healthz/ami", async () => amiStatus());

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
  try {
    await connectAMI();
  } catch (e) {
    fastify.log.error({ err: e }, "AMI connect error (continuing without AMI)");
  }
  const port = +(process.env.PORT || 8088);
  await fastify.listen({ port, host: "0.0.0.0" });
  fastify.log.info("API on :" + port);
}
start().catch((e) => { console.error(e); process.exit(1); });
