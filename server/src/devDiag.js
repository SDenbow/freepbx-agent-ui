import fp from "fastify-plugin";
import { getAMI, amiCommand } from "./ami.js";
import { discoverQueuesForExt } from "./queueDiscovery.js";

export default fp(async (fastify) => {

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
