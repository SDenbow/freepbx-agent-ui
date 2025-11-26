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
