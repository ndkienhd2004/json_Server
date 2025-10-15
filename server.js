const jsonServer = require("json-server");
const fs = require("fs");
const path = require("path");

const server = jsonServer.create();
const middlewares = jsonServer.defaults();
server.use(middlewares);
server.use(jsonServer.bodyParser);

// Load DB
const filePath = path.join(__dirname, "data/db.json");
const dbJSON = JSON.parse(fs.readFileSync(filePath, "utf-8"));
const router = jsonServer.router(dbJSON);
const db = router.db;

// Rewriter để prefix /api
server.use(
  jsonServer.rewriter({
    "/api/*": "/$1",
  })
);

/* ======================================================
   AUTH MOCK: register, login, refresh, logout, me
   ====================================================== */

// Bộ nhớ tạm giữ refresh token
globalThis.__refreshStore = globalThis.__refreshStore || new Map();

const createToken = (payload, ttlSec = 3600) => {
  const exp = Date.now() + ttlSec * 1000;
  const body = { ...payload, exp };
  return Buffer.from(JSON.stringify(body)).toString("base64url");
};
const parseToken = (token = "") => {
  try {
    const obj = JSON.parse(Buffer.from(token, "base64url").toString("utf8"));
    if (!obj?.exp || obj.exp < Date.now()) return null;
    return obj;
  } catch {
    return null;
  }
};

const findUser = (iden, pw) =>
  db
    .get("users")
    .value()
    .find(
      (u) =>
        (u.email === iden || u.username === iden) &&
        String(u.password) === String(pw)
    );

const nextId = (collectionName) => {
  const arr = db.get(collectionName).value() || [];
  return arr.length ? Math.max(...arr.map((x) => Number(x.id) || 0)) + 1 : 1;
};

// ========== REGISTER ==========
server.post("/auth/register", (req, res) => {
  const { email, username, password, full_name, role } = req.body || {};
  if (!(email || username) || !password)
    return res
      .status(400)
      .json({ error: "email hoặc username và password là bắt buộc" });

  const users = db.get("users");
  const exists = users
    .value()
    .some((u) => u.email === email || u.username === username);
  if (exists) return res.status(409).json({ error: "User đã tồn tại" });

  const user = {
    id: nextId("users"),
    email: email || "",
    username: username || (email ? email.split("@")[0] : ""),
    password: String(password),
    full_name: full_name || "",
    role: role || "CLIENT",
    created_at: new Date().toISOString(),
  };
  users.push(user).write();

  const access_token = createToken({ sub: user.id }, 3600);
  const refresh_token = createToken(
    { sub: user.id, type: "refresh" },
    7 * 24 * 3600
  );
  __refreshStore.set(refresh_token, user.id);

  const { password: _pw, ...safeUser } = user;
  res.status(201).json({
    data: { user: safeUser, access_token, refresh_token },
  });
});

// ========== LOGIN ==========
server.post("/auth/login", (req, res) => {
  const { identifier, email, username, password } = req.body || {};
  const iden = identifier || email || username;
  if (!iden || !password)
    return res
      .status(400)
      .json({ error: "identifier/email/username & password required" });

  const user = findUser(iden, password);
  if (!user)
    return res.status(401).json({ error: "Sai tài khoản hoặc mật khẩu" });

  const access_token = createToken({ sub: user.id }, 3600);
  const refresh_token = createToken(
    { sub: user.id, type: "refresh" },
    7 * 24 * 3600
  );
  __refreshStore.set(refresh_token, user.id);

  const { password: _pw, ...safeUser } = user;
  res.json({ data: { user: safeUser, access_token, refresh_token } });
});

// ========== REFRESH TOKEN ==========
server.post("/auth/refresh", (req, res) => {
  const { refresh_token } = req.body || {};
  const decoded = parseToken(refresh_token);
  const subInStore = __refreshStore.get(refresh_token);
  if (!decoded || !subInStore || decoded.sub !== subInStore)
    return res.status(401).json({ error: "Refresh token không hợp lệ" });
  const access_token = createToken({ sub: decoded.sub }, 3600);
  res.json({ data: { access_token } });
});

// ========== LOGOUT ==========
server.post("/auth/logout", (req, res) => {
  __refreshStore.delete(req.body?.refresh_token);
  res.json({ data: { ok: true } });
});

// ========== ME ==========
server.get("/auth/me", (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const decoded = parseToken(token);
  if (!decoded) return res.status(401).json({ error: "Unauthorized" });
  const user = db.get("users").find({ id: decoded.sub }).value();
  if (!user) return res.status(404).json({ error: "User không tồn tại" });
  const { password: _pw, ...safeUser } = user;
  res.json({ data: safeUser });
});

// Dưới cùng: gắn router JSON Server
server.use(router);

// Chạy local
if (require.main === module) {
  server.listen(3000, () => {
    console.log("🚀 JSON Server + Auth đang chạy tại http://localhost:3000");
  });
}

// Export cho Vercel
module.exports = server;
