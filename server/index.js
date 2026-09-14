import "dotenv/config";
import express from "express";
import http from "http";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Server } from "socket.io";
import { Users, Devices, Invites, Contacts, AuditLog } from "./db.js";
import { generateCode, deliverCode, verifyCode } from "./otp.js";

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("FATAL: set JWT_SECRET in your environment before starting the server.");
  process.exit(1);
}
const ALLOWED_ORIGIN = process.env.CLIENT_ORIGIN || "http://localhost:5173";

const app = express();
app.use(helmet());
app.use(cors({ origin: ALLOWED_ORIGIN, credentials: true }));
app.use(express.json());

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
app.use("/auth", authLimiter);

function issueToken(username) {
  return jwt.sign({ username }, JWT_SECRET, { expiresIn: "30d" });
}

function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.replace(/^Bearer\s+/, "");
    req.username = jwt.verify(token, JWT_SECRET).username;
    next();
  } catch {
    res.status(401).json({ error: "Unauthorized." });
  }
}

app.post("/auth/register", async (req, res) => {
  const { username, phone, password } = req.body || {};
  if (!username || !phone || !password || password.length < 8) {
    return res.status(400).json({ error: "username, phone, and an 8+ char password are required." });
  }
  if (Users.byUsername(username)) return res.status(409).json({ error: "Username already taken." });
  if (Users.existsByPhone(phone)) return res.status(409).json({ error: "Phone number already registered." });

  const passwordHash = await bcrypt.hash(password, 12);
  Users.create({ username, phone, passwordHash });

  const code = generateCode(phone);
  deliverCode(phone, code);
  res.json({ ok: true, message: "Verification code sent." });
});

app.post("/auth/verify", (req, res) => {
  const { phone, code, username } = req.body || {};
  const result = verifyCode(phone, code);
  if (!result.ok) return res.status(400).json({ error: result.reason });
  Users.markVerified(username);
  AuditLog.append(username, "account_verified", null);
  res.json({ ok: true, token: issueToken(username) });
});

app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  const user = Users.byUsername(username);
  if (!user || !user.verified) return res.status(401).json({ error: "Invalid credentials." });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: "Invalid credentials." });
  AuditLog.append(username, "login", null);
  res.json({ ok: true, token: issueToken(username) });
});

app.post("/contacts/invite", requireAuth, (req, res) => {
  const code = Invites.create(req.username);
  res.json({ code, expiresInMinutes: 15 });
});

app.post("/contacts/redeem", requireAuth, (req, res) => {
  const { code } = req.body || {};
  const result = Invites.redeem(code, req.username);
  if (!result.ok) return res.status(400).json({ error: result.reason });
  AuditLog.append(req.username, "contact_added", result.contactUsername);
  AuditLog.append(result.contactUsername, "contact_added", req.username);
  res.json({ ok: true, contact: result.contactUsername });
});

app.get("/contacts", requireAuth, (req, res) => {
  res.json({ contacts: Contacts.forUser(req.username) });
});

app.get("/audit-log", requireAuth, (req, res) => {
  res.json({ entries: AuditLog.forUser(req.username) });
});

app.get("/audit-log/verify", requireAuth, (req, res) => {
  res.json(AuditLog.verifyChain(req.username));
});

app.get("/health", (_req, res) => res.json({ status: "ok" }));

// Fetches real TURN relay credentials from Metered's Open Relay service
// so calls connect even when both people are on different networks.
app.get("/ice-servers", async (_req, res) => {
  const servers = [{ urls: "stun:stun.l.google.com:19302" }];
  if (process.env.METERED_DOMAIN && process.env.METERED_API_KEY) {
    try {
      const r = await fetch(
        `https://${process.env.METERED_DOMAIN}/api/v1/turn/credentials?apiKey=${process.env.METERED_API_KEY}`
      );
      const turnServers = await r.json();
      if (Array.isArray(turnServers)) servers.push(...turnServers);
    } catch (err) {
      console.error("Failed to fetch TURN credentials:", err.message);
    }
  }
  res.json({ iceServers: servers });
});

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: ALLOWED_ORIGIN, methods: ["GET", "POST"] } });

const onlineDevices = new Map();
const offlineQueue = new Map();

io.use((socket, next) => {
  try {
    const { token } = socket.handshake.auth || {};
    socket.username = jwt.verify(token, JWT_SECRET).username;
    next();
  } catch {
    next(new Error("unauthorized"));
  }
});

function socketsForUser(username) {
  const devices = onlineDevices.get(username);
  return devices ? Array.from(devices.values()) : [];
}

function pushPresenceTo(username) {
  const list = Contacts.forUser(username).map((c) => ({ username: c, online: socketsForUser(c).length > 0 }));
  socketsForUser(username).forEach((sid) => io.to(sid).emit("presence:update", list));
}
function notifyContactsOfPresenceChange(username) {
  Contacts.forUser(username).forEach((contact) => pushPresenceTo(contact));
}

io.on("connection", (socket) => {
  const username = socket.username;

  socket.on("register", ({ deviceId, publicKeyJwk }) => {
    if (!deviceId || !publicKeyJwk) return;
    Devices.upsert({ username, deviceId, publicKeyJwk });

    if (!onlineDevices.has(username)) onlineDevices.set(username, new Map());
    onlineDevices.get(username).set(deviceId, socket.id);
    socket.deviceId = deviceId;

    pushPresenceTo(username);
    notifyContactsOfPresenceChange(username);

    const queued = offlineQueue.get(username) || [];
    if (queued.length) {
      queued.forEach((payload) => socket.emit("message:receive", payload));
      offlineQueue.delete(username);
    }
  });

  socket.on("presence:list", () => pushPresenceTo(username));

  socket.on("key:request", (targetUsername) => {
    if (!Contacts.areMutual(username, targetUsername)) {
      return socket.emit("key:response", { username: targetUsername, devices: [], error: "not_a_contact" });
    }
    AuditLog.append(targetUsername, "key_requested", username);
    const devices = Devices.forUser(targetUsername);
    socket.emit("key:response", { username: targetUsername, devices });
  });

  socket.on("message:send", (payload) => {
    const { to } = payload;
    if (!Contacts.areMutual(username, to)) return;
    const targets = socketsForUser(to);
    if (targets.length) {
      targets.forEach((sid) => io.to(sid).emit("message:receive", payload));
    } else {
      const q = offlineQueue.get(to) || [];
      q.push(payload);
      offlineQueue.set(to, q);
    }
    socket.emit("message:ack", { id: payload.id, delivered: targets.length > 0 });
  });

  socket.on("call:invite", ({ to, from, callType, offer }) => {
    if (!Contacts.areMutual(username, to)) return;
    AuditLog.append(to, "call_received", from);
    socketsForUser(to).forEach((sid) => io.to(sid).emit("call:incoming", { from, callType, offer }));
  });
  socket.on("call:answer", ({ to, answer }) => {
    socketsForUser(to).forEach((sid) => io.to(sid).emit("call:answered", { answer }));
  });
  socket.on("call:ice-candidate", ({ to, candidate }) => {
    socketsForUser(to).forEach((sid) => io.to(sid).emit("call:ice-candidate", { candidate }));
  });
  socket.on("call:reject", ({ to }) => socketsForUser(to).forEach((sid) => io.to(sid).emit("call:rejected")));
  socket.on("call:end", ({ to }) => socketsForUser(to).forEach((sid) => io.to(sid).emit("call:ended")));

  socket.on("disconnect", () => {
    const devices = onlineDevices.get(username);
    if (devices && socket.deviceId) {
      devices.delete(socket.deviceId);
      if (devices.size === 0) onlineDevices.delete(username);
      notifyContactsOfPresenceChange(username);
    }
  });
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => console.log(`SecureChat server running on :${PORT}`));
