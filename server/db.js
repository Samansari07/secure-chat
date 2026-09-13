import Database from "better-sqlite3";
import crypto from "node:crypto";

const db = new Database(process.env.DB_PATH || "securechat.db");
db.pragma("journal_mode = WAL");

const PHONE_SALT = process.env.PHONE_HASH_SALT;
if (!PHONE_SALT) {
  console.error("FATAL: set PHONE_HASH_SALT in your environment (openssl rand -hex 32).");
  process.exit(1);
}
function hashPhone(phone) {
  return crypto.createHmac("sha256", PHONE_SALT).update(phone).digest("hex");
}

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    phone_hash TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    device_id TEXT NOT NULL,
    public_key_jwk TEXT NOT NULL,
    last_seen INTEGER NOT NULL,
    UNIQUE(username, device_id)
  );

  CREATE TABLE IF NOT EXISTS invite_codes (
    code TEXT PRIMARY KEY,
    owner_username TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS contacts (
    owner_username TEXT NOT NULL,
    contact_username TEXT NOT NULL,
    added_at INTEGER NOT NULL,
    PRIMARY KEY (owner_username, contact_username)
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT,
    created_at INTEGER NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
  );
`);

export const Users = {
  create({ username, phone, passwordHash }) {
    return db
      .prepare(
        "INSERT INTO users (username, phone_hash, password_hash, verified, created_at) VALUES (?, ?, ?, 0, ?)"
      )
      .run(username, hashPhone(phone), passwordHash, Date.now());
  },
  markVerified(username) {
    db.prepare("UPDATE users SET verified = 1 WHERE username = ?").run(username);
  },
  byUsername(username) {
    return db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  },
  existsByPhone(phone) {
    return !!db.prepare("SELECT 1 FROM users WHERE phone_hash = ?").get(hashPhone(phone));
  },
};

export const Devices = {
  upsert({ username, deviceId, publicKeyJwk }) {
    db.prepare(
      `INSERT INTO devices (username, device_id, public_key_jwk, last_seen)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(username, device_id) DO UPDATE SET public_key_jwk = excluded.public_key_jwk, last_seen = excluded.last_seen`
    ).run(username, deviceId, JSON.stringify(publicKeyJwk), Date.now());
  },
  forUser(username) {
    return db
      .prepare("SELECT device_id, public_key_jwk FROM devices WHERE username = ?")
      .all(username)
      .map((d) => ({ deviceId: d.device_id, publicKeyJwk: JSON.parse(d.public_key_jwk) }));
  },
};

export const Invites = {
  create(ownerUsername) {
    const code = crypto.randomBytes(6).toString("hex");
    db.prepare("INSERT INTO invite_codes (code, owner_username, expires_at, used) VALUES (?, ?, ?, 0)").run(
      code,
      ownerUsername,
      Date.now() + 15 * 60 * 1000
    );
    return code;
  },
  redeem(code, redeemerUsername) {
    const invite = db.prepare("SELECT * FROM invite_codes WHERE code = ?").get(code);
    if (!invite) return { ok: false, reason: "Invalid invite code." };
    if (invite.used) return { ok: false, reason: "This invite code was already used." };
    if (Date.now() > invite.expires_at) return { ok: false, reason: "Invite code expired." };
    if (invite.owner_username === redeemerUsername) return { ok: false, reason: "You can't add yourself." };

    db.prepare("UPDATE invite_codes SET used = 1 WHERE code = ?").run(code);
    const now = Date.now();
    const addPair = db.prepare(
      "INSERT OR IGNORE INTO contacts (owner_username, contact_username, added_at) VALUES (?, ?, ?)"
    );
    addPair.run(invite.owner_username, redeemerUsername, now);
    addPair.run(redeemerUsername, invite.owner_username, now);
    return { ok: true, contactUsername: invite.owner_username };
  },
};

export const Contacts = {
  forUser(username) {
    return db
      .prepare("SELECT contact_username FROM contacts WHERE owner_username = ?")
      .all(username)
      .map((r) => r.contact_username);
  },
  areMutual(a, b) {
    return !!db
      .prepare("SELECT 1 FROM contacts WHERE owner_username = ? AND contact_username = ?")
      .get(a, b);
  },
};

export const AuditLog = {
  append(username, eventType, actor) {
    const last = db
      .prepare("SELECT entry_hash FROM audit_log WHERE username = ? ORDER BY id DESC LIMIT 1")
      .get(username);
    const prevHash = last ? last.entry_hash : "GENESIS";
    const createdAt = Date.now();
    const entryHash = crypto
      .createHash("sha256")
      .update(`${prevHash}|${username}|${eventType}|${actor || ""}|${createdAt}`)
      .digest("hex");
    db.prepare(
      "INSERT INTO audit_log (username, event_type, actor, created_at, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(username, eventType, actor || null, createdAt, prevHash, entryHash);
  },
  forUser(username) {
    return db
      .prepare("SELECT * FROM audit_log WHERE username = ? ORDER BY id ASC")
      .all(username);
  },
  verifyChain(username) {
    const rows = AuditLog.forUser(username);
    let prevHash = "GENESIS";
    for (const row of rows) {
      const expected = crypto
        .createHash("sha256")
        .update(`${prevHash}|${row.username}|${row.event_type}|${row.actor || ""}|${row.created_at}`)
        .digest("hex");
      if (expected !== row.entry_hash) return { ok: false, brokenAt: row.id };
      prevHash = row.entry_hash;
    }
    return { ok: true };
  },
};

export default db;
