import { useEffect, useRef, useState } from "react";
import { socket } from "./socket";
import {
  generateIdentity,
  importPeerPublicKey,
  RatchetSession,
  ratchetEncrypt,
  ratchetDecrypt,
} from "./crypto";
import { useCall } from "./useCall";
import {
  register,
  verifyOtp,
  login,
  getOrCreateDeviceId,
  createInvite,
  redeemInvite,
  fetchAuditLog,
  verifyAuditLog,
} from "./auth";
import "./styles.css";

function saveToken(t) { sessionStorage.setItem("sc_token", t); }
function loadToken() { return sessionStorage.getItem("sc_token"); }

function decodeJwtPayload(token) {
  const b64 = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "=");
  return JSON.parse(atob(padded));
}

export default function App() {
  const [screen, setScreen] = useState(loadToken() ? "app" : "auth");
  const [authMode, setAuthMode] = useState("login");
  const [form, setForm] = useState({ username: "", phone: "", password: "", code: "" });
  const [authError, setAuthError] = useState("");
  const [token, setToken] = useState(loadToken());
  const [username, setUsername] = useState("");

  const [contacts, setContacts] = useState([]);
  const [activeChat, setActiveChat] = useState(null);
  const [messages, setMessages] = useState({});
  const [draft, setDraft] = useState("");
  const [showAddContact, setShowAddContact] = useState(false);
  const [inviteCode, setInviteCode] = useState(null);
  const [redeemInput, setRedeemInput] = useState("");
  const [contactError, setContactError] = useState("");
  const [showAuditLog, setShowAuditLog] = useState(false);
  const [auditEntries, setAuditEntries] = useState([]);
  const [auditVerified, setAuditVerified] = useState(null);

  const identityRef = useRef(null);
  const sessionsRef = useRef(new Map());
  const pendingKeyRequests = useRef(new Map());
  const deviceId = useRef(getOrCreateDeviceId());

  const call = useCall(username);

  useEffect(() => {
    if (screen === "app" && token) connectSocket();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [screen]);

  useEffect(() => {
    call.attachListeners();
  }, [call]);

  async function connectSocket() {
    const payload = decodeJwtPayload(token);
    setUsername(payload.username);

    identityRef.current = await generateIdentity();
    socket.auth = { token };
    socket.connect();
    socket.emit("register", { deviceId: deviceId.current, publicKeyJwk: identityRef.current.publicKeyJwk });

    socket.on("presence:update", (list) => setContacts(list));

    socket.on("key:response", async ({ username: peer, devices }) => {
      if (!devices?.length) return;
      const peerKey = await importPeerPublicKey(devices[0].publicKeyJwk);
      const session = await RatchetSession.create(
        identityRef.current.keyPair.privateKey,
        peerKey,
        payload.username,
        peer
      );
      sessionsRef.current.set(peer, session);
      pendingKeyRequests.current.get(peer)?.();
      pendingKeyRequests.current.delete(peer);
    });

    socket.on("message:receive", async (msg) => {
      const session = await ensureSession(msg.from);
      if (!session) return;
      try {
        const text = await ratchetDecrypt(session, msg);
        setMessages((prev) => ({
          ...prev,
          [msg.from]: [...(prev[msg.from] || []), { from: msg.from, text, ts: msg.ts }],
        }));
      } catch (e) {
        console.error("Failed to decrypt message:", e.message);
      }
    });
  }

  function ensureSession(peer) {
    if (sessionsRef.current.has(peer)) return Promise.resolve(sessionsRef.current.get(peer));
    return new Promise((resolve) => {
      pendingKeyRequests.current.set(peer, () => resolve(sessionsRef.current.get(peer)));
      socket.emit("key:request", peer);
      setTimeout(() => resolve(sessionsRef.current.get(peer)), 3000);
    });
  }

  async function handleRegister(e) {
    e.preventDefault();
    setAuthError("");
    try {
      await register(form.username, form.phone, form.password);
      setScreen("verify");
    } catch (err) {
      setAuthError(err.message);
    }
  }

  async function handleVerify(e) {
    e.preventDefault();
    setAuthError("");
    try {
      const { token: t } = await verifyOtp(form.username, form.phone, form.code);
      saveToken(t);
      setToken(t);
      setScreen("app");
    } catch (err) {
      setAuthError(err.message);
    }
  }

  async function handleLogin(e) {
    e.preventDefault();
    setAuthError("");
    try {
      const { token: t } = await login(form.username, form.password);
      saveToken(t);
      setToken(t);
      setScreen("app");
    } catch (err) {
      setAuthError(err.message);
    }
  }

  async function handleCreateInvite() {
    setContactError("");
    try {
      const { code } = await createInvite(token);
      setInviteCode(code);
    } catch (err) {
      setContactError(err.message);
    }
  }

  async function handleRedeemInvite(e) {
    e.preventDefault();
    setContactError("");
    try {
      await redeemInvite(redeemInput.trim(), token);
      setRedeemInput("");
      setShowAddContact(false);
      setInviteCode(null);
    } catch (err) {
      setContactError(err.message);
    }
  }

  async function openAuditLog() {
    setShowAuditLog(true);
    const { entries } = await fetchAuditLog(token);
    setAuditEntries(entries);
    const result = await verifyAuditLog(token);
    setAuditVerified(result.ok);
  }

  async function openChat(peer) {
    setActiveChat(peer);
    ensureSession(peer);
  }

  async function sendMessage() {
    if (!draft.trim() || !activeChat) return;
    const session = await ensureSession(activeChat);
    if (!session) return;
    const { iv, ciphertext, counter } = await ratchetEncrypt(session, draft.trim());
    const payload = { id: crypto.randomUUID(), to: activeChat, from: username, iv, ciphertext, counter, ts: Date.now() };
    socket.emit("message:send", payload);
    setMessages((prev) => ({
      ...prev,
      [activeChat]: [...(prev[activeChat] || []), { from: username, text: draft.trim(), ts: payload.ts }],
    }));
    setDraft("");
  }

  if (screen === "auth") {
    return (
      <div className="auth-screen">
        <div className="auth-card">
          <div className="wordmark">SecureChat</div>
          <p className="tagline">Private by design. Nobody in between — not even us.</p>
          <div className="auth-tabs">
            <button className={authMode === "login" ? "active" : ""} onClick={() => setAuthMode("login")}>Log in</button>
            <button className={authMode === "register" ? "active" : ""} onClick={() => setAuthMode("register")}>Register</button>
          </div>
          {authMode === "login" ? (
            <form onSubmit={handleLogin}>
              <input placeholder="Username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
              <input type="password" placeholder="Password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
              {authError && <p className="auth-error">{authError}</p>}
              <button type="submit">Log in</button>
            </form>
          ) : (
            <form onSubmit={handleRegister}>
              <input placeholder="Choose a username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
              <input placeholder="Phone number (for verification)" value={form.phone} onChange={(e) => setForm({ ...form, phone: e.target.value })} />
              <input type="password" placeholder="Password (8+ characters)" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
              {authError && <p className="auth-error">{authError}</p>}
              <button type="submit">Create account</button>
            </form>
          )}
        </div>
      </div>
    );
  }

  if (screen === "verify") {
    return (
      <div className="auth-screen">
        <div className="auth-card">
          <div className="wordmark small">Verify your number</div>
          <p className="tagline">
            We sent a 6-digit code to {form.phone}. (Dev note: check the server console — real SMS
            delivery needs a provider like Twilio plugged into server/otp.js.)
          </p>
          <form onSubmit={handleVerify}>
            <input placeholder="6-digit code" value={form.code} onChange={(e) => setForm({ ...form, code: e.target.value })} />
            {authError && <p className="auth-error">{authError}</p>}
            <button type="submit">Verify & continue</button>
          </form>
        </div>
      </div>
    );
  }

  const activeMessages = messages[activeChat] || [];
  const inCall = call.callState !== "idle";

  return (
    <div className="app-shell">
      <aside className={`sidebar ${activeChat ? "sidebar--hidden-mobile" : ""}`}>
        <div className="sidebar__header">
          <div className="wordmark small">SecureChat</div>
          <span className="me">{username}</span>
        </div>
        <div className="sidebar__actions">
          <button onClick={() => setShowAddContact(true)}>+ Add contact</button>
          <button onClick={openAuditLog}>Audit log</button>
        </div>
        <div className="contact-list">
          {contacts.length === 0 && <p className="empty">No contacts yet — add one with an invite code.</p>}
          {contacts.map((c) => (
            <button
              key={c.username}
              className={`contact ${activeChat === c.username ? "contact--active" : ""}`}
              onClick={() => openChat(c.username)}
            >
              <span className={`dot ${c.online ? "" : "dot--offline"}`} />
              {c.username}
            </button>
          ))}
        </div>
      </aside>

      <main className={`chat-pane ${activeChat ? "" : "chat-pane--hidden-mobile"}`}>
        {activeChat ? (
          <>
            <header className="chat-header">
              <button className="back" onClick={() => setActiveChat(null)}>←</button>
              <span>{activeChat}</span>
              <div className="call-actions">
                <button onClick={() => call.startCall(activeChat, "audio")} title="Voice call">📞</button>
                <button onClick={() => call.startCall(activeChat, "video")} title="Video call">🎥</button>
              </div>
            </header>
            <div className="messages">
              {activeMessages.map((m, i) => (
                <div key={i} className={`bubble ${m.from === username ? "bubble--mine" : ""}`}>{m.text}</div>
              ))}
            </div>
            <div className="composer">
              <input
                placeholder="Message (encrypted before it leaves your device)"
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && sendMessage()}
              />
              <button onClick={sendMessage}>Send</button>
            </div>
          </>
        ) : (
          <div className="placeholder">Pick someone from the list to start an encrypted chat.</div>
        )}
      </main>

      {inCall && (
        <div className="call-overlay">
          <video ref={call.remoteVideoRef} autoPlay playsInline className="remote-video" />
          <video ref={call.localVideoRef} autoPlay playsInline muted className="local-video" />
          <div className="call-info">
            {call.callState === "ringing" && <p>{call.remoteUser} is calling you…</p>}
            {call.callState === "calling" && <p>Calling {call.remoteUser}…</p>}
            {call.callState === "connected" && <p>Connected with {call.remoteUser}</p>}
          </div>
          <div className="call-controls">
            {call.callState === "ringing" ? (
              <>
                <button className="accept" onClick={call.acceptCall}>Accept</button>
                <button className="decline" onClick={call.rejectCall}>Decline</button>
              </>
            ) : (
              <button className="decline" onClick={call.endCall}>End call</button>
            )}
          </div>
        </div>
      )}
      {showAddContact && (
        <div className="modal-overlay" onClick={() => setShowAddContact(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>Add a contact</h3>
            <p className="modal-help">
              No phone-number lookup — share a one-time code out-of-band (in person, QR, any chat you
              already trust) instead. Codes expire in 15 minutes.
            </p>
            <div className="modal-section">
              <button onClick={handleCreateInvite}>Generate my invite code</button>
              {inviteCode && <div className="invite-code">{inviteCode}</div>}
            </div>
            <div className="modal-section">
              <form onSubmit={handleRedeemInvite}>
                <input
                  placeholder="Enter a code someone shared with you"
                  value={redeemInput}
                  onChange={(e) => setRedeemInput(e.target.value)}
                />
                <button type="submit">Add</button>
              </form>
            </div>
            {contactError && <p className="auth-error">{contactError}</p>}
            <button className="modal-close" onClick={() => setShowAddContact(false)}>Close</button>
          </div>
        </div>
      )}

      {showAuditLog && (
        <div className="modal-overlay" onClick={() => setShowAuditLog(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>Audit log</h3>
            <p className="modal-help">
              Every login, key request, and contact change on your account, hash-chained so tampering is
              detectable.{" "}
              {auditVerified === null ? "Verifying…" : auditVerified ? "✅ Chain verified intact." : "⚠️ Chain integrity check failed."}
            </p>
            <div className="audit-list">
              {auditEntries.map((e) => (
                <div key={e.id} className="audit-entry">
                  <strong>{e.event_type}</strong>
                  {e.actor ? ` — by ${e.actor}` : ""}
                  <span className="audit-ts">{new Date(e.created_at).toLocaleString()}</span>
                </div>
              ))}
            </div>
            <button className="modal-close" onClick={() => setShowAuditLog(false)}>Close</button>
          </div>
        </div>
      )}
    </div>
  );
}
