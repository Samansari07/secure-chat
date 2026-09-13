const API_BASE = import.meta.env.VITE_SERVER_URL || "http://localhost:4000";

async function post(path, body, token) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

async function get(path, token) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

export const register = (username, phone, password) => post("/auth/register", { username, phone, password });
export const verifyOtp = (username, phone, code) => post("/auth/verify", { username, phone, code });
export const login = (username, password) => post("/auth/login", { username, password });

export const createInvite = (token) => post("/contacts/invite", {}, token);
export const redeemInvite = (code, token) => post("/contacts/redeem", { code }, token);
export const fetchContacts = (token) => get("/contacts", token);

export const fetchAuditLog = (token) => get("/audit-log", token);
export const verifyAuditLog = (token) => get("/audit-log/verify", token);

export function getOrCreateDeviceId() {
  let id = localStorage.getItem("sc_device_id");
  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem("sc_device_id", id);
  }
  return id;
  }
