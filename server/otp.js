const codes = new Map();

export function generateCode(phone) {
  const code = String(Math.floor(100000 + Math.random() * 900000));
  codes.set(phone, { code, expiresAt: Date.now() + 5 * 60 * 1000, attempts: 0 });
  return code;
}

export function deliverCode(phone, code) {
  console.log(`[OTP] Would send "${code}" to ${phone} (plug in Twilio/MSG91/etc. here)`);
}

export function verifyCode(phone, submitted) {
  const entry = codes.get(phone);
  if (!entry) return { ok: false, reason: "No code requested for this number." };
  if (Date.now() > entry.expiresAt) {
    codes.delete(phone);
    return { ok: false, reason: "Code expired, request a new one." };
  }
  entry.attempts += 1;
  if (entry.attempts > 5) {
    codes.delete(phone);
    return { ok: false, reason: "Too many attempts, request a new code." };
  }
  if (entry.code !== submitted) return { ok: false, reason: "Incorrect code." };
  codes.delete(phone);
  return { ok: true };
}
