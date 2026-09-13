const ECDH_PARAMS = { name: "ECDH", namedCurve: "P-256" };
const enc = new TextEncoder();
const dec = new TextDecoder();

export async function generateIdentity() {
  const keyPair = await crypto.subtle.generateKey(ECDH_PARAMS, true, ["deriveKey", "deriveBits"]);
  const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  return { keyPair, publicKeyJwk };
}

export async function importPeerPublicKey(jwk) {
  return crypto.subtle.importKey("jwk", jwk, ECDH_PARAMS, true, []);
}

function toBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function fromBase64(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

async function deriveRootSecretBits(privateKey, peerPublicKey) {
  return crypto.subtle.deriveBits({ name: "ECDH", public: peerPublicKey }, privateKey, 256);
}

async function hkdfExpand(rootBits, infoLabel) {
  const hkdfKey = await crypto.subtle.importKey("raw", rootBits, "HKDF", false, ["deriveBits"]);
  return crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode(infoLabel) },
    hkdfKey,
    256
  );
}

async function hmacStep(chainKeyBits, label) {
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    chainKeyBits,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return crypto.subtle.sign("HMAC", hmacKey, enc.encode(label));
}

export class RatchetSession {
  static async create(privateKey, peerPublicKey, me, peer) {
    const root = await deriveRootSecretBits(privateKey, peerPublicKey);
    const [low, high] = [me, peer].sort();
    const chainLowToHigh = await hkdfExpand(root, `${low}->${high}`);
    const chainHighToLow = await hkdfExpand(root, `${high}->${low}`);
    const session = new RatchetSession();
    session.sendChain = me === low ? chainLowToHigh : chainHighToLow;
    session.recvChain = me === low ? chainHighToLow : chainLowToHigh;
    session.sendCounter = 0;
    session.recvCounter = 0;
    session.skippedKeys = new Map();
    return session;
  }

  async nextSendKey() {
    const msgKeyBits = await hmacStep(this.sendChain, "msg");
    this.sendChain = await hmacStep(this.sendChain, "chain");
    const counter = this.sendCounter++;
    return { msgKeyBits, counter };
  }

  async keyForCounter(counter) {
    if (this.skippedKeys.has(counter)) {
      const bits = this.skippedKeys.get(counter);
      this.skippedKeys.delete(counter);
      return bits;
    }
    while (this.recvCounter <= counter) {
      const msgKeyBits = await hmacStep(this.recvChain, "msg");
      this.recvChain = await hmacStep(this.recvChain, "chain");
      if (this.recvCounter === counter) {
        this.recvCounter++;
        return msgKeyBits;
      }
      this.skippedKeys.set(this.recvCounter, msgKeyBits);
      this.recvCounter++;
    }
    return null;
  }
}

async function importAesKey(rawBits) {
  return crypto.subtle.importKey("raw", rawBits, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}

export async function ratchetEncrypt(session, plaintext) {
  const { msgKeyBits, counter } = await session.nextSendKey();
  const aesKey = await importAesKey(msgKeyBits);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc.encode(plaintext));
  return { iv: toBase64(iv), ciphertext: toBase64(ciphertext), counter };
}

export async function ratchetDecrypt(session, { iv, ciphertext, counter }) {
  const msgKeyBits = await session.keyForCounter(counter);
  if (!msgKeyBits) throw new Error("Cannot decrypt: replayed or already-consumed message counter.");
  const aesKey = await importAesKey(msgKeyBits);
  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(iv) },
    aesKey,
    fromBase64(ciphertext)
  );
  return dec.decode(plainBuf);
    }
