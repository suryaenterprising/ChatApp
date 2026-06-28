import {
  base64UrlToBytes,
  bytesToBase64Url,
  decodeJson,
  encodeJson,
  randomBytes,
  sha256
} from "./utils.js";

export async function exportPublicKey(publicKey) {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  return bytesToBase64Url(new Uint8Array(spki));
}

export async function importPublicKey(encoded) {
  return crypto.subtle.importKey(
    "spki",
    base64UrlToBytes(encoded),
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );
}

export async function fingerprintPublicKey(encoded) {
  const digest = await sha256(base64UrlToBytes(encoded));
  return Array.from(digest.slice(0, 16), (byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .match(/.{1,4}/g)
    .join(" ");
}

export async function createSessionOffer(peerPublicKey) {
  // The session AES key is briefly extractable only on the initiating device so
  // it can be RSA-wrapped for the peer. The receiving import is non-extractable.
  const sessionKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt"
  ]);
  const rawKey = await crypto.subtle.exportKey("raw", sessionKey);
  const wrappedKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, peerPublicKey, rawKey);
  const nonExtractableSessionKey = await crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
  new Uint8Array(rawKey).fill(0);
  const sessionId = bytesToBase64Url(randomBytes(16));
  return {
    sessionKey: nonExtractableSessionKey,
    sessionId,
    wrappedKey: bytesToBase64Url(new Uint8Array(wrappedKey))
  };
}

export async function acceptSessionOffer(privateKey, wrappedKey) {
  const rawKey = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    base64UrlToBytes(wrappedKey)
  );
  return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt"
  ]);
}

export async function encryptEnvelope(sessionKey, sessionId, payload) {
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: new TextEncoder().encode(sessionId)
    },
    sessionKey,
    encodeJson(payload)
  );
  return {
    iv: bytesToBase64Url(iv),
    ciphertext: bytesToBase64Url(new Uint8Array(ciphertext))
  };
}

export async function decryptEnvelope(sessionKey, sessionId, envelope) {
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64UrlToBytes(envelope.iv),
      additionalData: new TextEncoder().encode(sessionId)
    },
    sessionKey,
    base64UrlToBytes(envelope.ciphertext)
  );
  return decodeJson(new Uint8Array(plaintext));
}

export async function createPinRecord(pin) {
  const salt = randomBytes(16);
  return {
    salt: bytesToBase64Url(salt),
    hash: bytesToBase64Url(await derivePinHash(pin, salt)),
    iterations: 310_000
  };
}

export async function verifyPin(pin, record) {
  if (!record?.salt || !record?.hash) return false;
  const actual = await derivePinHash(pin, base64UrlToBytes(record.salt), record.iterations);
  const expected = base64UrlToBytes(record.hash);
  if (actual.length !== expected.length) return false;
  let difference = 0;
  for (let index = 0; index < actual.length; index += 1) {
    difference |= actual[index] ^ expected[index];
  }
  return difference === 0;
}

async function derivePinHash(pin, salt, iterations = 310_000) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(pin),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations },
      material,
      256
    )
  );
}
