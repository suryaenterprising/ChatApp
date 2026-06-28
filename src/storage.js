import { base64UrlToBytes, bytesToBase64Url, decodeJson, encodeJson, randomBytes } from "./utils.js";

const DATABASE_NAME = "hush-private-chat";
const DATABASE_VERSION = 1;
const KEY_STORE = "keys";
const MESSAGE_STORE = "messages";
let databasePromise;

function openDatabase() {
  if (!databasePromise) {
    databasePromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
      request.onupgradeneeded = () => {
        const database = request.result;
        if (!database.objectStoreNames.contains(KEY_STORE)) {
          database.createObjectStore(KEY_STORE);
        }
        if (!database.objectStoreNames.contains(MESSAGE_STORE)) {
          const store = database.createObjectStore(MESSAGE_STORE, { keyPath: "id" });
          store.createIndex("roomId", "roomId", { unique: false });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }
  return databasePromise;
}

function requestResult(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function transaction(storeName, mode, action) {
  const database = await openDatabase();
  const tx = database.transaction(storeName, mode);
  const store = tx.objectStore(storeName);
  const result = await action(store);
  await new Promise((resolve, reject) => {
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
  return result;
}

export async function getOrCreateDeviceKeys() {
  const existing = await transaction(KEY_STORE, "readonly", (store) =>
    requestResult(store.get("device-rsa"))
  );
  if (existing?.privateKey && existing?.publicKey) return existing;

  // The private RSA key is generated non-extractable. IndexedDB stores the
  // CryptoKey handle, never raw private-key bytes. Only the public SPKI is shared.
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    false,
    ["encrypt", "decrypt"]
  );
  const value = { publicKey: pair.publicKey, privateKey: pair.privateKey };
  await transaction(KEY_STORE, "readwrite", (store) => requestResult(store.put(value, "device-rsa")));
  return value;
}

export async function getOrCreateStorageKey() {
  const existing = await transaction(KEY_STORE, "readonly", (store) =>
    requestResult(store.get("history-aes"))
  );
  if (existing) return existing;

  // This non-extractable AES key encrypts local history before IndexedDB writes.
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt"
  ]);
  await transaction(KEY_STORE, "readwrite", (store) => requestResult(store.put(key, "history-aes")));
  return key;
}

export async function saveMessage(roomId, message, storageKey) {
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(roomId) },
    storageKey,
    encodeJson(message)
  );
  const record = {
    id: `${roomId}:${message.id}`,
    roomId,
    createdAt: message.createdAt,
    expiresAt: message.expiresAt || null,
    iv: bytesToBase64Url(iv),
    ciphertext: bytesToBase64Url(new Uint8Array(ciphertext))
  };
  await transaction(MESSAGE_STORE, "readwrite", (store) => requestResult(store.put(record)));
}

export async function loadMessages(roomId, storageKey) {
  const records = await transaction(MESSAGE_STORE, "readonly", (store) =>
    requestResult(store.index("roomId").getAll(roomId))
  );
  const now = Date.now();
  const messages = [];

  for (const record of records) {
    if (record.expiresAt && record.expiresAt <= now) {
      await deleteMessage(roomId, record.id.slice(roomId.length + 1));
      continue;
    }
    try {
      const plaintext = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: base64UrlToBytes(record.iv),
          additionalData: new TextEncoder().encode(roomId)
        },
        storageKey,
        base64UrlToBytes(record.ciphertext)
      );
      messages.push(decodeJson(new Uint8Array(plaintext)));
    } catch {
      // A corrupted local record is ignored; no plaintext fallback is attempted.
    }
  }

  return messages.sort((a, b) => a.createdAt - b.createdAt);
}

export async function deleteMessage(roomId, messageId) {
  return transaction(MESSAGE_STORE, "readwrite", (store) =>
    requestResult(store.delete(`${roomId}:${messageId}`))
  );
}

export async function clearRoom(roomId) {
  const database = await openDatabase();
  const tx = database.transaction(MESSAGE_STORE, "readwrite");
  const index = tx.objectStore(MESSAGE_STORE).index("roomId");
  const range = IDBKeyRange.only(roomId);
  const cursorRequest = index.openKeyCursor(range);
  cursorRequest.onsuccess = () => {
    const cursor = cursorRequest.result;
    if (!cursor) return;
    tx.objectStore(MESSAGE_STORE).delete(cursor.primaryKey);
    cursor.continue();
  };
  await new Promise((resolve, reject) => {
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}

export function savePinRecord(record) {
  localStorage.setItem("hush-pin", JSON.stringify(record));
}

export function getPinRecord() {
  try {
    return JSON.parse(localStorage.getItem("hush-pin"));
  } catch {
    return null;
  }
}

export function saveBiometricCredential(credentialId) {
  localStorage.setItem("hush-biometric", credentialId);
}

export function getBiometricCredential() {
  return localStorage.getItem("hush-biometric");
}

export function saveTrustedPeer(roomId, publicKey) {
  localStorage.setItem(`hush-trusted-peer:${roomId}`, publicKey);
}

export function getTrustedPeer(roomId) {
  return localStorage.getItem(`hush-trusted-peer:${roomId}`);
}
