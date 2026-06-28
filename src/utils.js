export function bytesToBase64Url(bytes) {
  const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function base64UrlToBytes(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function randomBytes(length = 32) {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function randomId() {
  return bytesToBase64Url(randomBytes(16));
}

export function encodeJson(value) {
  return new TextEncoder().encode(JSON.stringify(value));
}

export function decodeJson(bytes) {
  return JSON.parse(new TextDecoder().decode(bytes));
}

export async function sha256(value) {
  const input = typeof value === "string" ? new TextEncoder().encode(value) : value;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", input));
}

export function formatClock(timestamp) {
  return new Intl.DateTimeFormat([], { hour: "numeric", minute: "2-digit" }).format(timestamp);
}

export function formatDay(timestamp) {
  const date = new Date(timestamp);
  const today = new Date();
  const yesterday = new Date();
  yesterday.setDate(today.getDate() - 1);
  if (date.toDateString() === today.toDateString()) return "Today";
  if (date.toDateString() === yesterday.toDateString()) return "Yesterday";
  return new Intl.DateTimeFormat([], { month: "short", day: "numeric", year: "numeric" }).format(date);
}

export function humanDuration(milliseconds) {
  if (milliseconds === 300_000) return "5 minutes";
  if (milliseconds === 3_600_000) return "1 hour";
  if (milliseconds === 86_400_000) return "24 hours";
  return "off";
}
