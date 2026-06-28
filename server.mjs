import http from "node:http";
import { createHmac } from "node:crypto";
import { createReadStream, existsSync, statSync } from "node:fs";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocketServer, WebSocket } from "ws";

const root = fileURLToPath(new URL(".", import.meta.url));
const port = Number(process.env.PORT || 4173);
const rooms = new Map();
const invalidRooms = new Set();

const securityHeaders = {
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self' ws: wss:; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  "Permissions-Policy":
    "camera=(self), microphone=(self), geolocation=(), payment=(), usb=(), browsing-topics=()",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin"
};

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".webmanifest": "application/manifest+json"
};

const server = http.createServer((request, response) => {
  Object.entries(securityHeaders).forEach(([name, value]) => response.setHeader(name, value));

  const pathname = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
  if (pathname === "/config") {
    response.setHeader("Content-Type", "application/json; charset=utf-8");
    response.setHeader("Cache-Control", "no-store");
    response.end(JSON.stringify({ iceServers: getIceServers() }));
    return;
  }
  const requested = pathname === "/" ? "index.html" : pathname.slice(1);
  const safePath = normalize(requested).replace(/^(\.\.[/\\])+/, "");
  let filePath = join(root, "dist", safePath);

  if (!existsSync(filePath) || statSync(filePath).isDirectory()) {
    filePath = join(root, "dist", "index.html");
  }

  response.setHeader("Content-Type", mimeTypes[extname(filePath)] || "application/octet-stream");
  createReadStream(filePath).pipe(response);
});

const socketServer = new WebSocketServer({
  noServer: true,
  maxPayload: 64 * 1024,
  perMessageDeflate: false
});

server.on("upgrade", (request, socket, head) => {
  const url = new URL(request.url, "http://localhost");
  if (url.pathname !== "/signal" || !isSameOrigin(request)) {
    socket.destroy();
    return;
  }

  socketServer.handleUpgrade(request, socket, head, (webSocket) => {
    socketServer.emit("connection", webSocket);
  });
});

socketServer.on("connection", (socket) => {
  socket.isAlive = true;
  socket.rateWindow = { startedAt: Date.now(), count: 0 };

  socket.on("pong", () => {
    socket.isAlive = true;
  });

  socket.on("message", (raw) => {
    if (!withinRateLimit(socket)) {
      socket.close(1008, "Rate limit exceeded");
      return;
    }

    let message;
    try {
      message = JSON.parse(raw.toString());
    } catch {
      socket.close(1003, "Invalid JSON");
      return;
    }

    if (message.type === "join") {
      joinRoom(socket, message.roomId);
      return;
    }

    if (message.type === "signal" && socket.roomId && isSafeSignal(message.data)) {
      relayToPeer(socket, { type: "signal", data: message.data });
      return;
    }

    if (message.type === "invalidate" && socket.roomId) {
      invalidateRoom(socket.roomId);
    }
  });

  socket.on("close", () => leaveRoom(socket));
  socket.on("error", () => leaveRoom(socket));
});

const heartbeat = setInterval(() => {
  for (const socket of socketServer.clients) {
    if (!socket.isAlive) {
      socket.terminate();
      continue;
    }
    socket.isAlive = false;
    socket.ping();
  }
}, 30_000);

socketServer.on("close", () => clearInterval(heartbeat));

function joinRoom(socket, roomId) {
  if (socket.roomId || typeof roomId !== "string" || !/^[A-Za-z0-9_-]{24,64}$/.test(roomId)) {
    socket.close(1008, "Invalid room");
    return;
  }

  if (invalidRooms.has(roomId)) {
    send(socket, { type: "link-invalid" });
    socket.close(1008, "Pairing link invalid");
    return;
  }

  const room = rooms.get(roomId) || new Set();
  if (room.size >= 2) {
    send(socket, { type: "room-full" });
    socket.close(1008, "Room full");
    return;
  }

  socket.roomId = roomId;
  room.add(socket);
  rooms.set(roomId, room);

  const role = room.size === 1 ? "initiator" : "receiver";
  send(socket, { type: "joined", role, peers: room.size });

  if (room.size === 2) {
    for (const member of room) {
      send(member, { type: "peer-ready" });
    }
  }
}

function invalidateRoom(roomId) {
  invalidRooms.add(roomId);
  if (invalidRooms.size > 10_000) {
    invalidRooms.delete(invalidRooms.values().next().value);
  }
  const room = rooms.get(roomId);
  if (!room) return;
  for (const member of room) {
    send(member, { type: "link-invalid" });
    member.roomId = null;
    member.close(1000, "Pairing link invalidated");
  }
  rooms.delete(roomId);
}

function relayToPeer(sender, payload) {
  const room = rooms.get(sender.roomId);
  if (!room) return;
  for (const member of room) {
    if (member !== sender) send(member, payload);
  }
}

function leaveRoom(socket) {
  if (!socket.roomId) return;
  const roomId = socket.roomId;
  const room = rooms.get(roomId);
  socket.roomId = null;
  if (!room) return;
  room.delete(socket);
  for (const member of room) send(member, { type: "peer-left" });
  if (room.size === 0) rooms.delete(roomId);
}

function send(socket, payload) {
  if (socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(payload));
  }
}

function isSafeSignal(data) {
  if (!data || typeof data !== "object") return false;
  if (data.description) {
    return (
      ["offer", "answer"].includes(data.description.type) &&
      typeof data.description.sdp === "string" &&
      data.description.sdp.length < 100_000
    );
  }
  if (data.candidate) {
    return typeof data.candidate.candidate === "string" && data.candidate.candidate.length < 4_096;
  }
  return false;
}

function withinRateLimit(socket) {
  const now = Date.now();
  if (now - socket.rateWindow.startedAt > 10_000) {
    socket.rateWindow = { startedAt: now, count: 0 };
  }
  socket.rateWindow.count += 1;
  return socket.rateWindow.count <= 120;
}

function isSameOrigin(request) {
  const origin = request.headers.origin;
  if (!origin) return false;
  try {
    return new URL(origin).host === request.headers.host;
  } catch {
    return false;
  }
}

function getIceServers() {
  const iceServers = [
    { urls: ["stun:stun.cloudflare.com:3478", "stun:stun.l.google.com:19302"] }
  ];
  const urls = process.env.TURN_URLS?.split(",").map((value) => value.trim()).filter(Boolean);
  if (!urls?.length) return iceServers;

  if (process.env.TURN_AUTH_SECRET) {
    const ttlSeconds = Number(process.env.TURN_TTL_SECONDS || 86_400);
    const expiresAt = Math.floor(Date.now() / 1000) + Math.max(300, ttlSeconds);
    const username = `${expiresAt}:hush`;
    const credential = createHmac("sha1", process.env.TURN_AUTH_SECRET)
      .update(username)
      .digest("base64");
    iceServers.push({ urls, username, credential });
    return iceServers;
  }

  if (process.env.TURN_USERNAME && process.env.TURN_CREDENTIAL) {
    iceServers.push({
      urls,
      username: process.env.TURN_USERNAME,
      credential: process.env.TURN_CREDENTIAL
    });
  }
  return iceServers;
}

server.listen(port, "0.0.0.0", () => {
  console.log(`Hush is ready at http://localhost:${port}`);
});
