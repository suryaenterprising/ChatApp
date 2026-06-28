import QRCode from "qrcode";
import "./styles.css";
import {
  acceptSessionOffer,
  createPinRecord,
  createSessionOffer,
  decryptEnvelope,
  encryptEnvelope,
  exportPublicKey,
  fingerprintPublicKey,
  importPublicKey,
  verifyPin
} from "./crypto.js";
import { PeerTransport } from "./peer.js";
import { SignalingClient } from "./signaling.js";
import {
  deleteMessage,
  getBiometricCredential,
  getOrCreateDeviceKeys,
  getOrCreateStorageKey,
  getPinRecord,
  getTrustedPeer,
  loadMessages,
  saveBiometricCredential,
  saveMessage,
  savePinRecord,
  saveTrustedPeer
} from "./storage.js";
import {
  base64UrlToBytes,
  bytesToBase64Url,
  formatClock,
  formatDay,
  humanDuration,
  randomBytes,
  randomId,
  sha256
} from "./utils.js";

const elements = Object.fromEntries(
  [
    "messageArea",
    "messageList",
    "welcomeCard",
    "pairButton",
    "pairModal",
    "qrImage",
    "pairLink",
    "copyPairLink",
    "newLinkButton",
    "waitingText",
    "connectionStatus",
    "presenceDot",
    "messageForm",
    "messageInput",
    "sendButton",
    "imageButton",
    "imageInput",
    "timerButton",
    "timerMenu",
    "timerLabel",
    "themeButton",
    "audioCallButton",
    "videoCallButton",
    "settingsButton",
    "settingsModal",
    "lockButton",
    "pinSetupButton",
    "biometricButton",
    "fingerprintValue",
    "lockScreen",
    "unlockForm",
    "unlockPin",
    "unlockError",
    "biometricUnlock",
    "pinModal",
    "pinForm",
    "newPin",
    "confirmPin",
    "pinError",
    "incomingCallModal",
    "incomingCallTitle",
    "acceptCallButton",
    "declineCallButton",
    "callOverlay",
    "localVideo",
    "remoteVideo",
    "audioCallVisual",
    "callStatus",
    "muteButton",
    "cameraButton",
    "hangupButton",
    "toast"
  ].map((id) => [id, document.getElementById(id)])
);

const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
const IMAGE_CHUNK_SIZE = 12_000;
const ALLOWED_IMAGE_TYPES = new Set(["image/jpeg", "image/png", "image/webp", "image/gif"]);

const state = {
  roomSecret: null,
  roomId: null,
  signalRoomId: null,
  role: null,
  signaling: null,
  peer: null,
  deviceKeys: null,
  publicKeyEncoded: null,
  storageKey: null,
  sessionKey: null,
  sessionId: null,
  peerPublicKey: null,
  pendingPeerPublicKeyEncoded: null,
  peerFingerprint: null,
  iceServers: [{ urls: "stun:stun.cloudflare.com:3478" }],
  secureReady: false,
  roomFull: false,
  messages: [],
  vanishDuration: Number(localStorage.getItem("hush-vanish-duration") || 0),
  locked: false,
  incomingImages: new Map(),
  call: {
    id: null,
    type: null,
    phase: "idle",
    localStream: null,
    remoteStream: null,
    startedAt: null,
    timer: null
  },
  toastTimer: null
};

initialize().catch((error) => {
  setConnectionStatus("Initialization failed");
  showToast(`Hush could not start: ${error.message}`);
});

async function initialize() {
  applySavedTheme();
  bindEvents();
  updateTimerLabel();

  if (!window.isSecureContext) {
    showToast("Web Crypto, WebRTC, and device unlock require HTTPS or localhost.");
  }

  try {
    const [deviceKeys, storageKey, networkConfig] = await Promise.all([
      getOrCreateDeviceKeys(),
      getOrCreateStorageKey(),
      fetch("/config", { cache: "no-store" })
        .then((response) => (response.ok ? response.json() : null))
        .catch(() => null)
    ]);
    state.deviceKeys = deviceKeys;
    state.storageKey = storageKey;
    if (Array.isArray(networkConfig?.iceServers) && networkConfig.iceServers.length) {
      state.iceServers = networkConfig.iceServers;
    }
    state.publicKeyEncoded = await exportPublicKey(state.deviceKeys.publicKey);
  } catch (error) {
    setConnectionStatus("Secure storage unavailable");
    showToast(`Could not initialize local encryption: ${error.message}`);
    return;
  }

  const secret = readPairingSecret() || localStorage.getItem("hush-active-secret");
  if (secret) {
    await enterRoom(secret);
  }

  updateLockControls();
  startExpirySweep();
}

function bindEvents() {
  elements.pairButton.addEventListener("click", createAndShowPairing);
  elements.copyPairLink.addEventListener("click", copyPairingLink);
  elements.newLinkButton.addEventListener("click", invalidateAndCreatePairing);
  elements.messageForm.addEventListener("submit", handleSend);
  elements.imageButton.addEventListener("click", () => elements.imageInput.click());
  elements.imageInput.addEventListener("change", handleImageSelection);
  elements.messageInput.addEventListener("input", resizeComposer);
  elements.messageInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      elements.messageForm.requestSubmit();
    }
  });
  elements.themeButton.addEventListener("click", toggleTheme);
  elements.audioCallButton.addEventListener("click", () => startCall("audio"));
  elements.videoCallButton.addEventListener("click", () => startCall("video"));
  elements.timerButton.addEventListener("click", toggleTimerMenu);
  elements.timerMenu.addEventListener("click", chooseVanishDuration);
  elements.settingsButton.addEventListener("click", () => openModal(elements.settingsModal));
  elements.lockButton.addEventListener("click", lockApp);
  elements.pinSetupButton.addEventListener("click", setupPin);
  elements.pinForm.addEventListener("submit", savePin);
  elements.biometricButton.addEventListener("click", enableBiometric);
  elements.unlockForm.addEventListener("submit", unlockWithPin);
  elements.biometricUnlock.addEventListener("click", unlockWithBiometric);
  elements.acceptCallButton.addEventListener("click", acceptIncomingCall);
  elements.declineCallButton.addEventListener("click", declineIncomingCall);
  elements.hangupButton.addEventListener("click", () => endCall(true));
  elements.muteButton.addEventListener("click", toggleMute);
  elements.cameraButton.addEventListener("click", toggleCamera);

  document.addEventListener("click", (event) => {
    const closeButton = event.target.closest("[data-close-modal]");
    if (closeButton) closeModal(document.getElementById(closeButton.dataset.closeModal));
    if (!event.target.closest(".timer-row")) closeTimerMenu();
  });

  document.addEventListener("visibilitychange", () => {
    if (document.hidden && getPinRecord()) lockApp();
    if (!document.hidden) markIncomingAsRead();
  });
  window.addEventListener("focus", markIncomingAsRead);
}

async function createAndShowPairing() {
  const secret = bytesToBase64Url(randomBytes(32));
  history.replaceState(null, "", `${location.pathname}${location.search}#pair=${secret}`);
  await enterRoom(secret);
  await showPairingModal();
}

async function invalidateAndCreatePairing() {
  state.signaling?.invalidate();
  localStorage.removeItem("hush-active-secret");
  await createAndShowPairing();
}

function readPairingSecret() {
  const match = location.hash.match(/(?:^#|&)pair=([A-Za-z0-9_-]{40,64})/);
  return match?.[1] || null;
}

async function enterRoom(secret) {
  disconnect();
  state.roomSecret = secret;
  state.roomId = bytesToBase64Url(await sha256(`hush-room:${secret}`)).slice(0, 43);
  const trustedPeer = getTrustedPeer(state.roomId);
  if (trustedPeer) {
    const orderedKeys = [state.publicKeyEncoded, trustedPeer].sort().join(":");
    state.signalRoomId = bytesToBase64Url(
      await sha256(`hush-paired:${secret}:${orderedKeys}`)
    ).slice(0, 43);
  } else {
    state.signalRoomId = state.roomId;
  }
  state.secureReady = false;
  state.roomFull = false;
  state.pendingPeerPublicKeyEncoded = null;
  state.messages = await loadMessages(state.roomId, state.storageKey);
  renderMessages();
  setComposerEnabled(false);
  setConnectionStatus("Connecting to private relay…");

  state.signaling = new SignalingClient(state.signalRoomId);
  state.signaling.addEventListener("joined", handleJoined);
  state.signaling.addEventListener("peer-ready", handlePeerReady);
  state.signaling.addEventListener("peer-left", handlePeerLeft);
  state.signaling.addEventListener("room-full", () => {
    state.roomFull = true;
    state.signaling.close();
    setConnectionStatus("This pairing link is already in use");
    showToast("This private room already has two devices.");
  });
  state.signaling.addEventListener("link-invalid", () => {
    if (state.secureReady) {
      state.signaling.close();
      return;
    }
    state.roomFull = true;
    state.signaling.close();
    setConnectionStatus("This pairing link has been invalidated");
    showToast("Create a fresh private invitation on the original device.");
  });
  state.signaling.addEventListener("disconnected", () => {
    if (!state.secureReady && !state.roomFull) setConnectionStatus("Reconnecting to relay…");
  });
  state.signaling.connect();
}

function handleJoined(event) {
  state.role = event.detail.role;
  setConnectionStatus(event.detail.peers === 1 ? "Waiting for your peer…" : "Negotiating secure channel…");
  if (event.detail.peers === 1) showPairingModal();
}

function handlePeerReady() {
  elements.waitingText.textContent = "Peer found — securing connection…";
  setConnectionStatus("Negotiating secure channel…");
  createPeerTransport();
}

function createPeerTransport() {
  state.peer?.close();
  state.sessionKey = null;
  state.sessionId = null;
  state.secureReady = false;
  state.peer = new PeerTransport(state.signaling, state.role, state.iceServers);
  state.peer.addEventListener("open", sendKeyHello);
  state.peer.addEventListener("message", handlePeerMessage);
  state.peer.addEventListener("remotestream", (event) => {
    state.call.remoteStream = event.detail;
    elements.remoteVideo.srcObject = event.detail;
    if (state.call.phase !== "idle") {
      state.call.phase = "active";
      startCallTimer();
    }
  });
  state.peer.addEventListener("statechange", (event) => {
    if (["failed", "disconnected", "closed"].includes(event.detail)) {
      setComposerEnabled(false);
      state.secureReady = false;
      setConnectionStatus("Peer connection interrupted");
    }
  });
  state.peer.addEventListener("error", () => {
    setConnectionStatus("Could not establish peer connection");
  });
  state.peer.start();
}

function handlePeerLeft() {
  endCall(false);
  state.peer?.close();
  state.peer = null;
  state.sessionKey = null;
  state.secureReady = false;
  setComposerEnabled(false);
  elements.presenceDot.classList.remove("online");
  elements.waitingText.textContent = "Waiting for your peer…";
  setConnectionStatus("Peer disconnected");
}

function sendKeyHello() {
  state.peer.send({
    type: "key-hello",
    publicKey: state.publicKeyEncoded
  });
  setConnectionStatus("Exchanging encryption keys…");
}

async function handlePeerMessage(event) {
  const message = event.detail;
  try {
    if (message.type === "key-hello") {
      await handleKeyHello(message);
    } else if (message.type === "key-offer") {
      await handleKeyOffer(message);
    } else if (message.type === "secure") {
      await handleSecureEnvelope(message.envelope);
    } else if (message.type === "key-reject") {
      state.roomFull = true;
      setConnectionStatus("Unrecognized device blocked");
      setComposerEnabled(false);
      state.peer?.close();
      showToast("The peer key did not match the device paired previously.");
    }
  } catch {
    setConnectionStatus("Encryption handshake failed");
    showToast("The encrypted message or handshake could not be verified.");
  }
}

async function handleKeyHello(message) {
  const trustedPeer = getTrustedPeer(state.roomId);
  if (trustedPeer && trustedPeer !== message.publicKey) {
    state.peer.send({ type: "key-reject" });
    state.roomFull = true;
    setConnectionStatus("Unrecognized device blocked");
    state.peer.close();
    showToast("A device with an unexpected encryption key was blocked.");
    return;
  }

  state.peerPublicKey = await importPublicKey(message.publicKey);
  state.pendingPeerPublicKeyEncoded = message.publicKey;
  state.peerFingerprint = await fingerprintPublicKey(message.publicKey);
  elements.fingerprintValue.textContent = state.peerFingerprint;

  if (state.role === "initiator") {
    const offer = await createSessionOffer(state.peerPublicKey);
    state.sessionKey = offer.sessionKey;
    state.sessionId = offer.sessionId;
    state.peer.send({
      type: "key-offer",
      sessionId: offer.sessionId,
      wrappedKey: offer.wrappedKey
    });
  }
}

async function handleKeyOffer(message) {
  state.sessionKey = await acceptSessionOffer(state.deviceKeys.privateKey, message.wrappedKey);
  state.sessionId = message.sessionId;
  await sendEncrypted({ kind: "key-confirm", nonce: bytesToBase64Url(randomBytes(16)) });
  secureChannelReady();
}

async function handleSecureEnvelope(envelope) {
  if (!state.sessionKey || !state.sessionId) return;
  const payload = await decryptEnvelope(state.sessionKey, state.sessionId, envelope);

  if (payload.kind === "key-confirm") {
    await sendEncrypted({ kind: "key-confirm-ack", nonce: payload.nonce });
    secureChannelReady();
    return;
  }
  if (payload.kind === "key-confirm-ack") {
    secureChannelReady();
    return;
  }
  if (payload.kind === "chat") {
    await receiveChat(payload.message);
    return;
  }
  if (payload.kind === "image-start") {
    receiveImageStart(payload);
    return;
  }
  if (payload.kind === "image-chunk") {
    receiveImageChunk(payload);
    return;
  }
  if (payload.kind === "image-end") {
    await receiveImageEnd(payload);
    return;
  }
  if (payload.kind === "receipt") {
    await receiveReceipt(payload);
    return;
  }
  if (payload.kind?.startsWith("call-")) {
    await handleCallControl(payload);
    return;
  }
  if (payload.kind === "expired") {
    await expireMessage(payload.messageId, false);
  }
}

function secureChannelReady() {
  if (state.secureReady) return;
  state.secureReady = true;
  if (!getTrustedPeer(state.roomId) && state.pendingPeerPublicKeyEncoded) {
    saveTrustedPeer(state.roomId, state.pendingPeerPublicKeyEncoded);
  }
  localStorage.setItem("hush-active-secret", state.roomSecret);
  if (location.hash) {
    history.replaceState(null, "", `${location.pathname}${location.search}`);
  }
  // Keep signaling online after the encrypted data channel is ready. WebRTC media
  // calls add tracks later and need the same zero-log relay for renegotiation.
  elements.presenceDot.classList.add("online");
  setConnectionStatus("Online · end-to-end encrypted");
  setComposerEnabled(true);
  elements.waitingText.textContent = "Securely connected";
  closeModal(elements.pairModal);
  showToast("Secure peer-to-peer channel established.");
  markIncomingAsRead();
}

async function handleSend(event) {
  event.preventDefault();
  const text = elements.messageInput.value.trim();
  if (!text || !state.secureReady) return;

  const now = Date.now();
  const message = {
    id: randomId(),
    type: "text",
    text,
    createdAt: now,
    expiresAt: state.vanishDuration ? now + state.vanishDuration : null,
    direction: "outgoing",
    status: "sent"
  };

  state.messages.push(message);
  renderMessage(message);
  scrollToLatest();
  elements.messageInput.value = "";
  resizeComposer();
  await saveMessage(state.roomId, message, state.storageKey);

  try {
    await sendEncrypted({
      kind: "chat",
      message: {
        id: message.id,
        type: "text",
        text: message.text,
        createdAt: message.createdAt,
        expiresAt: message.expiresAt
      }
    });
  } catch {
    showToast("Message was saved locally but could not be sent.");
  }
}

async function handleImageSelection(event) {
  const file = event.target.files?.[0];
  elements.imageInput.value = "";
  if (!file) return;
  if (!state.secureReady) {
    showToast("Pair a device before sharing images.");
    return;
  }
  if (!ALLOWED_IMAGE_TYPES.has(file.type)) {
    showToast("Choose a JPEG, PNG, WebP, or GIF image.");
    return;
  }
  if (file.size > MAX_IMAGE_BYTES) {
    showToast("Images are limited to 5 MB for private peer transfer.");
    return;
  }

  try {
    const dataUrl = await readFileAsDataUrl(file);
    if (!isSafeImageDataUrl(dataUrl, file.type)) {
      showToast("That image format could not be verified.");
      return;
    }
    await sendImageMessage(file, dataUrl);
  } catch {
    showToast("Image could not be shared.");
  }
}

function readFileAsDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ""));
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
}

async function sendImageMessage(file, dataUrl) {
  const now = Date.now();
  const safeName = file.name.slice(0, 180) || "image";
  const message = {
    id: randomId(),
    type: "image",
    text: "",
    image: {
      dataUrl,
      mime: file.type,
      name: safeName,
      size: file.size
    },
    createdAt: now,
    expiresAt: state.vanishDuration ? now + state.vanishDuration : null,
    direction: "outgoing",
    status: "sent"
  };

  state.messages.push(message);
  renderMessage(message);
  scrollToLatest();
  await saveMessage(state.roomId, message, state.storageKey);

  try {
    const transferId = randomId();
    const chunks = [];
    for (let index = 0; index < dataUrl.length; index += IMAGE_CHUNK_SIZE) {
      chunks.push(dataUrl.slice(index, index + IMAGE_CHUNK_SIZE));
    }

    await sendEncrypted({
      kind: "image-start",
      transferId,
      totalChunks: chunks.length,
      message: {
        id: message.id,
        type: "image",
        text: "",
        image: {
          mime: file.type,
          name: safeName,
          size: file.size
        },
        createdAt: message.createdAt,
        expiresAt: message.expiresAt
      }
    });

    for (let index = 0; index < chunks.length; index += 1) {
      await state.peer.waitForWritable();
      await sendEncrypted({
        kind: "image-chunk",
        transferId,
        index,
        data: chunks[index]
      });
    }

    await sendEncrypted({ kind: "image-end", transferId });
  } catch {
    showToast("Image was saved locally but could not be sent.");
  }
}

function receiveImageStart(payload) {
  const transferId = payload.transferId;
  const totalChunks = payload.totalChunks;
  const message = normalizeIncomingImageMetadata(payload.message);
  if (
    typeof transferId !== "string" ||
    !Number.isInteger(totalChunks) ||
    totalChunks < 1 ||
    totalChunks > 600 ||
    !message
  ) {
    return;
  }
  state.incomingImages.set(transferId, {
    message,
    totalChunks,
    chunks: new Array(totalChunks),
    received: 0,
    receivedAt: Date.now()
  });
}

function receiveImageChunk(payload) {
  const transfer = state.incomingImages.get(payload.transferId);
  if (
    !transfer ||
    !Number.isInteger(payload.index) ||
    payload.index < 0 ||
    payload.index >= transfer.totalChunks ||
    typeof payload.data !== "string" ||
    payload.data.length > IMAGE_CHUNK_SIZE + 512
  ) {
    return;
  }
  if (transfer.chunks[payload.index] === undefined) {
    transfer.chunks[payload.index] = payload.data;
    transfer.received += 1;
  }
}

async function receiveImageEnd(payload) {
  const transfer = state.incomingImages.get(payload.transferId);
  if (!transfer || transfer.received !== transfer.totalChunks) return;
  state.incomingImages.delete(payload.transferId);

  const dataUrl = transfer.chunks.join("");
  if (!isSafeImageDataUrl(dataUrl, transfer.message.image.mime)) return;
  if (dataUrl.length > Math.ceil(MAX_IMAGE_BYTES * 1.4) + 128) return;

  await receiveChat({
    ...transfer.message,
    image: {
      ...transfer.message.image,
      dataUrl
    }
  });
}

function normalizeIncomingImageMetadata(incoming) {
  if (
    !incoming ||
    incoming.type !== "image" ||
    typeof incoming.id !== "string" ||
    !Number.isFinite(incoming.createdAt)
  ) {
    return null;
  }
  const image = incoming.image;
  if (!isSafeImagePayload(image, false)) return null;
  return {
    id: incoming.id,
    type: "image",
    text: typeof incoming.text === "string" ? incoming.text.slice(0, 4000) : "",
    image: {
      mime: image.mime,
      name: image.name || "image",
      size: image.size
    },
    createdAt: incoming.createdAt,
    expiresAt: Number.isFinite(incoming.expiresAt) ? incoming.expiresAt : null
  };
}

function isSafeImagePayload(image, requireDataUrl) {
  if (
    !image ||
    typeof image.mime !== "string" ||
    !ALLOWED_IMAGE_TYPES.has(image.mime) ||
    !Number.isFinite(image.size) ||
    image.size < 0 ||
    image.size > MAX_IMAGE_BYTES
  ) {
    return false;
  }
  if (image.name && (typeof image.name !== "string" || image.name.length > 180)) return false;
  if (!requireDataUrl) return true;
  return isSafeImageDataUrl(image.dataUrl, image.mime);
}

function isSafeImageDataUrl(dataUrl, mime) {
  return (
    typeof dataUrl === "string" &&
    ALLOWED_IMAGE_TYPES.has(mime) &&
    dataUrl.startsWith(`data:${mime};base64,`) &&
    dataUrl.length <= Math.ceil(MAX_IMAGE_BYTES * 1.4) + 128
  );
}

async function receiveChat(incoming) {
  const normalized = normalizeIncomingMessage(incoming);
  if (!normalized) return;
  if (state.messages.some((message) => message.id === normalized.id)) return;
  if (normalized.expiresAt && normalized.expiresAt <= Date.now()) return;

  const message = {
    ...normalized,
    direction: "incoming",
    status: document.hidden ? "delivered" : "read"
  };
  state.messages.push(message);
  state.messages.sort((a, b) => a.createdAt - b.createdAt);
  await saveMessage(state.roomId, message, state.storageKey);
  renderMessages();
  await sendEncrypted({
    kind: "receipt",
    messageId: message.id,
    status: message.status
  });
}

function normalizeIncomingMessage(incoming) {
  if (
    !incoming ||
    typeof incoming.id !== "string" ||
    !Number.isFinite(incoming.createdAt)
  ) {
    return null;
  }

  const expiresAt = Number.isFinite(incoming.expiresAt) ? incoming.expiresAt : null;
  const type = incoming.type || "text";
  if (type === "text") {
    if (typeof incoming.text !== "string" || incoming.text.length > 4000) return null;
    return {
      id: incoming.id,
      type,
      text: incoming.text,
      createdAt: incoming.createdAt,
      expiresAt
    };
  }

  if (type === "image") {
    const image = incoming.image;
    if (!isSafeImagePayload(image, true)) return null;
    const text = typeof incoming.text === "string" ? incoming.text.slice(0, 4000) : "";
    return {
      id: incoming.id,
      type,
      text,
      image,
      createdAt: incoming.createdAt,
      expiresAt
    };
  }

  return null;
}

async function receiveReceipt(receipt) {
  const message = state.messages.find(
    (candidate) => candidate.id === receipt.messageId && candidate.direction === "outgoing"
  );
  if (!message || !["delivered", "read"].includes(receipt.status)) return;
  if (message.status === "read") return;
  message.status = receipt.status;
  await saveMessage(state.roomId, message, state.storageKey);
  updateMessageStatus(message);
}

async function markIncomingAsRead() {
  if (!state.secureReady || document.hidden) return;
  const unread = state.messages.filter(
    (message) => message.direction === "incoming" && message.status !== "read"
  );
  for (const message of unread) {
    message.status = "read";
    await saveMessage(state.roomId, message, state.storageKey);
    await sendEncrypted({ kind: "receipt", messageId: message.id, status: "read" });
  }
}

async function sendEncrypted(payload) {
  if (!state.sessionKey || !state.sessionId) throw new Error("No secure session");
  const envelope = await encryptEnvelope(state.sessionKey, state.sessionId, payload);
  state.peer.send({ type: "secure", envelope });
}

async function startCall(type) {
  if (!state.secureReady || state.call.phase !== "idle") return;
  const callId = randomId();
  state.call.id = callId;
  state.call.type = type;
  state.call.phase = "outgoing";
  showCallOverlay(type, "Ringing securely…");

  try {
    await sendEncrypted({
      kind: "call-invite",
      callId,
      callType: type
    });
  } catch {
    showToast("Could not start the call.");
    resetCallUi();
  }
}

async function handleCallControl(payload) {
  if (payload.kind === "call-invite") {
    await handleCallInvite(payload);
  } else if (payload.kind === "call-accept") {
    await handleCallAccept(payload);
  } else if (payload.kind === "call-decline") {
    handleCallDecline(payload);
  } else if (payload.kind === "call-end") {
    handleCallEnd(payload);
  }
}

async function handleCallInvite(payload) {
  if (!["audio", "video"].includes(payload.callType) || typeof payload.callId !== "string") return;
  if (state.call.phase !== "idle") {
    await sendEncrypted({ kind: "call-decline", callId: payload.callId, reason: "busy" });
    return;
  }

  state.call.id = payload.callId;
  state.call.type = payload.callType;
  state.call.phase = "incoming";
  elements.incomingCallTitle.textContent =
    payload.callType === "video" ? "Incoming video call" : "Incoming audio call";
  openModal(elements.incomingCallModal);
}

async function acceptIncomingCall() {
  if (state.call.phase !== "incoming") return;
  closeModal(elements.incomingCallModal);
  showCallOverlay(state.call.type, "Opening camera and microphone…");

  try {
    await prepareLocalMedia(state.call.type);
    state.call.phase = state.call.remoteStream ? "active" : "connecting";
    await sendEncrypted({ kind: "call-accept", callId: state.call.id });
    if (state.call.phase === "active") {
      startCallTimer();
      return;
    }
    updateCallStatus("Connecting securely…");
  } catch (error) {
    showToast(error.message || "Could not access call devices.");
    await declineIncomingCall();
  }
}

async function declineIncomingCall() {
  const callId = state.call.id;
  if (!callId) return;
  try {
    await sendEncrypted({ kind: "call-decline", callId, reason: "declined" });
  } catch {
    // The remote side may already be gone.
  }
  resetCallUi();
}

async function handleCallAccept(payload) {
  if (
    payload.callId !== state.call.id ||
    !["outgoing", "active"].includes(state.call.phase)
  ) {
    return;
  }
  if (state.call.localStream) return;
  showCallOverlay(state.call.type, "Opening camera and microphone…");
  try {
    await prepareLocalMedia(state.call.type);
    state.call.phase = state.call.remoteStream ? "active" : "connecting";
    updateCallStatus("Connecting securely…");
  } catch (error) {
    showToast(error.message || "Could not access call devices.");
    await endCall(true);
  }
}

function handleCallDecline(payload) {
  if (payload.callId !== state.call.id) return;
  showToast(payload.reason === "busy" ? "Peer is already on a call." : "Call declined.");
  resetCallUi();
}

function handleCallEnd(payload) {
  if (payload.callId !== state.call.id) return;
  showToast("Call ended.");
  resetCallUi();
}

async function prepareLocalMedia(type) {
  if (!navigator.mediaDevices?.getUserMedia) {
    throw new Error("This browser does not expose camera or microphone access.");
  }
  const constraints = {
    audio: true,
    video:
      type === "video"
        ? {
            width: { ideal: 1280 },
            height: { ideal: 720 },
            facingMode: "user"
          }
        : false
  };
  const stream = await navigator.mediaDevices.getUserMedia(constraints);
  state.call.localStream = stream;
  elements.localVideo.srcObject = stream;
  await state.peer.addLocalStream(stream);
  updateMediaButtons();
}

async function endCall(notifyPeer) {
  const callId = state.call.id;
  if (notifyPeer && callId && state.secureReady) {
    try {
      await sendEncrypted({ kind: "call-end", callId });
    } catch {
      // The peer connection may already be closing.
    }
  }
  resetCallUi();
}

function showCallOverlay(type, status) {
  elements.callOverlay.hidden = false;
  elements.callOverlay.classList.toggle("audio-only", type === "audio");
  elements.localVideo.hidden = type !== "video";
  elements.remoteVideo.hidden = type !== "video";
  elements.cameraButton.hidden = type !== "video";
  updateCallStatus(status);
}

function updateCallStatus(status) {
  elements.callStatus.textContent = status;
}

function startCallTimer() {
  if (state.call.timer) return;
  state.call.startedAt = state.call.startedAt || Date.now();
  const render = () => {
    if (state.call.phase === "active") {
      updateCallStatus(`Connected · ${formatElapsed(Date.now() - state.call.startedAt)}`);
    }
  };
  render();
  state.call.timer = setInterval(render, 1000);
}

function formatElapsed(milliseconds) {
  const totalSeconds = Math.floor(milliseconds / 1000);
  const minutes = String(Math.floor(totalSeconds / 60)).padStart(2, "0");
  const seconds = String(totalSeconds % 60).padStart(2, "0");
  return `${minutes}:${seconds}`;
}

function toggleMute() {
  const audioTrack = state.call.localStream?.getAudioTracks()[0];
  if (!audioTrack) return;
  audioTrack.enabled = !audioTrack.enabled;
  updateMediaButtons();
}

function toggleCamera() {
  const videoTrack = state.call.localStream?.getVideoTracks()[0];
  if (!videoTrack) return;
  videoTrack.enabled = !videoTrack.enabled;
  updateMediaButtons();
}

function updateMediaButtons() {
  const audioTrack = state.call.localStream?.getAudioTracks()[0];
  const videoTrack = state.call.localStream?.getVideoTracks()[0];
  elements.muteButton.classList.toggle("active", Boolean(audioTrack && !audioTrack.enabled));
  elements.muteButton.setAttribute("aria-label", audioTrack?.enabled ? "Mute microphone" : "Unmute microphone");
  elements.cameraButton.classList.toggle("active", Boolean(videoTrack && !videoTrack.enabled));
  elements.cameraButton.setAttribute("aria-label", videoTrack?.enabled ? "Turn camera off" : "Turn camera on");
}

function resetCallUi() {
  clearInterval(state.call.timer);
  state.call.localStream?.getTracks().forEach((track) => track.stop());
  state.peer?.removeLocalStream();
  elements.callOverlay.hidden = true;
  elements.incomingCallModal.hidden = true;
  elements.localVideo.srcObject = null;
  elements.remoteVideo.srcObject = null;
  elements.localVideo.hidden = false;
  elements.remoteVideo.hidden = false;
  elements.cameraButton.hidden = false;
  elements.muteButton.classList.remove("active");
  elements.cameraButton.classList.remove("active");
  state.call = {
    id: null,
    type: null,
    phase: "idle",
    localStream: null,
    remoteStream: null,
    startedAt: null,
    timer: null
  };
}

function renderMessages() {
  elements.messageList.replaceChildren();
  if (state.messages.length === 0) {
    elements.messageList.append(elements.welcomeCard);
    elements.welcomeCard.hidden = false;
    return;
  }

  let previousDay = "";
  for (const message of state.messages) {
    const day = new Date(message.createdAt).toDateString();
    if (day !== previousDay) {
      const divider = document.createElement("div");
      divider.className = "day-divider";
      divider.textContent = formatDay(message.createdAt);
      elements.messageList.append(divider);
      previousDay = day;
    }
    renderMessage(message, false);
  }
  requestAnimationFrame(scrollToLatest);
}

function renderMessage(message, appendDayIfNeeded = true) {
  elements.welcomeCard.hidden = true;
  if (appendDayIfNeeded) {
    const lastMessage = state.messages.at(-2);
    if (!lastMessage || new Date(lastMessage.createdAt).toDateString() !== new Date(message.createdAt).toDateString()) {
      const divider = document.createElement("div");
      divider.className = "day-divider";
      divider.textContent = formatDay(message.createdAt);
      elements.messageList.append(divider);
    }
  }

  const wrapper = document.createElement("article");
  wrapper.className = `message ${message.direction}`;
  wrapper.dataset.messageId = message.id;

  const bubble = document.createElement("div");
  bubble.className = "bubble";

  const contentNodes = [];
  if (message.type === "image" && isSafeImagePayload(message.image, true)) {
    const image = document.createElement("img");
    image.className = "bubble-image";
    image.src = message.image.dataUrl;
    image.alt = message.image.name ? `Shared image: ${message.image.name}` : "Shared image";
    image.loading = "lazy";
    contentNodes.push(image);

    if (message.text) {
      const caption = document.createElement("p");
      caption.className = "image-caption";
      caption.textContent = message.text;
      contentNodes.push(caption);
    }
  } else {
    const text = document.createElement("p");
    text.className = "bubble-text";
    text.textContent = message.text || "";
    contentNodes.push(text);
  }

  const meta = document.createElement("div");
  meta.className = "bubble-meta";

  if (message.expiresAt) {
    const vanish = document.createElement("span");
    vanish.className = "vanish-meta";
    vanish.title = `Vanishes ${new Date(message.expiresAt).toLocaleString()}`;
    vanish.innerHTML = `<svg viewBox="0 0 24 24"><circle cx="12" cy="13" r="8"></circle><path d="M12 9v4l2.5 1.5M9 2h6"></path></svg>`;
    meta.append(vanish);
  }

  const time = document.createElement("time");
  time.dateTime = new Date(message.createdAt).toISOString();
  time.textContent = formatClock(message.createdAt);
  meta.append(time);

  if (message.direction === "outgoing") {
    meta.append(createStatusIcon(message.status));
  }

  bubble.append(...contentNodes, meta);
  wrapper.append(bubble);
  elements.messageList.append(wrapper);
}

function createStatusIcon(status) {
  const icon = document.createElement("span");
  icon.className = `message-status ${status || "sent"}`;
  icon.setAttribute("aria-label", status || "sent");
  icon.title = status || "sent";
  icon.innerHTML =
    status === "sent"
      ? `<svg viewBox="0 0 20 14"><path d="m3 7 3 3 6-7"></path></svg>`
      : `<svg viewBox="0 0 22 14"><path d="m1 7 3 3 6-7M8 10l2 2 9-9"></path></svg>`;
  return icon;
}

function updateMessageStatus(message) {
  const node = elements.messageList.querySelector(`[data-message-id="${CSS.escape(message.id)}"]`);
  const current = node?.querySelector(".message-status");
  if (current) current.replaceWith(createStatusIcon(message.status));
}

function setComposerEnabled(enabled) {
  elements.messageInput.disabled = !enabled;
  elements.sendButton.disabled = !enabled;
  elements.imageButton.disabled = !enabled;
  elements.audioCallButton.disabled = !enabled;
  elements.videoCallButton.disabled = !enabled;
  elements.messageInput.placeholder = enabled
    ? "Write a private message…"
    : "Pair a device to start messaging";
}

function setConnectionStatus(text) {
  elements.connectionStatus.textContent = text;
}

async function showPairingModal() {
  if (!state.roomSecret) return;
  const url = new URL(location.href);
  url.hash = `pair=${state.roomSecret}`;
  elements.pairLink.value = url.href;
  elements.qrImage.src = await QRCode.toDataURL(url.href, {
    width: 360,
    margin: 1,
    color: { dark: "#0b241b", light: "#ffffff" },
    errorCorrectionLevel: "H"
  });
  openModal(elements.pairModal);
}

async function copyPairingLink() {
  try {
    await navigator.clipboard.writeText(elements.pairLink.value);
    elements.copyPairLink.textContent = "Copied";
    setTimeout(() => {
      elements.copyPairLink.textContent = "Copy";
    }, 1400);
  } catch {
    elements.pairLink.select();
    showToast("Select and copy the pairing link manually.");
  }
}

function toggleTimerMenu() {
  const willOpen = elements.timerMenu.hidden;
  elements.timerMenu.hidden = !willOpen;
  elements.timerButton.setAttribute("aria-expanded", String(willOpen));
}

function closeTimerMenu() {
  elements.timerMenu.hidden = true;
  elements.timerButton.setAttribute("aria-expanded", "false");
}

function chooseVanishDuration(event) {
  const button = event.target.closest("[data-duration]");
  if (!button) return;
  state.vanishDuration = Number(button.dataset.duration);
  localStorage.setItem("hush-vanish-duration", String(state.vanishDuration));
  updateTimerLabel();
  closeTimerMenu();
  showToast(
    state.vanishDuration
      ? `New messages will vanish after ${humanDuration(state.vanishDuration)}.`
      : "Vanishing messages turned off."
  );
}

function updateTimerLabel() {
  elements.timerLabel.textContent = state.vanishDuration
    ? `Vanish after ${humanDuration(state.vanishDuration)}`
    : "Vanishing off";
}

function resizeComposer() {
  elements.messageInput.style.height = "auto";
  elements.messageInput.style.height = `${Math.min(elements.messageInput.scrollHeight, 126)}px`;
}

function scrollToLatest() {
  elements.messageList.scrollTop = elements.messageList.scrollHeight;
}

function startExpirySweep() {
  setInterval(async () => {
    const expired = state.messages.filter(
      (message) => message.expiresAt && message.expiresAt <= Date.now()
    );
    for (const message of expired) {
      await expireMessage(message.id, true);
    }
  }, 10_000);
}

async function expireMessage(messageId, notifyPeer) {
  const index = state.messages.findIndex((message) => message.id === messageId);
  if (index === -1) return;
  state.messages.splice(index, 1);
  await deleteMessage(state.roomId, messageId);
  renderMessages();
  if (notifyPeer && state.secureReady) {
    try {
      await sendEncrypted({ kind: "expired", messageId });
    } catch {
      // The peer will still expire the message using its shared expiration time.
    }
  }
}

function applySavedTheme() {
  const saved = localStorage.getItem("hush-theme");
  const theme =
    saved || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  document.documentElement.dataset.theme = theme;
  document.querySelector('meta[name="theme-color"]').content =
    theme === "dark" ? "#111b17" : "#f7f9f8";
}

function toggleTheme() {
  const theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = theme;
  localStorage.setItem("hush-theme", theme);
  document.querySelector('meta[name="theme-color"]').content =
    theme === "dark" ? "#111b17" : "#f7f9f8";
}

function setupPin() {
  elements.newPin.value = "";
  elements.confirmPin.value = "";
  elements.pinError.textContent = "";
  closeModal(elements.settingsModal);
  openModal(elements.pinModal);
  requestAnimationFrame(() => elements.newPin.focus());
}

async function savePin(event) {
  event.preventDefault();
  const first = elements.newPin.value;
  const second = elements.confirmPin.value;
  if (!/^\d{4,12}$/.test(first)) {
    elements.pinError.textContent = "Use 4–12 digits.";
    return;
  }
  if (first !== second) {
    elements.pinError.textContent = "The PINs do not match.";
    return;
  }
  savePinRecord(await createPinRecord(first));
  updateLockControls();
  closeModal(elements.pinModal);
  showToast("Quick-lock is enabled.");
}

function lockApp() {
  if (!getPinRecord()) {
    openModal(elements.settingsModal);
    showToast("Set a PIN before using quick lock.");
    return;
  }
  state.locked = true;
  elements.unlockPin.value = "";
  elements.unlockError.textContent = "";
  elements.lockScreen.hidden = false;
  requestAnimationFrame(() => elements.unlockPin.focus());
}

async function unlockWithPin(event) {
  event.preventDefault();
  const record = getPinRecord();
  const valid = await verifyPin(elements.unlockPin.value, record);
  if (!valid) {
    elements.unlockError.textContent = "Incorrect PIN";
    elements.unlockPin.select();
    return;
  }
  unlockApp();
}

function unlockApp() {
  state.locked = false;
  elements.lockScreen.hidden = true;
  elements.unlockError.textContent = "";
}

async function enableBiometric() {
  if (!window.PublicKeyCredential || !getPinRecord()) {
    showToast("Set a quick-lock PIN first, and use a browser with device unlock support.");
    return;
  }
  try {
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: randomBytes(32),
        rp: { name: "Hush Private Chat" },
        user: {
          id: randomBytes(16),
          name: "local-hush-user",
          displayName: "Hush device owner"
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 }
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          userVerification: "required",
          residentKey: "discouraged"
        },
        timeout: 60_000,
        attestation: "none"
      }
    });
    saveBiometricCredential(bytesToBase64Url(new Uint8Array(credential.rawId)));
    updateLockControls();
    showToast("Device unlock is enabled.");
  } catch {
    showToast("Device unlock was not enabled.");
  }
}

async function unlockWithBiometric() {
  const credentialId = getBiometricCredential();
  if (!credentialId) return;
  try {
    await navigator.credentials.get({
      publicKey: {
        challenge: randomBytes(32),
        allowCredentials: [
          { type: "public-key", id: base64UrlToBytes(credentialId) }
        ],
        userVerification: "required",
        timeout: 60_000
      }
    });
    unlockApp();
  } catch {
    elements.unlockError.textContent = "Device unlock was cancelled";
  }
}

function updateLockControls() {
  const hasPin = Boolean(getPinRecord());
  const hasBiometric = Boolean(getBiometricCredential());
  elements.pinSetupButton.textContent = hasPin ? "Change PIN" : "Set PIN";
  elements.biometricButton.textContent = hasBiometric ? "Enabled" : "Enable";
  elements.biometricButton.disabled = hasBiometric;
  elements.biometricUnlock.hidden = !hasBiometric;
}

function openModal(modal) {
  modal.hidden = false;
}

function closeModal(modal) {
  modal.hidden = true;
}

function showToast(message) {
  clearTimeout(state.toastTimer);
  elements.toast.textContent = message;
  elements.toast.classList.add("visible");
  state.toastTimer = setTimeout(() => elements.toast.classList.remove("visible"), 2800);
}

function disconnect() {
  resetCallUi();
  state.peer?.close();
  state.signaling?.close();
  state.peer = null;
  state.signaling = null;
}
