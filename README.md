# Hush

Hush is a private, two-device chat built with browser-native cryptography and WebRTC. It supports encrypted text, image sharing, disappearing messages, and peer-to-peer audio/video calls.

## Run it

```bash
npm install
npm run dev
```

Open `http://localhost:4173`, choose **Pair a device**, and open the generated link in a second browser profile or device.

For a production build:

```bash
npm run build
npm start
```

Deploy behind HTTPS. Web Crypto, WebRTC, clipboard access, and platform biometric prompts require a secure context (localhost is treated as secure during development).

For a real long-distance deployment with HTTPS and TURN relay support, use the included Docker setup:

```bash
cp .env.production.example .env
docker compose --env-file .env up -d --build
```

See [REAL_LONG_DISTANCE_DEPLOY.md](REAL_LONG_DISTANCE_DEPLOY.md) for DNS, firewall, and VPS setup.

## Long-distance connectivity

The app works over the internet as long as both devices can reach the same deployed server URL. The Node server is a zero-log signaling relay for pairing, SDP, and ICE messages only.

By default the server publishes public STUN servers. For restrictive mobile networks, office Wi-Fi, or carrier-grade NAT, deploy a TURN server.

The production Docker setup runs coturn and uses expiring TURN credentials generated from `TURN_AUTH_SECRET`. If you run your own TURN server manually, start Hush with:

```bash
TURN_URLS=turn:turn.example.com:3478?transport=udp,turn:turn.example.com:3478?transport=tcp TURN_AUTH_SECRET=your-coturn-auth-secret npm start
```

Use `TURN_URLS` as a comma-separated list if you have multiple TURN transports.

## Privacy model

- The URL fragment contains a random 256-bit pairing secret. URL fragments are not sent in HTTP requests. A SHA-256-derived room identifier is sent to the signaling server.
- The signaling server keeps only an in-memory set of at most two sockets per room. It relays SDP and ICE negotiation data and never receives chat messages.
- Active invitation room IDs can be invalidated in relay memory with **New link**, and each device pins the peer's RSA public key after the first successful handshake.
- Text and image messages travel over a WebRTC data channel and receive an additional application encryption layer using AES-256-GCM.
- Images are split into encrypted chunks before peer transfer, then encrypted again at rest with local history in IndexedDB.
- Each device creates a non-extractable RSA-OAEP private key. The initiator creates an ephemeral AES session key and wraps it with the peer's RSA public key.
- Local history is encrypted with a separate, non-extractable AES-256-GCM `CryptoKey` before being written to IndexedDB.
- Message text is inserted into the page with `textContent`, not HTML.
- Audio and video calls use WebRTC media tracks, which browsers encrypt with DTLS-SRTP. TURN servers can relay packets but cannot read call media.

## Important limits

- WebRTC peers necessarily learn each other's network metadata. The configured public STUN service can also observe connection metadata, but not message content.
- A TURN server is not bundled. Some restrictive networks will require one; TURN can relay encrypted WebRTC packets but adds a metadata observer.
- There is no offline queue because the server stores nothing. Both devices must be online to receive a new message.
- The PIN gates the interface. It is PBKDF2-hashed locally, but it is not a full operating-system disk-encryption boundary.
- Compare the displayed peer-key fingerprint on both devices through a separate trusted channel if protection against an active key-substitution attack is required.
- This is a reference implementation and has not undergone an independent professional security audit.
