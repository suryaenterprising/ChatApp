# Real long-distance deployment

This setup is for using Hush between two people on different networks, cities, or countries.

For reliable long-distance WebRTC, you need three public pieces:

1. A domain for the web app, for example `chat.example.com`.
2. A domain for TURN relay, for example `turn.example.com`.
3. A VPS/public server with a static public IPv4 address.

Both DNS records can point to the same VPS.

## 1. DNS

Create these `A` records:

```text
chat.example.com  -> your VPS public IP
turn.example.com  -> your VPS public IP
```

Wait until DNS resolves before starting the stack.

## 2. Firewall ports

Open these inbound ports on the VPS and in the cloud firewall:

```text
80/tcp              HTTPS certificate challenge
443/tcp             Hush web app
3478/tcp            TURN over TCP
3478/udp            TURN over UDP
49160-49200/udp     TURN relay media/data ports
```

UDP matters. If UDP is blocked, video/audio may connect slowly or fail on some networks.

## 3. Configure environment

Copy the example file:

```bash
cp .env.production.example .env
```

Edit `.env`:

```bash
APP_DOMAIN=chat.example.com
TURN_DOMAIN=turn.example.com
PUBLIC_IP=your.vps.public.ip
ACME_EMAIL=you@example.com
TURN_AUTH_SECRET=replace-with-output-of-openssl-rand-base64-32
TURN_TTL_SECONDS=86400
```

Generate the TURN secret:

```bash
openssl rand -base64 32
```

Do not share `TURN_AUTH_SECRET`. The browser never receives it. The Node server uses it to create short-lived TURN credentials.

## 4. Start production stack

Install Docker and Docker Compose on the VPS, then run:

```bash
docker compose --env-file .env up -d --build
```

Check logs:

```bash
docker compose logs -f
```

Open:

```text
https://chat.example.com
```

## 5. Test real long-distance pairing

1. Open `https://chat.example.com` on device A.
2. Tap **Pair a device**.
3. Send the generated link to device B.
4. Open it on device B.
5. Send a text message, share an image, then test audio/video.

If text works but calls/images fail, TURN/firewall is the first thing to check.

## 6. Production notes

- Caddy terminates HTTPS and proxies WebSocket signaling to the Node app.
- The Node app still stores no chat history server-side.
- coturn relays encrypted WebRTC packets when direct peer-to-peer paths fail.
- TURN can observe metadata such as IP addresses and timing, but not plaintext chat, images, or call media.
- For more than two active users or larger public usage, widen the TURN relay port range and add abuse monitoring/rate limiting.

## Quick health checks

From your laptop:

```bash
curl https://chat.example.com/config
```

You should see STUN plus TURN entries. The TURN username should include an expiry timestamp, and the credential should change over time.

On the VPS:

```bash
docker compose ps
docker compose logs caddy
docker compose logs coturn
docker compose logs hush-app
```
