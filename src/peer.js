export class PeerTransport extends EventTarget {
  constructor(signaling, role, iceServers) {
    super();
    this.signaling = signaling;
    this.role = role;
    this.iceServers = iceServers;
    this.connection = null;
    this.channel = null;
    this.pendingCandidates = [];
    this.makingOffer = false;
    this.ignoreOffer = false;
    this.polite = role === "receiver";
    this.boundSignalHandler = (event) => this.handleSignal(event.detail.data);
  }

  start() {
    this.signaling.addEventListener("signal", this.boundSignalHandler);
    this.createConnection();
  }

  createConnection() {
    this.closeConnection();
    this.connection = new RTCPeerConnection({
      iceServers: this.iceServers,
      iceCandidatePoolSize: 4
    });

    this.connection.addEventListener("icecandidate", ({ candidate }) => {
      if (candidate) this.signaling.sendSignal({ candidate });
    });

    this.connection.addEventListener("connectionstatechange", () => {
      const state = this.connection?.connectionState;
      this.dispatchEvent(new CustomEvent("statechange", { detail: state }));
      if (state === "failed") this.connection.restartIce();
    });

    this.connection.addEventListener("negotiationneeded", async () => {
      try {
        this.makingOffer = true;
        await this.connection.setLocalDescription();
        this.signaling.sendSignal({ description: this.connection.localDescription });
      } finally {
        this.makingOffer = false;
      }
    });

    this.connection.addEventListener("datachannel", (event) => {
      this.attachChannel(event.channel);
    });

    this.connection.addEventListener("track", (event) => {
      const stream = event.streams[0] || new MediaStream([event.track]);
      this.dispatchEvent(new CustomEvent("remotestream", { detail: stream }));
    });

    if (this.role === "initiator") {
      this.attachChannel(
        this.connection.createDataChannel("hush-secure", {
          ordered: true
        })
      );
    }
  }

  async handleSignal({ description, candidate }) {
    if (!this.connection) this.createConnection();

    try {
      if (description) {
        const offerCollision =
          description.type === "offer" &&
          (this.makingOffer || this.connection.signalingState !== "stable");
        this.ignoreOffer = !this.polite && offerCollision;
        if (this.ignoreOffer) return;

        await this.connection.setRemoteDescription(description);
        for (const queuedCandidate of this.pendingCandidates.splice(0)) {
          await this.connection.addIceCandidate(queuedCandidate);
        }
        if (description.type === "offer") {
          await this.connection.setLocalDescription();
          this.signaling.sendSignal({ description: this.connection.localDescription });
        }
      } else if (candidate) {
        if (this.connection.remoteDescription) {
          await this.connection.addIceCandidate(candidate);
        } else {
          this.pendingCandidates.push(candidate);
        }
      }
    } catch (error) {
      if (!this.ignoreOffer) {
        this.dispatchEvent(new CustomEvent("error", { detail: error }));
      }
    }
  }

  attachChannel(channel) {
    this.channel = channel;
    this.channel.addEventListener("open", () => this.dispatchEvent(new Event("open")));
    this.channel.addEventListener("close", () => this.dispatchEvent(new Event("close")));
    this.channel.addEventListener("message", (event) => {
      try {
        this.dispatchEvent(new CustomEvent("message", { detail: JSON.parse(event.data) }));
      } catch {
        this.dispatchEvent(new Event("protocol-error"));
      }
    });
  }

  send(payload) {
    if (this.channel?.readyState !== "open") {
      throw new Error("Peer channel is not open");
    }
    this.channel.send(JSON.stringify(payload));
  }

  async waitForWritable() {
    if (!this.channel || this.channel.readyState !== "open") {
      throw new Error("Peer channel is not open");
    }
    if (this.channel.bufferedAmount < 512 * 1024) return;
    this.channel.bufferedAmountLowThreshold = 128 * 1024;
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        cleanup();
        reject(new Error("Peer channel stayed congested"));
      }, 15_000);
      const onLow = () => {
        cleanup();
        resolve();
      };
      const cleanup = () => {
        clearTimeout(timeout);
        this.channel?.removeEventListener("bufferedamountlow", onLow);
      };
      this.channel.addEventListener("bufferedamountlow", onLow, { once: true });
    });
  }

  async addLocalStream(stream) {
    if (!this.connection) throw new Error("Peer connection is unavailable");
    for (const track of stream.getTracks()) {
      const sender = this.connection.getSenders().find(
        (candidate) => candidate.track?.kind === track.kind
      );
      if (sender) {
        await sender.replaceTrack(track);
      } else {
        this.connection.addTrack(track, stream);
      }
    }
  }

  removeLocalStream() {
    if (!this.connection) return;
    for (const sender of this.connection.getSenders()) {
      if (sender.track) this.connection.removeTrack(sender);
    }
  }

  closeConnection() {
    this.channel?.close();
    this.connection?.close();
    this.channel = null;
    this.connection = null;
    this.pendingCandidates = [];
  }

  close() {
    this.signaling.removeEventListener("signal", this.boundSignalHandler);
    this.closeConnection();
  }
}
