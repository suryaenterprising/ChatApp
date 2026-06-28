export class SignalingClient extends EventTarget {
  constructor(roomId) {
    super();
    this.roomId = roomId;
    this.socket = null;
    this.closedIntentionally = false;
    this.reconnectTimer = null;
  }

  connect() {
    clearTimeout(this.reconnectTimer);
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    this.socket = new WebSocket(`${protocol}//${location.host}/signal`);

    this.socket.addEventListener("open", () => {
      this.socket.send(JSON.stringify({ type: "join", roomId: this.roomId }));
    });

    this.socket.addEventListener("message", (event) => {
      try {
        const message = JSON.parse(event.data);
        this.dispatchEvent(new CustomEvent(message.type, { detail: message }));
      } catch {
        this.dispatchEvent(new Event("protocol-error"));
      }
    });

    this.socket.addEventListener("close", () => {
      this.dispatchEvent(new Event("disconnected"));
      if (!this.closedIntentionally) {
        this.reconnectTimer = setTimeout(() => this.connect(), 1800);
      }
    });
  }

  sendSignal(data) {
    if (this.socket?.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify({ type: "signal", data }));
    }
  }

  invalidate() {
    if (this.socket?.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify({ type: "invalidate" }));
    }
    this.closedIntentionally = true;
  }

  close() {
    this.closedIntentionally = true;
    clearTimeout(this.reconnectTimer);
    this.socket?.close();
  }
}
