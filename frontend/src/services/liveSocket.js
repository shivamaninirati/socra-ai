// Freeze a direct reference to the browser's raw, un-overridden native WebSocket constructor.
// This prevents Vite's development HMR client from intercepting our query configurations.
const NativeWebSocket = window.WebSocket || WebSocket;

// Native WebSocket readyState constants for clarity:
// 0: CONNECTING
// 1: OPEN
// 2: CLOSING
// 3: CLOSED

// Resolve the WebSocket base URL (scheme + host, no path) from the environment.
// VITE_WS_URL wins when set; otherwise the host is derived from the API base
// URL so http → ws and https → wss automatically (WSS in production).
function resolveWsBase() {
  const configured = import.meta.env.VITE_WS_URL;
  if (configured) return String(configured).replace(/\/+$/, "");

  const apiBase = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";
  try {
    const url = new URL(apiBase);
    const scheme = url.protocol === "https:" ? "wss:" : "ws:";
    return `${scheme}//${url.host}`;
  } catch {
    return "ws://127.0.0.1:8000";
  }
}

class LiveSocket {
  constructor() {
    this.socket = null;
    this.listeners = [];
    this.connected = false;
    this.connectionState = "disconnected"; // 'connecting' | 'connected' | 'disconnected' | 'reconnecting'
    this.heartbeat = null;
    this.reconnectTimeout = null;
    this.reconnectAttempts = 0;
    this.maxReconnectDelay = 30000; // 30 seconds max
    this.baseReconnectDelay = 1000; // 1 second initial
    this._destroyed = false;
  }

  connect() {
    // An explicit connect() call always means "the app wants a live socket
    // now". Reset any prior hard teardown (_destroyed) so a fresh login (or a
    // StrictMode remount) can establish a new connection after destroy().
    if (this._destroyed) {
      this._destroyed = false;
    }

    // ONE controlled connection per session: never stack a second socket on
    // top of one that is already CONNECTING or OPEN.
    if (this.socket) {
      const rs = this.socket.readyState;
      if (rs === NativeWebSocket.CONNECTING || rs === NativeWebSocket.OPEN) {
        console.log(`[LiveSocket] Connect skipped - socket already ${rs === NativeWebSocket.CONNECTING ? "CONNECTING" : "OPEN"}`);
        return;
      }
      // Stale CLOSING/CLOSED socket: detach its late callbacks so they cannot
      // fire into the lifecycle of the fresh connection being created below.
      const stale = this.socket;
      this.socket = null;
      stale.onopen = stale.onmessage = stale.onclose = stale.onerror = null;
    }

    if (this.connectionState === "connecting" || this.connectionState === "reconnecting") {
      console.log(`[LiveSocket] Connect skipped - already in ${this.connectionState} state`);
      return;
    }

    this.connectionState = "connecting";

    const token = localStorage.getItem("token");

    // Environment-driven WebSocket endpoint (VITE_WS_URL), defaulting to the
    // API base host (https → wss in production, no hardcoded URLs).
    const wsBase = resolveWsBase();

    // Never send the JWT over an insecure WebSocket when the app itself is
    // served over HTTPS — a ws:// downgrade would leak the token. Without the
    // token the server rejects the handshake (4401), the correct fail-safe
    // until a secure endpoint is configured.
    const pageIsSecure = typeof window !== "undefined" && window.location.protocol === "https:";
    const wsIsSecure = wsBase.startsWith("wss:");
    const canAttachToken = Boolean(token) && (!pageIsSecure || wsIsSecure);

    if (token && pageIsSecure && !wsIsSecure) {
      console.warn(
        "⚠️ Refusing to send JWT over an insecure WebSocket. " +
        "Configure VITE_WS_URL with wss:// for HTTPS deployments."
      );
    }

    // The JWT travels as a WebSocket subprotocol (Sec-WebSocket-Protocol
    // header) — never in the URL — so it cannot leak into access/proxy logs.
    const wsUrl = `${wsBase}/live/live`;
    const protocols = canAttachToken ? [token] : [];

    try {
      // Force use of the isolated native browser constructor. The JWT (when
      // allowed) is offered as the WebSocket subprotocol for the handshake.
      this.socket = new NativeWebSocket(wsUrl, protocols);

      this.socket.onopen = () => {
        console.log("✅ Live SOC Connected Successfully");
        this.connected = true;
        this.connectionState = "connected";
        this.reconnectAttempts = 0;
        this.startHeartbeat();
        this._notifyListeners({ type: "connection", status: "connected" });
      };

      this.socket.onmessage = (event) => {
        try {
          if (event.data === "heartbeat" || event.data === "pong") return;

          const data = JSON.parse(event.data);

          this.listeners.forEach((listener) => {
            try {
              listener(data);
            } catch (listenerError) {
              console.error("❌ Subscriber Context Update Error:", listenerError);
            }
          });
        } catch {
          // Gracefully skip raw non-JSON traffic strings
        }
      };

      this.socket.onclose = (event) => {
        console.log(`❌ Live SOC Disconnected (Code: ${event.code}, Reason: ${event.reason || "No reason provided"})`);
        console.log(`[WebSocketClose] wasClean: ${event.wasClean}, current readyState: ${this.socket?.readyState}`);
        this.connected = false;
        this.connectionState = "disconnected";
        this.stopHeartbeat();
        this.socket = null;
        this._notifyListeners({ type: "connection", status: "disconnected" });

        if (!this._destroyed && !this.reconnectTimeout) {
          this._scheduleReconnect();
        }
      };

      this.socket.onerror = () => {
        console.error("❌ WebSocket error occurred");
        console.log(`[WebSocketError] Socket readyState at error: ${this.socket?.readyState}`);
        // CRITICAL: never call close() on a CONNECTING socket from onerror.
        // Doing so makes Chrome log "WebSocket is closed before the connection
        // is established" and produces a synthetic 1006 close. A failed
        // handshake already fires onclose on its own, which drives reconnect.
        // Only an OPEN socket is closed explicitly here (rare); CONNECTING
        // sockets are left for the browser to settle and fire onclose.
        if (this.socket && this.socket.readyState === NativeWebSocket.OPEN) {
          this.socket.close();
        }
      };
    } catch (connectionError) {
      console.error("❌ Failed to initialize clean WebSocket connection:", connectionError);
      this.connectionState = "disconnected";
      if (!this._destroyed && !this.reconnectTimeout) {
        this._scheduleReconnect();
      }
    }
  }

  _scheduleReconnect() {
    this.reconnectAttempts++;
    this.connectionState = "reconnecting";
    this._notifyListeners({ type: "connection", status: "reconnecting" });

    // Exponential backoff with jitter
    const delay = Math.min(
      this.baseReconnectDelay * Math.pow(2, this.reconnectAttempts - 1),
      this.maxReconnectDelay
    );
    const jitter = delay * (0.5 + Math.random() * 0.5);

    console.log(`🔌 Reconnecting in ${Math.round(jitter)}ms (attempt ${this.reconnectAttempts})`);

    this.reconnectTimeout = setTimeout(() => {
      this.reconnectTimeout = null;
      // A reconnect timer firing IS the intent to connect. Clear the
      // 'reconnecting' marker first, otherwise connect() skips itself
      // ("already in reconnecting state") and the socket never reconnects.
      this.connectionState = "disconnected";
      this.connect();
    }, jitter);
  }

  startHeartbeat() {
    this.stopHeartbeat();
    this.heartbeat = setInterval(() => {
      if (this.socket && this.socket.readyState === NativeWebSocket.OPEN) {
        // Send as raw text "heartbeat" to match backend's expected format
        this.socket.send("heartbeat");
      }
    }, 10000);
  }

  stopHeartbeat() {
    if (this.heartbeat) {
      clearInterval(this.heartbeat);
      this.heartbeat = null;
    }
  }

  subscribe(callback) {
    if (!this.listeners.includes(callback)) {
      this.listeners.push(callback);
    }
  }

  unsubscribe(callback) {
    this.listeners = this.listeners.filter((listener) => listener !== callback);
  }

  _notifyListeners(data) {
    this.listeners.forEach((listener) => {
      try {
        listener(data);
      } catch (e) {
        console.error("❌ Listener error:", e);
      }
    });
  }

  // Hard teardown: closes the socket and permanently blocks auto-reconnect.
  // Used on a genuine unmount of the authenticated layout (logout) so the
  // reconnect loop cannot hammer the server without a token. The instance
  // stays reusable — a later explicit connect() re-arms it (_destroyed=false).
  destroy() {
    this._destroyed = true;
    this.stopHeartbeat();
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    if (this.socket) {
      const socket = this.socket;
      this.socket = null;
      // Detach late callbacks before closing so the close event cannot
      // schedule a reconnect or notify listeners after teardown.
      socket.onopen = socket.onmessage = socket.onclose = socket.onerror = null;
      try {
        // Only close an OPEN socket gracefully. Closing a CONNECTING socket
        // triggers the browser's "WebSocket is closed before the connection is
        // established" console error — detach first, then close anyway during
        // a deliberate teardown; the detached callbacks make it inert.
        socket.close();
      } catch (e) {
        // Socket already closed or aborting — nothing to do.
      }
    }
    this.connected = false;
    this.connectionState = "disconnected";
    this.listeners = [];
  }

  // Soft teardown used on logout / unmount of the authenticated layout.
  // Closes the socket and stops all timers so we never reconnect with a dead
  // or missing token — but unlike destroy(), the instance stays reusable and
  // a fresh login can simply connect() again.
  disconnect() {
    this.stopHeartbeat();
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    this.connected = false;
    this.connectionState = "disconnected";
  }
}

const liveSocket = new LiveSocket();
export default liveSocket;