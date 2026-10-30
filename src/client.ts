import { EventEmitter } from "node:events";
import { WebSocket } from "ws";
import { record, type Api, type Frame } from "./protocol.js";

const API_CODES: Readonly<Record<string, true>> = {
  UNKNOWN_CHAT: true, INVALID_REQUEST: true, RATE_LIMITED: true, SEND_FAILED: true,
  SCAM_CHECK_FAILED: true, SCAM_CHECK_UNAVAILABLE: true, UNKNOWN_TYPE: true,
  CHAT_ADMINS_FAILED: true, CHAT_ADMINS_UNSUPPORTED: true, AVATAR_CHECK_FAILED: true, AVATAR_CHECK_UNAVAILABLE: true,
  MEMBERSHIP_FAILED: true, MEMBERSHIP_UNSUPPORTED: true,
};

export class ApiError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

/** No cookies, Origin, LINE session, or Jev token cross this boundary. */
export class ApiClient extends EventEmitter implements Api {
  private socket?: WebSocket;
  // Correlation is socket-local, not authentication. Never reuse IDs after a timeout.
  private nextRequestId = 0n;
  private pending = new Map<string, {
    responseType: string;
    resolve: (frame: Frame) => void;
    reject: (error: Error) => void;
    timer: NodeJS.Timeout;
  }>();

  constructor(private readonly url: string, private readonly token: string, private readonly timeoutMs = 25_000) {
    super();
  }

  async connect(): Promise<void> {
    if (this.socket) throw new Error("ALREADY_CONNECTED");
    const socket = new WebSocket(this.url, {
      headers: { Authorization: `Bearer ${this.token}` },
      followRedirects: false,
      maxPayload: 256 * 1024,
      handshakeTimeout: this.timeoutMs,
    });
    this.socket = socket;
    socket.on("message", (bytes, binary) => {
      let frame: Frame;
      try {
        const parsed: unknown = JSON.parse(bytes.toString());
        if (binary || !record(parsed) || typeof parsed.type !== "string") throw new Error("frame");
        frame = parsed as Frame;
      } catch {
        this.emit("fault", "INVALID_SERVER_FRAME");
        this.close();
        return;
      }
      const requestId = frame.requestId;
      const request = typeof requestId === "string" ? this.pending.get(requestId) : undefined;
      if (request && requestId) {
        clearTimeout(request.timer);
        this.pending.delete(requestId);
        if (frame.type === "error") {
          request.reject(new ApiError(typeof frame.code === "string" && Object.hasOwn(API_CODES, frame.code) ? frame.code : "API_REQUEST_FAILED"));
        } else if (frame.type !== request.responseType) {
          request.reject(new ApiError("UNEXPECTED_RESPONSE"));
        } else {
          request.resolve(frame);
        }
      }
      this.emit("frame", frame);
    });
    socket.on("error", () => this.emit("fault", "WS_TRANSPORT_FAILED"));
    socket.on("close", (code) => {
      this.rejectPending();
      this.emit("disconnected", code);
    });
    const { promise, resolve, reject } = Promise.withResolvers<void>();
    const opened = () => { cleanup(); resolve(); };
    const failed = () => { cleanup(); reject(new ApiError("WS_CONNECT_FAILED")); };
    const cleanup = () => {
      socket.off("open", opened);
      socket.off("error", failed);
      socket.off("close", failed);
    };
    socket.once("open", opened);
    socket.once("error", failed);
    socket.once("close", failed);
    await promise;
  }

  request(type: string, fields: Record<string, unknown>, responseType: string): Promise<Frame> {
    const socket = this.socket;
    if (!socket || socket.readyState !== WebSocket.OPEN) return Promise.reject(new ApiError("WS_DISCONNECTED"));
    const requestId = (++this.nextRequestId).toString(36);
    let payload: string;
    try {
      // Serialization can fail before any bytes are sent; do not leave an orphaned
      // pending promise or timeout when fields contain cycles, BigInt, or getters.
      payload = JSON.stringify({ ...fields, type, requestId });
    } catch {
      return Promise.reject(new ApiError("INVALID_REQUEST"));
    }
    const { promise, resolve, reject } = Promise.withResolvers<Frame>();
    const timer = setTimeout(() => {
      this.pending.delete(requestId);
      // A timed-out send might already have reached LINE: never resend it automatically.
      reject(new ApiError("REQUEST_TIMEOUT"));
    }, this.timeoutMs);
    this.pending.set(requestId, { responseType, resolve, reject, timer });
    socket.send(payload, (error) => {
      if (!error || !this.pending.delete(requestId)) return;
      clearTimeout(timer);
      reject(new ApiError("WS_SEND_FAILED"));
    });
    return promise;
  }

  close(): void {
    this.rejectPending();
    this.socket?.terminate();
  }

  private rejectPending(): void {
    for (const request of this.pending.values()) {
      clearTimeout(request.timer);
      request.reject(new ApiError("WS_DISCONNECTED"));
    }
    this.pending.clear();
  }
}
