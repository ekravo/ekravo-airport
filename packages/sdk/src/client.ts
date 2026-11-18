import {
  bytesToText,
  exportSecret,
  fromBase64,
  generateIdentity,
  open,
  seal,
  toBase64,
  type Identity,
} from "./crypto.js";
import { AirportApiError, AirportSocketError } from "./errors.js";
import type {
  AckFrame,
  AuthResult,
  ContentType,
  DeliveredFrame,
  Device,
  EncryptionHeader,
  Grant,
  IncomingMessage,
  MessageOrigin,
  MessageTarget,
  PairingCode,
  PresenceFrame,
  ServerFrame,
  SharedDevice,
  Ticket,
  User,
  WelcomeFrame,
} from "./types.js";

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export type WebSocketConstructor = new (url: string) => WebSocket;

export interface AirportClientOptions {
  /** Origin of the Airport server, e.g. `https://airport.example.com`. */
  baseUrl: string;
  fetch?: FetchLike;
  /** Override for runtimes without a global WebSocket. */
  WebSocket?: WebSocketConstructor;
  accessToken?: string;
  refreshToken?: string;
  /** Reuse a persisted identity so peers can encrypt replies across reloads. */
  identity?: Identity;
  clientVersion?: string;
  /** Per-request HTTP deadline, including reading the response body. */
  requestTimeoutMs?: number;
  /** How long to wait for the WebSocket handshake and first `welcome`. */
  connectTimeoutMs?: number;
  /** Called whenever tokens are issued, rotated, or cleared, for persistence. */
  onTokens?: (tokens: {
    accessToken?: string;
    refreshToken?: string;
    expiresIn?: number;
  }) => void;
}

export interface TokenState {
  accessToken?: string;
  refreshToken?: string;
}

async function parseBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function combineSignals(
  ...signals: Array<AbortSignal | null | undefined>
): AbortSignal {
  const present = signals.filter((signal): signal is AbortSignal => signal != null);
  if (present.length === 0) return new AbortController().signal;
  if (present.length === 1) return present[0]!;
  if (typeof AbortSignal.any === "function") return AbortSignal.any(present);

  // `AbortSignal.any` is available in modern browsers and Node 20.3+, but keep
  // a small fallback for older runtimes that still satisfy the SDK's engines.
  const controller = new AbortController();
  const abort = (signal: AbortSignal) => controller.abort(signal.reason);
  for (const signal of present) {
    if (signal.aborted) {
      abort(signal);
      break;
    }
    signal.addEventListener("abort", () => abort(signal), { once: true });
  }
  return controller.signal;
}

async function withTimeout<T>(
  timeoutMs: number,
  operation: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(
        new AirportApiError(
          0,
          "timeout",
          `the request timed out after ${timeoutMs} ms`,
        ),
      );
    }, timeoutMs);
  });
  try {
    return await Promise.race([operation(controller.signal), deadline]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function webSocketBase(baseUrl: string): string {
  return baseUrl.replace(/^http/, "ws").replace(/\/+$/, "");
}

function newMessageId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return `msg_${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function encodeData(data: unknown): { payload: string; contentType: ContentType } {
  if (data === undefined) return { payload: "", contentType: "text" };
  if (typeof data === "string") return { payload: data, contentType: "text" };
  if (data instanceof Uint8Array) {
    return { payload: toBase64(data), contentType: "binary" };
  }
  return { payload: JSON.stringify(data) ?? "null", contentType: "json" };
}

function plaintextBytes(data: unknown): Uint8Array {
  if (data === undefined) return new Uint8Array();
  if (typeof data === "string") return new TextEncoder().encode(data);
  if (data instanceof Uint8Array) return data;
  return new TextEncoder().encode(JSON.stringify(data) ?? "null");
}

export interface SendOptions {
  to: MessageTarget;
  event: string;
  data?: unknown;
  /** Recipient's long-term X25519 public key; enables end-to-end encryption. */
  encryptWith?: string;
  replyTo?: string;
  msgId?: string;
  ttlMs?: number;
}

export interface DecodedMessage {
  msgId: string;
  event: string;
  data: unknown;
  encrypted: boolean;
  from: MessageOrigin;
  replyTo?: string;
  seq?: number;
  deliveryId: string;
  raw: IncomingMessage;
}

export type ConnectionState = "connecting" | "open" | "reconnecting" | "closed";

export interface ConnectionEvents {
  open: WelcomeFrame;
  message: DecodedMessage;
  ack: AckFrame;
  delivered: DeliveredFrame;
  presence: PresenceFrame;
  error: AirportSocketError;
  close: { reconnecting: boolean };
  state: ConnectionState;
}

export interface ConnectionOptions {
  autoReconnect?: boolean;
  autoAck?: boolean;
  reconnectMinMs?: number;
  reconnectMaxMs?: number;
}

/**
 * One authenticated client session.
 *
 * The socket reconnects on its own and requests a fresh single-use ticket each
 * time. Delivery to devices is at-least-once; this class deduplicates incoming
 * `msgId`s so application handlers see each message once per session.
 */
export class AirportConnection {
  readonly ready: Promise<WelcomeFrame>;

  private socket?: WebSocket;
  private connectTimer?: ReturnType<typeof setTimeout>;
  private state: ConnectionState = "connecting";
  private closed = false;
  private opened = false;
  private attempts = 0;
  private heartbeat?: ReturnType<typeof setInterval>;
  private reconnectTimer?: ReturnType<typeof setTimeout>;
  private listeners = new Map<string, Set<(payload: any) => void>>();
  private pending = new Map<
    string,
    {
      resolve: (message: DecodedMessage) => void;
      reject: (error: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  private seen = new Set<string>();
  private readyResolve!: (welcome: WelcomeFrame) => void;
  private readyReject!: (error: Error) => void;

  constructor(
    private readonly client: AirportClient,
    private readonly options: ConnectionOptions = {},
  ) {
    this.ready = new Promise<WelcomeFrame>((resolve, reject) => {
      this.readyResolve = resolve;
      this.readyReject = reject;
    });
    // A rejection only matters to callers who await `ready`; attach a no-op
    // handler so an unobserved close never becomes an unhandled rejection.
    this.ready.catch(() => undefined);
    void this.openSocket();
  }

  get currentState(): ConnectionState {
    return this.state;
  }

  on<K extends keyof ConnectionEvents>(
    event: K,
    handler: (payload: ConnectionEvents[K]) => void,
  ): () => void {
    let handlers = this.listeners.get(event);
    if (!handlers) {
      handlers = new Set();
      this.listeners.set(event, handlers);
    }
    handlers.add(handler as (payload: any) => void);
    return () => handlers?.delete(handler as (payload: any) => void);
  }

  /** Send a message. Returns the id used for acknowledgements and replies. */
  send(options: SendOptions): string {
    if (this.state !== "open") {
      throw new Error("the connection is not open");
    }
    const msgId = options.msgId ?? newMessageId();
    const encoded = encodeData(options.data);
    let payload = encoded.payload;
    let contentType = encoded.contentType;
    let enc: EncryptionHeader | undefined;

    if (options.encryptWith) {
      const sealed = seal(
        options.encryptWith,
        plaintextBytes(options.data),
        msgId,
        options.event,
      );
      payload = sealed.payload;
      contentType = "binary";
      enc = { ...sealed.enc, plainType: encoded.contentType };
    }

    const frame: Record<string, unknown> = {
      v: 1,
      type: "msg",
      msgId,
      to: options.to,
      event: options.event,
      payload,
      contentType,
    };
    if (enc) frame.enc = enc;
    if (options.replyTo) frame.replyTo = options.replyTo;
    if (options.ttlMs !== undefined) frame.ttlMs = options.ttlMs;

    this.sendFrame(frame);
    return msgId;
  }

  /** Send and wait for a message whose `replyTo` is this request. */
  request(options: SendOptions & { timeoutMs?: number }): Promise<DecodedMessage> {
    const msgId = newMessageId();
    const timeoutMs = options.timeoutMs ?? 30_000;
    const promise = new Promise<DecodedMessage>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(msgId);
        reject(new Error(`request ${msgId} timed out`));
      }, timeoutMs);
      this.pending.set(msgId, { resolve, reject, timer });
    });
    try {
      this.send({ ...options, msgId });
    } catch (error) {
      this.rejectPending(msgId, error as Error);
    }
    return promise;
  }

  /** Answer a received message on the connection that sent it. */
  reply(
    message: DecodedMessage | IncomingMessage,
    data?: unknown,
    options: { event?: string; encrypt?: boolean; ttlMs?: number } = {},
  ): string {
    const from = message.from;
    if (!from.connectionId) {
      throw new Error("the message has no return connection");
    }
    const defaultEvent =
      message.event && `${message.event}.reply`.length <= 128
        ? `${message.event}.reply`
        : "reply";
    return this.send({
      to: { kind: "connection", id: from.connectionId },
      event: options.event ?? defaultEvent,
      data,
      replyTo: message.msgId,
      encryptWith: options.encrypt === false ? undefined : from.publicKey,
      ttlMs: options.ttlMs,
    });
  }

  ack(msgId: string, seq?: number): void {
    const frame: Record<string, unknown> = { v: 1, type: "ack", msgId };
    if (seq !== undefined) frame.seq = seq;
    this.sendFrame(frame);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.stopHeartbeat();
    this.clearConnectTimer();
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    const socket = this.socket;
    this.socket = undefined;
    if (socket) {
      try {
        socket.close(1000, "client closed");
      } catch {
        // The socket may already be closed.
      }
    }
    this.rejectAll(new Error("the connection was closed"));
    if (!this.opened) {
      this.readyReject(new Error("the connection was closed before it opened"));
    }
    this.setState("closed");
    this.emit("close", { reconnecting: false });
  }

  private async openSocket(): Promise<void> {
    if (this.closed) return;
    this.setState(this.attempts === 0 ? "connecting" : "reconnecting");

    let ticket: Ticket;
    try {
      ticket = await this.client.createTicket("client");
    } catch (error) {
      // Bad or expired credentials will never recover by retrying. Stop and
      // surface a fatal error instead of reconnecting forever.
      if (
        error instanceof AirportApiError &&
        (error.status === 401 || error.status === 403)
      ) {
        this.closed = true;
        this.stopHeartbeat();
        this.clearConnectTimer();
        this.setState("closed");
        const fatal = new AirportSocketError("unauthorized", error.message, undefined, true);
        this.emit("error", fatal);
        this.readyReject(fatal);
        this.emit("close", { reconnecting: false });
        return;
      }
      this.scheduleReconnect(error);
      return;
    }
    if (this.closed) return;

    const url = ticket.url ?? `${webSocketBase(this.client.baseUrl)}${ticket.path}`;
    let socket: WebSocket;
    try {
      socket = this.client.webSocket(url);
    } catch (error) {
      this.scheduleReconnect(error);
      return;
    }
    this.socket = socket;
    this.clearConnectTimer();
    this.connectTimer = setTimeout(() => {
      this.connectTimer = undefined;
      if (this.closed || this.state === "open" || !this.socket) return;
      this.emit(
        "error",
        new AirportSocketError(
          "connect_timeout",
          `the WebSocket did not open within ${this.client.connectTimeoutMs} ms`,
        ),
      );
      try {
        this.socket.close();
      } catch {
        // The close handler still runs when the socket is already closing.
      }
    }, this.client.connectTimeoutMs);

    socket.addEventListener("open", () => {
      this.sendFrame({
        v: 1,
        type: "hello",
        clientVersion: this.client.clientVersion,
        publicKey: this.client.publicKey,
      });
    });
    socket.addEventListener("message", (event) => {
      this.onFrame(String(event.data));
    });
    socket.addEventListener("close", () => this.onSocketClosed());
    socket.addEventListener("error", () => {
      // A close event follows; reconnect is handled there.
    });
  }

  private onFrame(raw: string): void {
    let frame: ServerFrame;
    try {
      frame = JSON.parse(raw) as ServerFrame;
    } catch {
      this.emit(
        "error",
        new AirportSocketError("invalid_frame", "the server sent a non-JSON frame"),
      );
      return;
    }

    switch (frame.type) {
      case "welcome":
        this.clearConnectTimer();
        this.opened = true;
        this.attempts = 0;
        this.setState("open");
        this.startHeartbeat(frame.limits.heartbeatMs);
        this.readyResolve(frame);
        this.emit("open", frame);
        break;
      case "msg":
        this.handleMessage(frame);
        break;
      case "ack":
        this.emit("ack", frame);
        break;
      case "delivered":
        this.emit("delivered", frame);
        break;
      case "presence":
        this.emit("presence", frame);
        break;
      case "pong":
        break;
      case "error": {
        const error = new AirportSocketError(
          frame.code,
          frame.message,
          frame.msgId,
          frame.fatal,
        );
        if (frame.msgId) this.rejectPending(frame.msgId, error);
        this.emit("error", error);
        break;
      }
      case "revoked":
        this.emit(
          "error",
          new AirportSocketError("revoked", frame.reason || "the device was revoked", undefined, true),
        );
        this.close();
        break;
      case "replaced":
        this.close();
        break;
      default:
        break;
    }
  }

  private handleMessage(frame: IncomingMessage): void {
    // Two senders may reuse a msgId; Airport keys idempotency by sender and id.
    const dedupeKey = `${frame.from.userId}|${frame.from.deviceId ?? ""}|${frame.msgId}`;
    if (this.seen.has(dedupeKey)) {
      // Ack again: a replay means the previous ack did not reach the server.
      if (this.options.autoAck !== false) this.ack(frame.msgId, frame.seq);
      return;
    }
    // Bounded so a long-lived session cannot grow without limit. Recent ids,
    // which are the ones that can be replayed, stay in the set.
    if (this.seen.size >= 4096) this.seen.clear();
    this.seen.add(dedupeKey);
    if (this.options.autoAck !== false) this.ack(frame.msgId, frame.seq);

    let decoded: DecodedMessage;
    try {
      decoded = this.decode(frame);
    } catch (error) {
      this.emit(
        "error",
        new AirportSocketError(
          "decrypt_failed",
          error instanceof Error ? error.message : "the message could not be decrypted",
          frame.msgId,
        ),
      );
      return;
    }

    if (frame.replyTo) {
      const pending = this.pending.get(frame.replyTo);
      if (pending) {
        clearTimeout(pending.timer);
        this.pending.delete(frame.replyTo);
        pending.resolve(decoded);
      }
    }
    this.emit("message", decoded);
  }

  private decode(frame: IncomingMessage): DecodedMessage {
    let data: unknown;
    if (frame.enc) {
      const bytes = open(
        this.client.identity,
        frame.enc,
        frame.payload,
        frame.msgId,
        frame.event,
      );
      // The wire contentType is `binary`; the sender declares the plaintext
      // type inside the encryption header. Older senders default to text.
      const plainType = frame.enc.plainType ?? "text";
      if (plainType === "json") {
        data = JSON.parse(bytesToText(bytes));
      } else if (plainType === "text") {
        data = bytesToText(bytes);
      } else {
        data = bytes;
      }
    } else if (frame.contentType === "json") {
      data = JSON.parse(frame.payload);
    } else if (frame.contentType === "binary") {
      data = fromBase64(frame.payload);
    } else {
      data = frame.payload;
    }

    return {
      msgId: frame.msgId,
      event: frame.event,
      data,
      encrypted: Boolean(frame.enc),
      from: frame.from,
      replyTo: frame.replyTo,
      seq: frame.seq,
      deliveryId: frame.deliveryId,
      raw: frame,
    };
  }

  private sendFrame(frame: Record<string, unknown>): void {
    const socket = this.socket;
    if (!socket || socket.readyState !== 1) {
      throw new Error("the connection is not open");
    }
    socket.send(JSON.stringify(frame));
  }

  private onSocketClosed(): void {
    this.clearConnectTimer();
    this.stopHeartbeat();
    this.socket = undefined;
    this.rejectAll(new Error("the connection dropped"));
    if (this.closed) {
      this.setState("closed");
      return;
    }
    this.setState("reconnecting");
    this.emit("close", { reconnecting: true });
    this.scheduleReconnect(new Error("the connection dropped"));
  }

  private scheduleReconnect(_reason: unknown): void {
    if (this.closed) return;
    if (this.options.autoReconnect === false) {
      this.closed = true;
      if (!this.opened) {
        this.readyReject(new Error("the connection closed before it opened"));
      }
      this.setState("closed");
      this.emit("close", { reconnecting: false });
      return;
    }
    if (this.reconnectTimer) return;
    const base = this.options.reconnectMinMs ?? 500;
    const max = this.options.reconnectMaxMs ?? 30_000;
    const delay = Math.min(max, base * 2 ** this.attempts) + Math.random() * 250;
    this.attempts += 1;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      void this.openSocket();
    }, delay);
  }

  private startHeartbeat(intervalMs: number): void {
    this.stopHeartbeat();
    const period = Math.max(5_000, Math.min(intervalMs || 25_000, 30_000));
    this.heartbeat = setInterval(() => {
      try {
        this.sendFrame({ v: 1, type: "ping" });
      } catch {
        // The close handler will reconnect.
      }
    }, period);
    (this.heartbeat as { unref?: () => void }).unref?.();
  }

  private stopHeartbeat(): void {
    if (this.heartbeat) {
      clearInterval(this.heartbeat);
      this.heartbeat = undefined;
    }
  }

  private clearConnectTimer(): void {
    if (this.connectTimer) {
      clearTimeout(this.connectTimer);
      this.connectTimer = undefined;
    }
  }

  private rejectPending(msgId: string, error: Error): void {
    const pending = this.pending.get(msgId);
    if (!pending) return;
    clearTimeout(pending.timer);
    this.pending.delete(msgId);
    pending.reject(error);
  }

  private rejectAll(error: Error): void {
    for (const [msgId, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.reject(error);
      this.pending.delete(msgId);
    }
  }

  private setState(state: ConnectionState): void {
    if (this.state === state) return;
    this.state = state;
    this.emit("state", state);
  }

  private emit<K extends keyof ConnectionEvents>(
    event: K,
    payload: ConnectionEvents[K],
  ): void {
    const handlers = this.listeners.get(event);
    if (!handlers) return;
    for (const handler of handlers) {
      try {
        handler(payload);
      } catch {
        // A listener must not break the socket loop.
      }
    }
  }
}

/** Authenticated HTTP client and connection factory. */
export class AirportClient {
  readonly baseUrl: string;
  readonly identity: Identity;
  readonly publicKey: string;
  readonly webSocket: (url: string) => WebSocket;
  readonly clientVersion: string;
  readonly requestTimeoutMs: number;
  readonly connectTimeoutMs: number;

  private readonly fetchImpl: FetchLike;
  private refreshPromise?: Promise<void>;
  private readonly onTokens?: AirportClientOptions["onTokens"];
  private accessToken?: string;
  private refreshToken?: string;

  constructor(options: AirportClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.identity = options.identity ?? generateIdentity();
    this.publicKey = this.identity.publicKey;
    this.clientVersion = options.clientVersion ?? "airport-sdk/0.1.0";
    this.requestTimeoutMs =
      options.requestTimeoutMs !== undefined &&
      Number.isFinite(options.requestTimeoutMs) &&
      options.requestTimeoutMs > 0
        ? options.requestTimeoutMs
        : 30_000;
    this.connectTimeoutMs =
      options.connectTimeoutMs !== undefined &&
      Number.isFinite(options.connectTimeoutMs) &&
      options.connectTimeoutMs > 0
        ? options.connectTimeoutMs
        : 15_000;
    this.accessToken = options.accessToken;
    this.refreshToken = options.refreshToken;
    this.onTokens = options.onTokens;

    const fetchImpl = options.fetch ?? globalThis.fetch?.bind(globalThis);
    if (!fetchImpl) {
      throw new Error("no fetch implementation is available");
    }
    this.fetchImpl = fetchImpl;

    const WebSocketImpl =
      options.WebSocket ??
      (globalThis.WebSocket as unknown as WebSocketConstructor | undefined);
    if (!WebSocketImpl) {
      throw new Error("no WebSocket implementation is available");
    }
    this.webSocket = (url: string) => new WebSocketImpl(url);
  }

  get tokens(): TokenState {
    return { accessToken: this.accessToken, refreshToken: this.refreshToken };
  }

  /** The base64 secret, for persisting this client's identity yourself. */
  exportIdentity(): string {
    return exportSecret(this.identity);
  }

  setTokens(accessToken: string, refreshToken?: string): void {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
  }

  async register(
    email: string,
    password: string,
    displayName?: string,
  ): Promise<AuthResult> {
    const result = await this.request<AuthResult>(
      "/api/v1/auth/register",
      {
        method: "POST",
        body: JSON.stringify({ email, password, displayName }),
      },
      false,
    );
    this.applyAuth(result);
    return result;
  }

  async login(email: string, password: string): Promise<AuthResult> {
    const result = await this.request<AuthResult>(
      "/api/v1/auth/login",
      { method: "POST", body: JSON.stringify({ email, password }) },
      false,
    );
    this.applyAuth(result);
    return result;
  }

  /**
   * Rotate the refresh token. Called automatically after a 401.
   *
   * Concurrent 401s share one rotation. Without this, two requests would present
   * the same refresh token, the server would treat the second as token theft, and
   * the whole token family would be revoked.
   */
  async refreshSession(): Promise<void> {
    if (!this.refreshPromise) {
      this.refreshPromise = this.performRefresh().finally(() => {
        this.refreshPromise = undefined;
      });
    }
    return this.refreshPromise;
  }

  private async performRefresh(): Promise<void> {
    if (!this.refreshToken) {
      throw new AirportApiError(401, "unauthorized", "no refresh token is available");
    }
    const result = await this.request<{
      accessToken: string;
      refreshToken: string;
      expiresIn: number;
    }>(
      "/api/v1/auth/refresh",
      {
        method: "POST",
        body: JSON.stringify({ refreshToken: this.refreshToken }),
      },
      false,
    );
    this.accessToken = result.accessToken;
    this.refreshToken = result.refreshToken;
    this.onTokens?.({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      expiresIn: result.expiresIn,
    });
  }

  async logout(): Promise<void> {
    const refreshToken = this.refreshToken;
    // Clear local state first: a failed network call must not leave a usable
    // access token behind in memory.
    this.accessToken = undefined;
    this.refreshToken = undefined;
    this.onTokens?.({});
    if (!refreshToken) return;
    await this.request<void>(
      "/api/v1/auth/logout",
      { method: "POST", body: JSON.stringify({ refreshToken }) },
      false,
    );
  }

  async me(): Promise<{ user: User; devices: number }> {
    return this.request("/api/v1/me");
  }

  async listDevices(): Promise<Device[]> {
    const result = await this.request<{ devices: Device[] }>("/api/v1/devices");
    return result.devices;
  }

  async listSharedDevices(): Promise<SharedDevice[]> {
    const result = await this.request<{ devices: SharedDevice[] }>(
      "/api/v1/devices/shared",
    );
    return result.devices;
  }

  async createPairingCode(name: string, platform?: string): Promise<PairingCode> {
    return this.request("/api/v1/devices/pairing", {
      method: "POST",
      body: JSON.stringify({ name, platform }),
    });
  }

  async revokeDevice(deviceId: string): Promise<void> {
    await this.request(`/api/v1/devices/${encodeURIComponent(deviceId)}`, {
      method: "DELETE",
    });
  }

  async rotateDeviceCredential(
    deviceId: string,
  ): Promise<{ device: Device; credential: string }> {
    return this.request(`/api/v1/devices/${encodeURIComponent(deviceId)}/rotate`, {
      method: "POST",
      body: "{}",
    });
  }

  async listGrants(): Promise<{ owned: Grant[]; received: Grant[] }> {
    return this.request("/api/v1/grants");
  }

  async createGrant(input: {
    deviceId: string;
    granteeEmail: string;
    label?: string;
    allowedEvents?: string[];
  }): Promise<Grant> {
    return this.request("/api/v1/grants", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async revokeGrant(grantId: string): Promise<void> {
    await this.request(`/api/v1/grants/${encodeURIComponent(grantId)}`, {
      method: "DELETE",
    });
  }

  async createTicket(kind: "client" | "device" = "client"): Promise<Ticket> {
    return this.request("/api/v1/tickets", {
      method: "POST",
      body: JSON.stringify({ kind }),
    });
  }

  /** Open a live session, reconnecting until `close()` is called. */
  connect(options: ConnectionOptions = {}): AirportConnection {
    return new AirportConnection(this, options);
  }

  private applyAuth(result: AuthResult): void {
    this.accessToken = result.accessToken;
    this.refreshToken = result.refreshToken;
    this.onTokens?.({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      expiresIn: result.expiresIn,
    });
  }

  private async request<T>(
    path: string,
    init: RequestInit = {},
    authenticated = true,
    allowRefresh = true,
  ): Promise<T> {
    const headers = new Headers(init.headers);
    if (init.body !== undefined) headers.set("content-type", "application/json");
    if (authenticated && this.accessToken) {
      headers.set("authorization", `Bearer ${this.accessToken}`);
    }

    // Keep the deadline active while the body is read, not only until the
    // response headers arrive: a peer can otherwise send headers and stall.
    const { response, body } = await withTimeout(this.requestTimeoutMs, async (timeoutSignal) => {
      const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        ...init,
        headers,
        signal: combineSignals(init.signal, timeoutSignal),
      });
      return { response, body: await parseBody(response) };
    });

    if (response.status === 401 && authenticated && allowRefresh && this.refreshToken) {
      await this.refreshSession();
      return this.request<T>(path, init, authenticated, false);
    }

    if (!response.ok) {
      const detail = body as { error?: { code?: string; message?: string } } | undefined;
      throw new AirportApiError(
        response.status,
        detail?.error?.code ?? "http_error",
        detail?.error?.message ?? response.statusText,
      );
    }
    return body as T;
  }
}

export interface PairDeviceOptions {
  baseUrl: string;
  code: string;
  name: string;
  platform?: string;
  publicKey?: string;
  fetch?: FetchLike;
  /** Overall HTTP deadline, including reading the response body. */
  timeoutMs?: number;
}

/**
 * Exchange a pairing code for a device credential. Useful for a JavaScript
 * device runtime; browser pages normally create the code, not consume it.
 */
export async function pairDevice(
  options: PairDeviceOptions,
): Promise<{ device: Device; credential: string }> {
  const fetchImpl = options.fetch ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) throw new Error("no fetch implementation is available");
  const timeoutMs =
    options.timeoutMs !== undefined &&
    Number.isFinite(options.timeoutMs) &&
    options.timeoutMs > 0
      ? options.timeoutMs
      : 30_000;
  const { response, body } = await withTimeout(timeoutMs, async (timeoutSignal) => {
    const response = await fetchImpl(
      `${options.baseUrl.replace(/\/+$/, "")}/api/v1/devices/pair`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          code: options.code,
          name: options.name,
          platform: options.platform,
          publicKey: options.publicKey,
        }),
        signal: timeoutSignal,
      },
    );
    return { response, body: await parseBody(response) };
  });
  if (!response.ok) {
    const detail = body as { error?: { code?: string; message?: string } } | undefined;
    throw new AirportApiError(
      response.status,
      detail?.error?.code ?? "http_error",
      detail?.error?.message ?? response.statusText,
    );
  }
  return body as { device: Device; credential: string };
}
