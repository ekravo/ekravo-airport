export type TargetKind = "device" | "connection" | "user";

export interface MessageTarget {
  kind: TargetKind;
  id: string;
}

export type ContentType = "json" | "text" | "binary";

/** Forwarded verbatim by Airport; only the endpoints can read the payload. */
export interface EncryptionHeader {
  alg: string;
  epk: string;
  nonce: string;
  /** How to interpret the decrypted bytes; the wire contentType is `binary`. */
  plainType?: ContentType;
}

export interface Limits {
  maxPayloadBytes: number;
  maxQueueDepth: number;
  messagesPerSecond: number;
  heartbeatMs: number;
}

export interface WelcomeFrame {
  v: 1;
  type: "welcome";
  protocolVersion: number;
  connectionId: string;
  userId: string;
  deviceId?: string;
  role: "client" | "device";
  serverTime: number;
  limits: Limits;
}

export interface MessageOrigin {
  userId: string;
  deviceId?: string;
  deviceName?: string;
  connectionId: string;
  publicKey?: string;
}

export interface IncomingMessage {
  v: 1;
  type: "msg";
  deliveryId: string;
  msgId: string;
  seq?: number;
  from: MessageOrigin;
  event: string;
  payload: string;
  contentType: ContentType;
  enc?: EncryptionHeader;
  replyTo?: string;
  createdAt: number;
  expiresAt?: number;
}

export type ReceiptStatus = "queued" | "delivered" | "duplicate";

export interface AckFrame {
  v: 1;
  type: "ack";
  deliveryId: string;
  msgId: string;
  status: ReceiptStatus;
  queued: boolean;
  seq?: number;
  at: number;
}

export interface DeliveredFrame {
  v: 1;
  type: "delivered";
  deliveryId: string;
  msgId: string;
  at: number;
}

export interface PresenceFrame {
  v: 1;
  type: "presence";
  deviceId: string;
  status: "online" | "offline";
  at: number;
}

export interface ServerErrorFrame {
  v: 1;
  type: "error";
  code: string;
  message: string;
  msgId?: string;
  fatal: boolean;
}

export interface PongFrame {
  v: 1;
  type: "pong";
  at: number;
}

export type ServerFrame =
  | WelcomeFrame
  | IncomingMessage
  | AckFrame
  | DeliveredFrame
  | PresenceFrame
  | ServerErrorFrame
  | PongFrame
  | { v: 1; type: "revoked"; reason: string }
  | { v: 1; type: "replaced" };

export interface User {
  id: string;
  email: string;
  displayName?: string;
  createdAt: string;
}

export interface AuthResult {
  user: User;
  accessToken: string;
  refreshToken: string;
  tokenType: string;
  expiresIn: number;
}

export interface Device {
  id: string;
  name: string;
  platform?: string;
  publicKey?: string;
  online: boolean;
  createdAt: string;
  lastSeenAt?: string;
}

export interface SharedDevice extends Device {
  ownerName?: string;
  grantId: string;
  allowedEvents: string[];
}

export interface PairingCode {
  code: string;
  expiresAt: string;
}

export interface Ticket {
  ticket: string;
  kind: "client" | "device";
  expiresAt: string;
  path: string;
  url?: string;
}

export interface Grant {
  id: string;
  deviceId: string;
  deviceName: string;
  granteeEmail?: string;
  label?: string;
  allowedEvents: string[];
  createdAt: string;
}
