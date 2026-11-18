use serde::{Deserialize, Serialize};

use crate::error::ErrorCode;
use crate::frame::PROTOCOL_VERSION;
use crate::message::{ContentType, Encryption};

/// Whether a connection is a browser/application client or a paired device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionKind {
    Client,
    Device,
}

impl ConnectionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ConnectionKind::Client => "client",
            ConnectionKind::Device => "device",
        }
    }
}

/// Policy the peer must respect, advertised once in `welcome`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    pub max_payload_bytes: usize,
    pub max_queue_depth: usize,
    pub messages_per_second: u32,
    pub heartbeat_ms: u64,
}

/// First frame after a successful upgrade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WelcomeFrame {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub protocol_version: u32,
    pub connection_id: String,
    pub user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub role: ConnectionKind,
    pub server_time: i64,
    pub limits: Limits,
}

impl WelcomeFrame {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connection_id: String,
        user_id: String,
        device_id: Option<String>,
        role: ConnectionKind,
        server_time: i64,
        limits: Limits,
    ) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            kind: "welcome".into(),
            protocol_version: PROTOCOL_VERSION,
            connection_id,
            user_id,
            device_id,
            role,
            server_time,
            limits,
        }
    }
}

/// Who sent a relayed message, as established by Airport rather than claimed by
/// the peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageOrigin {
    pub user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    pub connection_id: String,
    /// Sender's long-term X25519 public key, if it advertised one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

/// A message delivered to its recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayedMessage {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub delivery_id: String,
    pub msg_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<i64>,
    pub from: MessageOrigin,
    pub event: String,
    pub payload: String,
    pub content_type: ContentType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc: Option<Encryption>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

impl RelayedMessage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        delivery_id: String,
        msg_id: String,
        seq: Option<i64>,
        from: MessageOrigin,
        event: String,
        payload: String,
        content_type: ContentType,
        enc: Option<Encryption>,
        reply_to: Option<String>,
        created_at: i64,
        expires_at: Option<i64>,
    ) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            kind: "msg".into(),
            delivery_id,
            msg_id,
            seq,
            from,
            event,
            payload,
            content_type,
            enc,
            reply_to,
            created_at,
            expires_at,
        }
    }
}

/// Status reported to the sender for a message it submitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReceiptStatus {
    /// Stored; the device is offline or the write is still in flight.
    Queued,
    /// Written to a live socket.
    Delivered,
    /// Already stored from this sender with this `msgId`; not sent again.
    Duplicate,
}

/// Immediate acknowledgement of a submitted message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AckReceipt {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub delivery_id: String,
    pub msg_id: String,
    pub status: ReceiptStatus,
    pub queued: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<i64>,
    pub at: i64,
}

impl AckReceipt {
    pub fn new(
        delivery_id: String,
        msg_id: String,
        status: ReceiptStatus,
        seq: Option<i64>,
        at: i64,
    ) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            kind: "ack".into(),
            delivery_id,
            msg_id,
            status,
            queued: status == ReceiptStatus::Queued,
            seq,
            at,
        }
    }
}

/// Sent to the original sender once the recipient acks a stored message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveredFrame {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub delivery_id: String,
    pub msg_id: String,
    pub at: i64,
}

impl DeliveredFrame {
    pub fn new(delivery_id: String, msg_id: String, at: i64) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            kind: "delivered".into(),
            delivery_id,
            msg_id,
            at,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresenceStatus {
    Online,
    Offline,
}

/// Broadcast to a device owner's client connections when a device connects or
/// disconnects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceFrame {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub device_id: String,
    pub status: PresenceStatus,
    pub at: i64,
}

impl PresenceFrame {
    pub fn new(device_id: String, status: PresenceStatus, at: i64) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            kind: "presence".into(),
            device_id,
            status,
            at,
        }
    }
}

/// A recoverable frame-level error. `fatal` means the server will close.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorFrame {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msg_id: Option<String>,
    pub fatal: bool,
}

impl ErrorFrame {
    pub fn new(code: ErrorCode, message: impl Into<String>, msg_id: Option<String>) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            kind: "error".into(),
            code,
            message: message.into(),
            msg_id,
            fatal: false,
        }
    }

    pub fn fatal(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            kind: "error".into(),
            code,
            message: message.into(),
            msg_id: None,
            fatal: true,
        }
    }
}

/// Answer to an application `ping`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PongFrame {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub at: i64,
}

impl PongFrame {
    pub fn new(at: i64) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            kind: "pong".into(),
            at,
        }
    }
}

/// The device credential was revoked while connected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokedFrame {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub reason: String,
}

impl RevokedFrame {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            kind: "revoked".into(),
            reason: reason.into(),
        }
    }
}

/// A newer socket took over this device. The old process must not reconnect and
/// fight for the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplacedFrame {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String,
}

impl ReplacedFrame {
    pub fn new() -> Self {
        Self {
            v: PROTOCOL_VERSION,
            kind: "replaced".into(),
        }
    }
}

impl Default for ReplacedFrame {
    fn default() -> Self {
        Self::new()
    }
}
