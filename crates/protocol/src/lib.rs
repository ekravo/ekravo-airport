//! Ekravo Airport wire protocol, version 1.
//!
//! Airport relays opaque application messages between a browser/client and a
//! locally running device. Every WebSocket text frame is one JSON object with a
//! `v` version and a `type` discriminator:
//!
//! ```json
//! { "v": 1, "type": "msg", "msgId": "…", "to": { "kind": "device", "id": "dev_…" } }
//! ```
//!
//! The protocol is deliberately small: Airport validates structure, size, and
//! authorization, but never needs to understand `payload`. When `enc` is
//! present the payload is base64 ciphertext for the recipient's X25519 key and
//! the server cannot read it (see [`crypto`]).
//!
//! Delivery to devices is at-least-once. A sender chooses a `msgId`, Airport
//! stores it once per sender, and a device deduplicates replayed messages by
//! that id. Messages to live client connections are best-effort.

pub mod codec;
pub mod crypto;
pub mod error;
pub mod frame;
pub mod ids;
pub mod message;
pub mod server;

pub use codec::{decode_client_frame, encode_frame, ClientFrame};
pub use crypto::{
    validate_encryption, validate_public_key, E2EE_ALG, E2EE_CONTEXT, NONCE_BYTES, PUBLIC_KEY_BYTES,
};
pub use error::{ErrorCode, ProtocolError};
pub use frame::{FrameHeader, DEFAULT_HEARTBEAT_MS, MAX_PROTOCOL_FRAME_BYTES, PROTOCOL_VERSION};
pub use message::{
    AckFrame, ContentType, Encryption, HelloFrame, MessageTarget, OutboundMessage, PingFrame,
    TargetKind,
};
pub use server::{
    AckReceipt, ConnectionKind, DeliveredFrame, ErrorFrame, Limits, MessageOrigin, PongFrame,
    PresenceFrame, PresenceStatus, ReceiptStatus, RelayedMessage, ReplacedFrame, RevokedFrame,
    WelcomeFrame,
};
