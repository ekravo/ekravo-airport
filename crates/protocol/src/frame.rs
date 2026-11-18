use serde::{Deserialize, Serialize};

/// The only protocol version this release speaks. A server that answers
/// `unsupported_version` wants a newer client; there is no negotiation.
pub const PROTOCOL_VERSION: u32 = 1;

/// Absolute ceiling for one WebSocket text frame, enforced by both ends before
/// buffering. Individual deployments can set a lower payload limit.
pub const MAX_PROTOCOL_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Default server heartbeat interval advertised in `welcome`.
pub const DEFAULT_HEARTBEAT_MS: u64 = 25_000;

/// The two fields every frame shares. Parsing this first lets a peer reject an
/// unknown frame without materializing a large body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameHeader {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String,
}
