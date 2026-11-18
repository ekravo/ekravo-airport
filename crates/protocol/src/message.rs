use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::crypto::{validate_encryption, validate_public_key};
use crate::error::ProtocolError;
use crate::frame::PROTOCOL_VERSION;
use crate::ids::{valid_event, valid_id};

/// Where a message should be delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    /// A registered device. Persisted and delivered at-least-once.
    Device,
    /// One live WebSocket connection. Best-effort.
    Connection,
    /// Every live client connection belonging to a user. Best-effort.
    User,
}

/// The address of a relayed message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageTarget {
    pub kind: TargetKind,
    pub id: String,
}

impl MessageTarget {
    pub fn device(id: impl Into<String>) -> Self {
        Self {
            kind: TargetKind::Device,
            id: id.into(),
        }
    }

    pub fn connection(id: impl Into<String>) -> Self {
        Self {
            kind: TargetKind::Connection,
            id: id.into(),
        }
    }

    pub fn user(id: impl Into<String>) -> Self {
        Self {
            kind: TargetKind::User,
            id: id.into(),
        }
    }
}

/// How the receiver should interpret `payload`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ContentType {
    /// A JSON document. SDKs parse it before handing it to the application.
    #[default]
    Json,
    /// A UTF-8 string.
    Text,
    /// Base64 bytes. Also used for ciphertext when `enc` is present.
    Binary,
}

/// End-to-end encryption metadata. Airport forwards this object untouched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Encryption {
    /// Always [`crate::crypto::E2EE_ALG`] in version 1.
    pub alg: String,
    /// Base64 X25519 ephemeral public key of the sender.
    pub epk: String,
    /// Base64 12-byte AES-GCM nonce.
    pub nonce: String,
    /// How to interpret the decrypted bytes: `json`, `text`, or `binary`.
    /// The wire `contentType` is always `binary` for ciphertext, so this is the
    /// only way a receiver knows what the plaintext means.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plain_type: Option<ContentType>,
}

/// First frame a client or device may send. Optional: `welcome` already
/// identifies the session, but a `hello` advertises the peer's long-term public
/// key so the other side can encrypt replies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelloFrame {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

impl HelloFrame {
    pub fn new() -> Self {
        Self {
            v: PROTOCOL_VERSION,
            kind: "hello".into(),
            client_version: None,
            platform: None,
            public_key: None,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if let Some(key) = &self.public_key {
            validate_public_key(key)?;
        }
        for value in [&self.client_version, &self.platform].into_iter().flatten() {
            if value.len() > 64 {
                return Err(ProtocolError::Invalid(
                    "client metadata must be 64 characters or fewer".into(),
                ));
            }
        }
        Ok(())
    }
}

impl Default for HelloFrame {
    fn default() -> Self {
        Self::new()
    }
}

/// Relay a message. `msg_id` is the idempotency key for device deliveries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundMessage {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String,
    /// Sender-chosen idempotency key, e.g. a UUID.
    pub msg_id: String,
    pub to: MessageTarget,
    /// Application-defined event name, e.g. `chat.send`.
    pub event: String,
    /// Payload text. JSON, plain text, or base64 ciphertext.
    pub payload: String,
    #[serde(default)]
    pub content_type: ContentType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc: Option<Encryption>,
    /// Message id this one answers, for request/response flows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    /// How long Airport should keep the message for an offline device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_ms: Option<u64>,
}

impl OutboundMessage {
    pub fn new(
        msg_id: impl Into<String>,
        to: MessageTarget,
        event: impl Into<String>,
        payload: impl Into<String>,
    ) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            kind: "msg".into(),
            msg_id: msg_id.into(),
            to,
            event: event.into(),
            payload: payload.into(),
            content_type: ContentType::Json,
            enc: None,
            reply_to: None,
            ttl_ms: None,
        }
    }

    /// Validate everything Airport relies on. The payload itself stays opaque.
    pub fn validate(&self, max_payload_bytes: usize) -> Result<(), ProtocolError> {
        if !valid_id(&self.msg_id) {
            return Err(ProtocolError::Invalid(
                "msgId must be 1-128 characters of [A-Za-z0-9._:-]".into(),
            ));
        }
        if !valid_id(&self.to.id) {
            return Err(ProtocolError::Invalid(
                "to.id must be 1-128 characters of [A-Za-z0-9._:-]".into(),
            ));
        }
        if !valid_event(&self.event) || self.event.contains('*') {
            return Err(ProtocolError::Invalid(
                "event must be 1-128 characters of [A-Za-z0-9._:-]".into(),
            ));
        }
        if let Some(reply_to) = &self.reply_to {
            if !valid_id(reply_to) {
                return Err(ProtocolError::Invalid(
                    "replyTo must be a valid message id".into(),
                ));
            }
        }
        if self.payload.len() > max_payload_bytes {
            return Err(ProtocolError::PayloadTooLarge {
                limit: max_payload_bytes,
            });
        }
        if let Some(ttl) = self.ttl_ms {
            if ttl == 0 || ttl > 7 * 24 * 60 * 60 * 1000 {
                return Err(ProtocolError::Invalid(
                    "ttlMs must be between 1 and 604800000".into(),
                ));
            }
        }
        match &self.enc {
            Some(enc) => {
                if self.content_type != ContentType::Binary {
                    return Err(ProtocolError::InvalidEncryption(
                        "encrypted messages must use contentType `binary`".into(),
                    ));
                }
                validate_encryption(enc, &self.payload)?;
            }
            None => {
                if self.content_type == ContentType::Binary
                    && base64::engine::general_purpose::STANDARD
                        .decode(&self.payload)
                        .is_err()
                {
                    return Err(ProtocolError::Invalid(
                        "binary messages must carry standard base64 payloads".into(),
                    ));
                }
                if self.content_type == ContentType::Json
                    && serde_json::from_str::<serde_json::Value>(&self.payload).is_err()
                {
                    return Err(ProtocolError::Invalid(
                        "contentType `json` requires a JSON payload".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Receiver acknowledgement. Devices ack with `seq` to confirm a mailbox entry;
/// clients ack to tell the sender a live message arrived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AckFrame {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub msg_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<i64>,
}

impl AckFrame {
    pub fn new(msg_id: impl Into<String>) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            kind: "ack".into(),
            msg_id: msg_id.into(),
            seq: None,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if !valid_id(&self.msg_id) {
            return Err(ProtocolError::Invalid("msgId is not valid".into()));
        }
        Ok(())
    }
}

/// Application-level liveness probe; the server answers `pong`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PingFrame {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String,
}

impl PingFrame {
    pub fn new() -> Self {
        Self {
            v: PROTOCOL_VERSION,
            kind: "ping".into(),
        }
    }
}

impl Default for PingFrame {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn sample() -> OutboundMessage {
        OutboundMessage::new(
            "m-1",
            MessageTarget::device("dev_abc"),
            "chat.send",
            r#"{"text":"hi"}"#,
        )
    }

    #[test]
    fn accepts_a_well_formed_message() {
        assert!(sample().validate(1024).is_ok());
    }

    #[test]
    fn rejects_oversized_payload() {
        let mut message = sample();
        message.payload = "x".repeat(64);
        assert!(matches!(
            message.validate(32),
            Err(ProtocolError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_bad_target_and_event() {
        let mut message = sample();
        message.to.id = "../secrets".into();
        assert!(message.validate(1024).is_err());

        let mut message = sample();
        message.event = "bad event".into();
        assert!(message.validate(1024).is_err());
    }

    #[test]
    fn encrypted_messages_must_be_binary_and_well_formed() {
        let mut message = sample();
        message.enc = Some(Encryption {
            alg: crate::crypto::E2EE_ALG.into(),
            epk: base64::engine::general_purpose::STANDARD.encode([5u8; 32]),
            nonce: base64::engine::general_purpose::STANDARD.encode([2u8; 12]),
            plain_type: Some(ContentType::Json),
        });
        assert!(message.validate(1024).is_err()); // still contentType json

        message.content_type = ContentType::Binary;
        message.payload = base64::engine::general_purpose::STANDARD.encode([0u8; 40]);
        assert!(message.validate(1024).is_ok());
    }
}
