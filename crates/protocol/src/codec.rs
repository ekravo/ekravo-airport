use serde::Serialize;

use crate::error::ProtocolError;
use crate::frame::{FrameHeader, MAX_PROTOCOL_FRAME_BYTES, PROTOCOL_VERSION};
use crate::message::{AckFrame, HelloFrame, OutboundMessage, PingFrame};

/// A validated frame received from a client or device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientFrame {
    Hello(HelloFrame),
    Message(OutboundMessage),
    Ack(AckFrame),
    Ping(PingFrame),
}

/// Parse one inbound text frame.
///
/// The frame is rejected before the body is decoded if it is too large or speaks
/// another version. Unknown frame types are rejected rather than ignored, so a
/// silent typo cannot look like success.
pub fn decode_client_frame(
    raw: &str,
    max_payload_bytes: usize,
) -> Result<ClientFrame, ProtocolError> {
    if raw.len() > MAX_PROTOCOL_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            limit: MAX_PROTOCOL_FRAME_BYTES,
        });
    }
    let header: FrameHeader =
        serde_json::from_str(raw).map_err(|error| ProtocolError::Invalid(error.to_string()))?;
    if header.v != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(header.v));
    }
    match header.kind.as_str() {
        "hello" => {
            let frame: HelloFrame =
                serde_json::from_str(raw).map_err(|e| ProtocolError::Invalid(e.to_string()))?;
            frame.validate()?;
            Ok(ClientFrame::Hello(frame))
        }
        "msg" => {
            let frame: OutboundMessage =
                serde_json::from_str(raw).map_err(|e| ProtocolError::Invalid(e.to_string()))?;
            frame.validate(max_payload_bytes)?;
            Ok(ClientFrame::Message(frame))
        }
        "ack" => {
            let frame: AckFrame =
                serde_json::from_str(raw).map_err(|e| ProtocolError::Invalid(e.to_string()))?;
            frame.validate()?;
            Ok(ClientFrame::Ack(frame))
        }
        "ping" => {
            let frame: PingFrame =
                serde_json::from_str(raw).map_err(|e| ProtocolError::Invalid(e.to_string()))?;
            Ok(ClientFrame::Ping(frame))
        }
        _ => Err(ProtocolError::UnknownFrameType),
    }
}

/// Serialize a server frame, refusing to emit one that no peer could accept.
pub fn encode_frame<T: Serialize>(frame: &T) -> Result<String, ProtocolError> {
    let text =
        serde_json::to_string(frame).map_err(|error| ProtocolError::Encode(error.to_string()))?;
    if text.len() > MAX_PROTOCOL_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            limit: MAX_PROTOCOL_FRAME_BYTES,
        });
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::MessageTarget;

    #[test]
    fn round_trips_a_message_frame() {
        let mut message = OutboundMessage::new(
            "m1",
            MessageTarget::device("dev_1"),
            "chat.send",
            r#"{"text":"hello"}"#,
        );
        message.reply_to = Some("m0".into());
        let encoded = encode_frame(&message).unwrap();
        let decoded = decode_client_frame(&encoded, 4096).unwrap();
        assert_eq!(decoded, ClientFrame::Message(message));
    }

    #[test]
    fn rejects_other_versions() {
        let raw = r#"{"v":2,"type":"ping"}"#;
        assert!(matches!(
            decode_client_frame(raw, 1024),
            Err(ProtocolError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn rejects_unknown_types_and_garbage() {
        assert!(matches!(
            decode_client_frame(r#"{"v":1,"type":"drop_tables"}"#, 1024),
            Err(ProtocolError::UnknownFrameType)
        ));
        assert!(decode_client_frame("not json", 1024).is_err());
        assert!(decode_client_frame(r#"{"v":1}"#, 1024).is_err());
    }

    #[test]
    fn rejects_oversized_raw_frames_before_decoding() {
        let huge = format!(
            r#"{{"v":1,"type":"ping","pad":"{}"}}"#,
            "x".repeat(MAX_PROTOCOL_FRAME_BYTES)
        );
        assert!(matches!(
            decode_client_frame(&huge, 1024),
            Err(ProtocolError::FrameTooLarge { .. })
        ));
    }
}
