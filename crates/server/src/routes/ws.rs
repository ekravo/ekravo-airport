use std::sync::Arc;
use std::time::Duration;

use airport_protocol::ids::event_allowed;
use airport_protocol::{
    decode_client_frame, encode_frame, AckFrame, AckReceipt, ClientFrame, ConnectionKind,
    ContentType, DeliveredFrame, Encryption, ErrorCode, ErrorFrame, Limits, MessageOrigin,
    OutboundMessage, PingFrame, PongFrame, PresenceFrame, PresenceStatus, ProtocolError,
    ReceiptStatus, RelayedMessage, ReplacedFrame, TargetKind, WelcomeFrame,
};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::header::ORIGIN;
use axum::http::HeaderMap;
use axum::response::Response;
use bytes::Bytes;
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::auth::sha256_hex;
use crate::error::ApiError;
use crate::ratelimit::TokenBucket;
use crate::registry::ConnHandle;
use crate::state::AppState;
use crate::store::{self, DeviceRow, InsertOutcome, MessageRow, NewMessage, StoreError, TicketRow};
use crate::util::{new_id, now_secs};

/// A peer that stops reading must not hold a connection task forever.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Deserialize)]
pub struct ConnectQuery {
    ticket: Option<String>,
}

/// Upgrade to a WebSocket. Authentication uses a single-use ticket because a
/// browser cannot attach an Authorization header to `new WebSocket(...)`, and a
/// long-lived secret in the URL would end up in proxy logs.
pub async fn connect(
    State(state): State<Arc<AppState>>,
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    Query(query): Query<ConnectQuery>,
) -> Result<Response, ApiError> {
    // CORS does not apply to WebSocket upgrades. When an operator has listed
    // browser origins, enforce the same list here, before the ticket is spent.
    // Non-browser clients send no Origin and are unaffected.
    if !state.config.trusted_origins.is_empty() {
        if let Some(origin) = headers.get(ORIGIN).and_then(|value| value.to_str().ok()) {
            if !state
                .config
                .trusted_origins
                .iter()
                .any(|allowed| allowed == origin)
            {
                return Err(ApiError::forbidden(
                    "this origin is not allowed to open a WebSocket",
                ));
            }
        }
    }

    let ticket = query
        .ticket
        .ok_or_else(|| ApiError::unauthorized("a connection ticket is required"))?;
    if ticket.len() < 20 || ticket.len() > 256 {
        return Err(ApiError::unauthorized("ticket is invalid or expired"));
    }

    let row = store::consume_ticket(&state.pool, &sha256_hex(&ticket))
        .await?
        .ok_or_else(|| ApiError::unauthorized("ticket is invalid or expired"))?;

    let role = match row.kind.as_str() {
        "device" => ConnectionKind::Device,
        "client" => ConnectionKind::Client,
        _ => return Err(ApiError::unauthorized("ticket is invalid")),
    };

    let device = match (role, row.device_id.as_deref()) {
        (ConnectionKind::Device, Some(device_id)) => {
            let device = store::device_by_id(&state.pool, device_id)
                .await?
                .filter(|device| device.revoked_at.is_none())
                .ok_or_else(|| ApiError::unauthorized("this device is no longer authorized"))?;
            Some(device)
        }
        (ConnectionKind::Client, _) => None,
        _ => return Err(ApiError::unauthorized("ticket is invalid")),
    };

    store::user_by_id(&state.pool, &row.user_id)
        .await?
        .filter(|user| user.disabled == 0)
        .ok_or_else(|| ApiError::unauthorized("account is not active"))?;

    let max = state.config.max_frame_bytes;
    Ok(ws
        .max_message_size(max)
        .max_frame_size(max)
        .on_upgrade(move |socket| run_socket(state, socket, row, role, device)))
}

/// One connection: a bounded writer queue, a heartbeat, and the frame loop.
async fn run_socket(
    state: Arc<AppState>,
    socket: WebSocket,
    ticket: TicketRow,
    role: ConnectionKind,
    device: Option<DeviceRow>,
) {
    // The account cap is enforced when the socket is established, not only when
    // a ticket is requested: a burst of tickets must not exceed the limit just
    // because they were all minted before the first connection appeared.
    let Some(_slot) = state
        .registry
        .try_reserve_user(&ticket.user_id, state.config.max_connections_per_user)
    else {
        let mut socket = socket;
        if let Ok(text) = encode_frame(&ErrorFrame::fatal(
            ErrorCode::RateLimited,
            "this account has reached its connection limit",
        )) {
            let _ =
                tokio::time::timeout(SEND_TIMEOUT, socket.send(Message::Text(text.into()))).await;
        }
        let _ = tokio::time::timeout(SEND_TIMEOUT, socket.close()).await;
        return;
    };

    let connection_id = new_id("conn");
    let device_id = ticket.device_id.clone();
    let device_name = device.as_ref().map(|device| device.name.clone());
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<String>(state.config.max_queue_depth.clamp(16, 4096));

    let handle = Arc::new(ConnHandle::new(
        connection_id.clone(),
        role,
        ticket.user_id.clone(),
        device_id.clone(),
        device_name,
        tx.clone(),
    ));
    if let Some(key) = device.as_ref().and_then(|device| device.public_key.clone()) {
        handle.set_public_key(Some(key));
    }

    // A second socket for the same device wins. Telling the old one prevents
    // two processes from fighting over one identity.
    if let Some(old) = state.registry.register(handle.clone()) {
        if let Ok(text) = encode_frame(&ReplacedFrame::new()) {
            let _ = old.tx.try_send(text);
        }
        old.shutdown.notify_one();
    }

    let welcome = WelcomeFrame::new(
        connection_id.clone(),
        ticket.user_id.clone(),
        device_id.clone(),
        role,
        now_secs(),
        Limits {
            max_payload_bytes: state.config.max_payload_bytes,
            max_queue_depth: state.config.max_queue_depth,
            messages_per_second: state.config.messages_per_second,
            heartbeat_ms: state.config.heartbeat_ms(),
        },
    );
    match encode_frame(&welcome) {
        Ok(text) => {
            if tx.try_send(text).is_err() {
                state.registry.unregister(&connection_id);
                return;
            }
        }
        Err(error) => {
            tracing::error!(error = %error, "welcome frame could not be encoded");
            state.registry.unregister(&connection_id);
            return;
        }
    }

    if let Some(device_id) = &device_id {
        let _ = store::touch_device(&state.pool, device_id).await;
        broadcast_presence(&state, &ticket.user_id, device_id, PresenceStatus::Online);
        replay_mailbox(&state, device_id, &tx, state.config.replay_batch).await;
    }

    tracing::info!(
        connection_id = %connection_id,
        user_id = %ticket.user_id,
        device_id = ?device_id,
        role = role.as_str(),
        "connection opened"
    );

    let mut bucket = TokenBucket::new(state.config.messages_per_second, state.config.message_burst);
    let mut heartbeat =
        tokio::time::interval(Duration::from_secs(state.config.heartbeat_interval_secs));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = handle.shutdown.notified() => break,
            outgoing = rx.recv() => {
                match outgoing {
                    Some(text) => {
                        if !send_message(&mut sink, Message::Text(text.into())).await {
                            break;
                        }
                    }
                    None => break,
                }
            }
            incoming = stream.next() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        handle.touch();
                        if handle_text(&state, &handle, &mut bucket, text.as_str()).await == Flow::Halt {
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        handle.touch();
                        if !send_message(&mut sink, Message::Pong(payload)).await {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => handle.touch(),
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Binary(_))) => send_error(
                        &handle,
                        ErrorCode::InvalidFrame,
                        "binary frames are not supported; send JSON text frames",
                        None,
                    ),
                    Some(Err(error)) => {
                        tracing::debug!(connection_id = %connection_id, error = %error, "socket error");
                        break;
                    }
                }
            }
            _ = heartbeat.tick() => {
                let silence = now_secs() - handle.last_seen();
                if silence > state.config.heartbeat_interval_secs as i64 * 3 {
                    tracing::debug!(connection_id = %connection_id, silence, "heartbeat expired");
                    break;
                }
                if !send_message(&mut sink, Message::Ping(Bytes::new())).await {
                    break;
                }
            }
        }
    }

    // Flush frames the loop queued (fatal errors, `replaced`, `revoked`) and
    // complete the close handshake. Without this the peer sees a TCP reset and
    // never learns why it was disconnected. Bounded so a stalled peer cannot
    // hold the task open.
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        while let Ok(text) = rx.try_recv() {
            if sink.send(Message::Text(text.into())).await.is_err() {
                break;
            }
        }
        let _ = sink.send(Message::Close(None)).await;
    })
    .await;

    state.registry.unregister(&connection_id);
    if let Some(device_id) = &device_id {
        // If a newer socket replaced this one, the device is still online.
        if state.registry.device(device_id).is_none() {
            let _ = store::touch_device(&state.pool, device_id).await;
            broadcast_presence(&state, &ticket.user_id, device_id, PresenceStatus::Offline);
        }
    }
    tracing::info!(
        connection_id = %connection_id,
        user_id = %ticket.user_id,
        device_id = ?device_id,
        "connection closed"
    );
}

#[derive(PartialEq, Eq)]
enum Flow {
    Continue,
    Halt,
}

async fn handle_text(
    state: &Arc<AppState>,
    handle: &Arc<ConnHandle>,
    bucket: &mut TokenBucket,
    text: &str,
) -> Flow {
    let frame = match decode_client_frame(text, state.config.max_payload_bytes) {
        Ok(frame) => frame,
        Err(ProtocolError::UnsupportedVersion(version)) => {
            send_frame(
                handle,
                &ErrorFrame::fatal(
                    ErrorCode::UnsupportedVersion,
                    format!("Airport speaks protocol version 1; this peer sent {version}"),
                ),
            );
            return Flow::Halt;
        }
        Err(error) => {
            if !bucket.try_acquire() {
                send_error(
                    handle,
                    ErrorCode::RateLimited,
                    "frame rate exceeded; slow down",
                    None,
                );
                return Flow::Continue;
            }
            send_error(handle, error_code_of(&error), error.to_string(), None);
            return Flow::Continue;
        }
    };

    // Pings, hellos, and messages are charged against the bucket. Acks are
    // exempt: they release stored mail, and dropping one would stall a mailbox
    // that is draining faster than the bucket refills.
    if !matches!(&frame, ClientFrame::Ack(_)) && !bucket.try_acquire() {
        send_error(
            handle,
            ErrorCode::RateLimited,
            "frame rate exceeded; slow down",
            None,
        );
        return Flow::Continue;
    }

    match frame {
        ClientFrame::Ping(PingFrame { .. }) => {
            send_frame(handle, &PongFrame::new(now_secs()));
            Flow::Continue
        }
        ClientFrame::Hello(hello) => {
            handle.set_public_key(hello.public_key);
            Flow::Continue
        }
        ClientFrame::Ack(ack) => {
            handle_ack(state, handle, ack).await;
            Flow::Continue
        }
        ClientFrame::Message(message) => {
            if state.config.require_e2ee && message.enc.is_none() {
                send_error(
                    handle,
                    ErrorCode::Forbidden,
                    "this server requires end-to-end encrypted messages",
                    Some(message.msg_id),
                );
                return Flow::Continue;
            }
            let msg_id = message.msg_id.clone();
            if let Err((code, message)) = route_message(state, handle, message).await {
                send_error(handle, code, message, Some(msg_id));
            }
            Flow::Continue
        }
    }
}

/// A device confirms receipt. The sender (if still connected) learns the message
/// is no longer pending.
async fn handle_ack(state: &Arc<AppState>, handle: &Arc<ConnHandle>, ack: AckFrame) {
    if handle.kind != ConnectionKind::Device {
        return;
    }
    let Some(device_id) = &handle.device_id else {
        return;
    };
    // `seq` identifies one mailbox row exactly. Without it (older peers),
    // acknowledge only the newest unacknowledged row with that msgId, because
    // two senders are allowed to choose the same id.
    let acknowledged = match ack.seq {
        Some(seq) => store::ack_message_by_seq(&state.pool, device_id, seq).await,
        None => store::ack_message_by_msg_id(&state.pool, device_id, &ack.msg_id).await,
    };
    let mut released = false;
    match acknowledged {
        Ok(Some(row)) => {
            released = true;
            if let Some(sender_connection) = &row.sender_connection_id {
                let frame = DeliveredFrame::new(row.id.clone(), row.msg_id.clone(), now_secs());
                if let Ok(text) = encode_frame(&frame) {
                    state.registry.send(sender_connection, &text);
                }
            }
        }
        Ok(None) => {}
        Err(error) => tracing::error!(error = %error, "could not acknowledge a message"),
    }

    // A mailbox larger than the initial replay batch drains one message per
    // acknowledgement. Without this, the remainder would wait for a reconnect
    // that may never come. Only a real ack (not a duplicate) advances it.
    if released {
        replay_mailbox(state, device_id, &handle.tx, 1).await;
    }
}

/// Preserve the distinction between a malformed frame and one that was valid
/// but simply too large; callers act on those differently.
fn error_code_of(error: &ProtocolError) -> ErrorCode {
    match error {
        ProtocolError::PayloadTooLarge { .. } | ProtocolError::FrameTooLarge { .. } => {
            ErrorCode::PayloadTooLarge
        }
        ProtocolError::UnsupportedVersion(_) => ErrorCode::UnsupportedVersion,
        _ => ErrorCode::InvalidFrame,
    }
}

fn internal() -> (ErrorCode, String) {
    (
        ErrorCode::Internal,
        "the server could not complete the request".to_string(),
    )
}

fn frame_too_large() -> (ErrorCode, String) {
    (
        ErrorCode::PayloadTooLarge,
        "the message does not fit in the configured WebSocket frame limit".to_string(),
    )
}

fn db_error(error: sqlx::Error) -> (ErrorCode, String) {
    tracing::error!(error = %error, "relay database error");
    internal()
}

async fn route_message(
    state: &Arc<AppState>,
    origin: &Arc<ConnHandle>,
    message: OutboundMessage,
) -> Result<(), (ErrorCode, String)> {
    let now = now_secs();
    match message.to.kind {
        TargetKind::Device => route_to_device(state, origin, message, now).await,
        TargetKind::Connection => route_to_connection(state, origin, message, now).await,
        TargetKind::User => route_to_user(state, origin, message, now).await,
    }
}

fn origin_of(handle: &ConnHandle) -> MessageOrigin {
    MessageOrigin {
        user_id: handle.user_id.clone(),
        device_id: handle.device_id.clone(),
        device_name: handle.device_name.clone(),
        connection_id: handle.connection_id.clone(),
        public_key: handle.public_key(),
    }
}

fn sender_key(handle: &ConnHandle) -> String {
    match (&handle.kind, &handle.device_id) {
        (ConnectionKind::Device, Some(device_id)) => format!("device:{device_id}"),
        _ => format!("user:{}", handle.user_id),
    }
}

async fn route_to_device(
    state: &Arc<AppState>,
    origin: &Arc<ConnHandle>,
    message: OutboundMessage,
    now: i64,
) -> Result<(), (ErrorCode, String)> {
    let device = store::device_by_id(&state.pool, &message.to.id)
        .await
        .map_err(db_error)?
        .filter(|device| device.revoked_at.is_none())
        .ok_or_else(|| {
            (
                ErrorCode::RecipientUnavailable,
                "the device is not available".to_string(),
            )
        })?;

    if device.user_id != origin.user_id {
        let grant = store::active_grant(&state.pool, &device.id, &origin.user_id)
            .await
            .map_err(db_error)?
            .ok_or_else(|| {
                (
                    ErrorCode::Forbidden,
                    "you do not have access to this device".to_string(),
                )
            })?;
        let patterns: Vec<String> = serde_json::from_str(&grant.allowed_events).unwrap_or_default();
        if !event_allowed(&patterns, &message.event) {
            return Err((
                ErrorCode::Forbidden,
                "the device owner has not granted this event".to_string(),
            ));
        }
    }

    let ttl_secs = message
        .ttl_ms
        .map(|ttl| (ttl / 1000).max(1) as i64)
        .unwrap_or(state.config.message_ttl_secs)
        .min(state.config.message_ttl_secs);
    let expires_at = Some(now + ttl_secs);
    let enc_json = match &message.enc {
        Some(enc) => Some(serde_json::to_string(enc).map_err(|_| internal())?),
        None => None,
    };
    let content_type = match message.content_type {
        ContentType::Json => "json",
        ContentType::Text => "text",
        ContentType::Binary => "binary",
    };
    let delivery_id = new_id("msg");
    let key = sender_key(origin);
    let sender_public_key = origin.public_key();

    // Validate the outbound frame before writing the mailbox row. `seq` is a
    // placeholder one digit wider than any real sequence, so an encoded frame
    // that fits here is guaranteed to fit after the insert. Without this check,
    // a payload under the configured payload limit could be stored and then
    // silently never delivered because the serialized frame exceeds the frame
    // limit.
    let candidate = RelayedMessage::new(
        delivery_id.clone(),
        message.msg_id.clone(),
        Some(i64::MAX),
        origin_of(origin),
        message.event.clone(),
        message.payload.clone(),
        message.content_type,
        message.enc.clone(),
        message.reply_to.clone(),
        now,
        expires_at,
    );
    let candidate_text = encode_frame(&candidate).map_err(|_| frame_too_large())?;
    if candidate_text.len() > state.config.max_frame_bytes {
        return Err(frame_too_large());
    }

    let outcome = store::insert_message(
        &state.pool,
        NewMessage {
            id: &delivery_id,
            target_device_id: &device.id,
            sender_key: &key,
            sender_user_id: &origin.user_id,
            sender_device_id: origin.device_id.as_deref(),
            sender_connection_id: Some(&origin.connection_id),
            sender_public_key: sender_public_key.as_deref(),
            msg_id: &message.msg_id,
            event: &message.event,
            content_type,
            payload: &message.payload,
            enc: enc_json.as_deref(),
            reply_to: message.reply_to.as_deref(),
            expires_at,
            queue_limit: state.config.offline_queue_limit,
        },
    )
    .await
    .map_err(|error| match error {
        StoreError::MailboxFull => (
            ErrorCode::MailboxFull,
            "the device mailbox is full; try again later".to_string(),
        ),
        StoreError::Sqlx(error) => db_error(error),
    })?;

    match outcome {
        InsertOutcome::Duplicate(row) => {
            send_receipt(state, origin, &row, ReceiptStatus::Duplicate);
            Ok(())
        }
        InsertOutcome::Inserted(row) => {
            let mut status = ReceiptStatus::Queued;
            if let Some(frame) = relayed_from_row(&row, origin.device_name.as_deref()) {
                if let Ok(text) = encode_frame(&frame) {
                    if state.registry.send_device(&device.id, &text) {
                        let _ = store::mark_delivered(&state.pool, &row.id).await;
                        status = ReceiptStatus::Delivered;
                    }
                }
            }
            send_receipt(state, origin, &row, status);
            Ok(())
        }
    }
}

fn send_receipt(
    state: &Arc<AppState>,
    origin: &ConnHandle,
    row: &MessageRow,
    status: ReceiptStatus,
) {
    let receipt = AckReceipt::new(
        row.id.clone(),
        row.msg_id.clone(),
        status,
        Some(row.seq),
        now_secs(),
    );
    if let Ok(text) = encode_frame(&receipt) {
        state.registry.send(&origin.connection_id, &text);
    }
}

async fn route_to_connection(
    state: &Arc<AppState>,
    origin: &Arc<ConnHandle>,
    message: OutboundMessage,
    now: i64,
) -> Result<(), (ErrorCode, String)> {
    let target = state.registry.get(&message.to.id).ok_or_else(|| {
        (
            ErrorCode::RecipientUnavailable,
            "the target connection is not online".to_string(),
        )
    })?;

    let allowed = if origin.user_id == target.user_id {
        true
    } else if let Some(device_id) = &origin.device_id {
        store::active_grant(&state.pool, device_id, &target.user_id)
            .await
            .map_err(db_error)?
            .is_some()
    } else {
        false
    };
    if !allowed {
        return Err((
            ErrorCode::Forbidden,
            "the target connection belongs to another account".to_string(),
        ));
    }

    let frame = RelayedMessage::new(
        new_id("msg"),
        message.msg_id.clone(),
        None,
        origin_of(origin),
        message.event,
        message.payload,
        message.content_type,
        message.enc,
        message.reply_to,
        now,
        None,
    );
    let text = encode_frame(&frame).map_err(|_| frame_too_large())?;
    if text.len() > state.config.max_frame_bytes {
        return Err(frame_too_large());
    }
    if !state.registry.send(&target.connection_id, &text) {
        return Err((
            ErrorCode::RecipientUnavailable,
            "the target connection is busy".to_string(),
        ));
    }

    let receipt = AckReceipt::new(
        new_id("msg"),
        message.msg_id,
        ReceiptStatus::Delivered,
        None,
        now_secs(),
    );
    if let Ok(text) = encode_frame(&receipt) {
        state.registry.send(&origin.connection_id, &text);
    }
    Ok(())
}

async fn route_to_user(
    state: &Arc<AppState>,
    origin: &Arc<ConnHandle>,
    message: OutboundMessage,
    now: i64,
) -> Result<(), (ErrorCode, String)> {
    if message.to.id != origin.user_id {
        return Err((
            ErrorCode::Forbidden,
            "messages can only be broadcast to your own connections".to_string(),
        ));
    }

    let frame = RelayedMessage::new(
        new_id("msg"),
        message.msg_id.clone(),
        None,
        origin_of(origin),
        message.event,
        message.payload,
        message.content_type,
        message.enc,
        message.reply_to,
        now,
        None,
    );
    let text = encode_frame(&frame).map_err(|_| frame_too_large())?;
    if text.len() > state.config.max_frame_bytes {
        return Err(frame_too_large());
    }
    let delivered =
        state
            .registry
            .broadcast_clients(&origin.user_id, &text, Some(&origin.connection_id));
    if delivered == 0 {
        return Err((
            ErrorCode::RecipientUnavailable,
            "no other client connection is online for this account".to_string(),
        ));
    }

    let receipt = AckReceipt::new(
        new_id("msg"),
        message.msg_id,
        ReceiptStatus::Delivered,
        None,
        now_secs(),
    );
    if let Ok(text) = encode_frame(&receipt) {
        state.registry.send(&origin.connection_id, &text);
    }
    Ok(())
}

async fn send_message(sink: &mut SplitSink<WebSocket, Message>, message: Message) -> bool {
    matches!(
        tokio::time::timeout(SEND_TIMEOUT, sink.send(message)).await,
        Ok(Ok(()))
    )
}

fn content_type_of(value: &str) -> ContentType {
    match value {
        "text" => ContentType::Text,
        "binary" => ContentType::Binary,
        _ => ContentType::Json,
    }
}

/// Rebuild a stored message. `None` means the encryption header is unreadable,
/// in which case the message is skipped rather than delivered as plaintext.
fn relayed_from_row(row: &MessageRow, sender_device_name: Option<&str>) -> Option<RelayedMessage> {
    let enc: Option<Encryption> = match &row.enc {
        Some(raw) => Some(serde_json::from_str(raw).ok()?),
        None => None,
    };
    Some(RelayedMessage::new(
        row.id.clone(),
        row.msg_id.clone(),
        Some(row.seq),
        MessageOrigin {
            user_id: row.sender_user_id.clone(),
            device_id: row.sender_device_id.clone(),
            device_name: sender_device_name.map(str::to_string),
            connection_id: row.sender_connection_id.clone().unwrap_or_default(),
            public_key: row.sender_public_key.clone(),
        },
        row.event.clone(),
        row.payload.clone(),
        content_type_of(&row.content_type),
        enc,
        row.reply_to.clone(),
        row.created_at,
        row.expires_at,
    ))
}

async fn replay_mailbox(
    state: &Arc<AppState>,
    device_id: &str,
    tx: &mpsc::Sender<String>,
    limit: i64,
) {
    let rows = match store::pending_messages(&state.pool, device_id, limit).await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!(error = %error, "could not read the device mailbox");
            return;
        }
    };
    if !rows.is_empty() {
        tracing::info!(device_id = %device_id, pending = rows.len(), "replaying the mailbox");
    }
    for row in rows {
        let Some(frame) = relayed_from_row(&row, None) else {
            tracing::error!(message_id = %row.id, "stored message has an unreadable encryption header");
            continue;
        };
        let Ok(text) = encode_frame(&frame) else {
            continue;
        };
        if text.len() > state.config.max_frame_bytes {
            tracing::error!(message_id = %row.id, "stored message exceeds the configured frame limit");
            continue;
        }
        if tx.try_send(text).is_err() {
            break;
        }
        let _ = store::mark_delivered(&state.pool, &row.id).await;
    }
}

fn broadcast_presence(
    state: &Arc<AppState>,
    user_id: &str,
    device_id: &str,
    status: PresenceStatus,
) {
    let frame = PresenceFrame::new(device_id.to_string(), status, now_secs());
    if let Ok(text) = encode_frame(&frame) {
        state.registry.broadcast_clients(user_id, &text, None);
    }
}

fn send_frame<T: serde::Serialize>(handle: &ConnHandle, frame: &T) {
    if let Ok(text) = encode_frame(frame) {
        let _ = handle.tx.try_send(text);
    }
}

fn send_error(
    handle: &ConnHandle,
    code: ErrorCode,
    message: impl Into<String>,
    msg_id: Option<String>,
) {
    send_frame(handle, &ErrorFrame::new(code, message, msg_id));
}
