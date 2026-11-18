//! End-to-end tests: a real TCP listener, the real router, real SQLite, and real
//! WebSocket clients. Nothing is mocked, so a test passing here exercises the
//! same path a deployment does.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use airport_server::config::Config;
use airport_server::db;
use airport_server::routes;
use airport_server::state::AppState;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

const PASSWORD: &str = "correct horse battery staple";

struct TestServer {
    http: String,
    ws: String,
    state: Arc<AppState>,
}

async fn spawn_with(config: Config) -> TestServer {
    let pool = db::connect(&config.database_url, 1)
        .await
        .expect("database");
    db::migrate(&pool).await.expect("schema");
    let state = Arc::new(AppState::new(config, pool));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let addr = listener.local_addr().expect("address");
    let app =
        routes::build_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    TestServer {
        http: format!("http://{addr}"),
        ws: format!("ws://{addr}"),
        state,
    }
}

async fn spawn() -> TestServer {
    spawn_with(Config::dev_defaults()).await
}

async fn post(server: &TestServer, path: &str, body: Value, token: Option<&str>) -> (u16, Value) {
    let mut request = reqwest::Client::new()
        .post(format!("{}{path}", server.http))
        .json(&body);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.expect("request");
    decode(response).await
}

async fn get(server: &TestServer, path: &str, token: Option<&str>) -> (u16, Value) {
    let mut request = reqwest::Client::new().get(format!("{}{path}", server.http));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.expect("request");
    decode(response).await
}

async fn delete(server: &TestServer, path: &str, token: &str) -> (u16, Value) {
    let response = reqwest::Client::new()
        .delete(format!("{}{path}", server.http))
        .bearer_auth(token)
        .send()
        .await
        .expect("request");
    decode(response).await
}

async fn decode(response: reqwest::Response) -> (u16, Value) {
    let status = response.status().as_u16();
    let text = response.text().await.expect("body");
    let value = if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or_else(|_| panic!("non-JSON response: {text}"))
    };
    (status, value)
}

async fn register(server: &TestServer, email: &str) -> (String, String) {
    let (status, body) = post(
        server,
        "/api/v1/auth/register",
        json!({ "email": email, "password": PASSWORD, "displayName": "Test User" }),
        None,
    )
    .await;
    assert_eq!(status, 201, "registration failed: {body}");
    (
        body["accessToken"]
            .as_str()
            .expect("access token")
            .to_string(),
        body["user"]["id"].as_str().expect("user id").to_string(),
    )
}

async fn pair_device(server: &TestServer, token: &str, name: &str) -> (String, String) {
    let (status, body) = post(
        server,
        "/api/v1/devices/pairing",
        json!({ "name": name }),
        Some(token),
    )
    .await;
    assert_eq!(status, 201, "pairing code failed: {body}");
    let code = body["code"].as_str().expect("code");

    let (status, body) = post(
        server,
        "/api/v1/devices/pair",
        json!({ "code": code, "name": name, "platform": "test" }),
        None,
    )
    .await;
    assert_eq!(status, 201, "pairing failed: {body}");
    (
        body["device"]["id"]
            .as_str()
            .expect("device id")
            .to_string(),
        body["credential"].as_str().expect("credential").to_string(),
    )
}

async fn ticket(server: &TestServer, token: &str, kind: &str) -> String {
    let (status, body) = post(
        server,
        "/api/v1/tickets",
        json!({ "kind": kind }),
        Some(token),
    )
    .await;
    assert_eq!(status, 201, "ticket failed: {body}");
    body["ticket"].as_str().expect("ticket").to_string()
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(server: &TestServer, ticket: &str) -> Ws {
    let url = format!("{}/v1/connect?ticket={ticket}", server.ws);
    let (socket, response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("websocket connect");
    assert_eq!(response.status().as_u16(), 101);
    socket
}

async fn read_frame(socket: &mut Ws) -> Value {
    let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("timed out waiting for a frame")
        .expect("socket closed")
        .expect("socket error");
    match message {
        Message::Text(text) => serde_json::from_str(&text).expect("JSON frame"),
        other => panic!("expected a text frame, got {other:?}"),
    }
}

async fn read_type(socket: &mut Ws, kind: &str) -> Value {
    loop {
        let frame = read_frame(socket).await;
        if frame["type"] == kind {
            return frame;
        }
    }
}

async fn send_frame(socket: &mut Ws, frame: Value) {
    socket
        .send(Message::Text(
            serde_json::to_string(&frame).expect("frame serializes"),
        ))
        .await
        .expect("frame send");
}

fn message(device_id: &str, msg_id: &str, event: &str, payload: &str) -> Value {
    json!({
        "v": 1,
        "type": "msg",
        "msgId": msg_id,
        "to": { "kind": "device", "id": device_id },
        "event": event,
        "payload": payload,
    })
}

// --- Tests ------------------------------------------------------------------

#[tokio::test]
async fn health_version_and_readiness_are_public() {
    let server = spawn().await;

    let (status, body) = get(&server, "/healthz", None).await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");

    let (status, body) = get(&server, "/readyz", None).await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ready");

    let (status, body) = get(&server, "/version", None).await;
    assert_eq!(status, 200);
    assert_eq!(body["protocolVersion"], 1);

    let (status, body) = get(&server, "/nope", None).await;
    assert_eq!(status, 404);
    assert_eq!(body["error"]["code"], "not_found");
}

#[tokio::test]
async fn auth_requires_credentials_and_refresh_tokens_rotate() {
    let server = spawn().await;
    let (access, user_id) = register(&server, "alice@example.com").await;

    let (status, body) = get(&server, "/api/v1/me", Some(&access)).await;
    assert_eq!(status, 200);
    assert_eq!(body["user"]["id"], user_id);

    let (status, _) = get(&server, "/api/v1/me", None).await;
    assert_eq!(status, 401);

    let (status, _) = post(
        &server,
        "/api/v1/auth/login",
        json!({ "email": "alice@example.com", "password": "wrong password" }),
        None,
    )
    .await;
    assert_eq!(status, 401);

    let (status, _) = post(
        &server,
        "/api/v1/auth/register",
        json!({ "email": "alice@example.com", "password": PASSWORD }),
        None,
    )
    .await;
    assert_eq!(status, 409);

    let (status, login) = post(
        &server,
        "/api/v1/auth/login",
        json!({ "email": "alice@example.com", "password": PASSWORD }),
        None,
    )
    .await;
    assert_eq!(status, 200);
    let refresh = login["refreshToken"].as_str().expect("refresh token");

    let (status, rotated) = post(
        &server,
        "/api/v1/auth/refresh",
        json!({ "refreshToken": refresh }),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_ne!(rotated["refreshToken"], refresh);

    // Reusing the old token is treated as theft: it fails and revokes the family.
    let (status, _) = post(
        &server,
        "/api/v1/auth/refresh",
        json!({ "refreshToken": refresh }),
        None,
    )
    .await;
    assert_eq!(status, 401);

    let (status, _) = post(
        &server,
        "/api/v1/auth/refresh",
        json!({ "refreshToken": rotated["refreshToken"] }),
        None,
    )
    .await;
    assert_eq!(status, 401, "the rotated token must also be revoked");
}

#[tokio::test]
async fn pairing_codes_are_single_use_and_credentials_rotate() {
    let server = spawn().await;
    let (access, _) = register(&server, "owner@example.com").await;

    let (status, body) = post(
        &server,
        "/api/v1/devices/pairing",
        json!({ "name": "Laptop" }),
        Some(&access),
    )
    .await;
    assert_eq!(status, 201);
    let code = body["code"].as_str().expect("code").to_string();

    let (status, paired) = post(
        &server,
        "/api/v1/devices/pair",
        json!({ "code": code, "name": "Laptop", "platform": "linux" }),
        None,
    )
    .await;
    assert_eq!(status, 201);
    let device_id = paired["device"]["id"].as_str().expect("device id");
    let credential = paired["credential"].as_str().expect("credential");

    // The code cannot be used again.
    let (status, _) = post(
        &server,
        "/api/v1/devices/pair",
        json!({ "code": code, "name": "Laptop" }),
        None,
    )
    .await;
    assert_eq!(status, 400);

    let (status, _) = post(
        &server,
        "/api/v1/tickets",
        json!({ "kind": "device" }),
        Some(credential),
    )
    .await;
    assert_eq!(status, 201);

    let (status, rotated) = post(
        &server,
        &format!("/api/v1/devices/{device_id}/rotate"),
        json!({}),
        Some(&access),
    )
    .await;
    assert_eq!(status, 200);
    let new_credential = rotated["credential"].as_str().expect("new credential");

    let (status, _) = post(
        &server,
        "/api/v1/tickets",
        json!({ "kind": "device" }),
        Some(credential),
    )
    .await;
    assert_eq!(status, 401, "the old credential must stop working");

    let (status, _) = post(
        &server,
        "/api/v1/tickets",
        json!({ "kind": "device" }),
        Some(new_credential),
    )
    .await;
    assert_eq!(status, 201);

    let (status, body) = get(&server, "/api/v1/devices", Some(&access)).await;
    assert_eq!(status, 200);
    assert_eq!(body["devices"].as_array().expect("devices").len(), 1);
}

#[tokio::test]
async fn relay_delivers_and_reports_acknowledgement() {
    let server = spawn().await;
    let (access, _) = register(&server, "relay@example.com").await;
    let (device_id, credential) = pair_device(&server, &access, "Desktop").await;

    let device_ticket = ticket(&server, &credential, "device").await;
    let mut device = connect(&server, &device_ticket).await;
    let welcome = read_type(&mut device, "welcome").await;
    assert_eq!(welcome["role"], "device");
    assert_eq!(welcome["deviceId"], device_id);

    let client_ticket = ticket(&server, &access, "client").await;
    let mut client = connect(&server, &client_ticket).await;
    assert_eq!(read_type(&mut client, "welcome").await["role"], "client");

    // The client advertises its long-term key so the device can encrypt a reply.
    let client_key = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    send_frame(
        &mut client,
        json!({ "v": 1, "type": "hello", "publicKey": client_key }),
    )
    .await;

    send_frame(
        &mut client,
        message(&device_id, "m-1", "chat.send", r#"{"text":"hello"}"#),
    )
    .await;

    let receipt = read_type(&mut client, "ack").await;
    assert_eq!(receipt["msgId"], "m-1");
    assert_eq!(receipt["status"], "delivered");

    let delivered = read_type(&mut device, "msg").await;
    assert_eq!(delivered["msgId"], "m-1");
    assert_eq!(delivered["event"], "chat.send");
    assert_eq!(delivered["payload"], r#"{"text":"hello"}"#);
    assert_eq!(delivered["from"]["publicKey"], client_key);
    assert!(delivered["from"]["connectionId"]
        .as_str()
        .map(|value| value.starts_with("conn_"))
        .unwrap_or(false));
    assert!(delivered["seq"].as_i64().unwrap() >= 1);

    send_frame(
        &mut device,
        json!({ "v": 1, "type": "ack", "msgId": "m-1", "seq": delivered["seq"] }),
    )
    .await;

    let confirmed = read_type(&mut client, "delivered").await;
    assert_eq!(confirmed["msgId"], "m-1");
}

#[tokio::test]
async fn offline_messages_queue_and_replay_once_on_reconnect() {
    let server = spawn().await;
    let (access, _) = register(&server, "offline@example.com").await;
    let (device_id, credential) = pair_device(&server, &access, "Laptop").await;

    let client_ticket = ticket(&server, &access, "client").await;
    let mut client = connect(&server, &client_ticket).await;
    read_type(&mut client, "welcome").await;

    send_frame(
        &mut client,
        message(&device_id, "queued-1", "chat.send", r#"{"text":"later"}"#),
    )
    .await;
    let receipt = read_type(&mut client, "ack").await;
    assert_eq!(receipt["status"], "queued");
    assert_eq!(receipt["queued"], true);

    // The device was never online, so the message waited in the mailbox.
    let device_ticket = ticket(&server, &credential, "device").await;
    let mut device = connect(&server, &device_ticket).await;
    read_type(&mut device, "welcome").await;
    let replayed = read_type(&mut device, "msg").await;
    assert_eq!(replayed["msgId"], "queued-1");
    assert_eq!(replayed["payload"], r#"{"text":"later"}"#);

    send_frame(
        &mut device,
        json!({ "v": 1, "type": "ack", "msgId": "queued-1" }),
    )
    .await;
    assert_eq!(
        read_type(&mut client, "delivered").await["msgId"],
        "queued-1"
    );

    // Drop the device socket (a network interruption) and reconnect. An
    // acknowledged message must not be replayed.
    drop(device);
    let second_ticket = ticket(&server, &credential, "device").await;
    let mut device = connect(&server, &second_ticket).await;
    read_type(&mut device, "welcome").await;
    assert!(
        tokio::time::timeout(Duration::from_millis(600), device.next())
            .await
            .is_err(),
        "an acknowledged message must not be replayed"
    );
}

#[tokio::test]
async fn duplicate_msg_ids_are_stored_and_delivered_once() {
    let server = spawn().await;
    let (access, _) = register(&server, "dupe@example.com").await;
    let (device_id, credential) = pair_device(&server, &access, "Desktop").await;

    let client_ticket = ticket(&server, &access, "client").await;
    let mut client = connect(&server, &client_ticket).await;
    read_type(&mut client, "welcome").await;

    let frame = message(&device_id, "same-id", "chat.send", r#"{"n":1}"#);
    send_frame(&mut client, frame.clone()).await;
    let first = read_type(&mut client, "ack").await;
    send_frame(&mut client, frame).await;
    let second = read_type(&mut client, "ack").await;

    assert_eq!(first["status"], "queued");
    assert_eq!(second["status"], "duplicate");
    assert_eq!(first["seq"], second["seq"]);

    let device_ticket = ticket(&server, &credential, "device").await;
    let mut device = connect(&server, &device_ticket).await;
    read_type(&mut device, "welcome").await;
    assert_eq!(read_type(&mut device, "msg").await["msgId"], "same-id");
    assert!(
        tokio::time::timeout(Duration::from_millis(600), device.next())
            .await
            .is_err(),
        "a duplicate must not produce a second delivery"
    );
}

#[tokio::test]
async fn grants_bound_cross_account_access() {
    let server = spawn().await;
    let (owner, _) = register(&server, "device-owner@example.com").await;
    let (guest, _) = register(&server, "guest@example.com").await;
    let (device_id, _credential) = pair_device(&server, &owner, "Workstation").await;

    let guest_ticket = ticket(&server, &guest, "client").await;
    let mut guest_socket = connect(&server, &guest_ticket).await;
    read_type(&mut guest_socket, "welcome").await;

    send_frame(
        &mut guest_socket,
        message(&device_id, "denied-1", "chat.send", r#"{"text":"hi"}"#),
    )
    .await;
    let denied = read_type(&mut guest_socket, "error").await;
    assert_eq!(denied["code"], "forbidden");

    let (status, grant) = post(
        &server,
        "/api/v1/grants",
        json!({
            "deviceId": device_id,
            "granteeEmail": "guest@example.com",
            "label": "chat only",
            "allowedEvents": ["chat.*"]
        }),
        Some(&owner),
    )
    .await;
    assert_eq!(status, 201, "{grant}");
    let grant_id = grant["id"].as_str().expect("grant id");

    send_frame(
        &mut guest_socket,
        message(&device_id, "allowed-1", "chat.send", r#"{"text":"hi"}"#),
    )
    .await;
    let receipt = read_type(&mut guest_socket, "ack").await;
    assert_eq!(receipt["status"], "queued");

    send_frame(
        &mut guest_socket,
        message(&device_id, "denied-2", "shell.exec", r#"{"cmd":"rm"}"#),
    )
    .await;
    let denied = read_type(&mut guest_socket, "error").await;
    assert_eq!(denied["code"], "forbidden");

    let (status, body) = get(&server, "/api/v1/devices/shared", Some(&guest)).await;
    assert_eq!(status, 200);
    assert_eq!(body["devices"].as_array().expect("shared").len(), 1);

    let (status, _) = delete(&server, &format!("/api/v1/grants/{grant_id}"), &owner).await;
    assert_eq!(status, 204);

    send_frame(
        &mut guest_socket,
        message(&device_id, "denied-3", "chat.send", r#"{"text":"again"}"#),
    )
    .await;
    assert_eq!(
        read_type(&mut guest_socket, "error").await["code"],
        "forbidden"
    );
}

#[tokio::test]
async fn websocket_origin_allowlist_is_enforced_before_the_ticket_is_spent() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let mut config = Config::dev_defaults();
    config.trusted_origins = vec!["https://app.example.com".to_string()];
    let server = spawn_with(config).await;
    let (access, _) = register(&server, "origin@example.com").await;

    let ticket = ticket(&server, &access, "client").await;
    let url = format!("{}/v1/connect?ticket={ticket}", server.ws);
    let mut request = url.into_client_request().expect("request");
    request
        .headers_mut()
        .insert("origin", "https://evil.example".parse().unwrap());
    assert!(
        tokio_tungstenite::connect_async(request).await.is_err(),
        "an unlisted browser origin must be refused"
    );

    // The rejected attempt did not consume the ticket, so a non-browser client
    // (no Origin header) can still use it.
    let mut socket = connect(&server, &ticket).await;
    assert_eq!(read_type(&mut socket, "welcome").await["role"], "client");
}

#[tokio::test]
async fn revoked_devices_are_disconnected_and_cannot_reconnect() {
    let server = spawn().await;
    let (access, _) = register(&server, "revoke@example.com").await;
    let (device_id, credential) = pair_device(&server, &access, "Old Laptop").await;

    let device_ticket = ticket(&server, &credential, "device").await;
    let mut device = connect(&server, &device_ticket).await;
    read_type(&mut device, "welcome").await;

    let (status, _) = delete(&server, &format!("/api/v1/devices/{device_id}"), &access).await;
    assert_eq!(status, 204);

    let notice = read_type(&mut device, "revoked").await;
    assert_eq!(notice["reason"], "device was revoked");

    let (status, _) = post(
        &server,
        "/api/v1/tickets",
        json!({ "kind": "device" }),
        Some(&credential),
    )
    .await;
    assert_eq!(status, 401);

    let (status, body) = get(&server, "/api/v1/devices", Some(&access)).await;
    assert_eq!(status, 200);
    assert_eq!(body["devices"].as_array().expect("devices").len(), 0);
}

#[tokio::test]
async fn tickets_are_single_use() {
    let server = spawn().await;
    let (access, _) = register(&server, "tickets@example.com").await;
    let client_ticket = ticket(&server, &access, "client").await;

    let mut socket = connect(&server, &client_ticket).await;
    read_type(&mut socket, "welcome").await;
    drop(socket);

    let url = format!("{}/v1/connect?ticket={client_ticket}", server.ws);
    assert!(
        tokio_tungstenite::connect_async(&url).await.is_err(),
        "a consumed ticket must not be accepted twice"
    );
}

#[tokio::test]
async fn oversized_payloads_and_rate_limits_are_reported() {
    let mut config = Config::dev_defaults();
    config.max_payload_bytes = 1024;
    config.messages_per_second = 1;
    config.message_burst = 1;
    let server = spawn_with(config).await;

    let (access, _) = register(&server, "limits@example.com").await;
    let (device_id, _credential) = pair_device(&server, &access, "Desktop").await;

    let client_ticket = ticket(&server, &access, "client").await;
    let mut client = connect(&server, &client_ticket).await;
    read_type(&mut client, "welcome").await;

    let huge = "x".repeat(2048);
    send_frame(
        &mut client,
        message(&device_id, "too-big", "chat.send", &huge),
    )
    .await;
    let error = read_type(&mut client, "error").await;
    assert_eq!(error["code"], "payload_too_large", "{error}");

    // The first of these consumes the single token; a later one is throttled.
    for index in 0..4 {
        send_frame(
            &mut client,
            message(
                &device_id,
                &format!("rate-{index}"),
                "chat.send",
                r#"{"text":"x"}"#,
            ),
        )
        .await;
    }
    let mut saw_rate_limit = false;
    for _ in 0..10 {
        let frame = read_frame(&mut client).await;
        if frame["type"] == "error" && frame["code"] == "rate_limited" {
            saw_rate_limit = true;
            break;
        }
    }
    assert!(saw_rate_limit, "the connection must report a rate limit");
}

#[tokio::test]
async fn expired_tokens_codes_and_missing_tickets_are_rejected() {
    let server = spawn().await;
    let (_access, user_id) = register(&server, "expiry@example.com").await;
    let now = airport_server::util::now_secs();

    // A correctly signed access token whose exp is in the past must fail.
    let secret = Config::dev_defaults().jwt_secret;
    let claims = json!({
        "sub": user_id,
        "exp": now - 10,
        "iat": now - 100,
        "jti": "test",
        "iss": "ekravo-airport",
        "typ": "access"
    });
    let expired = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("token");
    let (status, _) = get(&server, "/api/v1/me", Some(&expired)).await;
    assert_eq!(status, 401);

    // An expired pairing code cannot be exchanged.
    let code = "airport_pair_expired-smoke";
    airport_server::store::create_pairing_code(
        &server.state.pool,
        &airport_server::auth::sha256_hex(code),
        &user_id,
        "Old device",
        now - 5,
    )
    .await
    .expect("expired code");
    let (status, _) = post(
        &server,
        "/api/v1/devices/pair",
        json!({ "code": code, "name": "Old device" }),
        None,
    )
    .await;
    assert_eq!(status, 400);

    // An expired refresh token cannot be rotated.
    let refresh = "expired-refresh-token-value";
    airport_server::store::insert_refresh_token(
        &server.state.pool,
        "rt_expired",
        &user_id,
        &airport_server::auth::sha256_hex(refresh),
        now - 60,
    )
    .await
    .expect("expired refresh");
    let (status, _) = post(
        &server,
        "/api/v1/auth/refresh",
        json!({ "refreshToken": refresh }),
        None,
    )
    .await;
    assert_eq!(status, 401);

    // The socket endpoint requires a ticket.
    assert!(
        tokio_tungstenite::connect_async(format!("{}/v1/connect", server.ws))
            .await
            .is_err(),
        "a ticketless upgrade must be refused"
    );
}

#[tokio::test]
async fn encrypted_payloads_pass_through_untouched() {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    let server = spawn().await;
    let (access, _) = register(&server, "crypto@example.com").await;
    let (device_id, credential) = pair_device(&server, &access, "Secure Desktop").await;

    let device_ticket = ticket(&server, &credential, "device").await;
    let mut device = connect(&server, &device_ticket).await;
    read_type(&mut device, "welcome").await;

    let client_ticket = ticket(&server, &access, "client").await;
    let mut client = connect(&server, &client_ticket).await;
    read_type(&mut client, "welcome").await;

    let ciphertext = B64.encode([7u8; 48]);
    let epk = B64.encode([3u8; 32]);
    let nonce = B64.encode([1u8; 12]);
    send_frame(
        &mut client,
        json!({
            "v": 1,
            "type": "msg",
            "msgId": "enc-1",
            "to": { "kind": "device", "id": device_id },
            "event": "vault.get",
            "payload": ciphertext,
            "contentType": "binary",
            "enc": { "alg": "x25519-hkdf-sha256-aes-256-gcm", "epk": epk, "nonce": nonce },
        }),
    )
    .await;

    let delivered = read_type(&mut device, "msg").await;
    assert_eq!(delivered["payload"], ciphertext);
    assert_eq!(delivered["enc"]["epk"], epk);
    assert_eq!(delivered["enc"]["nonce"], nonce);
    assert_eq!(delivered["contentType"], "binary");
}

#[tokio::test]
async fn mailbox_drains_past_the_replay_batch() {
    let mut config = Config::dev_defaults();
    config.replay_batch = 1;
    let server = spawn_with(config).await;
    let (access, _) = register(&server, "drain@example.com").await;
    let (device_id, credential) = pair_device(&server, &access, "Drain").await;

    // Queue three messages while the device is offline.
    let client_ticket = ticket(&server, &access, "client").await;
    let mut client = connect(&server, &client_ticket).await;
    read_type(&mut client, "welcome").await;
    for index in 0..3 {
        send_frame(
            &mut client,
            message(
                &device_id,
                &format!("drain-{index}"),
                "chat.send",
                r#"{"text":"queued"}"#,
            ),
        )
        .await;
        assert_eq!(read_type(&mut client, "ack").await["status"], "queued");
    }

    let device_ticket = ticket(&server, &credential, "device").await;
    let mut device = connect(&server, &device_ticket).await;
    read_type(&mut device, "welcome").await;

    // Only one message is replayed initially. Each acknowledgement must release
    // the next one without waiting for a reconnect.
    let mut seen = Vec::new();
    for _ in 0..3 {
        let frame = read_type(&mut device, "msg").await;
        seen.push(frame["msgId"].as_str().expect("msgId").to_string());
        send_frame(
            &mut device,
            json!({ "v": 1, "type": "ack", "msgId": frame["msgId"], "seq": frame["seq"] }),
        )
        .await;
    }
    assert_eq!(seen, ["drain-0", "drain-1", "drain-2"]);
    assert!(
        tokio::time::timeout(Duration::from_millis(500), device.next())
            .await
            .is_err(),
        "the drained mailbox must be empty"
    );
}

#[tokio::test]
async fn acknowledgements_are_scoped_to_one_delivery() {
    let server = spawn().await;
    let (owner, _) = register(&server, "ack-owner@example.com").await;
    let (guest, _) = register(&server, "ack-guest@example.com").await;
    let (device_id, credential) = pair_device(&server, &owner, "Shared").await;

    let (status, _) = post(
        &server,
        "/api/v1/grants",
        json!({ "deviceId": device_id, "granteeEmail": "ack-guest@example.com" }),
        Some(&owner),
    )
    .await;
    assert_eq!(status, 201);

    // Two different senders are allowed to choose the same msgId.
    let guest_ticket = ticket(&server, &guest, "client").await;
    let mut guest_socket = connect(&server, &guest_ticket).await;
    read_type(&mut guest_socket, "welcome").await;
    send_frame(
        &mut guest_socket,
        message(&device_id, "shared-id", "chat.send", r#"{"from":"guest"}"#),
    )
    .await;
    assert_eq!(
        read_type(&mut guest_socket, "ack").await["status"],
        "queued"
    );

    let owner_ticket = ticket(&server, &owner, "client").await;
    let mut owner_socket = connect(&server, &owner_ticket).await;
    read_type(&mut owner_socket, "welcome").await;
    send_frame(
        &mut owner_socket,
        message(&device_id, "shared-id", "chat.send", r#"{"from":"owner"}"#),
    )
    .await;
    assert_eq!(
        read_type(&mut owner_socket, "ack").await["status"],
        "queued"
    );

    let device_ticket = ticket(&server, &credential, "device").await;
    let mut device = connect(&server, &device_ticket).await;
    read_type(&mut device, "welcome").await;

    let first = read_type(&mut device, "msg").await;
    let second = read_type(&mut device, "msg").await;
    assert_eq!(first["msgId"], "shared-id");
    assert_eq!(second["msgId"], "shared-id");
    assert_ne!(first["from"]["userId"], second["from"]["userId"]);

    // Acknowledge only the first delivery.
    send_frame(
        &mut device,
        json!({ "v": 1, "type": "ack", "msgId": "shared-id", "seq": first["seq"] }),
    )
    .await;
    drop(device);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let device_ticket = ticket(&server, &credential, "device").await;
    let mut device = connect(&server, &device_ticket).await;
    read_type(&mut device, "welcome").await;
    let replayed = read_type(&mut device, "msg").await;
    assert_eq!(replayed["seq"], second["seq"]);
    assert!(
        tokio::time::timeout(Duration::from_millis(500), device.next())
            .await
            .is_err(),
        "the acknowledged delivery must not replay"
    );
}

#[tokio::test]
async fn connection_limit_is_enforced_at_handshake_and_released() {
    let mut config = Config::dev_defaults();
    config.max_connections_per_user = 1;
    let server = spawn_with(config).await;
    let (access, _) = register(&server, "slots@example.com").await;

    let first_ticket = ticket(&server, &access, "client").await;
    let second_ticket = ticket(&server, &access, "client").await;

    let mut first = connect(&server, &first_ticket).await;
    read_type(&mut first, "welcome").await;

    let mut second = connect(&server, &second_ticket).await;
    let error = read_type(&mut second, "error").await;
    assert_eq!(error["code"], "rate_limited");
    assert_eq!(error["fatal"], true);

    drop(first);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let third_ticket = ticket(&server, &access, "client").await;
    let mut third = connect(&server, &third_ticket).await;
    assert_eq!(read_type(&mut third, "welcome").await["role"], "client");
}

#[tokio::test]
async fn malformed_json_and_wrong_methods_use_the_error_envelope() {
    let server = spawn().await;

    let response = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/login", server.http))
        .header("content-type", "application/json")
        .body("{ not json")
        .send()
        .await
        .expect("request");
    assert_eq!(response.status().as_u16(), 400);
    let body: Value = response.json().await.expect("JSON error body");
    assert_eq!(body["error"]["code"], "invalid_request");

    let (status, body) = get(&server, "/api/v1/auth/login", None).await;
    assert_eq!(status, 405);
    assert_eq!(body["error"]["code"], "method_not_allowed");
}

#[tokio::test]
async fn a_payload_that_cannot_fit_the_outbound_frame_is_rejected_before_storage() {
    let mut config = Config::dev_defaults();
    config.max_payload_bytes = 33 * 1024;
    config.max_frame_bytes = 64 * 1024;
    let server = spawn_with(config).await;
    let (access, _) = register(&server, "frame-limit@example.com").await;
    let (device_id, _credential) = pair_device(&server, &access, "Limit").await;

    let client_ticket = ticket(&server, &access, "client").await;
    let mut client = connect(&server, &client_ticket).await;
    read_type(&mut client, "welcome").await;

    let frame = json!({
        "v": 1,
        "type": "msg",
        "msgId": "frame-limit",
        "to": { "kind": "device", "id": device_id },
        "event": "chat.send",
        "payload": "\"".repeat(32_675),
        "contentType": "text"
    });
    assert!(
        serde_json::to_string(&frame).expect("frame").len() < 64 * 1024,
        "the inbound frame must fit the WebSocket limit; the relayed frame must not"
    );
    send_frame(&mut client, frame).await;

    let error = read_type(&mut client, "error").await;
    assert_eq!(error["code"], "payload_too_large");
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
        .fetch_one(&server.state.pool)
        .await
        .expect("message count");
    assert_eq!(rows, 0, "an undeliverable frame must not be stored");
}

#[tokio::test]
async fn oversized_http_bodies_use_the_error_envelope() {
    let mut config = Config::dev_defaults();
    config.max_payload_bytes = 1024;
    config.max_frame_bytes = 1024;
    let server = spawn_with(config).await;

    let response = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/login", server.http))
        .header("content-type", "application/json")
        .body("x".repeat(8 * 1024))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status().as_u16(), 413);
    let body: Value = response.json().await.expect("JSON error body");
    assert_eq!(body["error"]["code"], "payload_too_large");
}

#[tokio::test]
async fn ticket_creation_is_rate_limited_per_account() {
    let mut config = Config::dev_defaults();
    config.auth_attempts_per_minute = 1;
    let server = spawn_with(config).await;
    let (access, _) = register(&server, "tickets-rate@example.com").await;

    let (status, _) = post(
        &server,
        "/api/v1/tickets",
        json!({ "kind": "client" }),
        Some(&access),
    )
    .await;
    assert_eq!(status, 201);

    let (status, body) = post(
        &server,
        "/api/v1/tickets",
        json!({ "kind": "client" }),
        Some(&access),
    )
    .await;
    assert_eq!(status, 429);
    assert_eq!(body["error"]["code"], "rate_limited");
}

#[tokio::test]
async fn unsupported_versions_are_fatal_and_require_e2ee_is_enforced() {
    let mut config = Config::dev_defaults();
    config.require_e2ee = true;
    let server = spawn_with(config).await;
    let (access, _) = register(&server, "policy@example.com").await;
    let (device_id, _) = pair_device(&server, &access, "Policy").await;

    let client_ticket = ticket(&server, &access, "client").await;
    let mut client = connect(&server, &client_ticket).await;
    read_type(&mut client, "welcome").await;

    send_frame(
        &mut client,
        message(&device_id, "plain-1", "chat.send", r#"{"text":"hi"}"#),
    )
    .await;
    let error = read_type(&mut client, "error").await;
    assert_eq!(error["code"], "forbidden");

    send_frame(&mut client, json!({ "v": 2, "type": "ping" })).await;
    let error = read_type(&mut client, "error").await;
    assert_eq!(error["code"], "unsupported_version");
    assert_eq!(error["fatal"], true);
}

#[tokio::test]
async fn invalid_pairing_input_does_not_burn_the_code() {
    let server = spawn().await;
    let (access, _) = register(&server, "preserve@example.com").await;

    let (status, body) = post(
        &server,
        "/api/v1/devices/pairing",
        json!({ "name": "Laptop" }),
        Some(&access),
    )
    .await;
    assert_eq!(status, 201);
    let code = body["code"].as_str().expect("code").to_string();

    // An invalid request must be rejected before the single-use code is spent.
    let (status, _) = post(
        &server,
        "/api/v1/devices/pair",
        json!({ "code": code, "name": "   " }),
        None,
    )
    .await;
    assert_eq!(status, 400);

    let (status, body) = post(
        &server,
        "/api/v1/devices/pair",
        json!({ "code": code, "name": "Laptop" }),
        None,
    )
    .await;
    assert_eq!(status, 201, "the code must still be usable: {body}");
}

#[tokio::test]
async fn revoking_a_device_removes_its_shares() {
    let server = spawn().await;
    let (owner, _) = register(&server, "share-owner@example.com").await;
    let (guest, _) = register(&server, "share-guest@example.com").await;
    let (device_id, _) = pair_device(&server, &owner, "Shared").await;

    let (status, _) = post(
        &server,
        "/api/v1/grants",
        json!({ "deviceId": device_id, "granteeEmail": "share-guest@example.com" }),
        Some(&owner),
    )
    .await;
    assert_eq!(status, 201);

    let (status, _) = delete(&server, &format!("/api/v1/devices/{device_id}"), &owner).await;
    assert_eq!(status, 204);

    let (status, body) = get(&server, "/api/v1/devices/shared", Some(&guest)).await;
    assert_eq!(status, 200);
    assert_eq!(body["devices"].as_array().expect("devices").len(), 0);

    let (status, body) = get(&server, "/api/v1/grants", Some(&owner)).await;
    assert_eq!(status, 200);
    assert_eq!(body["owned"].as_array().expect("owned").len(), 0);
}
