//! Reference Ekravo Airport device client.
//!
//! It dials out, pairs once, keeps one WebSocket open, acknowledges messages,
//! and answers `echo` requests. It demonstrates the protocol; it deliberately
//! exposes no shell or filesystem surface.

mod config;
mod crypto;
mod tls;

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use base64::Engine;
use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

use airport_protocol::{ContentType, Encryption, E2EE_ALG};

use crate::config::DeviceConfig;
use crate::crypto::DeviceKeys;

#[derive(Parser)]
#[command(
    name = "airport-device",
    about = "Reference device client for Ekravo Airport",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Pair this computer with an Airport account using a one-time code.
    Pair {
        #[arg(long, env = "AIRPORT_SERVER", default_value = "http://127.0.0.1:8787")]
        server: String,
        #[arg(long)]
        code: String,
        #[arg(long, default_value = "My computer")]
        name: String,
        #[arg(long)]
        platform: Option<String>,
        /// PEM CA certificate to trust for a private Airport instance.
        #[arg(long, env = "AIRPORT_CA_CERT")]
        ca_cert: Option<PathBuf>,
    },
    /// Keep the outbound tunnel open and answer echo requests.
    Run {
        #[arg(long, env = "AIRPORT_SERVER")]
        server: Option<String>,
        /// PEM CA certificate to trust for a private Airport instance.
        #[arg(long, env = "AIRPORT_CA_CERT")]
        ca_cert: Option<PathBuf>,
    },
    /// Show the local pairing state.
    Status,
    /// Forget the credential and the local identity.
    Logout,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PairResponse {
    device: PairDevice,
    credential: String,
}

#[derive(Debug, Deserialize)]
struct PairDevice {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TicketResponse {
    path: String,
    url: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Pair {
            server,
            code,
            name,
            platform,
            ca_cert,
        } => pair(&server, &code, &name, platform, ca_cert.as_deref()).await,
        Command::Run { server, ca_cert } => run(server, ca_cert).await,
        Command::Status => status(),
        Command::Logout => logout(),
    }
}

async fn pair(
    server: &str,
    code: &str,
    name: &str,
    platform: Option<String>,
    ca_cert: Option<&std::path::Path>,
) -> Result<()> {
    let keys = DeviceKeys::generate();
    let platform =
        platform.unwrap_or_else(|| format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH));
    let response = tls::http_client(ca_cert)?
        .post(format!(
            "{}/api/v1/devices/pair",
            server.trim_end_matches('/')
        ))
        .json(&json!({
            "code": code.trim(),
            "name": name,
            "platform": platform,
            "publicKey": keys.public_b64(),
        }))
        .send()
        .await
        .context("could not reach the Airport server")?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("pairing failed ({status}): {body}");
    }
    let paired: PairResponse =
        serde_json::from_str(&body).context("Airport returned an unexpected pairing response")?;

    DeviceConfig {
        server: server.trim_end_matches('/').to_string(),
        device_id: paired.device.id.clone(),
        device_name: paired.device.name.clone(),
        credential: paired.credential,
        private_key: keys.secret_b64(),
        public_key: keys.public_b64().to_string(),
    }
    .save()?;

    println!("Paired as {} ({}).", paired.device.name, paired.device.id);
    println!("Start the tunnel with `airport-device run`.");
    Ok(())
}

fn status() -> Result<()> {
    let path = DeviceConfig::path()?;
    // A missing file means "not paired". A file that exists but cannot be read
    // or parsed is a real problem and must not be disguised as a fresh device.
    if !path.exists() {
        println!(
            "Not paired. Create a code in your client and run `airport-device pair --code …`."
        );
        return Ok(());
    }
    let config = DeviceConfig::load()?;
    println!("config:      {}", path.display());
    println!("server:      {}", config.server);
    println!("device:      {} ({})", config.device_name, config.device_id);
    println!(
        "public key:  {}…",
        &config.public_key[..config.public_key.len().min(12)]
    );
    println!("credential:  stored");
    Ok(())
}

fn logout() -> Result<()> {
    if DeviceConfig::delete()? {
        println!("Local device identity removed.");
    } else {
        println!("This computer was not paired.");
    }
    Ok(())
}

const NETWORK_TIMEOUT: Duration = Duration::from_secs(30);
const SILENCE_TIMEOUT: Duration = Duration::from_secs(90);

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

enum SessionEnd {
    Closed,
    Revoked,
    Replaced,
}

async fn send_text(socket: &mut Socket, text: String) -> Result<()> {
    tokio::time::timeout(NETWORK_TIMEOUT, socket.send(Message::Text(text)))
        .await
        .context("timed out sending a WebSocket frame")?
        .context("could not send a WebSocket frame")?;
    Ok(())
}

async fn run(server_override: Option<String>, ca_cert: Option<PathBuf>) -> Result<()> {
    let config = DeviceConfig::load()?;
    let server = server_override.unwrap_or_else(|| config.server.clone());
    let keys = DeviceKeys::from_secret_b64(&config.private_key)?;
    let ca_cert = ca_cert.as_deref();

    println!("Connecting to {server} as {}…", config.device_name);
    let mut backoff = Duration::from_secs(1);

    loop {
        let started = Instant::now();
        match session(&server, &config, &keys, ca_cert).await {
            Ok(SessionEnd::Revoked) => {
                println!("This device was revoked. Pair it again to reconnect.");
                return Ok(());
            }
            Ok(SessionEnd::Replaced) => {
                println!("Another process took over this device; stopping.");
                return Ok(());
            }
            Ok(SessionEnd::Closed) => {}
            Err(error) => eprintln!("tunnel: {error:#}"),
        }

        // A session that lasted is a normal network blip, so retry promptly.
        if started.elapsed() > Duration::from_secs(120) {
            backoff = Duration::from_secs(1);
        }
        println!("Reconnecting in {}s…", backoff.as_secs().max(1));
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

async fn session(
    server: &str,
    config: &DeviceConfig,
    keys: &DeviceKeys,
    ca_cert: Option<&std::path::Path>,
) -> Result<SessionEnd> {
    let ticket: TicketResponse = {
        let response = tls::http_client(ca_cert)?
            .post(format!("{server}/api/v1/tickets"))
            .bearer_auth(&config.credential)
            .json(&json!({ "kind": "device" }))
            .send()
            .await
            .context("could not request a connection ticket")?;
        let status = response.status();
        if status.as_u16() == 401 {
            // Retrying a revoked or rotated credential forever would hide the
            // problem. Treat it as a terminal session ending.
            return Ok(SessionEnd::Revoked);
        }
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("ticket request failed ({status}): {body}");
        }
        serde_json::from_str(&body).context("unexpected ticket response")?
    };

    let ws_base = if let Some(rest) = server.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = server.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        bail!("the configured server must start with http:// or https://");
    };
    // Prefer the absolute URL the server built from AIRPORT_PUBLIC_URL; it may
    // differ from the HTTP base when a reverse proxy terminates TLS.
    let url = ticket
        .url
        .clone()
        .unwrap_or_else(|| format!("{ws_base}{}", ticket.path));
    let connector = tls::websocket_connector(ca_cert)?;

    let (mut socket, _) = tokio::time::timeout(
        NETWORK_TIMEOUT,
        tokio_tungstenite::connect_async_tls_with_config(&url, None, false, connector),
    )
    .await
    .context("timed out opening the WebSocket")?
    .context("could not open the WebSocket")?;
    println!("Connected.");

    let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    let mut last_received = Instant::now();

    let mut seen: HashSet<String> = HashSet::new();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\nStopping.");
                return Ok(SessionEnd::Closed);
            }
            _ = heartbeat.tick() => {
                if last_received.elapsed() > SILENCE_TIMEOUT {
                    anyhow::bail!(
                        "the server has not sent anything for {} seconds",
                        SILENCE_TIMEOUT.as_secs()
                    );
                }
                let ping = json!({ "v": 1, "type": "ping" });
                send_text(&mut socket, serde_json::to_string(&ping)?).await?;
            }
            incoming = socket.next() => {
                let Some(incoming) = incoming else {
                    return Ok(SessionEnd::Closed);
                };
                last_received = Instant::now();
                let message = incoming.context("websocket error")?;
                match message {
                    Message::Text(text) => {
                        let frame: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                        match frame["type"].as_str() {
                            Some("welcome") => {
                                println!(
                                    "Registered as {} (heartbeat {} ms).",
                                    frame["deviceId"].as_str().unwrap_or(&config.device_id),
                                    frame["limits"]["heartbeatMs"].as_u64().unwrap_or(25_000)
                                );
                            }
                            Some("msg") => {
                                handle_message(&mut socket, &frame, keys, &mut seen).await?;
                            }
                            Some("revoked") => {
                                return Ok(SessionEnd::Revoked);
                            }
                            Some("replaced") => {
                                return Ok(SessionEnd::Replaced);
                            }
                            Some("error") => {
                                eprintln!(
                                    "server error: {} ({})",
                                    frame["message"].as_str().unwrap_or("unknown"),
                                    frame["code"].as_str().unwrap_or("unknown")
                                );
                            }
                            _ => {}
                        }
                    }
                    Message::Close(_) => return Ok(SessionEnd::Closed),
                    _ => {}
                }
            }
        }
    }
}

async fn handle_message(
    socket: &mut Socket,
    frame: &Value,
    keys: &DeviceKeys,
    seen: &mut HashSet<String>,
) -> Result<()> {
    let msg_id = frame["msgId"].as_str().unwrap_or_default().to_string();
    if msg_id.is_empty() {
        return Ok(());
    }
    // Two senders may reuse a msgId, and the server treats them as distinct.
    // Deduplicate by sender and id, exactly like the server's idempotency key.
    let sender = frame["from"]["userId"].as_str().unwrap_or_default();
    let sender_device = frame["from"]["deviceId"].as_str().unwrap_or_default();
    let dedupe_key = format!("{sender}|{sender_device}|{msg_id}");

    // Bounded so a long-lived tunnel cannot grow memory without limit. Clearing
    // only relaxes duplicate suppression for old ids, which are already acked.
    if seen.len() >= 4096 {
        seen.clear();
    }
    if !seen.insert(dedupe_key) {
        // A replay means the previous ack was not seen. Ack again with the
        // frame's exact seq so a throttled or lost ack cannot strand the row.
        let ack = json!({ "v": 1, "type": "ack", "msgId": msg_id, "seq": frame["seq"] });
        send_text(socket, serde_json::to_string(&ack)?).await?;
        return Ok(());
    }
    let event = frame["event"].as_str().unwrap_or_default().to_string();

    // Acknowledge first: the server can stop replaying even if handling fails.
    let ack = json!({ "v": 1, "type": "ack", "msgId": msg_id, "seq": frame["seq"] });
    send_text(socket, serde_json::to_string(&ack)?).await?;

    let wire_type = frame["contentType"].as_str().unwrap_or("json");
    let (plaintext, plain_type) = match frame.get("enc") {
        Some(enc) if !enc.is_null() => {
            let enc_header: Encryption =
                serde_json::from_value(enc.clone()).context("bad encryption header")?;
            match crypto::open(
                keys,
                &enc_header,
                frame["payload"].as_str().unwrap_or_default(),
                &msg_id,
                &event,
            ) {
                Ok(bytes) => (bytes, enc_header.plain_type.unwrap_or(ContentType::Text)),
                Err(error) => {
                    eprintln!("could not decrypt {msg_id}: {error:#}");
                    return Ok(());
                }
            }
        }
        _ => {
            let payload = frame["payload"].as_str().unwrap_or_default();
            let kind = parse_content_type(wire_type);
            let bytes = if kind == ContentType::Binary {
                B64.decode(payload)
                    .context("binary payload is not standard base64")?
            } else {
                payload.as_bytes().to_vec()
            };
            (bytes, kind)
        }
    };
    let text = String::from_utf8_lossy(&plaintext);
    println!("<- {event} ({} bytes)", plaintext.len());

    let reply_to = frame["from"]["connectionId"].as_str().unwrap_or_default();
    if reply_to.is_empty() {
        return Ok(());
    }
    let reply_event = "echo.reply";
    let reply_id = new_msg_id();
    let mut reply = json!({
        "v": 1,
        "type": "msg",
        "msgId": reply_id,
        "to": { "kind": "connection", "id": reply_to },
        "event": reply_event,
        "replyTo": msg_id,
    });

    match frame["from"]["publicKey"].as_str() {
        Some(public_key) if !public_key.is_empty() => {
            let sealed = crypto::seal(public_key, &plaintext, &reply_id, reply_event)?;
            reply["payload"] = json!(sealed.payload_b64);
            reply["contentType"] = json!("binary");
            reply["enc"] = json!({
                "alg": E2EE_ALG,
                "epk": sealed.epk,
                "nonce": sealed.nonce,
                "plainType": plain_type,
            });
        }
        _ => match plain_type {
            ContentType::Binary => {
                reply["payload"] = json!(B64.encode(&plaintext));
                reply["contentType"] = json!("binary");
            }
            other => {
                reply["payload"] = json!(text);
                reply["contentType"] = json!(other);
            }
        },
    }

    send_text(socket, serde_json::to_string(&reply)?).await?;
    Ok(())
}

fn parse_content_type(value: &str) -> ContentType {
    match value {
        "text" => ContentType::Text,
        "binary" => ContentType::Binary,
        _ => ContentType::Json,
    }
}

fn new_msg_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("msg_{}", URL_SAFE_NO_PAD.encode(bytes))
}
