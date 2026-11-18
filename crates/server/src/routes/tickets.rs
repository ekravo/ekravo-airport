use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::{new_secret, sha256_hex};
use crate::error::ApiError;
use crate::extract::{Actor, ApiJson, DeviceActor};
use crate::state::AppState;
use crate::store;
use crate::util::{iso, new_id, now_secs};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TicketRequest {
    /// `client` (default) or `device`.
    pub kind: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TicketResponse {
    pub ticket: String,
    pub kind: String,
    pub expires_at: String,
    /// Relative path every client can use.
    pub path: String,
    /// Absolute URL when `AIRPORT_PUBLIC_URL` is configured.
    pub url: Option<String>,
}

/// A browser cannot set an Authorization header on a WebSocket handshake, and
/// putting a long-lived secret in a URL leaks it into logs. Instead a caller
/// trades its credential for a 90-second, single-use ticket.
pub async fn create(
    State(state): State<Arc<AppState>>,
    actor: Actor,
    ApiJson(request): ApiJson<TicketRequest>,
) -> Result<(StatusCode, Json<TicketResponse>), ApiError> {
    // A ticket is a database row and a single-use credential. Without a rate
    // limit an authenticated caller can mint them without bound while staying
    // under the live-connection cap; cleanup only runs hourly.
    if !state.http_limits.check(
        &format!("ticket:{}", actor.user_id()),
        state.config.auth_attempts_per_minute,
    ) {
        return Err(ApiError::too_many_requests(
            "too many connection tickets requested; try again shortly",
        ));
    }

    let kind = request.kind.as_deref().unwrap_or("client").to_string();
    let (role, device_id) = match kind.as_str() {
        "client" => ("client", None),
        "device" => match &actor {
            Actor::Device(DeviceActor { device_id, .. }) => ("device", Some(device_id.clone())),
            Actor::User(_) => {
                return Err(ApiError::forbidden(
                    "a device ticket can only be requested with a device credential",
                ))
            }
        },
        _ => return Err(ApiError::bad_request("kind must be `client` or `device`")),
    };

    if role == "device" {
        if let Some(device_id) = &device_id {
            let device = store::device_by_id(&state.pool, device_id)
                .await?
                .filter(|device| device.revoked_at.is_none())
                .ok_or_else(|| ApiError::unauthorized("this device is no longer authorized"))?;
            let _ = store::touch_device(&state.pool, &device.id).await;
        }
    }

    if state.registry.count_user_connections(actor.user_id())
        >= state.config.max_connections_per_user
    {
        return Err(ApiError::too_many_requests(
            "this account has reached its connection limit",
        ));
    }

    let ticket = new_secret(32);
    let expires_at = now_secs() + state.config.ticket_ttl_secs;
    store::create_ticket(
        &state.pool,
        &new_id("tkt"),
        &sha256_hex(&ticket),
        actor.user_id(),
        device_id.as_deref(),
        role,
        expires_at,
    )
    .await?;

    let path = format!("/v1/connect?ticket={ticket}");
    let url = state
        .config
        .websocket_url(&ticket)
        .or_else(|| state.config.public_url.as_ref().map(|_| path.clone()));

    Ok((
        StatusCode::CREATED,
        Json(TicketResponse {
            ticket,
            kind: role.to_string(),
            expires_at: iso(expires_at),
            path,
            url,
        }),
    ))
}
