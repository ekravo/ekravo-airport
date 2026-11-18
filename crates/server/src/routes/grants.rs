use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::{is_unique_violation, ApiError};
use crate::extract::{ApiJson, AuthUser};
use crate::routes::auth::normalize_email;
use crate::state::AppState;
use crate::store::{self, GrantRow};
use crate::util::{iso, new_id, now_secs};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateGrantRequest {
    pub device_id: String,
    pub grantee_email: String,
    pub label: Option<String>,
    #[serde(default)]
    pub allowed_events: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnedGrantDto {
    pub id: String,
    pub device_id: String,
    pub device_name: String,
    pub grantee_email: String,
    pub label: Option<String>,
    pub allowed_events: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceivedGrantDto {
    pub id: String,
    pub device_id: String,
    pub device_name: String,
    pub label: Option<String>,
    pub allowed_events: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantListResponse {
    pub owned: Vec<OwnedGrantDto>,
    pub received: Vec<ReceivedGrantDto>,
}

/// `*`, an exact event name, or a `prefix*` pattern.
fn valid_pattern(pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    match pattern.strip_suffix('*') {
        Some(prefix) => {
            !prefix.is_empty()
                && prefix.len() < 128
                && !prefix.contains('*')
                && airport_protocol::ids::valid_event(prefix)
        }
        None => airport_protocol::ids::valid_event(pattern) && !pattern.contains('*'),
    }
}

fn patterns_of(grant: &GrantRow) -> Vec<String> {
    serde_json::from_str(&grant.allowed_events).unwrap_or_default()
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    AuthUser { user_id }: AuthUser,
    ApiJson(request): ApiJson<CreateGrantRequest>,
) -> Result<(StatusCode, Json<OwnedGrantDto>), ApiError> {
    // Grant creation looks accounts up by email. Rate limiting it per account
    // keeps that from becoming an unlimited address-enumeration oracle.
    if !state.http_limits.check(
        &format!("grant:{user_id}"),
        state.config.auth_attempts_per_minute,
    ) {
        return Err(ApiError::too_many_requests(
            "too many grant requests; try again shortly",
        ));
    }
    let device = store::device_by_id(&state.pool, &request.device_id)
        .await?
        .filter(|device| device.revoked_at.is_none())
        .ok_or_else(|| ApiError::not_found("device not found"))?;
    if device.user_id != user_id {
        return Err(ApiError::not_found("device not found"));
    }

    let email = normalize_email(&request.grantee_email)?;
    let grantee = store::user_by_email(&state.pool, &email)
        .await?
        .ok_or_else(|| ApiError::not_found("no account with that email"))?;
    if grantee.id == user_id {
        return Err(ApiError::bad_request(
            "you already have access to your own devices",
        ));
    }

    let allowed_events = request
        .allowed_events
        .unwrap_or_else(|| vec!["*".to_string()]);
    if allowed_events.is_empty() || allowed_events.len() > 20 {
        return Err(ApiError::bad_request(
            "allowedEvents must contain between 1 and 20 patterns",
        ));
    }
    for pattern in &allowed_events {
        if !valid_pattern(pattern) {
            return Err(ApiError::bad_request(format!(
                "`{pattern}` is not a valid event pattern"
            )));
        }
    }
    let allowed_json = serde_json::to_string(&allowed_events)
        .map_err(|_| ApiError::internal("could not store the grant"))?;

    let grant = GrantRow {
        id: new_id("grant"),
        device_id: device.id.clone(),
        owner_user_id: user_id.clone(),
        grantee_user_id: grantee.id.clone(),
        label: request
            .label
            .as_deref()
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .map(|label| label.chars().take(80).collect()),
        allowed_events: allowed_json,
        created_at: now_secs(),
        revoked_at: None,
    };
    if let Err(error) = store::create_grant(&state.pool, &grant).await {
        if is_unique_violation(&error) {
            return Err(ApiError::conflict(
                "that account already has access to this device",
            ));
        }
        return Err(error.into());
    }

    tracing::info!(owner = %user_id, device_id = %device.id, "share grant created");
    Ok((
        StatusCode::CREATED,
        Json(OwnedGrantDto {
            id: grant.id,
            device_id: device.id,
            device_name: device.name,
            grantee_email: grantee.email,
            label: grant.label,
            allowed_events,
            created_at: iso(grant.created_at),
        }),
    ))
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    AuthUser { user_id }: AuthUser,
) -> Result<Json<GrantListResponse>, ApiError> {
    let owned_rows = store::grants_owned_by(&state.pool, &user_id).await?;
    let mut owned = Vec::new();
    for grant in owned_rows {
        let Some(device) = store::device_by_id(&state.pool, &grant.device_id).await? else {
            continue;
        };
        let Some(grantee) = store::user_by_id(&state.pool, &grant.grantee_user_id).await? else {
            continue;
        };
        let allowed_events = patterns_of(&grant);
        owned.push(OwnedGrantDto {
            id: grant.id,
            device_id: grant.device_id,
            device_name: device.name,
            grantee_email: grantee.email,
            label: grant.label,
            allowed_events,
            created_at: iso(grant.created_at),
        });
    }

    let received_rows = store::grants_for_grantee(&state.pool, &user_id).await?;
    let mut received = Vec::new();
    for grant in received_rows {
        let Some(device) = store::device_by_id(&state.pool, &grant.device_id).await? else {
            continue;
        };
        let allowed_events = patterns_of(&grant);
        received.push(ReceivedGrantDto {
            id: grant.id,
            device_id: grant.device_id,
            device_name: device.name,
            label: grant.label,
            allowed_events,
            created_at: iso(grant.created_at),
        });
    }

    Ok(Json(GrantListResponse { owned, received }))
}

/// Both the owner and the grantee may revoke. A stranger gets 404 so the id's
/// existence is not confirmed.
pub async fn revoke(
    State(state): State<Arc<AppState>>,
    AuthUser { user_id }: AuthUser,
    Path(grant_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let grant = store::grant_by_id(&state.pool, &grant_id)
        .await?
        .ok_or_else(|| ApiError::not_found("grant not found"))?;
    if grant.owner_user_id != user_id && grant.grantee_user_id != user_id {
        return Err(ApiError::not_found("grant not found"));
    }
    store::revoke_grant(&state.pool, &grant_id).await?;
    tracing::info!(user_id = %user_id, grant_id = %grant_id, "grant revoked");
    Ok(StatusCode::NO_CONTENT)
}
