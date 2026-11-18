use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use airport_protocol::{encode_frame, validate_public_key, RevokedFrame};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::{new_device_credential, new_pairing_code, secret_prefix, sha256_hex};
use crate::error::{is_unique_violation, ApiError};
use crate::extract::{ApiJson, AuthUser};
use crate::routes::client_ip;
use crate::state::AppState;
use crate::store::{self, DeviceRow};
use crate::util::{iso, new_id, now_secs};

const MAX_DEVICE_NAME: usize = 60;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePairingRequest {
    pub name: String,
    pub platform: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingResponse {
    pub code: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairRequest {
    pub code: String,
    pub name: String,
    pub platform: Option<String>,
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceDto {
    pub id: String,
    pub name: String,
    pub platform: Option<String>,
    pub public_key: Option<String>,
    pub online: bool,
    pub created_at: String,
    pub last_seen_at: Option<String>,
}

fn device_dto(state: &Arc<AppState>, device: &DeviceRow) -> DeviceDto {
    DeviceDto {
        id: device.id.clone(),
        name: device.name.clone(),
        platform: device.platform.clone(),
        public_key: device.public_key.clone(),
        online: state.registry.is_device_online(&device.id),
        created_at: iso(device.created_at),
        last_seen_at: device.last_seen_at.map(iso),
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceListResponse {
    pub devices: Vec<DeviceDto>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairResponse {
    pub device: DeviceDto,
    /// Shown once. The device stores it in the OS credential store.
    pub credential: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateResponse {
    pub device: DeviceDto,
    pub credential: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedDeviceDto {
    #[serde(flatten)]
    pub device: DeviceDto,
    pub owner_name: Option<String>,
    pub grant_id: String,
    pub allowed_events: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedDeviceListResponse {
    pub devices: Vec<SharedDeviceDto>,
}

fn clean_name(raw: &str) -> Result<String, ApiError> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("a device name is required"));
    }
    Ok(name.chars().take(MAX_DEVICE_NAME).collect())
}

fn clean_platform(raw: Option<&str>) -> Result<Option<String>, ApiError> {
    Ok(raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(64).collect::<String>()))
}

pub async fn create_pairing(
    State(state): State<Arc<AppState>>,
    AuthUser { user_id }: AuthUser,
    ApiJson(request): ApiJson<CreatePairingRequest>,
) -> Result<(StatusCode, Json<PairingResponse>), ApiError> {
    if !state.http_limits.check(
        &format!("pairing:{user_id}"),
        state.config.auth_attempts_per_minute,
    ) {
        return Err(ApiError::too_many_requests(
            "too many pairing codes requested; try again shortly",
        ));
    }
    let name = clean_name(&request.name)?;
    clean_platform(request.platform.as_deref())?;

    let active = store::active_device_count(&state.pool, &user_id).await?;
    if active >= state.config.max_devices_per_user {
        return Err(ApiError::forbidden(format!(
            "you can pair up to {} devices; revoke one first",
            state.config.max_devices_per_user
        )));
    }

    let code = new_pairing_code();
    let expires_at = now_secs() + state.config.pairing_ttl_secs;
    store::create_pairing_code(&state.pool, &sha256_hex(&code), &user_id, &name, expires_at)
        .await?;

    tracing::info!(user_id = %user_id, "pairing code created");
    Ok((
        StatusCode::CREATED,
        Json(PairingResponse {
            code,
            expires_at: iso(expires_at),
        }),
    ))
}

/// Exchange a one-time code for a per-device credential. The code is the only
/// authorization here, which is why it is high-entropy, short-lived, single-use,
/// and IP rate-limited.
pub async fn pair(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<PairRequest>,
) -> Result<(StatusCode, Json<PairResponse>), ApiError> {
    let ip = client_ip(&headers, addr, state.config.trust_proxy);
    if !state
        .http_limits
        .check(&format!("pair:{ip}"), state.config.auth_attempts_per_minute)
    {
        return Err(ApiError::too_many_requests(
            "too many pairing attempts; try again shortly",
        ));
    }

    if request.code.len() > 256 {
        return Err(ApiError::bad_request("pairing code is invalid"));
    }
    // Validate the request before spending the code. A malformed name or key
    // must not burn a valid single-use credential.
    let name = clean_name(&request.name)?;
    let platform = clean_platform(request.platform.as_deref())?;
    if let Some(key) = &request.public_key {
        validate_public_key(key)
            .map_err(|error| ApiError::bad_request(format!("public key is invalid: {error}")))?;
    }

    let pairing = store::consume_pairing_code(&state.pool, &sha256_hex(request.code.trim()))
        .await?
        .ok_or_else(|| {
            ApiError::bad_request("pairing code is invalid, already used, or expired")
        })?;

    let user = store::user_by_id(&state.pool, &pairing.user_id)
        .await?
        .filter(|user| user.disabled == 0)
        .ok_or_else(|| ApiError::bad_request("the account is not active"))?;

    let active = store::active_device_count(&state.pool, &user.id).await?;
    if active >= state.config.max_devices_per_user {
        return Err(ApiError::forbidden(format!(
            "this account already has {} paired devices",
            state.config.max_devices_per_user
        )));
    }

    let device_id = new_id("dev");
    let credential = new_device_credential();
    let credential_hash = sha256_hex(&credential);
    let device = DeviceRow {
        id: device_id.clone(),
        user_id: user.id.clone(),
        name: name.clone(),
        platform: platform.clone(),
        public_key: request.public_key.clone(),
        credential_hash: credential_hash.clone(),
        credential_prefix: secret_prefix(&credential_hash),
        created_at: now_secs(),
        last_seen_at: None,
        revoked_at: None,
    };
    match store::create_device_guarded(&state.pool, &device, state.config.max_devices_per_user)
        .await
    {
        Ok(store::CreateDeviceOutcome::Created) => {}
        Ok(store::CreateDeviceOutcome::LimitReached) => {
            return Err(ApiError::forbidden(format!(
                "this account already has {} paired devices",
                state.config.max_devices_per_user
            )))
        }
        Err(error) if is_unique_violation(&error) => {
            return Err(ApiError::conflict("the device could not be registered"))
        }
        Err(error) => return Err(error.into()),
    }

    tracing::info!(user_id = %user.id, device_id = %device_id, "device paired");
    Ok((
        StatusCode::CREATED,
        Json(PairResponse {
            device: device_dto(&state, &device),
            credential,
        }),
    ))
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    AuthUser { user_id }: AuthUser,
) -> Result<Json<DeviceListResponse>, ApiError> {
    let devices = store::devices_for_user(&state.pool, &user_id).await?;
    Ok(Json(DeviceListResponse {
        devices: devices
            .iter()
            .map(|device| device_dto(&state, device))
            .collect(),
    }))
}

pub async fn shared(
    State(state): State<Arc<AppState>>,
    AuthUser { user_id }: AuthUser,
) -> Result<Json<SharedDeviceListResponse>, ApiError> {
    let grants = store::grants_for_grantee(&state.pool, &user_id).await?;
    let mut devices = Vec::new();
    for grant in grants {
        let Some(device) = store::device_by_id(&state.pool, &grant.device_id).await? else {
            continue;
        };
        if device.revoked_at.is_some() {
            continue;
        }
        let owner = store::user_by_id(&state.pool, &grant.owner_user_id).await?;
        let allowed_events: Vec<String> =
            serde_json::from_str(&grant.allowed_events).unwrap_or_default();
        devices.push(SharedDeviceDto {
            device: device_dto(&state, &device),
            owner_name: owner.and_then(|owner| owner.display_name),
            grant_id: grant.id,
            allowed_events,
        });
    }
    Ok(Json(SharedDeviceListResponse { devices }))
}

/// Send a final frame, give the writer a moment to flush it, then stop the loop.
/// Called when a device is revoked or its credential rotates.
fn disconnect_device(state: &Arc<AppState>, device_id: &str, frame_text: Option<String>) {
    let Some(handle) = state.registry.device(device_id) else {
        return;
    };
    tokio::spawn(async move {
        if let Some(text) = frame_text {
            let _ = handle.tx.send(text).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        handle.shutdown.notify_one();
    });
}

pub async fn revoke(
    State(state): State<Arc<AppState>>,
    AuthUser { user_id }: AuthUser,
    Path(device_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if !device_id.starts_with("dev_") || device_id.len() > 64 {
        return Err(ApiError::not_found("device not found"));
    }
    if !store::revoke_device(&state.pool, &user_id, &device_id).await? {
        return Err(ApiError::not_found("device not found"));
    }
    let frame = encode_frame(&RevokedFrame::new("device was revoked")).ok();
    disconnect_device(&state, &device_id, frame);
    tracing::info!(user_id = %user_id, device_id = %device_id, "device revoked");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn rotate(
    State(state): State<Arc<AppState>>,
    AuthUser { user_id }: AuthUser,
    Path(device_id): Path<String>,
) -> Result<Json<RotateResponse>, ApiError> {
    if !device_id.starts_with("dev_") || device_id.len() > 64 {
        return Err(ApiError::not_found("device not found"));
    }
    let credential = new_device_credential();
    let hash = sha256_hex(&credential);
    if !store::rotate_device_credential(
        &state.pool,
        &user_id,
        &device_id,
        &hash,
        &secret_prefix(&hash),
    )
    .await?
    {
        return Err(ApiError::not_found("device not found"));
    }
    let device = store::device_by_id(&state.pool, &device_id)
        .await?
        .ok_or_else(|| ApiError::not_found("device not found"))?;
    let frame = encode_frame(&RevokedFrame::new("device credential was rotated")).ok();
    disconnect_device(&state, &device_id, frame);
    tracing::info!(user_id = %user_id, device_id = %device_id, "device credential rotated");
    Ok(Json(RotateResponse {
        device: device_dto(&state, &device),
        credential,
    }))
}
