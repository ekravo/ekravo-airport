use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::{hash_password, issue_access_token, new_secret, sha256_hex, verify_password};
use crate::error::{is_unique_violation, ApiError};
use crate::extract::{ApiJson, AuthUser};
use crate::routes::client_ip;
use crate::state::AppState;
use crate::store::{self, UserRow};
use crate::util::{iso, new_id, now_secs};

const MIN_PASSWORD_LEN: usize = 10;
const MAX_PASSWORD_LEN: usize = 256;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserDto {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub created_at: String,
}

impl From<&UserRow> for UserDto {
    fn from(user: &UserRow) -> Self {
        Self {
            id: user.id.clone(),
            email: user.email.clone(),
            display_name: user.display_name.clone(),
            created_at: iso(user.created_at),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponse {
    pub user: UserDto,
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
}

/// Lowercase, trimmed email with a deliberately small validity check. RFC 5322
/// compliance is not the goal; rejecting whitespace and missing parts is.
pub(crate) fn normalize_email(raw: &str) -> Result<String, ApiError> {
    let email = raw.trim().to_lowercase();
    let valid = email.len() <= 254
        && !email.contains(char::is_whitespace)
        && email.matches('@').count() == 1
        && email
            .split_once('@')
            .map(|(local, domain)| !local.is_empty() && !domain.is_empty() && domain.contains('.'))
            .unwrap_or(false);
    if !valid {
        return Err(ApiError::bad_request("a valid email address is required"));
    }
    Ok(email)
}

fn validate_password(password: &str) -> Result<(), ApiError> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(ApiError::bad_request(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(ApiError::bad_request("password is too long"));
    }
    Ok(())
}

/// Create a refresh token row and mint an access token.
async fn issue_session(state: &Arc<AppState>, user: &UserRow) -> Result<AuthResponse, ApiError> {
    let (access_token, expires_in) = issue_access_token(
        &state.config.jwt_secret,
        &user.id,
        state.config.access_token_ttl_secs,
    )?;
    let refresh_token = new_secret(32);
    store::insert_refresh_token(
        &state.pool,
        &new_id("rt"),
        &user.id,
        &sha256_hex(&refresh_token),
        now_secs() + state.config.refresh_token_ttl_secs,
    )
    .await?;
    Ok(AuthResponse {
        user: UserDto::from(user),
        access_token,
        refresh_token,
        token_type: "Bearer",
        expires_in,
    })
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<RegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let ip = client_ip(&headers, addr, state.config.trust_proxy);
    if !state.http_limits.check(
        &format!("register:{ip}"),
        state.config.auth_attempts_per_minute,
    ) {
        return Err(ApiError::too_many_requests(
            "too many registration attempts; try again shortly",
        ));
    }

    let email = normalize_email(&request.email)?;
    validate_password(&request.password)?;
    let display_name = request
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| name.chars().take(80).collect::<String>());

    // A closed instance still needs its first account, otherwise self-hosting
    // requires editing the database by hand.
    if !state.config.allow_registration && store::user_count(&state.pool).await? > 0 {
        return Err(ApiError::forbidden(
            "registration is closed on this Airport instance",
        ));
    }

    if store::user_by_email(&state.pool, &email).await?.is_some() {
        return Err(ApiError::conflict(
            "an account with that email already exists",
        ));
    }

    let user_id = new_id("usr");
    let password_hash = hash_password(&request.password)?;
    match store::create_user_guarded(
        &state.pool,
        &user_id,
        &email,
        &password_hash,
        display_name.as_deref(),
        state.config.allow_registration,
    )
    .await
    {
        Ok(store::CreateUserOutcome::Created) => {}
        Ok(store::CreateUserOutcome::RegistrationClosed) => {
            return Err(ApiError::forbidden(
                "registration is closed on this Airport instance",
            ))
        }
        Err(error) if is_unique_violation(&error) => {
            return Err(ApiError::conflict(
                "an account with that email already exists",
            ))
        }
        Err(error) => return Err(error.into()),
    }

    let user = store::user_by_id(&state.pool, &user_id)
        .await?
        .ok_or_else(|| ApiError::internal("the account could not be created"))?;
    let session = issue_session(&state, &user).await?;
    tracing::info!(user_id = %user.id, "account registered");
    Ok((StatusCode::CREATED, Json(session)))
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<LoginRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    // Reject absurd inputs before hashing or querying, so an oversized body
    // cannot turn into unnecessary CPU work.
    if request.email.len() > 254 || request.password.len() > MAX_PASSWORD_LEN {
        return Err(ApiError::unauthorized("invalid email or password"));
    }
    let ip = client_ip(&headers, addr, state.config.trust_proxy);
    if !state.http_limits.check(
        &format!("login:{ip}"),
        state.config.auth_attempts_per_minute,
    ) {
        return Err(ApiError::too_many_requests(
            "too many sign-in attempts; try again shortly",
        ));
    }

    let email = request.email.trim().to_lowercase();
    let user = store::user_by_email(&state.pool, &email).await?;
    let Some(user) = user else {
        // Do the same work as a real verification so timing does not reveal
        // whether the address exists. The dummy hash never verifies.
        let _ = verify_password(
            &request.password,
            "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$7Zmq0hE1eC0nT5wPZQ1YgG6rZ1n9bYhLrB0V0u3Zx8k",
        );
        return Err(ApiError::unauthorized("invalid email or password"));
    };
    if !verify_password(&request.password, &user.password_hash) {
        return Err(ApiError::unauthorized("invalid email or password"));
    }
    if user.disabled != 0 {
        return Err(ApiError::forbidden("this account is disabled"));
    }

    let session = issue_session(&state, &user).await?;
    tracing::info!(user_id = %user.id, "sign-in");
    Ok(Json(session))
}

/// Rotate a refresh token. Reuse of an already-rotated token revokes the whole
/// family, which is the standard response to a stolen-token replay.
pub async fn refresh(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<RefreshRequest>,
) -> Result<Json<RefreshResponse>, ApiError> {
    let ip = client_ip(&headers, addr, state.config.trust_proxy);
    if !state.http_limits.check(
        &format!("refresh:{ip}"),
        state.config.auth_attempts_per_minute,
    ) {
        return Err(ApiError::too_many_requests(
            "too many refresh attempts; try again shortly",
        ));
    }
    if request.refresh_token.len() > 512 {
        return Err(ApiError::unauthorized("refresh token is invalid"));
    }
    let hash = sha256_hex(&request.refresh_token);
    let row = store::refresh_by_hash(&state.pool, &hash)
        .await?
        .ok_or_else(|| ApiError::unauthorized("refresh token is invalid"))?;

    if row.revoked_at.is_some() {
        tracing::warn!(user_id = %row.user_id, "refresh token reuse detected; revoking the family");
        store::revoke_all_refresh_tokens(&state.pool, &row.user_id).await?;
        return Err(ApiError::unauthorized("refresh token was already used"));
    }
    if row.expires_at <= now_secs() {
        return Err(ApiError::unauthorized("refresh token has expired"));
    }

    let user = store::user_by_id(&state.pool, &row.user_id)
        .await?
        .filter(|user| user.disabled == 0)
        .ok_or_else(|| ApiError::unauthorized("account is not active"))?;

    let refresh_token = new_secret(32);
    let new_id_value = new_id("rt");
    // The read above is only a shortcut. The rotation itself is a conditional
    // update in one transaction, so two simultaneous refreshes cannot both
    // succeed and split the token family.
    let rotated = store::rotate_refresh_token(
        &state.pool,
        &row.id,
        &new_id_value,
        &user.id,
        &sha256_hex(&refresh_token),
        now_secs() + state.config.refresh_token_ttl_secs,
    )
    .await?;
    if rotated.is_none() {
        tracing::warn!(user_id = %user.id, "concurrent refresh token use detected; revoking the family");
        store::revoke_all_refresh_tokens(&state.pool, &user.id).await?;
        return Err(ApiError::unauthorized("refresh token was already used"));
    }

    let (access_token, expires_in) = issue_access_token(
        &state.config.jwt_secret,
        &user.id,
        state.config.access_token_ttl_secs,
    )?;

    Ok(Json(RefreshResponse {
        access_token,
        refresh_token,
        token_type: "Bearer",
        expires_in,
    }))
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<RefreshRequest>,
) -> Result<StatusCode, ApiError> {
    let ip = client_ip(&headers, addr, state.config.trust_proxy);
    if !state.http_limits.check(
        &format!("logout:{ip}"),
        state.config.auth_attempts_per_minute,
    ) {
        return Err(ApiError::too_many_requests(
            "too many logout attempts; try again shortly",
        ));
    }
    // Logout is idempotent and does not reveal whether the token existed. A
    // value longer than any real token cannot match, so avoid hashing an
    // attacker-sized string.
    if request.refresh_token.len() > 512 {
        return Ok(StatusCode::NO_CONTENT);
    }
    let hash = sha256_hex(&request.refresh_token);
    store::revoke_refresh_token(&state.pool, &hash).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeResponse {
    pub user: UserDto,
    pub devices: i64,
}

pub async fn me(
    State(state): State<Arc<AppState>>,
    AuthUser { user_id }: AuthUser,
) -> Result<Json<MeResponse>, ApiError> {
    let user = store::user_by_id(&state.pool, &user_id)
        .await?
        .ok_or_else(|| ApiError::unauthorized("account is not active"))?;
    let devices = store::active_device_count(&state.pool, &user_id).await?;
    Ok(Json(MeResponse {
        user: UserDto::from(&user),
        devices,
    }))
}
