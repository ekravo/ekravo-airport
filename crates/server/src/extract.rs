use std::sync::Arc;

use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use serde::de::DeserializeOwned;
use subtle::ConstantTimeEq;

use crate::auth::{
    bearer_token, decode_access_token, secret_prefix, sha256_hex, DEVICE_CREDENTIAL_PREFIX,
};
use crate::error::ApiError;
use crate::state::AppState;
use crate::store;

/// JSON request body with a consistent error envelope.
///
/// Axum's built-in `Json` rejection is plain text, which breaks the API's
/// documented `{ "error": { "code", "message" } }` shape. Parsing through this
/// wrapper keeps malformed bodies on the same contract as every other failure.
pub struct ApiJson<T>(pub T);

impl<T, S> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(request, state).await {
            Ok(axum::Json(value)) => Ok(ApiJson(value)),
            Err(rejection) => Err(ApiError::new(
                rejection.status(),
                "invalid_request",
                format!("request body is invalid: {}", rejection.body_text()),
            )),
        }
    }
}

/// A user authenticated by a short-lived access token.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: String,
}

impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        let token = bearer_token(header)
            .ok_or_else(|| ApiError::unauthorized("authentication required"))?;
        if token.starts_with(DEVICE_CREDENTIAL_PREFIX) {
            return Err(ApiError::unauthorized(
                "device credentials cannot be used for this endpoint",
            ));
        }
        let claims = decode_access_token(&state.config.jwt_secret, token)?;
        let user = store::user_by_id(&state.pool, &claims.sub)
            .await?
            .filter(|user| user.disabled == 0)
            .ok_or_else(|| ApiError::unauthorized("account is not active"))?;
        Ok(AuthUser { user_id: user.id })
    }
}

/// A device authenticated by its long-lived credential.
#[derive(Debug, Clone)]
pub struct DeviceActor {
    pub device_id: String,
    pub user_id: String,
}

/// Either a user token or a device credential. Used by the ticket endpoint,
/// which is the only HTTP route a device needs.
#[derive(Debug, Clone)]
pub enum Actor {
    User(AuthUser),
    Device(DeviceActor),
}

impl Actor {
    pub fn user_id(&self) -> &str {
        match self {
            Actor::User(user) => &user.user_id,
            Actor::Device(device) => &device.user_id,
        }
    }

    pub fn device_id(&self) -> Option<&str> {
        match self {
            Actor::User(_) => None,
            Actor::Device(device) => Some(&device.device_id),
        }
    }
}

impl FromRequestParts<Arc<AppState>> for Actor {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        let token = bearer_token(header)
            .ok_or_else(|| ApiError::unauthorized("authentication required"))?;

        if !token.starts_with(DEVICE_CREDENTIAL_PREFIX) {
            let user = AuthUser::from_request_parts(parts, state).await?;
            return Ok(Actor::User(user));
        }

        let hash = sha256_hex(token);
        let prefix = secret_prefix(&hash);
        let device = store::device_by_credential_prefix(&state.pool, &prefix)
            .await?
            .ok_or_else(|| ApiError::unauthorized("device credential is invalid"))?;

        // Lookup is by a hash prefix; the full hash is still compared in
        // constant time so a prefix collision cannot authenticate.
        if device
            .credential_hash
            .as_bytes()
            .ct_eq(hash.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(ApiError::unauthorized("device credential is invalid"));
        }

        store::user_by_id(&state.pool, &device.user_id)
            .await?
            .filter(|user| user.disabled == 0)
            .ok_or_else(|| ApiError::unauthorized("account is not active"))?;

        Ok(Actor::Device(DeviceActor {
            device_id: device.id,
            user_id: device.user_id,
        }))
    }
}
