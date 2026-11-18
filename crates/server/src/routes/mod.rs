use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::Request;
use axum::http::header::{self, HeaderName, HeaderValue};
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::error::ApiError;
use crate::state::AppState;

/// Upper bound on a single HTTP API request, from headers through body and the
/// handler. The WebSocket endpoint is deliberately excluded: it is long-lived.
const API_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub mod auth;
pub mod devices;
pub mod grants;
pub mod health;
pub mod tickets;
pub mod ws;

/// The trusted client IP for rate limiting.
///
/// `X-Forwarded-For` is honored only when `AIRPORT_TRUST_PROXY=true`, because
/// otherwise any caller could choose its own bucket by spoofing the header.
pub fn client_ip(headers: &axum::http::HeaderMap, addr: SocketAddr, trust_proxy: bool) -> String {
    if trust_proxy {
        if let Some(value) = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
        {
            if let Some(first) = value.split(',').next() {
                let candidate = first.trim();
                if !candidate.is_empty() && candidate.len() <= 64 {
                    return candidate.to_string();
                }
            }
        }
    }
    addr.ip().to_string()
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let api = Router::new()
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/logout", post(auth::logout))
        .route("/me", get(auth::me))
        .route("/devices", get(devices::list))
        .route("/devices/pairing", post(devices::create_pairing))
        .route("/devices/pair", post(devices::pair))
        .route("/devices/shared", get(devices::shared))
        .route("/devices/{device_id}", delete(devices::revoke))
        .route("/devices/{device_id}/rotate", post(devices::rotate))
        .route("/grants", get(grants::list).post(grants::create))
        .route("/grants/{grant_id}", delete(grants::revoke))
        .route("/tickets", post(tickets::create))
        // Tokens and account details must never be stored by a browser or an
        // intermediary, including successful responses.
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(middleware::from_fn(request_timeout));

    let mut router = Router::new()
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
        .route("/version", get(health::version))
        .nest("/api/v1", api)
        .route("/v1/connect", get(ws::connect));

    if !state.config.trusted_origins.is_empty() {
        let origins: Vec<HeaderValue> = state
            .config
            .trusted_origins
            .iter()
            .filter_map(|origin| origin.parse::<HeaderValue>().ok())
            .collect();
        router = router.layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
                .max_age(Duration::from_secs(600)),
        );
    }

    let security = (
        SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ),
        SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ),
    );

    let mut router = router
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(security)
        .layer(RequestBodyLimitLayer::new(state.config.max_frame_bytes))
        // The body-limit layer rejects with an empty 413. The public API contract
        // is the JSON error envelope, so normalize only that empty response.
        .layer(middleware::from_fn(normalize_payload_limit))
        // Log the path, never the full URI: a WebSocket ticket lives in the
        // query string and must not end up in debug logs.
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request| {
                tracing::debug_span!(
                    "request",
                    method = %request.method(),
                    path = %request.uri().path(),
                )
            }),
        );

    if state.config.tls.is_some() {
        router = router.layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ));
    }

    router.with_state(state)
}

/// Bound the complete API request, including reading a slow body and waiting
/// for a database connection. A caller that exceeds it gets the same JSON
/// envelope as every other failure.
async fn request_timeout(request: Request, next: Next) -> Response {
    timeout_response(API_REQUEST_TIMEOUT, next.run(request)).await
}

async fn timeout_response<F>(duration: Duration, future: F) -> Response
where
    F: Future<Output = Response>,
{
    match tokio::time::timeout(duration, future).await {
        Ok(response) => response,
        Err(_) => ApiError::new(
            StatusCode::REQUEST_TIMEOUT,
            "request_timeout",
            "the request did not complete in time",
        )
        .into_response(),
    }
}

/// Convert the empty 413 from `RequestBodyLimitLayer` into the documented error
/// envelope. Handler-produced 413s already carry JSON and are left alone.
async fn normalize_payload_limit(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    let already_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.starts_with("application/json"))
        .unwrap_or(false);
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE && !already_json {
        return ApiError::payload_too_large("request body is too large").into_response();
    }
    response
}

async fn not_found() -> ApiError {
    ApiError::not_found("route not found")
}

async fn method_not_allowed() -> ApiError {
    ApiError::new(
        axum::http::StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "method not allowed for this route",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn a_slow_request_gets_the_documented_error_envelope() {
        let response = timeout_response(Duration::from_millis(5), async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            StatusCode::OK.into_response()
        })
        .await;

        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON error body");
        assert_eq!(body["error"]["code"], "request_timeout");
    }
}
