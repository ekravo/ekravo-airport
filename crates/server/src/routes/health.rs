use std::sync::Arc;

use airport_protocol::PROTOCOL_VERSION;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

use crate::error::ApiError;
use crate::state::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    status: &'static str,
    version: &'static str,
    uptime_seconds: u64,
    connections: usize,
}

pub async fn healthz(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: state.uptime_seconds(),
        connections: state.registry.connection_count(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadyResponse {
    status: &'static str,
    checks: ReadyChecks,
}

#[derive(Serialize)]
pub struct ReadyChecks {
    database: &'static str,
}

/// Readiness proves the server can reach its database. It is intentionally
/// separate from liveness: a database blip should drain traffic, not restart the
/// process.
pub async fn readyz(
    State(state): State<Arc<AppState>>,
) -> Result<(StatusCode, Json<ReadyResponse>), ApiError> {
    match sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.pool)
        .await
    {
        Ok(_) => Ok((
            StatusCode::OK,
            Json(ReadyResponse {
                status: "ready",
                checks: ReadyChecks { database: "ok" },
            }),
        )),
        Err(error) => {
            tracing::error!(error = %error, "readiness check failed");
            Err(ApiError::service_unavailable("database is not ready"))
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionResponse {
    name: &'static str,
    version: &'static str,
    protocol_version: u32,
}

pub async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        name: "ekravo-airport",
        version: env!("CARGO_PKG_VERSION"),
        protocol_version: PROTOCOL_VERSION,
    })
}
