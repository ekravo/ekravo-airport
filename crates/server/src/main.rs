use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use airport_server::config::{Config, LogFormat};
use airport_server::state::AppState;
use airport_server::{db, routes, store};
use anyhow::Context;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Both `ring` and `aws-lc-rs` can arrive through transitive dependencies.
    // Rustls 0.23 refuses to guess in that case and panics when a TLS config is
    // built, so choose a provider once before anything touches TLS.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    load_environment()?;

    let config = Config::from_env().context("invalid Airport configuration")?;
    init_tracing(config.log_format);

    let pool = db::connect(&config.database_url, 8).await?;
    db::migrate(&pool).await?;

    let state = Arc::new(AppState::new(config.clone(), pool));
    spawn_cleanup(state.clone());

    let service =
        routes::build_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        bind = %config.bind_addr,
        tls = config.tls.is_some(),
        registration = config.allow_registration,
        "Ekravo Airport starting"
    );

    let handle = axum_server::Handle::new();
    let shutdown = handle.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!("shutdown requested");
        shutdown.graceful_shutdown(Some(Duration::from_secs(10)));
    });

    match &config.tls {
        Some(tls) => {
            let rustls =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(&tls.cert_path, &tls.key_path)
                    .await
                    .with_context(|| {
                        format!(
                            "could not load TLS material from {} and {}",
                            tls.cert_path.display(),
                            tls.key_path.display()
                        )
                    })?;
            axum_server::bind_rustls(config.bind_addr, rustls)
                .handle(handle)
                .serve(service)
                .await?;
        }
        None => {
            axum_server::bind(config.bind_addr)
                .handle(handle)
                .serve(service)
                .await?;
        }
    }

    tracing::info!("Airport stopped");
    Ok(())
}

/// Load configuration from `.env` or an explicit `AIRPORT_ENV_FILE`.
///
/// An explicit file that cannot be read is a configuration error, not a
/// reason to fall back to an empty environment. The default `.env` may be
/// absent, but a malformed one is also an error: silently ignoring it makes a
/// typo look like a missing secret or a silent fallback to a default.
fn load_environment() -> anyhow::Result<()> {
    if let Ok(path) = std::env::var("AIRPORT_ENV_FILE") {
        let path = path.trim();
        if !path.is_empty() {
            dotenvy::from_path(path)
                .with_context(|| format!("could not load AIRPORT_ENV_FILE at {path}"))?;
            return Ok(());
        }
    }

    match dotenvy::dotenv() {
        Ok(_) => Ok(()),
        // No .env is the normal case for a service manager or container that
        // passes real environment variables directly.
        Err(error) if error.not_found() => Ok(()),
        Err(error) => Err(error).context("could not parse .env"),
    }
}

fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("airport_server=info,airport=info,tower_http=warn"));
    match format {
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .with_target(true)
            .init(),
        LogFormat::Text => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .init(),
    }
}

/// Expired pairing codes, tickets, refresh tokens, and old delivered messages
/// have no further use. Running this hourly keeps the database bounded.
fn spawn_cleanup(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            match store::cleanup(&state.pool, state.config.retention_secs).await {
                Ok(()) => tracing::debug!("retention cleanup complete"),
                Err(error) => tracing::warn!(error = %error, "retention cleanup failed"),
            }
        }
    });
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
