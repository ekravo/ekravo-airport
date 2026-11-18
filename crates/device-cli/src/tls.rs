//! Optional private-CA trust.
//!
//! Public deployments use the platform roots. A self-hosted Airport with a
//! private CA (or a locally generated test certificate) can be trusted with
//! `--ca-cert` / `AIRPORT_CA_CERT`, which applies to both the HTTP API and the
//! WebSocket listener. That is deliberately explicit: the client never disables
//! certificate verification.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use tokio_tungstenite::Connector;

fn read_ca(path: &Path) -> Result<Vec<u8>> {
    fs::read(path)
        .with_context(|| format!("could not read the CA certificate at {}", path.display()))
}

/// Build the HTTP client, adding the CA when one is configured.
pub fn http_client(ca: Option<&Path>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .user_agent(concat!("airport-device/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(30));
    if let Some(path) = ca {
        let pem = read_ca(path)?;
        let certificate = reqwest::Certificate::from_pem(&pem)
            .context("the CA file is not a valid PEM certificate")?;
        builder = builder.add_root_certificate(certificate);
    }
    builder.build().context("could not build the HTTP client")
}

/// Build a WebSocket TLS connector that trusts exactly the configured CA.
pub fn websocket_connector(ca: Option<&Path>) -> Result<Option<Connector>> {
    let Some(path) = ca else {
        return Ok(None);
    };
    let pem = read_ca(path)?;
    let mut store = RootCertStore::empty();
    let certificates = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .context("the CA file is not valid PEM")?;
    if certificates.is_empty() {
        return Err(anyhow!("the CA file contains no certificates"));
    }
    for certificate in certificates {
        store
            .add(certificate)
            .map_err(|error| anyhow!("the CA certificate was rejected: {error}"))?;
    }

    // Pick the provider explicitly: rustls 0.23 requires it when more than one
    // crypto backend is compiled in.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("could not configure TLS")?
        .with_root_certificates(store)
        .with_no_client_auth();

    Ok(Some(Connector::Rustls(Arc::new(config))))
}
