//! Device-local configuration. The credential and private key live here with
//! owner-only permissions; on systems with a credential store, a production
//! client should move the credential there (see docs/integration.md).

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub server: String,
    pub device_id: String,
    pub device_name: String,
    pub credential: String,
    /// Base64 X25519 static secret.
    pub private_key: String,
    pub public_key: String,
}

impl DeviceConfig {
    pub fn dir() -> Result<PathBuf> {
        let base = dirs::config_dir().context("no config directory is available")?;
        Ok(base.join("ekravo-airport"))
    }

    /// `AIRPORT_DEVICE_CONFIG` overrides the path, which is useful for
    /// service managers, tests, and hosts that keep state outside the home
    /// directory. Otherwise `<config>/ekravo-airport/device.json` is used.
    pub fn path() -> Result<PathBuf> {
        if let Some(path) = std::env::var_os("AIRPORT_DEVICE_CONFIG") {
            let path = PathBuf::from(path);
            if path.as_os_str().is_empty() {
                return Err(anyhow::anyhow!(
                    "AIRPORT_DEVICE_CONFIG is empty; unset it or give a file path"
                ));
            }
            return Ok(path);
        }
        Ok(Self::dir()?.join("device.json"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        let raw = fs::read_to_string(&path).with_context(|| {
            format!(
                "this device is not paired yet (no config at {}); run `airport-device pair`",
                path.display()
            )
        })?;
        serde_json::from_str(&raw).context("the device config is not valid JSON")
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        let dir = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("the device config path has no directory"))?;
        fs::create_dir_all(dir)?;
        restrict_dir(dir)?;
        let temporary = path.with_extension("tmp");
        let data = serde_json::to_vec_pretty(self)?;
        fs::write(&temporary, &data)?;
        restrict(&temporary)?;
        fs::rename(&temporary, &path)?;
        Ok(())
    }

    pub fn delete() -> Result<bool> {
        let path = Self::path()?;
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error).context("could not remove the device config"),
        }
    }
}

#[cfg(unix)]
fn restrict(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(unix)]
fn restrict_dir(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict(path: &std::path::Path) -> Result<()> {
    // Windows ACLs are inherited from the user profile; SECURITY.md documents
    // that a production client should use DPAPI or the credential manager.
    let _ = path;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_dir(path: &std::path::Path) -> Result<()> {
    let _ = path;
    Ok(())
}
