pub mod cloudflare;
pub mod local;
pub mod unifi;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::IpAddr;

/// Common trait exposed by all IP source and target providers.
#[async_trait]
pub trait Provider: Send + Sync {
    /// Initializes the provider instance using settings from its `config` block.
    async fn initialize(&mut self, config: &HashMap<String, String>) -> Result<()>;

    /// Validates that `name` is a valid selector when this provider is used as a watcher `source`.
    fn validate_source(&self, _name: &str) -> Result<()> {
        Ok(())
    }

    /// Validates that `name` is a valid selector when this provider is used as a watcher `target`.
    fn validate_target(&self, _name: &str) -> Result<()> {
        Ok(())
    }

    /// Returns the list of IPs for the provided selector/name (the part after `<instance>:`).
    async fn get(&self, name: &str) -> Result<Vec<IpAddr>>;

    /// Updates the target identified by `name` (the part after `<instance>:`) to `ip`.
    async fn set(&self, name: &str, ip: IpAddr) -> Result<()>;
}

/// Factory function to instantiate a provider by its type name.
pub fn create_provider(provider_type: &str) -> Result<Box<dyn Provider>> {
    match provider_type.trim().to_ascii_lowercase().as_str() {
        "local" => Ok(Box::new(local::LocalProvider::new())),
        "cloudflare" => Ok(Box::new(cloudflare::CloudflareProvider::new())),
        "unifi" => Ok(Box::new(unifi::UnifiProvider::new())),
        other => Err(anyhow!("unknown provider type '{}'", other)),
    }
}
