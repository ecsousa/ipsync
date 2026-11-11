use crate::providers::Provider;
use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Default)]
pub struct LocalProvider;

impl LocalProvider {
    pub fn new() -> Self {
        Self
    }
}

fn is_usable_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified()
}

fn is_usable_ipv6(ip: Ipv6Addr) -> bool {
    !ip.is_loopback() && !ip.is_unicast_link_local() && !ip.is_unspecified()
}

#[async_trait]
impl Provider for LocalProvider {
    async fn initialize(&mut self, _config: &HashMap<String, String>) -> Result<()> {
        Ok(())
    }

    async fn get(&self, name: &str) -> Result<Vec<IpAddr>> {
        let selector = name.trim().to_ascii_lowercase();
        if !selector.is_empty() && selector != "ipv4" && selector != "ipv6" {
            bail!(
                "invalid local provider parameter '{}': expected empty, 'ipv4', or 'ipv6'",
                name
            );
        }

        let interfaces = if_addrs::get_if_addrs()
            .map_err(|e| anyhow!("failed to enumerate local network interfaces: {}", e))?;

        let mut ips = Vec::new();
        for iface in interfaces {
            if iface.is_loopback() {
                continue;
            }
            match iface.ip() {
                IpAddr::V4(v4) if is_usable_ipv4(v4) => {
                    if selector.is_empty() || selector == "ipv4" {
                        let ip = IpAddr::V4(v4);
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
                IpAddr::V6(v6) if is_usable_ipv6(v6) => {
                    if selector.is_empty() || selector == "ipv6" {
                        let ip = IpAddr::V6(v6);
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(ips)
    }

    async fn set(&self, _name: &str, _ip: IpAddr) -> Result<()> {
        bail!("local provider is read-only and does not support setting IP addresses")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_provider_initialize_and_get() {
        let mut provider = LocalProvider::new();
        provider.initialize(&HashMap::new()).await.unwrap();

        let all_ips = provider.get("").await.unwrap();
        let v4_ips = provider.get("ipv4").await.unwrap();
        let v6_ips = provider.get("ipv6").await.unwrap();

        assert!(v4_ips.iter().all(|ip| ip.is_ipv4()));
        assert!(v6_ips.iter().all(|ip| ip.is_ipv6()));
        assert_eq!(all_ips.len(), v4_ips.len() + v6_ips.len());
    }

    #[tokio::test]
    async fn test_local_provider_invalid_selector_and_set_error() {
        let provider = LocalProvider::new();
        assert!(provider.get("invalid").await.is_err());
        assert!(
            provider
                .set("ipv4", "192.168.1.1".parse().unwrap())
                .await
                .is_err()
        );
    }
}
