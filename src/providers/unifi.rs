use crate::providers::Provider;
use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tracing::{debug, info};

#[derive(Debug, Deserialize)]
struct UnifiEnvelope<T> {
    data: Vec<T>,
}

pub struct UnifiProvider {
    client: Client,
    base_url: String,
    apikey: String,
}

impl Default for UnifiProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl UnifiProvider {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("failed to build reqwest client");
        Self {
            client,
            base_url: String::new(),
            apikey: String::new(),
        }
    }

    async fn get_wan_ips(&self, wan_field: &str, want_ipv6: bool) -> Result<Vec<IpAddr>> {
        let url = format!("{}/proxy/network/api/s/default/stat/device", self.base_url);
        debug!("Querying UniFi device stats from {}", url);

        let resp = self
            .client
            .get(&url)
            .header("X-API-KEY", &self.apikey)
            .send()
            .await
            .context("failed to query UniFi stat/device endpoint")?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .context("failed to read UniFi stat/device response body")?;

        if !status.is_success() {
            bail!("UniFi API error in stat/device: HTTP {} - {}", status, text);
        }

        let env: UnifiEnvelope<Value> = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse UniFi stat/device JSON: {}", text))?;

        let mut ips = Vec::new();
        for device in &env.data {
            let Some(wan_obj) = device.get(wan_field) else {
                continue;
            };

            if want_ipv6 {
                if let Some(ipv6_arr) = wan_obj.get("ipv6").and_then(|v| v.as_array()) {
                    for ip_val in ipv6_arr {
                        if let Some(ip_str) = ip_val.as_str() {
                            if let Some(v6) = parse_unifi_ipv6(ip_str) {
                                let ip = IpAddr::V6(v6);
                                if !ips.contains(&ip) {
                                    ips.push(ip);
                                }
                            }
                        }
                    }
                } else if let Some(ip_str) = wan_obj.get("ipv6").and_then(|v| v.as_str()) {
                    if let Some(v6) = parse_unifi_ipv6(ip_str) {
                        let ip = IpAddr::V6(v6);
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
            } else if let Some(ip_str) = wan_obj.get("ip").and_then(|v| v.as_str()) {
                let clean = ip_str.split('/').next().unwrap_or(ip_str).trim();
                if let Ok(v4) = clean.parse::<Ipv4Addr>() {
                    if !v4.is_unspecified() && !v4.is_loopback() {
                        let ip = IpAddr::V4(v4);
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
            }
        }

        Ok(ips)
    }

    async fn fetch_network_configs(&self) -> Result<Vec<Value>> {
        let url = format!(
            "{}/proxy/network/api/s/default/rest/networkconf/",
            self.base_url
        );
        debug!("Querying UniFi networkconf from {}", url);

        let resp = self
            .client
            .get(&url)
            .header("X-API-KEY", &self.apikey)
            .send()
            .await
            .context("failed to query UniFi rest/networkconf endpoint")?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .context("failed to read UniFi networkconf response")?;

        if !status.is_success() {
            bail!(
                "UniFi API error in rest/networkconf: HTTP {} - {}",
                status,
                text
            );
        }

        let env: UnifiEnvelope<Value> = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse UniFi networkconf JSON: {}", text))?;

        Ok(env.data)
    }

    async fn get_vpn_client_ip(&self, vpn_name: &str) -> Result<Vec<IpAddr>> {
        let configs = self.fetch_network_configs().await?;
        let node = configs
            .into_iter()
            .find(|c| c.get("name").and_then(|v| v.as_str()) == Some(vpn_name))
            .ok_or_else(|| anyhow!("UniFi VPN client '{}' not found", vpn_name))?;

        if let Some(peer_ip_str) = node
            .get("wireguard_client_peer_ip")
            .and_then(|v| v.as_str())
        {
            if let Ok(ip) = peer_ip_str.trim().parse::<IpAddr>() {
                return Ok(vec![ip]);
            }
        }

        Ok(Vec::new())
    }

    async fn set_vpn_client_ip(&self, vpn_name: &str, ip: IpAddr) -> Result<()> {
        let configs = self.fetch_network_configs().await?;
        let mut node = configs
            .into_iter()
            .find(|c| c.get("name").and_then(|v| v.as_str()) == Some(vpn_name))
            .ok_or_else(|| anyhow!("UniFi VPN client '{}' not found", vpn_name))?;

        let id = node
            .get("_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("UniFi VPN client '{}' is missing '_id'", vpn_name))?
            .to_string();

        if let Some(obj) = node.as_object_mut() {
            obj.insert(
                "wireguard_client_peer_ip".to_string(),
                json!(ip.to_string()),
            );
        }

        let put_url = format!(
            "{}/proxy/network/api/s/default/rest/networkconf/{}",
            self.base_url, id
        );
        info!(
            "Updating UniFi VPN client '{}' (id: {}) peer IP -> {}",
            vpn_name, id, ip
        );

        let resp = self
            .client
            .put(&put_url)
            .header("X-API-KEY", &self.apikey)
            .json(&node)
            .send()
            .await
            .with_context(|| format!("failed to update UniFi VPN client '{}'", vpn_name))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!(
                "updating UniFi VPN client '{}' failed: HTTP {} - {}",
                vpn_name,
                status,
                body
            );
        }

        Ok(())
    }
}

fn parse_unifi_ipv6(raw: &str) -> Option<Ipv6Addr> {
    let clean = raw.split('/').next().unwrap_or(raw).trim();
    let v6 = clean.parse::<Ipv6Addr>().ok()?;
    if v6.is_loopback() || v6.is_unspecified() || v6.is_unicast_link_local() {
        return None;
    }
    Some(v6)
}

#[async_trait]
impl Provider for UnifiProvider {
    async fn initialize(&mut self, config: &HashMap<String, String>) -> Result<()> {
        let host = config
            .get("host")
            .ok_or_else(|| anyhow!("unifi provider requires 'host' in config"))?
            .trim();
        let apikey = config
            .get("apikey")
            .ok_or_else(|| anyhow!("unifi provider requires 'apikey' in config"))?
            .trim()
            .to_string();

        if host.is_empty() {
            bail!("unifi 'host' cannot be empty");
        }
        if apikey.is_empty() {
            bail!("unifi 'apikey' cannot be empty");
        }

        let insecure = config
            .get("insecure")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes"))
            .unwrap_or(false);

        self.client = Client::builder()
            .timeout(Duration::from_secs(15))
            .danger_accept_invalid_certs(insecure)
            .build()
            .context("failed to build reqwest client for unifi provider")?;

        if let Some(base_url) = config.get("base_url") {
            self.base_url = base_url.trim_end_matches('/').to_string();
        } else {
            let clean_host = host
                .strip_prefix("https://")
                .or_else(|| host.strip_prefix("http://"))
                .unwrap_or(host)
                .trim_end_matches('/');
            self.base_url = format!("https://{}", clean_host);
        }

        self.apikey = apikey;
        Ok(())
    }

    async fn get(&self, name: &str) -> Result<Vec<IpAddr>> {
        let name = name.trim();
        match name {
            "wan1.ipv4" => self.get_wan_ips("wan1", false).await,
            "wan1.ipv6" => self.get_wan_ips("wan1", true).await,
            "wan2.ipv4" => self.get_wan_ips("wan2", false).await,
            "wan2.ipv6" => self.get_wan_ips("wan2", true).await,
            _ if name.starts_with("vpnclient:") => {
                let vpn_name = name["vpnclient:".len()..].trim();
                if vpn_name.is_empty() {
                    bail!("unifi vpnclient selector requires a name (vpnclient:$NAME)");
                }
                self.get_vpn_client_ip(vpn_name).await
            }
            other => bail!(
                "unsupported unifi get selector '{}': expected wan1.ipv4, wan1.ipv6, wan2.ipv4, wan2.ipv6, or vpnclient:$NAME",
                other
            ),
        }
    }

    async fn set(&self, name: &str, ip: IpAddr) -> Result<()> {
        let name = name.trim();
        if let Some(vpn_name) = name.strip_prefix("vpnclient:") {
            let vpn_name = vpn_name.trim();
            if vpn_name.is_empty() {
                bail!("unifi vpnclient selector requires a name (vpnclient:$NAME)");
            }
            self.set_vpn_client_ip(vpn_name, ip).await
        } else {
            bail!(
                "unsupported unifi set selector '{}': only 'vpnclient:$NAME' can be updated",
                name
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_unifi_wan1_wan2_ipv4_and_ipv6() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/proxy/network/api/s/default/stat/device"))
            .and(header("X-API-KEY", "unifi-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "meta": { "rc": "ok" },
                "data": [
                    {
                        "name": "USW-Switch",
                        "type": "usw"
                    },
                    {
                        "name": "UDM-Pro",
                        "type": "udm",
                        "wan1": {
                            "ip": "203.0.113.10",
                            "ipv6": [
                                "fe80::1234:56ff:fe78:9abc/64",
                                "2600:1700:1111:2222::1/64"
                            ]
                        },
                        "wan2": {
                            "ip": "198.51.100.42",
                            "ipv6": [
                                "2001:db8:9999::2/64"
                            ]
                        }
                    }
                ]
            })))
            .mount(&server)
            .await;

        let mut provider = UnifiProvider::new();
        let mut cfg = HashMap::new();
        cfg.insert("host".to_string(), "unifi.site-a.example.com".to_string());
        cfg.insert("apikey".to_string(), "unifi-key".to_string());
        cfg.insert("base_url".to_string(), server.uri());
        provider.initialize(&cfg).await.unwrap();

        assert_eq!(
            provider.get("wan1.ipv4").await.unwrap(),
            vec!["203.0.113.10".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            provider.get("wan1.ipv6").await.unwrap(),
            vec!["2600:1700:1111:2222::1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            provider.get("wan2.ipv4").await.unwrap(),
            vec!["198.51.100.42".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            provider.get("wan2.ipv6").await.unwrap(),
            vec!["2001:db8:9999::2".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn test_unifi_vpnclient_get_and_set() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/proxy/network/api/s/default/rest/networkconf/"))
            .and(header("X-API-KEY", "unifi-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "meta": { "rc": "ok" },
                "data": [
                    {
                        "_id": "net-default",
                        "name": "Default",
                        "purpose": "corporate"
                    },
                    {
                        "_id": "vpn-br-id",
                        "name": "Unifi-BR",
                        "wireguard_client_peer_ip": "2001:db8::1"
                    }
                ]
            })))
            .mount(&server)
            .await;

        Mock::given(method("PUT"))
            .and(path(
                "/proxy/network/api/s/default/rest/networkconf/vpn-br-id",
            ))
            .and(header("X-API-KEY", "unifi-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "meta": { "rc": "ok" },
                "data": []
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut provider = UnifiProvider::new();
        let mut cfg = HashMap::new();
        cfg.insert("host".to_string(), "unifi.site-a.example.com".to_string());
        cfg.insert("apikey".to_string(), "unifi-key".to_string());
        cfg.insert("base_url".to_string(), server.uri());
        provider.initialize(&cfg).await.unwrap();

        let current = provider.get("vpnclient:Unifi-BR").await.unwrap();
        assert_eq!(current, vec!["2001:db8::1".parse::<IpAddr>().unwrap()]);

        provider
            .set("vpnclient:Unifi-BR", "2001:db8::1234".parse().unwrap())
            .await
            .unwrap();
    }
}
