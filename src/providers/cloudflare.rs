use crate::providers::Provider;
use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use reqwest::Client;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::OnceCell;
use tracing::debug;

const DEFAULT_CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";

pub struct CloudflareProvider {
    client: Client,
    api_base: String,
    zone: String,
    apikey: String,
    zone_id: OnceCell<String>,
}

impl Default for CloudflareProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudflareProvider {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("failed to build reqwest client");
        Self {
            client,
            api_base: DEFAULT_CF_API_BASE.to_string(),
            zone: String::new(),
            apikey: String::new(),
            zone_id: OnceCell::new(),
        }
    }

    async fn resolve_zone_id(&self) -> Result<&str> {
        self.zone_id
            .get_or_try_init(|| async {
                let url = format!(
                    "{}/zones?name={}&status=active",
                    self.api_base,
                    urlencoding::encode(&self.zone)
                );
                debug!("Resolving Cloudflare zone ID for '{}'", self.zone);
                let resp = self
                    .client
                    .get(&url)
                    .header("Authorization", format!("Bearer {}", self.apikey))
                    .send()
                    .await
                    .context("failed to query Cloudflare zones endpoint")?;

                let status = resp.status();
                let body: Value = resp
                    .json()
                    .await
                    .context("failed to parse Cloudflare zone lookup JSON")?;

                if !status.is_success()
                    || body.get("success").and_then(|v| v.as_bool()) != Some(true)
                {
                    bail!(
                        "Cloudflare zone lookup failed for '{}': HTTP {} - {}",
                        self.zone,
                        status,
                        body
                    );
                }

                let id = body
                    .get("result")
                    .and_then(|r| r.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|item| item.get("id"))
                    .and_then(|id| id.as_str())
                    .ok_or_else(|| {
                        anyhow!("no active Cloudflare zone found with name '{}'", self.zone)
                    })?;

                Ok(id.to_string())
            })
            .await
            .map(String::as_str)
    }
}

#[async_trait]
impl Provider for CloudflareProvider {
    async fn initialize(&mut self, config: &HashMap<String, String>) -> Result<()> {
        let zone = config
            .get("zone")
            .ok_or_else(|| anyhow!("cloudflare provider requires 'zone' in config"))?
            .trim()
            .to_string();
        let apikey = config
            .get("apikey")
            .ok_or_else(|| anyhow!("cloudflare provider requires 'apikey' in config"))?
            .trim()
            .to_string();

        if zone.is_empty() {
            bail!("cloudflare 'zone' cannot be empty");
        }
        if apikey.is_empty() {
            bail!("cloudflare 'apikey' cannot be empty");
        }

        if let Some(base_url) = config.get("api_base_url") {
            self.api_base = base_url.trim_end_matches('/').to_string();
        }

        self.zone = zone;
        self.apikey = apikey;
        self.zone_id = OnceCell::new();
        Ok(())
    }

    fn validate_source(&self, name: &str) -> Result<()> {
        if name.trim().is_empty() {
            bail!("cloudflare source requires a DNS record name");
        }
        Ok(())
    }

    fn validate_target(&self, name: &str) -> Result<()> {
        if name.trim().is_empty() {
            bail!("cloudflare target requires a DNS record name");
        }
        Ok(())
    }

    async fn get(&self, name: &str) -> Result<Vec<IpAddr>> {
        let name = name.trim();
        if name.is_empty() {
            bail!("cloudflare get requires a DNS record name");
        }

        let zone_id = self.resolve_zone_id().await?;
        let url = format!(
            "{}/zones/{}/dns_records?name={}",
            self.api_base,
            zone_id,
            urlencoding::encode(name)
        );

        let resp = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.apikey))
            .send()
            .await
            .with_context(|| format!("failed to fetch DNS records for '{}'", name))?;

        let status = resp.status();
        let body: Value = resp
            .json()
            .await
            .context("failed to parse Cloudflare dns_records response")?;

        if !status.is_success() || body.get("success").and_then(|v| v.as_bool()) != Some(true) {
            bail!(
                "Cloudflare DNS query failed for '{}': HTTP {} - {}",
                name,
                status,
                body
            );
        }

        let mut ips = Vec::new();
        if let Some(records) = body.get("result").and_then(|r| r.as_array()) {
            for record in records {
                let rec_type = record.get("type").and_then(|t| t.as_str()).unwrap_or("");
                if rec_type == "A" || rec_type == "AAAA" {
                    if let Some(content) = record.get("content").and_then(|c| c.as_str()) {
                        if let Ok(ip) = content.trim().parse::<IpAddr>() {
                            ips.push(ip);
                        }
                    }
                }
            }
        }

        Ok(ips)
    }

    async fn set(&self, name: &str, ip: IpAddr) -> Result<()> {
        let name = name.trim();
        if name.is_empty() {
            bail!("cloudflare set requires a DNS record name");
        }

        let zone_id = self.resolve_zone_id().await?;
        let record_type = match ip {
            IpAddr::V4(_) => "A",
            IpAddr::V6(_) => "AAAA",
        };

        let lookup_url = format!(
            "{}/zones/{}/dns_records?type={}&name={}",
            self.api_base,
            zone_id,
            record_type,
            urlencoding::encode(name)
        );

        let lookup_resp = self
            .client
            .get(&lookup_url)
            .header("Authorization", format!("Bearer {}", self.apikey))
            .send()
            .await
            .with_context(|| format!("failed to look up {} record for '{}'", record_type, name))?;

        let lookup_status = lookup_resp.status();
        let lookup_body: Value = lookup_resp
            .json()
            .await
            .context("failed to parse Cloudflare DNS lookup response")?;

        if !lookup_status.is_success()
            || lookup_body.get("success").and_then(|v| v.as_bool()) != Some(true)
        {
            bail!(
                "Cloudflare DNS lookup failed for '{}' ({}): HTTP {} - {}",
                name,
                record_type,
                lookup_status,
                lookup_body
            );
        }

        let existing = lookup_body
            .get("result")
            .and_then(|r| r.as_array())
            .and_then(|arr| arr.first());

        let existing_id = existing
            .and_then(|r| r.get("id"))
            .and_then(|id| id.as_str());
        let proxied = existing
            .and_then(|r| r.get("proxied"))
            .and_then(|p| p.as_bool())
            .unwrap_or(false);
        let ttl = existing
            .and_then(|r| r.get("ttl"))
            .and_then(|t| t.as_u64())
            .unwrap_or(60);

        let payload = json!({
            "type": record_type,
            "name": name,
            "content": ip.to_string(),
            "ttl": ttl,
            "proxied": proxied,
        });

        let resp = if let Some(record_id) = existing_id {
            let update_url = format!(
                "{}/zones/{}/dns_records/{}",
                self.api_base, zone_id, record_id
            );
            debug!(
                "Updating Cloudflare {} record for '{}' -> {}",
                record_type, name, ip
            );
            self.client
                .put(&update_url)
                .header("Authorization", format!("Bearer {}", self.apikey))
                .json(&payload)
                .send()
                .await
                .with_context(|| format!("failed to update DNS record '{}'", name))?
        } else {
            let create_url = format!("{}/zones/{}/dns_records", self.api_base, zone_id);
            debug!(
                "Creating Cloudflare {} record for '{}' -> {}",
                record_type, name, ip
            );
            self.client
                .post(&create_url)
                .header("Authorization", format!("Bearer {}", self.apikey))
                .json(&payload)
                .send()
                .await
                .with_context(|| format!("failed to create DNS record '{}'", name))?
        };

        let status = resp.status();
        let body: Value = resp
            .json()
            .await
            .context("failed to parse Cloudflare DNS upsert response")?;

        if !status.is_success() || body.get("success").and_then(|v| v.as_bool()) != Some(true) {
            bail!(
                "Cloudflare DNS update failed for '{}' ({}): HTTP {} - {}",
                name,
                record_type,
                status,
                body
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_cloudflare_get_and_set_a_and_aaaa() {
        let server = MockServer::start().await;

        // Zone lookup mock
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "example.com"))
            .and(query_param("status", "active"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "result": [{ "id": "zone-123", "name": "example.com" }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        // Get all records for nas.example.com
        Mock::given(method("GET"))
            .and(path("/zones/zone-123/dns_records"))
            .and(query_param("name", "nas.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "result": [
                    { "id": "rec-a", "type": "A", "name": "nas.example.com", "content": "192.168.1.10", "proxied": false, "ttl": 60 },
                    { "id": "rec-aaaa", "type": "AAAA", "name": "nas.example.com", "content": "2600:1700::6", "proxied": false, "ttl": 60 }
                ]
            })))
            .mount(&server)
            .await;

        let mut provider = CloudflareProvider::new();
        let mut cfg = HashMap::new();
        cfg.insert("zone".to_string(), "example.com".to_string());
        cfg.insert("apikey".to_string(), "test-token".to_string());
        cfg.insert("api_base_url".to_string(), server.uri());
        provider.initialize(&cfg).await.unwrap();

        let ips = provider.get("nas.example.com").await.unwrap();
        assert_eq!(
            ips,
            vec![
                "192.168.1.10".parse::<IpAddr>().unwrap(),
                "2600:1700::6".parse::<IpAddr>().unwrap()
            ]
        );

        // Mock updating existing A record (PUT)
        Mock::given(method("GET"))
            .and(path("/zones/zone-123/dns_records"))
            .and(query_param("type", "A"))
            .and(query_param("name", "nas.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "result": [
                    { "id": "rec-a", "type": "A", "name": "nas.example.com", "content": "192.168.1.10", "proxied": true, "ttl": 120 }
                ]
            })))
            .mount(&server)
            .await;

        Mock::given(method("PUT"))
            .and(path("/zones/zone-123/dns_records/rec-a"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "result": { "id": "rec-a" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        provider
            .set("nas.example.com", "192.168.1.20".parse().unwrap())
            .await
            .unwrap();

        // Mock creating new AAAA record (POST)
        Mock::given(method("GET"))
            .and(path("/zones/zone-123/dns_records"))
            .and(query_param("type", "AAAA"))
            .and(query_param("name", "new.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "result": []
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/zones/zone-123/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "result": { "id": "rec-new-aaaa" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        provider
            .set("new.example.com", "2600:1700::99".parse().unwrap())
            .await
            .unwrap();
    }
}
