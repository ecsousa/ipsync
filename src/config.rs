use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub config: GlobalConfig,
    #[serde(default)]
    pub providers: Vec<ProviderInstanceConfig>,
    #[serde(default)]
    pub watchers: Vec<WatcherConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GlobalConfig {
    #[serde(alias = "polling", with = "humantime_serde")]
    pub pooling: Duration,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderInstanceConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub provider_type: String,
    #[serde(default, deserialize_with = "deserialize_provider_config")]
    pub config: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WatcherConfig {
    pub source: String,
    #[serde(default)]
    pub include: Option<String>,
    #[serde(default)]
    pub includes: Vec<String>,
    #[serde(default)]
    pub exclude: Option<String>,
    #[serde(default)]
    pub excludes: Vec<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub targets: Vec<String>,
}

impl WatcherConfig {
    /// Returns all configured include masks (combining `include` and `includes`).
    pub fn all_includes(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(inc) = &self.include {
            out.push(inc.clone());
        }
        out.extend(self.includes.iter().cloned());
        out
    }

    /// Returns all configured exclude masks (combining `exclude` and `excludes`).
    pub fn all_excludes(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(exc) = &self.exclude {
            out.push(exc.clone());
        }
        out.extend(self.excludes.iter().cloned());
        out
    }

    /// Returns all configured targets (combining `target` and `targets`).
    pub fn all_targets(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(tgt) = &self.target {
            out.push(tgt.clone());
        }
        out.extend(self.targets.iter().cloned());
        out
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawProviderConfig {
    List(Vec<HashMap<String, serde_yaml::Value>>),
    Map(HashMap<String, serde_yaml::Value>),
}

fn yaml_value_to_string(v: serde_yaml::Value) -> Result<String, String> {
    match v {
        serde_yaml::Value::String(s) => Ok(s),
        serde_yaml::Value::Bool(b) => Ok(b.to_string()),
        serde_yaml::Value::Number(n) => Ok(n.to_string()),
        serde_yaml::Value::Null => Ok(String::new()),
        other => Err(format!("unsupported config value type: {other:?}")),
    }
}

fn deserialize_provider_config<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<RawProviderConfig>::deserialize(deserializer)?;
    let mut map = HashMap::new();
    if let Some(raw) = raw {
        match raw {
            RawProviderConfig::List(list) => {
                for item in list {
                    for (k, v) in item {
                        let val_str = yaml_value_to_string(v).map_err(serde::de::Error::custom)?;
                        map.insert(k, val_str);
                    }
                }
            }
            RawProviderConfig::Map(raw_map) => {
                for (k, v) in raw_map {
                    let val_str = yaml_value_to_string(v).map_err(serde::de::Error::custom)?;
                    map.insert(k, val_str);
                }
            }
        }
    }
    Ok(map)
}

impl AppConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("failed to read config file {:?}", path.as_ref()))?;
        Self::from_yaml_str(&content)
    }

    pub fn from_yaml_str(yaml: &str) -> Result<Self> {
        serde_yaml::from_str(yaml).context("failed to parse YAML configuration")
    }
}

/// Splits a provider endpoint string (e.g. `local:ipv6`, `local`, `site-a:vpnclient:Site-B`)
/// into `(provider_instance_name, parameter)`.
pub fn parse_endpoint(endpoint: &str) -> (&str, &str) {
    match endpoint.split_once(':') {
        Some((provider, param)) => (provider.trim(), param.trim()),
        None => (endpoint.trim(), ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_full_config_yaml() {
        let yaml = r#"
config:
  pooling: 5m

providers:
  - name: example.com
    type: cloudflare
    config:
      - zone: example.com
      - apikey: redacted
  - name: site-a
    type: unifi
    config:
      - host: unifi.site-a.example.com
      - apikey: redacted
  - name: site-b
    type: unifi
    config:
      - host: unifi.site-b.example.com
      - apikey: redacted

watchers:
  - source: local:ipv6
    include: ::6/::ffff:ffff:ffff:ffff
    exclude: fd00::/7
    target: example.com:nas.example.com
  - source: local:ipv4
    includes:
      - 192.168.0.0/16
      - 10.0.0.0/8
    target: example.com:nas.example.com
  - source: site-a:wan1.ipv6
    target: example.com:vpn.example.com
  - source: site-a:wan1.ipv4
    targets:
      - example.com:vpn.example.com
      - example.com:vpn-b.example.com
  - source: site-b:wan1.ipv6
    targets:
      - example.com:vpn-b.example.com
      - site-a:vpnclient:Site-B-VPN
"#;
        let cfg = AppConfig::from_yaml_str(yaml).expect("should parse sample config yaml");
        assert_eq!(cfg.config.pooling, Duration::from_secs(300));
        assert_eq!(cfg.providers.len(), 3);

        assert_eq!(cfg.providers[0].name, "example.com");
        assert_eq!(cfg.providers[0].provider_type, "cloudflare");
        assert_eq!(
            cfg.providers[0].config.get("zone").map(String::as_str),
            Some("example.com")
        );
        assert_eq!(
            cfg.providers[0].config.get("apikey").map(String::as_str),
            Some("redacted")
        );

        assert_eq!(cfg.providers[1].name, "site-a");
        assert_eq!(cfg.providers[1].provider_type, "unifi");
        assert_eq!(
            cfg.providers[1].config.get("host").map(String::as_str),
            Some("unifi.site-a.example.com")
        );

        assert_eq!(cfg.watchers.len(), 5);
        assert_eq!(cfg.watchers[0].source, "local:ipv6");
        assert_eq!(
            cfg.watchers[0].all_includes(),
            vec!["::6/::ffff:ffff:ffff:ffff"]
        );
        assert_eq!(cfg.watchers[0].all_excludes(), vec!["fd00::/7"]);
        assert_eq!(
            cfg.watchers[0].all_targets(),
            vec!["example.com:nas.example.com"]
        );

        assert_eq!(
            cfg.watchers[1].all_includes(),
            vec!["192.168.0.0/16", "10.0.0.0/8"]
        );
        assert_eq!(
            cfg.watchers[4].all_targets(),
            vec!["example.com:vpn-b.example.com", "site-a:vpnclient:Site-B-VPN"]
        );
    }

    #[test]
    fn test_parse_endpoint() {
        assert_eq!(parse_endpoint("local"), ("local", ""));
        assert_eq!(parse_endpoint("local:ipv6"), ("local", "ipv6"));
        assert_eq!(
            parse_endpoint("site-a:vpnclient:Site-B-VPN"),
            ("site-a", "vpnclient:Site-B-VPN")
        );
    }

    #[test]
    fn test_provider_config_map_and_bool() {
        let yaml = r#"
config:
  pooling: 1m
providers:
  - name: udm
    type: unifi
    config:
      host: 192.168.1.1
      apikey: secret
      insecure: true
watchers: []
"#;
        let cfg = AppConfig::from_yaml_str(yaml).unwrap();
        assert_eq!(
            cfg.providers[0].config.get("insecure").map(String::as_str),
            Some("true")
        );
    }
}
