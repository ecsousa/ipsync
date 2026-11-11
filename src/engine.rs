use crate::config::{AppConfig, WatcherConfig, parse_endpoint};
use crate::filter::{IpFilter, apply_filters};
use crate::providers::local::LocalProvider;
use crate::providers::{Provider, create_provider};
use anyhow::{Context, Result, anyhow, bail};
use std::collections::HashMap;
use std::net::IpAddr;
use tracing::{debug, error, info, warn};

pub struct WatcherState {
    pub source: String,
    pub includes: Vec<IpFilter>,
    pub excludes: Vec<IpFilter>,
    pub targets: Vec<String>,
    pub last_ip: Option<IpAddr>,
}

impl WatcherState {
    pub fn from_config(cfg: &WatcherConfig) -> Result<Self> {
        let mut includes = Vec::new();
        for inc_str in cfg.all_includes() {
            let filter: IpFilter = inc_str
                .parse()
                .with_context(|| format!("invalid include filter '{}' in watcher '{}'", inc_str, cfg.source))?;
            includes.push(filter);
        }

        let mut excludes = Vec::new();
        for exc_str in cfg.all_excludes() {
            let filter: IpFilter = exc_str
                .parse()
                .with_context(|| format!("invalid exclude filter '{}' in watcher '{}'", exc_str, cfg.source))?;
            excludes.push(filter);
        }

        let targets = cfg.all_targets();
        if targets.is_empty() {
            bail!("watcher for source '{}' has no target configured", cfg.source);
        }

        Ok(Self {
            source: cfg.source.clone(),
            includes,
            excludes,
            targets,
            last_ip: None,
        })
    }
}

pub struct DdnsEngine {
    providers: HashMap<String, Box<dyn Provider>>,
    watchers: Vec<WatcherState>,
}

impl DdnsEngine {
    /// Builds and initializes a `DdnsEngine` from `AppConfig`.
    pub async fn from_config(app_cfg: &AppConfig) -> Result<Self> {
        let mut providers: HashMap<String, Box<dyn Provider>> = HashMap::new();

        // Register hardcoded `local` provider instance
        let mut local_provider = Box::new(LocalProvider::new());
        local_provider.initialize(&HashMap::new()).await?;
        providers.insert("local".to_string(), local_provider);

        // Register configured provider instances
        for prov_cfg in &app_cfg.providers {
            if prov_cfg.name == "local" {
                bail!("provider instance name 'local' is reserved for the built-in local provider");
            }
            let mut provider = create_provider(&prov_cfg.provider_type).with_context(|| {
                format!(
                    "failed to create provider '{}' of type '{}'",
                    prov_cfg.name, prov_cfg.provider_type
                )
            })?;
            provider
                .initialize(&prov_cfg.config)
                .await
                .with_context(|| format!("failed to initialize provider '{}'", prov_cfg.name))?;
            providers.insert(prov_cfg.name.clone(), provider);
        }

        let mut watchers = Vec::with_capacity(app_cfg.watchers.len());
        for w_cfg in &app_cfg.watchers {
            let watcher = WatcherState::from_config(w_cfg)?;
            // Validate referenced source and target provider instances exist
            let (src_prov, _) = parse_endpoint(&watcher.source);
            if !providers.contains_key(src_prov) {
                bail!(
                    "watcher source '{}' references unknown provider instance '{}'",
                    watcher.source,
                    src_prov
                );
            }
            for target in &watcher.targets {
                let (tgt_prov, _) = parse_endpoint(target);
                if !providers.contains_key(tgt_prov) {
                    bail!(
                        "watcher target '{}' references unknown provider instance '{}'",
                        target,
                        tgt_prov
                    );
                }
            }
            watchers.push(watcher);
        }

        Ok(Self {
            providers,
            watchers,
        })
    }

    /// Creates a `DdnsEngine` from custom pre-initialized providers and watcher configs (useful for testing).
    #[cfg(test)]
    pub fn with_providers(
        providers: HashMap<String, Box<dyn Provider>>,
        watchers: Vec<WatcherState>,
    ) -> Self {
        Self {
            providers,
            watchers,
        }
    }

    /// Executes a single check-and-update cycle across all configured watchers.
    pub async fn run_cycle(&mut self) {
        for watcher in &mut self.watchers {
            if let Err(err) = Self::process_watcher(&self.providers, watcher).await {
                error!("Error processing watcher '{}': {:#}", watcher.source, err);
            }
        }
    }

    async fn process_watcher(
        providers: &HashMap<String, Box<dyn Provider>>,
        watcher: &mut WatcherState,
    ) -> Result<()> {
        let (src_instance, src_param) = parse_endpoint(&watcher.source);
        let src_provider = providers
            .get(src_instance)
            .ok_or_else(|| anyhow!("unknown source provider '{}'", src_instance))?;

        let raw_ips = src_provider
            .get(src_param)
            .await
            .with_context(|| format!("failed to get IPs from source '{}'", watcher.source))?;

        debug!(
            "Source '{}' returned {} raw IP(s): {:?}",
            watcher.source,
            raw_ips.len(),
            raw_ips
        );

        let filtered_ips = apply_filters(raw_ips, &watcher.includes, &watcher.excludes);
        debug!(
            "Source '{}' after filtering has {} IP(s): {:?}",
            watcher.source,
            filtered_ips.len(),
            filtered_ips
        );

        let Some(&current_ip) = filtered_ips.first() else {
            warn!(
                "No matching IP address found for watcher source '{}'",
                watcher.source
            );
            return Ok(());
        };

        if watcher.last_ip == Some(current_ip) {
            debug!(
                "Watcher '{}': IP {} unchanged since last check; skipping target checks",
                watcher.source, current_ip
            );
            return Ok(());
        }

        info!(
            "Watcher '{}': IP is {} (previous: {:?}); verifying targets",
            watcher.source, current_ip, watcher.last_ip
        );

        let mut all_targets_succeeded = true;

        for target in &watcher.targets {
            let (tgt_instance, tgt_param) = parse_endpoint(target);
            let Some(tgt_provider) = providers.get(tgt_instance) else {
                error!("Target '{}' references unknown provider '{}'", target, tgt_instance);
                all_targets_succeeded = false;
                continue;
            };

            match Self::sync_target(tgt_provider.as_ref(), target, tgt_param, current_ip).await {
                Ok(()) => {}
                Err(err) => {
                    error!(
                        "Watcher '{}': failed to sync target '{}' with IP {}: {:#}",
                        watcher.source, target, current_ip, err
                    );
                    all_targets_succeeded = false;
                }
            }
        }

        if all_targets_succeeded {
            watcher.last_ip = Some(current_ip);
        }

        Ok(())
    }

    async fn sync_target(
        tgt_provider: &dyn Provider,
        target_full: &str,
        tgt_param: &str,
        current_ip: IpAddr,
    ) -> Result<()> {
        let existing_ips = tgt_provider
            .get(tgt_param)
            .await
            .with_context(|| format!("failed to get current IPs from target '{}'", target_full))?;

        // Compare against existing target addresses of the same IP family (IPv4 vs IPv4, IPv6 vs IPv6)
        let same_family: Vec<IpAddr> = existing_ips
            .into_iter()
            .filter(|ip| ip.is_ipv4() == current_ip.is_ipv4())
            .collect();

        if same_family.len() == 1 && same_family[0] == current_ip {
            info!(
                "Target '{}' already has matching address {}; no update needed",
                target_full, current_ip
            );
            return Ok(());
        }

        info!(
            "Target '{}' current address for family is {:?}, updating to {}",
            target_full, same_family, current_ip
        );
        tgt_provider
            .set(tgt_param, current_ip)
            .await
            .with_context(|| format!("failed to set IP {} on target '{}'", current_ip, target_full))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct MockProvider {
        records: Arc<Mutex<HashMap<String, Vec<IpAddr>>>>,
        get_calls: Arc<Mutex<usize>>,
        set_calls: Arc<Mutex<Vec<(String, IpAddr)>>>,
    }

    impl MockProvider {
        fn new_with_ips(key: &str, ips: Vec<IpAddr>) -> Self {
            let mut map = HashMap::new();
            map.insert(key.to_string(), ips);
            Self {
                records: Arc::new(Mutex::new(map)),
                get_calls: Arc::new(Mutex::new(0)),
                set_calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn set_source_ips(&self, key: &str, ips: Vec<IpAddr>) {
            self.records.lock().unwrap().insert(key.to_string(), ips);
        }
    }

    #[async_trait]
    impl Provider for MockProvider {
        async fn initialize(&mut self, _config: &HashMap<String, String>) -> Result<()> {
            Ok(())
        }

        async fn get(&self, name: &str) -> Result<Vec<IpAddr>> {
            *self.get_calls.lock().unwrap() += 1;
            Ok(self
                .records
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .unwrap_or_default())
        }

        async fn set(&self, name: &str, ip: IpAddr) -> Result<()> {
            self.set_calls
                .lock()
                .unwrap()
                .push((name.to_string(), ip));
            let mut map = self.records.lock().unwrap();
            let entry = map.entry(name.to_string()).or_default();
            // Replace same-family IP or insert
            entry.retain(|existing| existing.is_ipv4() != ip.is_ipv4());
            entry.push(ip);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_engine_dual_stack_and_last_ip_caching() {
        let local_mock = MockProvider::default();
        local_mock.set_source_ips(
            "ipv6",
            vec![
                "fd00::6".parse().unwrap(),
                "2600:1700::6".parse().unwrap(),
                "2600:1700::99".parse().unwrap(),
            ],
        );
        local_mock.set_source_ips("ipv4", vec!["192.168.1.50".parse().unwrap()]);

        let cf_mock = MockProvider::new_with_ips(
            "nas.example.com",
            vec!["192.168.1.50".parse().unwrap()], // A record already matches, AAAA missing
        );

        let mut providers: HashMap<String, Box<dyn Provider>> = HashMap::new();
        providers.insert("local".to_string(), Box::new(local_mock.clone()));
        providers.insert("example.com".to_string(), Box::new(cf_mock.clone()));

        let w_v6 = WatcherState::from_config(&WatcherConfig {
            source: "local:ipv6".to_string(),
            include: Some("::6/::ffff:ffff:ffff:ffff".to_string()),
            includes: vec![],
            exclude: Some("fd00::/7".to_string()),
            excludes: vec![],
            target: Some("example.com:nas.example.com".to_string()),
            targets: vec![],
        })
        .unwrap();

        let w_v4 = WatcherState::from_config(&WatcherConfig {
            source: "local:ipv4".to_string(),
            include: None,
            includes: vec!["192.168.0.0/16".to_string(), "10.0.0.0/8".to_string()],
            exclude: None,
            excludes: vec![],
            target: Some("example.com:nas.example.com".to_string()),
            targets: vec![],
        })
        .unwrap();

        let mut engine = DdnsEngine::with_providers(providers, vec![w_v6, w_v4]);

        // Cycle 1 (initial run):
        // - w_v6 filters down to 2600:1700::6, sees AAAA missing on CF, calls set
        // - w_v4 filters down to 192.168.1.50, sees A already matches on CF, does NOT call set
        engine.run_cycle().await;

        assert_eq!(*cf_mock.get_calls.lock().unwrap(), 2);
        assert_eq!(
            *cf_mock.set_calls.lock().unwrap(),
            vec![(
                "nas.example.com".to_string(),
                "2600:1700::6".parse::<IpAddr>().unwrap()
            )]
        );

        // Cycle 2 (no IP change on either watcher):
        // Neither watcher should query or update CF!
        engine.run_cycle().await;
        assert_eq!(*cf_mock.get_calls.lock().unwrap(), 2);
        assert_eq!(cf_mock.set_calls.lock().unwrap().len(), 1);

        // Cycle 3 (IPv4 changes to 10.0.0.25):
        local_mock.set_source_ips("ipv4", vec!["10.0.0.25".parse().unwrap()]);
        engine.run_cycle().await;
        assert_eq!(*cf_mock.get_calls.lock().unwrap(), 3);
        assert_eq!(cf_mock.set_calls.lock().unwrap().len(), 2);
        assert_eq!(
            cf_mock.set_calls.lock().unwrap()[1],
            (
                "nas.example.com".to_string(),
                "10.0.0.25".parse::<IpAddr>().unwrap()
            )
        );
    }
}
