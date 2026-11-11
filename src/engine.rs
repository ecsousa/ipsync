use crate::config::{AppConfig, WatcherConfig, parse_endpoint};
use crate::filter::{IpFilter, apply_filters};
use crate::providers::local::LocalProvider;
use crate::providers::{Provider, create_provider};
use anyhow::{Context, Result, anyhow, bail};
use std::collections::HashMap;
use std::net::IpAddr;
use tracing::{debug, error, info};

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
            let filter: IpFilter = inc_str.parse().with_context(|| {
                format!(
                    "invalid include filter '{}' in watcher '{}'",
                    inc_str, cfg.source
                )
            })?;
            includes.push(filter);
        }

        let mut excludes = Vec::new();
        for exc_str in cfg.all_excludes() {
            let filter: IpFilter = exc_str.parse().with_context(|| {
                format!(
                    "invalid exclude filter '{}' in watcher '{}'",
                    exc_str, cfg.source
                )
            })?;
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
    dry_run: bool,
}

impl DdnsEngine {
    /// Builds, validates, and initializes a `DdnsEngine` from `AppConfig`.
    pub async fn from_config(app_cfg: &AppConfig, dry_run: bool) -> Result<Self> {
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
            if providers.contains_key(&prov_cfg.name) {
                bail!("duplicate provider instance name '{}'", prov_cfg.name);
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
            let (src_prov, src_param) = parse_endpoint(&watcher.source);
            let Some(src_provider) = providers.get(src_prov) else {
                bail!(
                    "watcher source '{}' references unknown provider instance '{}'",
                    watcher.source,
                    src_prov
                );
            };
            src_provider
                .validate_source(src_param)
                .with_context(|| format!("invalid watcher source '{}'", watcher.source))?;

            for target in &watcher.targets {
                let (tgt_prov, tgt_param) = parse_endpoint(target);
                let Some(tgt_provider) = providers.get(tgt_prov) else {
                    bail!(
                        "watcher target '{}' references unknown provider instance '{}'",
                        target,
                        tgt_prov
                    );
                };
                tgt_provider
                    .validate_target(tgt_param)
                    .with_context(|| format!("invalid watcher target '{}'", target))?;
            }
            watchers.push(watcher);
        }

        Ok(Self {
            providers,
            watchers,
            dry_run,
        })
    }

    /// Creates a `DdnsEngine` from custom pre-initialized providers and watcher configs (useful for testing).
    #[cfg(test)]
    pub fn with_providers(
        providers: HashMap<String, Box<dyn Provider>>,
        watchers: Vec<WatcherState>,
        dry_run: bool,
    ) -> Self {
        Self {
            providers,
            watchers,
            dry_run,
        }
    }

    /// Executes a single check-and-update cycle across all configured watchers.
    pub async fn run_cycle(&mut self) {
        let dry_run = self.dry_run;
        for watcher in &mut self.watchers {
            if let Err(err) = Self::process_watcher(&self.providers, watcher, dry_run).await {
                error!("Error processing watcher '{}': {:#}", watcher.source, err);
            }
        }
    }

    async fn process_watcher(
        providers: &HashMap<String, Box<dyn Provider>>,
        watcher: &mut WatcherState,
        dry_run: bool,
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
            "Provider read [source '{}']: {:?}",
            watcher.source, raw_ips
        );

        let filtered_ips = apply_filters(raw_ips, &watcher.includes, &watcher.excludes);
        debug!(
            "Filter result [source '{}']: matched {:?} (selected: {:?})",
            watcher.source,
            filtered_ips,
            filtered_ips.first()
        );

        let Some(&current_ip) = filtered_ips.first() else {
            debug!(
                "No matching IP address found for watcher source '{}'",
                watcher.source
            );
            return Ok(());
        };

        if watcher.last_ip == Some(current_ip) {
            debug!(
                "Comparison result [source '{}']: current IP {} matches last checked IP; skipping target checks",
                watcher.source, current_ip
            );
            return Ok(());
        }

        debug!(
            "Comparison result [source '{}']: current IP {} differs from last checked IP ({:?}); checking targets",
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

            match Self::sync_target(
                tgt_provider.as_ref(),
                target,
                tgt_param,
                current_ip,
                dry_run,
            )
            .await
            {
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
        dry_run: bool,
    ) -> Result<()> {
        let existing_ips = tgt_provider
            .get(tgt_param)
            .await
            .with_context(|| format!("failed to get current IPs from target '{}'", target_full))?;

        debug!(
            "Provider read [target '{}']: {:?}",
            target_full, existing_ips
        );

        // Compare against existing target addresses of the same IP family (IPv4 vs IPv4, IPv6 vs IPv6)
        let same_family: Vec<IpAddr> = existing_ips
            .into_iter()
            .filter(|ip| ip.is_ipv4() == current_ip.is_ipv4())
            .collect();

        if same_family.len() == 1 && same_family[0] == current_ip {
            debug!(
                "Comparison result [target '{}']: existing address for family {:?} matches {}; no update needed",
                target_full, same_family, current_ip
            );
            return Ok(());
        }

        debug!(
            "Comparison result [target '{}']: existing address for family {:?} differs from {}; update needed",
            target_full, same_family, current_ip
        );

        if dry_run {
            info!(
                "[DRY RUN] Would set '{}' to {}",
                target_full, current_ip
            );
            return Ok(());
        }

        info!("Setting '{}' to {}", target_full, current_ip);
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

        let mut engine = DdnsEngine::with_providers(providers, vec![w_v6, w_v4], false);

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

    #[tokio::test]
    async fn test_engine_dry_run_does_not_call_set() {
        let local_mock = MockProvider::new_with_ips("ipv4", vec!["10.0.0.42".parse().unwrap()]);
        let cf_mock = MockProvider::new_with_ips("nas.example.com", vec![]);

        let mut providers: HashMap<String, Box<dyn Provider>> = HashMap::new();
        providers.insert("local".to_string(), Box::new(local_mock));
        providers.insert("example.com".to_string(), Box::new(cf_mock.clone()));

        let watcher = WatcherState::from_config(&WatcherConfig {
            source: "local:ipv4".to_string(),
            include: None,
            includes: vec![],
            exclude: None,
            excludes: vec![],
            target: Some("example.com:nas.example.com".to_string()),
            targets: vec![],
        })
        .unwrap();

        let mut engine = DdnsEngine::with_providers(providers, vec![watcher], true);
        engine.run_cycle().await;

        // Target was read for comparison, but set was NOT called in dry-run mode
        assert_eq!(*cf_mock.get_calls.lock().unwrap(), 1);
        assert!(cf_mock.set_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_engine_config_validation_errors() {
        let bad_local_target_yaml = r#"
config:
  pooling: 5m
providers: []
watchers:
  - source: local:ipv4
    target: local:ipv4
"#;
        let cfg = AppConfig::from_yaml_str(bad_local_target_yaml).unwrap();
        assert!(DdnsEngine::from_config(&cfg, true).await.is_err());

        let bad_unifi_target_yaml = r#"
config:
  pooling: 5m
providers:
  - name: site-a
    type: unifi
    config:
      - host: unifi.site-a.example.com
      - apikey: secret
watchers:
  - source: local:ipv4
    target: site-a:wan1.ipv4
"#;
        let cfg2 = AppConfig::from_yaml_str(bad_unifi_target_yaml).unwrap();
        assert!(DdnsEngine::from_config(&cfg2, true).await.is_err());
    }
}
