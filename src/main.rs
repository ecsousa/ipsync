mod config;
mod engine;
mod filter;
mod providers;

use anyhow::Result;
use clap::Parser;
use config::AppConfig;
use engine::DdnsEngine;
use std::path::PathBuf;
use tracing::{debug, error};

#[derive(Parser, Debug)]
#[command(
    name = "ddnsplus",
    author,
    version,
    about = "Cross-platform Dynamic DNS and IP synchronization client"
)]
struct Args {
    /// Path to the YAML configuration file
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,

    /// Execute a single check cycle and exit
    #[arg(short, long)]
    once: bool,

    /// Validate config, enable verbose logging, run once, and log actions without making changes
    #[arg(short, long)]
    dry_run: bool,

    /// Enable verbose (debug) logging
    #[arg(short, long)]
    verbose: bool,
}

#[cfg(target_os = "linux")]
fn notify_systemd_ready() {
    use sd_notify::NotifyState;
    if let Err(e) = sd_notify::notify(
        false,
        &[
            NotifyState::Ready,
            NotifyState::Status("ddnsplus initialized and monitoring IPs"),
        ],
    ) {
        debug!("systemd notify (ready) skipped or failed: {}", e);
    }
}

#[cfg(not(target_os = "linux"))]
fn notify_systemd_ready() {}

#[cfg(target_os = "linux")]
fn notify_systemd_status(status: &str) {
    use sd_notify::NotifyState;
    let _ = sd_notify::notify(false, &[NotifyState::Status(status), NotifyState::Watchdog]);
}

#[cfg(not(target_os = "linux"))]
fn notify_systemd_status(_status: &str) {}

#[cfg(target_os = "linux")]
fn notify_systemd_stopping() {
    use sd_notify::NotifyState;
    let _ = sd_notify::notify(
        false,
        &[
            NotifyState::Stopping,
            NotifyState::Status("Shutting down ddnsplus"),
        ],
    );
}

#[cfg(not(target_os = "linux"))]
fn notify_systemd_stopping() {}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                debug!("Received SIGINT, shutting down...");
            }
            _ = sigterm.recv() => {
                debug!("Received SIGTERM, shutting down...");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        debug!("Received Ctrl+C / stop signal, shutting down...");
    }
}

async fn run(args: Args) -> Result<()> {
    debug!("Loading configuration from {:?}", args.config);
    let app_config = AppConfig::from_file(&args.config)?;
    let poll_interval = app_config.config.pooling;

    let mut engine = DdnsEngine::from_config(&app_config, args.dry_run).await?;
    debug!("Configuration validated and providers initialized successfully");

    notify_systemd_ready();

    if args.dry_run || args.once {
        debug!(
            "Running single check cycle (dry_run={}, once={})",
            args.dry_run, args.once
        );
        notify_systemd_status("Running single check cycle");
        engine.run_cycle().await;
        notify_systemd_stopping();
        return Ok(());
    }

    debug!(
        "Starting polling loop with interval {}",
        humantime::format_duration(poll_interval)
    );

    loop {
        notify_systemd_status("Running check cycle");
        engine.run_cycle().await;
        notify_systemd_status(&format!(
            "Idle (waiting {} for next check)",
            humantime::format_duration(poll_interval)
        ));

        tokio::select! {
            _ = tokio::time::sleep(poll_interval) => {}
            _ = wait_for_shutdown_signal() => {
                notify_systemd_stopping();
                break;
            }
        }
    }

    debug!("ddnsplus stopped cleanly");
    Ok(())
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let verbose = args.verbose || args.dry_run;
    let default_filter = if verbose {
        "ddnsplus=debug"
    } else {
        "ddnsplus=info"
    };
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter));

    tracing_subscriber::fmt()
        .with_writer(std::io::stdout)
        .with_env_filter(env_filter)
        .init();

    if let Err(err) = run(args).await {
        error!("Fatal error: {:#}", err);
        std::process::exit(1);
    }
}
