# AGENTS.md — `ipsync` Project Context

## Overview

`ipsync` (`https://github.com/ecsousa/ipsync`) is a single-binary, cross-platform Dynamic DNS and IP synchronization client written in Rust (`1.99.1`, `edition = "2024"`).

It decouples **IP sources** from **IP targets** via a unified `Provider` trait, filters discovered IPv4/IPv6 addresses using CIDR prefixes or arbitrary bitmasks, and synchronizes changes across DNS records (Cloudflare) and non-DNS endpoints (UniFi WireGuard VPN clients).

## Build, Test, and Toolchain

- **Rust toolchain**: Requires `rustc >= 1.99.1` (`edition = "2024"`). On macOS, ensure `rustup` or Homebrew toolchain is up to date.
- **Build release**: `cargo build --release`
- **Run tests**: `cargo test`
  - Note: HTTP provider tests (`cloudflare` and `unifi`) use `wiremock`, which binds to `127.0.0.1` on an ephemeral port.
- **Minimal dynamic linking**: Uses `reqwest` with `rustls-tls` (no OpenSSL), `sd-notify` on Linux (no `libsystemd.so`), `musl` static builds on Linux, and `+crt-static` on Windows.

## Architecture & Module Map

| File | Responsibility |
|---|---|
| `src/main.rs` | CLI (`--config`, `--once`, `--dry-run`, `--verbose`), `stdout` logging (`tracing-subscriber`), polling loop, graceful shutdown (`SIGINT`/`SIGTERM`), and Linux `sd-notify` (`Ready`, `Status`, `Watchdog`, `Stopping`). |
| `src/config.rs` | YAML parsing (`AppConfig`, `GlobalConfig`, `ProviderInstanceConfig`, `WatcherConfig`, `parse_endpoint`). Supports both list-of-maps (`- key: val`) and standard maps in provider `config` blocks, as well as singular/plural `include`/`includes`, `exclude`/`excludes`, and `target`/`targets`. |
| `src/filter.rs` | `IpFilter` and `apply_filters` supporting IPv4/IPv6 CIDR prefixes (`192.168.0.0/16`, `fd00::/7`), explicit bitmasks (`::6/::ffff:ffff:ffff:ffff`, `192.168.1.0/255.255.255.0`), and exact IPs. |
| `src/engine.rs` | `DdnsEngine` and `WatcherState`. Validates config and provider selectors upfront, tracks `last_ip` per watcher, skips target checks when source IP is unchanged, compares target IPs by address family (`IPv4` vs `IPv6`), and enforces `--dry-run`. |
| `src/providers/mod.rs` | `Provider` async trait (`initialize`, `validate_source`, `validate_target`, `get`, `set`) and `create_provider` factory. |
| `src/providers/local.rs` | Built-in `local` provider (always registered under instance name `local`, read-only). Enumerates non-loopback/non-link-local IPs via `if-addrs`, sorted by `InterfacePriority`: `PhysicalWired` → `PhysicalWifi` → `VirtualVpn` → `VirtualContainer` → `VirtualHypervisor` → `Other`. |
| `src/providers/cloudflare.rs` | Cloudflare API v4 provider (`zone`, `apikey`). `get` returns all `A` and `AAAA` records for a name; `set` upserts (`PUT`/`POST`) `A` (IPv4) or `AAAA` (IPv6) while preserving `ttl` and `proxied`. |
| `src/providers/unifi.rs` | UniFi OS Network API provider (`host`, `apikey`, optional `insecure: true/false` defaulting to strict HTTPS). `get` supports `wan1.ipv4`, `wan1.ipv6`, `wan2.ipv4`, `wan2.ipv6`, and `vpnclient:$NAME`; `set` updates `wireguard_client_peer_ip` for `vpnclient:$NAME`. |
| `.github/workflows/build.yml` | Runs `cargo test --all-targets` and builds release binaries for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` (via `gcc-aarch64-linux-gnu`), `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`. |

## Key Behavioral Rules

1. **Logging**:
   - All logs go to `stdout`.
   - **Normal mode**: Logs at `INFO` level **only** when setting an IP on a target provider (or on errors).
   - **Verbose mode (`-v` / `--verbose`)**: Logs at `DEBUG` level—all provider reads, filter results, IP comparisons, and actions taken.
   - **Dry-run mode (`-d` / `--dry-run`)**: Validates config/selectors, implicitly enables verbose logging, ignores polling (runs once), and logs `[DRY RUN] Would set ...` without calling `Provider::set`.
2. **Watcher Logic**:
   - After `include`/`exclude` filtering, the **first** matching IP is selected.
   - `last_ip` is cached per watcher and only updated when all targets for that watcher succeed.
   - Target comparison filters existing target IPs by the same IP family as `current_ip`, allowing dual-stack `A` + `AAAA` watchers to target the same DNS hostname independently.
3. **Adding a New Provider**:
   - Implement `Provider` in `src/providers/<name>.rs`.
   - Register the type string in `create_provider()` in `src/providers/mod.rs`.
4. **Privacy / Git Hygiene**:
   - `config.yaml` and `specs` are gitignored. Never commit personal hostnames, domains, or API keys in code, tests, or docs—use `example.com` in fixtures and documentation.
