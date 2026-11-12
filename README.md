# ipsync

`ipsync` is a single-binary, cross-platform Dynamic DNS (DDNS) and IP synchronization client written in Rust.

Unlike traditional DDNS clients that only query a single local/public IP and update a DNS record, `ipsync` decouples **IP sources** from **IP targets** through a unified `Provider` interface:
- Obtain IPv4 and IPv6 addresses from multiple sources (local network interfaces, UniFi router WAN interfaces, etc.).
- Filter discovered IP addresses using standard CIDR prefixes (`192.168.0.0/16`, `fd00::/7`) or arbitrary bitmasks (`::6/::ffff:ffff:ffff:ffff`).
- Update IP addresses across multiple target systems (Cloudflare `A`/`AAAA` DNS records, UniFi WireGuard VPN Client endpoints, etc.).
- Run natively as a service on **Linux** (`systemd` with `sd_notify`), **macOS** (`LaunchDaemon`), and **Windows** (`NSSM`).

Repository: [https://github.com/ecsousa/ipsync](https://github.com/ecsousa/ipsync)

---

## Features

- **Single Self-Contained Executable**: Uses pure-Rust TLS (`rustls`), pure-Rust systemd socket notifications (`sd-notify`), and static C runtime linking (`musl` on Linux, `+crt-static` on Windows).
- **Smart State Tracking**: Tracks the last-seen IP per watcher and only queries/updates targets on startup or when the source IP changes.
- **Dual-Stack (`A` + `AAAA`) Aware**: Multiple watchers can target the same DNS hostname (one for IPv4, one for IPv6) without interfering with each other.
- **Extensible Architecture**: Adding a new provider only requires implementing the 3-method `Provider` trait (`initialize`, `get`, `set`).

---

## Command-Line Usage

```bash
ipsync [OPTIONS]

Options:
  -c, --config <CONFIG>  Path to the YAML configuration file [default: config.yaml]
  -o, --once             Execute a single check cycle and exit
  -d, --dry-run          Validate config, enable verbose logging, run once, and log actions without making changes
  -v, --verbose          Enable verbose (debug) logging
  -h, --help             Print help
  -V, --version          Print version
```

---

## Configuration (`config.yaml`)

```yaml
config:
  pooling: 5m

providers:
  - name: example.com
    type: cloudflare
    config:
      - zone: example.com
      - apikey: your-cloudflare-api-token
  - name: site-a
    type: unifi
    config:
      - host: unifi.site-a.example.com
      - apikey: your-unifi-api-key
  - name: site-b
    type: unifi
    config:
      - host: unifi.site-b.example.com
      - apikey: your-unifi-api-key

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
```

### Configuration Sections

#### 1. `config`
- `pooling` (or `polling`): How frequently `ipsync` checks watchers (e.g., `30s`, `5m`, `1h`).

#### 2. `providers`
Defines named provider instances. Note that the `local` provider instance is always built-in under the name `local` and does not need to be declared in `providers`.

| Provider `type` | Config Keys | Supported `get` Selectors | Supported `set` Selectors |
|---|---|---|---|
| `local` *(built-in)* | *(none)* | *(empty)* (all local IPs), `ipv4`, `ipv6` | *(not supported - read-only)* |
| `cloudflare` | `zone` (zone name), `apikey` (API token) | `<record_name>` (returns all `A` and `AAAA` records) | `<record_name>` (`A` for IPv4, `AAAA` for IPv6) |
| `unifi` | `host` (router hostname), `apikey` (API key), `insecure` (optional `true`/`false`, default `false`) | `wan1.ipv4`, `wan1.ipv6`, `wan2.ipv4`, `wan2.ipv6`, `vpnclient:$NAME` | `vpnclient:$NAME` (updates `wireguard_client_peer_ip`) |

#### 3. `watchers`
Each watcher links a `source` (`<provider_instance>:<selector>`) to one or more `target` / `targets` (`<provider_instance>:<selector>`):
- `include` / `includes`: Optional filter(s). If specified, an IP must match at least one include filter.
- `exclude` / `excludes`: Optional filter(s). Any IP matching an exclude filter is discarded.
- Both CIDR notation (`192.168.0.0/16`, `fd00::/7`) and explicit bitmask notation (`::6/::ffff:ffff:ffff:ffff`, `192.168.1.0/255.255.255.0`) are supported.
- If multiple IPs remain after filtering, the **first** matching IP is selected.

---

## Running as a System Service

### Linux (`systemd` with `Type=notify`)

`ipsync` natively supports `systemd` readiness, status, and stopping notifications via `NOTIFY_SOCKET`.

Create `/etc/systemd/system/ipsync.service`:

```ini
[Unit]
Description=ipsync Dynamic DNS and IP Synchronization Client
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/ipsync --config /etc/ipsync/config.yaml
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ipsync
sudo systemctl status ipsync
```

---

### macOS (`LaunchDaemon`)

Create `/Library/LaunchDaemons/com.example.ipsync.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.ipsync</string>

  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/ipsync</string>
    <string>--config</string>
    <string>/usr/local/etc/ipsync/config.yaml</string>
  </array>

  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>

  <key>StandardOutPath</key>
  <string>/var/log/ipsync.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/ipsync.err</string>
</dict>
</plist>
```

Load and start the daemon:

```bash
sudo chown root:wheel /Library/LaunchDaemons/com.example.ipsync.plist
sudo chmod 644 /Library/LaunchDaemons/com.example.ipsync.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.example.ipsync.plist
```

---

### Windows (`NSSM` - Non-Sucking Service Manager)

Install and configure `ipsync` as a Windows service using `nssm.exe` from an elevated PowerShell or Command Prompt:

```powershell
nssm install ipsync "C:\Program Files\ipsync\ipsync.exe" "--config \"C:\ProgramData\ipsync\config.yaml\""
nssm set ipsync AppDirectory "C:\Program Files\ipsync"
nssm set ipsync AppStdout "C:\ProgramData\ipsync\ipsync.log"
nssm set ipsync AppStderr "C:\ProgramData\ipsync\ipsync-error.log"
nssm start ipsync
```

---

## Adding a New Provider

To add a new provider type:
1. Create a module under `src/providers/` implementing the `Provider` trait (`src/providers/mod.rs`):
   ```rust
   #[async_trait]
   pub trait Provider: Send + Sync {
       async fn initialize(&mut self, config: &HashMap<String, String>) -> Result<()>;
       async fn get(&self, name: &str) -> Result<Vec<IpAddr>>;
       async fn set(&self, name: &str, ip: IpAddr) -> Result<()>;
   }
   ```
2. Register the provider type string in `create_provider()` in `src/providers/mod.rs`.

---

## Building and Testing

```bash
# Run unit tests
cargo test

# Build optimized release binary
cargo build --release
```
