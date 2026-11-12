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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum InterfacePriority {
    PhysicalWired = 0,
    PhysicalWifi = 1,
    VirtualVpn = 2,
    VirtualContainer = 3,
    VirtualHypervisor = 4,
    Other = 5,
}

fn is_usable_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified()
}

fn is_usable_ipv6(ip: Ipv6Addr) -> bool {
    !ip.is_loopback() && !ip.is_unicast_link_local() && !ip.is_unspecified()
}

pub(crate) fn classify_interface_by_name(name: &str) -> InterfacePriority {
    let lower = name.trim().to_ascii_lowercase();

    // 1. Virtual - VPN
    if lower.starts_with("tun")
        || lower.starts_with("tap")
        || lower.starts_with("wg")
        || lower.starts_with("utun")
        || lower.starts_with("ppp")
        || lower.starts_with("ipsec")
        || lower.starts_with("tailscale")
        || lower.starts_with("zt")
        || lower.starts_with("nordlynx")
        || lower.starts_with("mullvad")
        || lower.starts_with("proton")
        || lower.starts_with("ovpn")
        || lower.contains("vpn")
        || lower.contains("wireguard")
        || lower.contains("tailscale")
        || lower.contains("zerotier")
        || lower.contains("mullvad")
        || lower.contains("nordlynx")
        || lower.contains("anyconnect")
    {
        return InterfacePriority::VirtualVpn;
    }

    // 2. Virtual - Container networks (Docker, Podman, Kubernetes, LXC, etc.)
    if lower.starts_with("docker")
        || lower.starts_with("br-")
        || (lower.starts_with("veth") && !lower.starts_with("vethernet"))
        || lower.starts_with("cni")
        || lower.starts_with("flannel")
        || lower.starts_with("cali")
        || lower.starts_with("cilium")
        || lower.starts_with("podman")
        || lower.starts_with("kube")
        || lower.starts_with("lxc")
        || lower.starts_with("lxd")
        || lower.contains("docker")
        || lower.contains("container")
        || lower.contains("podman")
        || lower.contains("orbstack")
    {
        return InterfacePriority::VirtualContainer;
    }

    // 3. Virtual - Hypervisor connections (VMware, VirtualBox, Hyper-V, KVM/QEMU, WSL, etc.)
    if lower.starts_with("virbr")
        || lower.starts_with("vnet")
        || lower.starts_with("vmnet")
        || lower.starts_with("vboxnet")
        || lower.starts_with("vmbus")
        || lower.starts_with("vmenet")
        || lower.starts_with("xenbr")
        || lower.starts_with("macvtap")
        || lower.starts_with("vethernet")
        || lower.contains("hyper-v")
        || lower.contains("hyperv")
        || lower.contains("vmware")
        || lower.contains("virtualbox")
        || lower.contains("vbox")
        || lower.contains("parallels")
        || lower.contains("qemu")
        || lower.contains("kvm")
        || lower.contains("wsl")
    {
        return InterfacePriority::VirtualHypervisor;
    }

    // 4. Physical - Wi-Fi (check before wired so "Wireless Ethernet" / "Wi-Fi" isn't caught as wired)
    if lower.starts_with("wlan")
        || lower.starts_with("wlp")
        || lower.starts_with("wlo")
        || lower.starts_with("wls")
        || lower.starts_with("ath")
        || lower.contains("wi-fi")
        || lower.contains("wifi")
        || lower.contains("wireless")
        || lower.contains("wlan")
        || lower.contains("airport")
    {
        return InterfacePriority::PhysicalWifi;
    }

    // 5. Physical - Wired
    if lower.starts_with("eth")
        || lower.starts_with("enp")
        || lower.starts_with("eno")
        || lower.starts_with("ens")
        || lower.starts_with("enx")
        || lower.starts_with("em")
        || (lower.starts_with("en") && lower[2..].chars().all(|c| c.is_ascii_digit()))
        || lower.contains("ethernet")
        || lower.contains("local area connection")
    {
        return InterfacePriority::PhysicalWired;
    }

    // 6. All others
    InterfacePriority::Other
}

fn classify_interface(name: &str) -> InterfacePriority {
    let by_name = classify_interface_by_name(name);

    #[cfg(target_os = "linux")]
    {
        // On Linux, sysfs accurately distinguishes physical wired vs. wireless interfaces.
        if matches!(
            by_name,
            InterfacePriority::PhysicalWired
                | InterfacePriority::PhysicalWifi
                | InterfacePriority::Other
        ) {
            let sys_base = std::path::Path::new("/sys/class/net").join(name);
            if sys_base.join("wireless").exists() || sys_base.join("phy80211").exists() {
                return InterfacePriority::PhysicalWifi;
            }
            if sys_base.join("device").exists() {
                return InterfacePriority::PhysicalWired;
            }
        }
    }

    by_name
}

#[async_trait]
impl Provider for LocalProvider {
    async fn initialize(&mut self, _config: &HashMap<String, String>) -> Result<()> {
        Ok(())
    }

    fn validate_source(&self, name: &str) -> Result<()> {
        let selector = name.trim().to_ascii_lowercase();
        if !selector.is_empty() && selector != "ipv4" && selector != "ipv6" {
            bail!(
                "invalid local provider parameter '{}': expected empty, 'ipv4', or 'ipv6'",
                name
            );
        }
        Ok(())
    }

    fn validate_target(&self, _name: &str) -> Result<()> {
        bail!("local provider is read-only and does not support setting IP addresses")
    }

    async fn get(&self, name: &str) -> Result<Vec<IpAddr>> {
        self.validate_source(name)?;
        let selector = name.trim().to_ascii_lowercase();

        let interfaces = if_addrs::get_if_addrs()
            .map_err(|e| anyhow!("failed to enumerate local network interfaces: {}", e))?;

        let mut candidates: Vec<(InterfacePriority, IpAddr)> = Vec::new();
        for iface in interfaces {
            if iface.is_loopback() {
                continue;
            }
            let priority = classify_interface(&iface.name);
            match iface.ip() {
                IpAddr::V4(v4) if is_usable_ipv4(v4) => {
                    if selector.is_empty() || selector == "ipv4" {
                        candidates.push((priority, IpAddr::V4(v4)));
                    }
                }
                IpAddr::V6(v6) if is_usable_ipv6(v6) => {
                    if selector.is_empty() || selector == "ipv6" {
                        candidates.push((priority, IpAddr::V6(v6)));
                    }
                }
                _ => {}
            }
        }

        // Stable sort by priority: Wired -> Wifi -> VPN -> Container -> Hypervisor -> Other
        candidates.sort_by_key(|(priority, _)| *priority);

        let mut ips = Vec::with_capacity(candidates.len());
        for (_, ip) in candidates {
            if !ips.contains(&ip) {
                ips.push(ip);
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

    #[test]
    fn test_interface_classification_and_ordering() {
        // Physical Wired
        assert_eq!(
            classify_interface_by_name("eth0"),
            InterfacePriority::PhysicalWired
        );
        assert_eq!(
            classify_interface_by_name("enp3s0"),
            InterfacePriority::PhysicalWired
        );
        assert_eq!(
            classify_interface_by_name("en0"),
            InterfacePriority::PhysicalWired
        );
        assert_eq!(
            classify_interface_by_name("Ethernet"),
            InterfacePriority::PhysicalWired
        );

        // Physical Wi-Fi
        assert_eq!(
            classify_interface_by_name("wlan0"),
            InterfacePriority::PhysicalWifi
        );
        assert_eq!(
            classify_interface_by_name("wlp2s0"),
            InterfacePriority::PhysicalWifi
        );
        assert_eq!(
            classify_interface_by_name("Wi-Fi"),
            InterfacePriority::PhysicalWifi
        );

        // Virtual VPN
        assert_eq!(
            classify_interface_by_name("wg0"),
            InterfacePriority::VirtualVpn
        );
        assert_eq!(
            classify_interface_by_name("tun0"),
            InterfacePriority::VirtualVpn
        );
        assert_eq!(
            classify_interface_by_name("utun4"),
            InterfacePriority::VirtualVpn
        );
        assert_eq!(
            classify_interface_by_name("tailscale0"),
            InterfacePriority::VirtualVpn
        );
        assert_eq!(
            classify_interface_by_name("WireGuard Tunnel"),
            InterfacePriority::VirtualVpn
        );

        // Virtual Container
        assert_eq!(
            classify_interface_by_name("docker0"),
            InterfacePriority::VirtualContainer
        );
        assert_eq!(
            classify_interface_by_name("br-123456789abc"),
            InterfacePriority::VirtualContainer
        );
        assert_eq!(
            classify_interface_by_name("veth9f3a2b"),
            InterfacePriority::VirtualContainer
        );
        assert_eq!(
            classify_interface_by_name("cni0"),
            InterfacePriority::VirtualContainer
        );

        // Virtual Hypervisor
        assert_eq!(
            classify_interface_by_name("virbr0"),
            InterfacePriority::VirtualHypervisor
        );
        assert_eq!(
            classify_interface_by_name("vmnet8"),
            InterfacePriority::VirtualHypervisor
        );
        assert_eq!(
            classify_interface_by_name("vboxnet0"),
            InterfacePriority::VirtualHypervisor
        );
        assert_eq!(
            classify_interface_by_name("vEthernet (Default Switch)"),
            InterfacePriority::VirtualHypervisor
        );

        // Other
        assert_eq!(
            classify_interface_by_name("awdl0"),
            InterfacePriority::Other
        );
        assert_eq!(
            classify_interface_by_name("bridge0"),
            InterfacePriority::Other
        );

        // Verify overall priority order
        let mut names = vec![
            "awdl0",
            "virbr0",
            "docker0",
            "wg0",
            "wlan0",
            "eth0",
        ];
        names.sort_by_key(|name| classify_interface_by_name(name));
        assert_eq!(
            names,
            vec!["eth0", "wlan0", "wg0", "docker0", "virbr0", "awdl0"]
        );
    }
}
