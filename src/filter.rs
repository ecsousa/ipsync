use anyhow::{Result, anyhow};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFilter {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl FromStr for IpFilter {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if let Some((addr_part, mask_part)) = s.split_once('/') {
            let ip: IpAddr = addr_part
                .trim()
                .parse()
                .map_err(|e| anyhow!("invalid IP address in filter '{}': {}", s, e))?;
            let mask_part = mask_part.trim();

            match ip {
                IpAddr::V4(v4) => {
                    let network = u32::from(v4);
                    let mask = if let Ok(prefix) = mask_part.parse::<u8>() {
                        if prefix > 32 {
                            return Err(anyhow!(
                                "IPv4 CIDR prefix length out of range (0..=32) in '{}'",
                                s
                            ));
                        }
                        if prefix == 0 {
                            0
                        } else {
                            !0u32 << (32 - prefix)
                        }
                    } else if let Ok(mask_ip) = mask_part.parse::<Ipv4Addr>() {
                        u32::from(mask_ip)
                    } else {
                        return Err(anyhow!("invalid IPv4 mask or prefix in '{}'", s));
                    };
                    Ok(IpFilter::V4 { network, mask })
                }
                IpAddr::V6(v6) => {
                    let network = u128::from(v6);
                    let mask = if let Ok(prefix) = mask_part.parse::<u8>() {
                        if prefix > 128 {
                            return Err(anyhow!(
                                "IPv6 CIDR prefix length out of range (0..=128) in '{}'",
                                s
                            ));
                        }
                        if prefix == 0 {
                            0
                        } else {
                            !0u128 << (128 - prefix)
                        }
                    } else if let Ok(mask_ip) = mask_part.parse::<Ipv6Addr>() {
                        u128::from(mask_ip)
                    } else {
                        return Err(anyhow!("invalid IPv6 mask or prefix in '{}'", s));
                    };
                    Ok(IpFilter::V6 { network, mask })
                }
            }
        } else {
            let ip: IpAddr = s
                .parse()
                .map_err(|e| anyhow!("invalid IP address in filter '{}': {}", s, e))?;
            match ip {
                IpAddr::V4(v4) => Ok(IpFilter::V4 {
                    network: u32::from(v4),
                    mask: u32::MAX,
                }),
                IpAddr::V6(v6) => Ok(IpFilter::V6 {
                    network: u128::from(v6),
                    mask: u128::MAX,
                }),
            }
        }
    }
}

impl IpFilter {
    pub fn matches(&self, ip: IpAddr) -> bool {
        match (*self, ip) {
            (IpFilter::V4 { network, mask }, IpAddr::V4(v4)) => {
                (u32::from(v4) & mask) == (network & mask)
            }
            (IpFilter::V6 { network, mask }, IpAddr::V6(v6)) => {
                (u128::from(v6) & mask) == (network & mask)
            }
            _ => false,
        }
    }
}

/// Applies include and exclude filters to a list of IP addresses.
/// - If `includes` is non-empty, only IPs matching at least one `include` filter are kept.
/// - Any IP matching at least one `exclude` filter is removed.
pub fn apply_filters(
    ips: Vec<IpAddr>,
    includes: &[IpFilter],
    excludes: &[IpFilter],
) -> Vec<IpAddr> {
    ips.into_iter()
        .filter(|&ip| {
            let included = if includes.is_empty() {
                true
            } else {
                includes.iter().any(|f| f.matches(ip))
            };
            let excluded = excludes.iter().any(|f| f.matches(ip));
            included && !excluded
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_suffix_bitmask_and_ula_exclude() {
        let include: IpFilter = "::6/::ffff:ffff:ffff:ffff".parse().unwrap();
        let exclude: IpFilter = "fd00::/7".parse().unwrap();

        let global_match: IpAddr = "2600:1700:abcd:1234::6".parse().unwrap();
        let global_other: IpAddr = "2600:1700:abcd:1234::7".parse().unwrap();
        let ula_match_suffix: IpAddr = "fd12:3456:789a:bcde::6".parse().unwrap();

        assert!(include.matches(global_match));
        assert!(!include.matches(global_other));
        assert!(include.matches(ula_match_suffix));
        assert!(exclude.matches(ula_match_suffix));
        assert!(!exclude.matches(global_match));

        let filtered = apply_filters(
            vec![ula_match_suffix, global_other, global_match],
            &[include],
            &[exclude],
        );
        assert_eq!(filtered, vec![global_match]);
    }

    #[test]
    fn test_ipv4_cidr_includes() {
        let inc1: IpFilter = "192.168.0.0/16".parse().unwrap();
        let inc2: IpFilter = "10.0.0.0/8".parse().unwrap();

        let ip1: IpAddr = "192.168.10.25".parse().unwrap();
        let ip2: IpAddr = "10.24.0.5".parse().unwrap();
        let ip3: IpAddr = "172.16.0.1".parse().unwrap();
        let ip4: IpAddr = "8.8.8.8".parse().unwrap();

        let filtered = apply_filters(vec![ip3, ip4, ip1, ip2], &[inc1, inc2], &[]);
        assert_eq!(filtered, vec![ip1, ip2]);
    }

    #[test]
    fn test_ipv4_explicit_netmask_and_exact_ip() {
        let netmask_filter: IpFilter = "192.168.1.0/255.255.255.0".parse().unwrap();
        assert!(netmask_filter.matches("192.168.1.42".parse().unwrap()));
        assert!(!netmask_filter.matches("192.168.2.42".parse().unwrap()));

        let exact_filter: IpFilter = "10.0.0.1".parse().unwrap();
        assert!(exact_filter.matches("10.0.0.1".parse().unwrap()));
        assert!(!exact_filter.matches("10.0.0.2".parse().unwrap()));
    }
}
