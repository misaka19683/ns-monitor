use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::process::Command;

use anyhow::{Context, Result};
use regex::Regex;

/// Get all IPv6 addresses assigned to the specified interface
pub fn get_interface_addresses(interface: &str) -> Result<HashSet<Ipv6Addr>> {
    // Use get_if_addrs crate to get interface addresses natively
    let mut addresses = HashSet::new();
    let ifaces = get_if_addrs::get_if_addrs().context("Failed to get network interfaces")?;
    for iface in ifaces {
        if iface.name == interface {
            if let std::net::IpAddr::V6(ipv6) = iface.ip() {
                addresses.insert(ipv6);
            }
        }
    }
    Ok(addresses)
}

/// Get MAC address of the specified interface
pub fn get_interface_mac(interface: &str) -> Result<[u8; 6]> {
    let output = Command::new("ip")
        .args(["link", "show", "dev", interface])
        .output()
        .context("Failed to execute ip command")?;
    
    if !output.status.success() {
        anyhow::bail!("Failed to get MAC for interface {}", interface);
    }
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    
    // Use regex to extract MAC address
    let mac_regex = Regex::new(r"link/ether\s+([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})")
        .context("Failed to compile regex")?;
    
    if let Some(cap) = mac_regex.captures(&output_str) {
        if let Some(mac_str) = cap.get(1) {
            let mac_parts: Vec<&str> = mac_str.as_str().split(':').collect();
            if mac_parts.len() == 6 {
                let mut mac = [0u8; 6];
                for i in 0..6 {
                    mac[i] = u8::from_str_radix(mac_parts[i], 16)
                        .context("Failed to parse MAC address part")?;
                }
                return Ok(mac);
            }
        }
    }
    
    anyhow::bail!("Failed to parse MAC address for interface {}", interface)
}