use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::process::Command;

use anyhow::{Context, Result};

/// Get all IPv6 addresses assigned to the specified interface
pub fn get_interface_addresses(interface: &str) -> Result<HashSet<Ipv6Addr>> {
    let output = Command::new("ip")
        .args(["-6", "addr", "show", "dev", interface])
        .output()
        .context("Failed to execute ip command")?;

    if !output.status.success() {
        anyhow::bail!("Failed to get addresses for interface {}", interface);
    }

    let output_str = String::from_utf8_lossy(&output.stdout);

    // Parse output to extract IPv6 addresses
    let mut addresses = HashSet::new();

    for line in output_str.lines() {
        if line.contains("inet6") {
            // Extract the IPv6 address part
            if let Some(addr_part) = line.split_whitespace().nth(1) {
                // Remove prefix length if present
                let addr_str = addr_part.split('/').next().unwrap_or(addr_part);

                // Parse IPv6 address
                if let Ok(addr) = addr_str.parse::<Ipv6Addr>() {
                    // Skip link-local addresses if needed, or include them
                    addresses.insert(addr);
                }
            }
        }
    }

    Ok(addresses)
}