use anyhow::{Context, Result};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};

/// Get MAC address of the specified interface
pub fn get_interface_mac(interface: &str) -> Result<[u8; 6]> {
    let interfaces = NetworkInterface::show().context("Failed to get network interfaces")?;
    for iface in interfaces {
        if iface.name == interface {
            if let Some(mac) = iface.mac_addr {
                let octets: Vec<u8> = mac
                    .split(':')
                    .map(|s| u8::from_str_radix(s, 16))
                    .collect::<Result<_, _>>()
                    .context(format!("Failed to parse MAC address: {}", mac))?;
                if octets.len() == 6 {
                    let mut arr = [0u8; 6];
                    arr.copy_from_slice(&octets);
                    return Ok(arr);
                } else {
                    anyhow::bail!("MAC address has invalid length: {}", mac);
                }
            } else {
                anyhow::bail!("No MAC address found for interface {}", interface);
            }
        }
    }
    anyhow::bail!("Interface {} not found", interface)
}