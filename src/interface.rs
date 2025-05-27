use anyhow::{Context, Result};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};

/// Get MAC address of the specified interface
pub fn get_interface_mac(interface: &str) -> Result<[u8; 6]> {
    let interfaces = NetworkInterface::show().context("Failed to get network interfaces")?;
    
    for iface in interfaces {
        if iface.name == interface {
            if let Some(mac) = iface.mac_addr {
                // Validate MAC address format
                if !mac.contains(':') {
                    anyhow::bail!("Invalid MAC address format for interface {}: {}", interface, mac);
                }
                
                let octets: Vec<u8> = mac
                    .split(':')
                    .map(|s| {
                        if s.len() != 2 {
                            return Err(anyhow::anyhow!("Invalid MAC octet length: {}", s));
                        }
                        u8::from_str_radix(s, 16)
                            .map_err(|e| anyhow::anyhow!("Failed to parse MAC octet '{}': {}", s, e))
                    })
                    .collect::<Result<_, _>>()
                    .context(format!("Failed to parse MAC address: {}", mac))?;
                    
                if octets.len() != 6 {
                    anyhow::bail!("MAC address has invalid length for interface {}: {} (expected 6 octets, got {})", 
                                  interface, mac, octets.len());
                }
                
                let mut arr = [0u8; 6];
                arr.copy_from_slice(&octets);
                return Ok(arr);
            } else {
                anyhow::bail!("No MAC address found for interface {} (interface might be virtual or down)", interface);
            }
        }
    }
    anyhow::bail!("Interface {} not found in system interface list", interface)
}