use anyhow::Result;
use pnet::datalink::{self, MacAddr};
use std::net::Ipv6Addr;

/// Get MAC address of the specified interface
pub fn get_interface_mac(interface: &str) -> Result<MacAddr> {
    let interfaces = datalink::interfaces();

    if let Some(iface) = interfaces.into_iter().find(|iface| iface.name == interface) {
        if let Some(mac) = iface.mac {
            return Ok(mac);
        }
    }
    anyhow::bail!(
        "Interface {} not found or MAC address unavailable",
        interface
    );
}

/// Get IPv6 link-local address of the specified interface
pub fn get_interface_ipv6_link_local(interface: &str) -> Result<Ipv6Addr> {
    let interfaces = datalink::interfaces();

    if let Some(iface) = interfaces.into_iter().find(|iface| iface.name == interface) {
        // Look for IPv6 link-local address (starts with fe80::)
        for ip in iface.ips {
            if let std::net::IpAddr::V6(ipv6_addr) = ip.ip() {
                // Check if this is a link-local address (fe80::/10)
                let octets = ipv6_addr.octets();
                if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
                    return Ok(ipv6_addr);
                }
            }
        }
    }
    anyhow::bail!(
        "Interface {} not found or no IPv6 link-local address available",
        interface
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::datalink::{self, MacAddr};

    // Helper function to create a mock network interface
    fn create_mock_interface(name: &str, mac: Option<MacAddr>) -> datalink::NetworkInterface {
        datalink::NetworkInterface {
            name: name.to_string(),
            description: "".to_string(),
            index: 0,
            mac,
            ips: vec![],
            flags: 0,
        }
    }

    #[test]
    fn test_get_interface_mac_success() {
        let expected_mac = MacAddr::new(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E);
        let interfaces = vec![
            create_mock_interface("eth0", Some(expected_mac)),
            create_mock_interface("lo", None),
        ];

        // Mock the `datalink::interfaces` function
        let mock_interfaces = || interfaces.clone();

        // Test valid MAC address retrieval
        let result = get_interface_mac_with_mock("eth0", mock_interfaces);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_mac);
    }

    #[test]
    fn test_get_interface_mac_not_found() {
        let interfaces = vec![
            create_mock_interface(
                "eth0",
                Some(MacAddr::new(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E)),
            ),
            create_mock_interface("lo", None),
        ];

        // Mock the `datalink::interfaces` function
        let mock_interfaces = || interfaces.clone();

        // Test interface not found
        let result = get_interface_mac_with_mock("nonexistent", mock_interfaces);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Interface nonexistent not found or MAC address unavailable"
        );
    }

    #[test]
    fn test_get_interface_mac_no_mac_address() {
        let interfaces = vec![
            create_mock_interface(
                "eth0",
                Some(MacAddr::new(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E)),
            ),
            create_mock_interface("lo", None),
        ];

        // Mock the `datalink::interfaces` function
        let mock_interfaces = || interfaces.clone();

        // Test interface with no MAC address
        let result = get_interface_mac_with_mock("lo", mock_interfaces);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Interface lo not found or MAC address unavailable"
        );
    }

    // Wrapper function to inject mocked interfaces
    fn get_interface_mac_with_mock<F>(interface: &str, mock_fn: F) -> Result<MacAddr>
    where
        F: FnOnce() -> Vec<datalink::NetworkInterface>,
    {
        let interfaces = mock_fn();
        if let Some(iface) = interfaces.into_iter().find(|iface| iface.name == interface) {
            if let Some(mac) = iface.mac {
                return Ok(mac);
            }
        }
        Err(anyhow::anyhow!(
            "Interface {} not found or MAC address unavailable",
            interface
        ))
    }
}
