use anyhow::Result;
use pnet::datalink;
/// Get MAC address of the specified interface
pub fn get_interface_mac(interface: &str) -> Result<[u8; 6]> {
    let interfaces = datalink::interfaces();

    if let Some(iface) = interfaces.into_iter().find(|iface| iface.name == interface) {
        if let Some(mac) = iface.mac {
            return Ok(mac.octets());
        }
    }
    anyhow::bail!(
        "Interface {} not found or MAC address unavailable",
        interface
    );
}
#[cfg(test)]
mod tests {
    use super::*;
    use pnet::datalink::{self, MacAddr};

    // Helper function to create a mock network interface
    fn create_mock_interface(name: &str, mac: Option<[u8; 6]>) -> datalink::NetworkInterface {
        datalink::NetworkInterface {
            name: name.to_string(),
            description: "".to_string(),
            index: 0,
            mac: mac.map(|m| MacAddr::new(m[0], m[1], m[2], m[3], m[4], m[5])),

            ips: vec![],
            flags: 0,
        }
    }

    #[test]
    fn test_get_interface_mac_success() {
        let interfaces = vec![
            create_mock_interface("eth0", Some([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E])),
            create_mock_interface("lo", None),
        ];

        // Mock the `datalink::interfaces` function
        let mock_interfaces = || interfaces.clone();

        // Test valid MAC address retrieval
        let result = get_interface_mac_with_mock("eth0", mock_interfaces);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
    }

    #[test]
    fn test_get_interface_mac_not_found() {
        let interfaces = vec![
            create_mock_interface("eth0", Some([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E])),
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
            create_mock_interface("eth0", Some([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E])),
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
    fn get_interface_mac_with_mock<F>(interface: &str, mock_fn: F) -> Result<[u8; 6]>
    where
        F: FnOnce() -> Vec<datalink::NetworkInterface>,
    {
        let interfaces = mock_fn();
        if let Some(iface) = interfaces.into_iter().find(|iface| iface.name == interface) {
            if let Some(mac) = iface.mac {
                return Ok(mac.octets());
            }
        }
        Err(anyhow::anyhow!(
            "Interface {} not found or MAC address unavailable",
            interface
        ))
    }
}
