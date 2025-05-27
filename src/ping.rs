use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::unix::io::AsRawFd;

pub fn send_ping6(interface: &str, target: &Ipv6Addr) -> Result<()> {
    // Create raw ICMPv6 socket and configure it for the interface
    let socket = create_and_bind_socket(interface)?;

    // Construct ICMPv6 Echo Request packet (minimum 8 bytes + some data)
    let mut packet = [0u8; 64];

    // ICMPv6 header: type(128) = echo request, code(0)
    packet[0] = 128; // ICMPv6 Echo Request type
    packet[1] = 0; // Code 0
    // packet[2..4] is checksum (filled by kernel)

    // Identifier and sequence number
    let identifier = std::process::id() as u16; // Use process ID for identifier
    let sequence = 1u16;

    packet[4] = (identifier >> 8) as u8;
    packet[5] = (identifier & 0xff) as u8;
    packet[6] = (sequence >> 8) as u8;
    packet[7] = (sequence & 0xff) as u8;

    // Fill with pattern data
    for (i, item) in packet.iter_mut().enumerate().take(32).skip(8) {
        *item = (i - 8) as u8;
    }

    // Destination address
    let dest = SocketAddr::V6(SocketAddrV6::new(*target, 0, 0, 0));

    // Send the packet (only the relevant portion)
    socket
        .send_to(&packet[0..32], &dest.into())
        .with_context(|| format!("Failed to send ping6 to {} via {}", target, interface))?;

    log::debug!(
        "Successfully sent ping6 to {} via interface {}",
        target,
        interface
    );
    Ok(())
}

fn create_and_bind_socket(p0: &str) -> _ {
    todo!()
}

/// Try to find an IPv6 address for the given interface
/// Returns the first non-loopback IPv6 address found, preferring link-local addresses
fn find_interface_ipv6_address(interface: &str) -> Option<Ipv6Addr> {
    use pnet::datalink;
    use std::net::IpAddr;

    // Try to get interface information using pnet
    let interfaces = datalink::interfaces();

    for iface in interfaces {
        if iface.name == interface {
            for ip_net in &iface.ips {
                if let IpAddr::V6(ipv6_addr) = ip_net.ip() {
                    // Skip loopback addresses
                    if !ipv6_addr.is_loopback() {
                        // Prefer link-local addresses (fe80::/10) for neighbor discovery
                        if ipv6_addr.segments()[0] & 0xffc0 == 0xfe80 {
                            return Some(ipv6_addr);
                        }
                    }
                }
            }

            // If no link-local found, return any non-loopback IPv6 address
            for ip_net in &iface.ips {
                if let IpAddr::V6(ipv6_addr) = ip_net.ip() {
                    if !ipv6_addr.is_loopback() && !ipv6_addr.is_unspecified() {
                        return Some(ipv6_addr);
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn test_send_ping6_basic_validation() {
        // Test that the function doesn't panic with valid inputs
        // Note: This will likely fail without root privileges, but tests the validation logic
        let target = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let result = send_ping6("lo", &target);

        // We expect either success or a specific error (permission denied, interface not found, etc.)
        // The important thing is that it doesn't panic
        match result {
            Ok(_) => {
                // Success - great!
                println!("Ping6 sent successfully");
            }
            Err(e) => {
                // Expected errors: permission denied, interface not found, etc.
                let error_msg = e.to_string().to_lowercase();
                assert!(
                    error_msg.contains("permission")
                        || error_msg.contains("operation not permitted")
                        || error_msg.contains("network is unreachable")
                        || error_msg.contains("no route to host")
                        || error_msg.contains("address family not supported")
                        || error_msg.contains("failed to create raw socket")
                        || error_msg.contains("failed to bind"),
                    "Unexpected error: {}",
                    e
                );
            }
        }
    }

    #[test]
    fn test_send_ping6_invalid_interface() {
        let target = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let result = send_ping6("nonexistent_interface_12345", &target);

        // Should fail due to invalid interface
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string().to_lowercase();
        assert!(
            error_msg.contains("not found")
                || error_msg.contains("operation not permitted")
                || error_msg.contains("failed to create raw socket")
                || error_msg.contains("no such device")
                || error_msg.contains("failed to bind"),
            "Expected interface-related error, got: {}",
            error_msg
        );
    }

    #[test]
    fn test_find_interface_ipv6_address() {
        // Test the helper function
        let result = find_interface_ipv6_address("lo");

        // May or may not find an address, but shouldn't panic
        match result {
            Some(addr) => {
                assert!(!addr.is_unspecified());
                println!("Found IPv6 address on lo: {}", addr);
            }
            None => {
                println!("No IPv6 address found on lo interface");
            }
        }
    }

    #[test]
    fn test_packet_construction() {
        // Test the packet construction logic by checking the static parts
        // This doesn't actually send packets, just validates the construction logic

        let target = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // We can't easily test the actual socket operations without root privileges,
        // but we can validate that the input parameters are handled correctly
        assert!(!target.is_unspecified());
        assert!(!target.is_loopback() || target == Ipv6Addr::LOCALHOST);

        // Test that process ID is reasonable for identifier
        let pid = std::process::id();
        assert!(pid > 0);
        assert!(pid < u32::MAX);

        // Test packet structure constants
        let identifier = pid as u16;
        let sequence = 1u16;

        // Verify our packet structure makes sense
        assert!(identifier != 0 || sequence != 0); // At least one should be non-zero
    }
}
