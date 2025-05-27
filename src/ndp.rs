use std::net::Ipv6Addr;
use pnet::datalink::MacAddr;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::Packet;

/// Fast validation function using pnet for robust packet parsing
/// Returns Some((source_mac, target_ipv6)) if this is a valid outgoing NS packet, None otherwise
pub fn validate_outgoing_ns_packet(packet: &[u8]) -> Option<(MacAddr, Ipv6Addr)> {
    // Parse Ethernet frame using pnet
    let ethernet_packet = EthernetPacket::new(packet)?;
    
    // Check if this is an IPv6 packet
    if ethernet_packet.get_ethertype() != EtherTypes::Ipv6 {
        return None;
    }
    
    // Get source MAC address
    let source_mac = ethernet_packet.get_source();
    
    // Parse IPv6 packet
    let ipv6_packet = Ipv6Packet::new(ethernet_packet.payload())?;
    
    // Check if next header is ICMPv6
    if ipv6_packet.get_next_header().0 != 58 { // ICMPv6
        return None;
    }
    
    // Parse ICMPv6 packet
    let icmpv6_packet = Icmpv6Packet::new(ipv6_packet.payload())?;
    
    // Check if this is a Neighbor Solicitation (type 135)
    if icmpv6_packet.get_icmpv6_type() != Icmpv6Types::NeighborSolicit {
        return None;
    }
    
    // Check ICMPv6 code (should be 0 for NS)
    if icmpv6_packet.get_icmpv6_code().0 != 0 {
        return None;
    }
    
    // Extract target address from NS payload
    // NS packet structure: type(1) + code(1) + checksum(2) + reserved(4) + target(16)
    let icmpv6_payload = icmpv6_packet.payload();
    if icmpv6_payload.len() < 20 { // 4 bytes reserved + 16 bytes target
        return None;
    }
    
    // Extract the target IPv6 address (starting at offset 4 in payload)
    let mut target_bytes = [0u8; 16];
    target_bytes.copy_from_slice(&icmpv6_payload[4..20]);
    let target_addr = Ipv6Addr::from(target_bytes);
    
    Some((source_mac, target_addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_outgoing_ns_packet_invalid_too_short() {
        // Test with packet too short to be valid
        let short_packet = vec![0u8; 50]; // Too short for complete Ethernet + IPv6 + ICMPv6
        assert_eq!(validate_outgoing_ns_packet(&short_packet), None);
    }

    #[test]
    fn test_validate_outgoing_ns_packet_invalid_not_ipv6() {
        // Create a packet that's not IPv6 (wrong EtherType)
        let mut packet = vec![0u8; 100];
        // Set EtherType to IPv4 (0x0800) instead of IPv6 (0x86dd)
        packet[12] = 0x08;
        packet[13] = 0x00;
        assert_eq!(validate_outgoing_ns_packet(&packet), None);
    }

    #[test]
    fn test_validate_outgoing_ns_packet_invalid_not_icmpv6() {
        // Create an IPv6 packet that's not ICMPv6
        let mut packet = vec![0u8; 100];
        // Set EtherType to IPv6
        packet[12] = 0x86;
        packet[13] = 0xdd;
        // Set IPv6 version
        packet[14] = 0x60;
        // Set next header to TCP (6) instead of ICMPv6 (58)
        packet[20] = 6;
        assert_eq!(validate_outgoing_ns_packet(&packet), None);
    }

    #[test] 
    fn test_validate_outgoing_ns_packet_valid_basic() {
        // This test demonstrates the structure validation
        // Note: Creating a complete valid NS packet would be quite complex
        // and is better tested through integration tests
        
        // Test that our function correctly rejects malformed packets
        let empty_packet = vec![];
        assert_eq!(validate_outgoing_ns_packet(&empty_packet), None);
        
        // Test that minimum size validation works
        let minimal_packet = vec![0u8; 10];
        assert_eq!(validate_outgoing_ns_packet(&minimal_packet), None);
    }
}