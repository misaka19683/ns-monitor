use std::net::Ipv6Addr;

// Ethernet header size
const ETH_HEADER_SIZE: usize = 14;
// Ethernet header offsets
const ETH_SRC_MAC_OFFSET: usize = 6;

// IPv6 header offsets
const IPV6_SRC_ADDR_OFFSET: usize = 8;
const IPV6_DST_ADDR_OFFSET: usize = 24;
const IPV6_HEADER_SIZE: usize = 40;

// ICMPv6 header offsets
const ICMPV6_TYPE_OFFSET: usize = 0;
const ICMPV6_CODE_OFFSET: usize = 1;
const ICMPV6_CHECKSUM_OFFSET: usize = 2;
const ND_NS_TARGET_OFFSET: usize = 8;

// ICMPv6 type for Neighbor Solicitation
const ND_NEIGHBOR_SOLICIT: u8 = 135;

/// Parse an Ethernet frame containing an ICMPv6 NS packet, extracting source MAC and target IPv6
pub fn parse_ethernet_ns_packet(packet: &[u8]) -> Option<([u8; 6], Ipv6Addr)> {
    // Check if packet is large enough for Ethernet + IPv6 + ICMPv6 + NS target
    if packet.len() < ETH_HEADER_SIZE + IPV6_HEADER_SIZE + ND_NS_TARGET_OFFSET + 16 {
        return None;
    }
    
    // Extract source MAC address from Ethernet header
    let src_mac_bytes = &packet[ETH_SRC_MAC_OFFSET..ETH_SRC_MAC_OFFSET + 6];
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(src_mac_bytes);
    
    // Skip Ethernet header to get IPv6 packet
    let ipv6_packet = &packet[ETH_HEADER_SIZE..];
    
    // Verify IPv6 version
    if (ipv6_packet[0] >> 4) != 6 {
        return None;
    }
    
    // Check if next header is ICMPv6 (58)
    if ipv6_packet[6] != 58 {
        return None;
    }
    
    // Skip IPv6 header to get ICMPv6 data
    let icmpv6_data = &ipv6_packet[IPV6_HEADER_SIZE..];
    
    // Check if this is a Neighbor Solicitation message
    if icmpv6_data[ICMPV6_TYPE_OFFSET] != ND_NEIGHBOR_SOLICIT || 
       icmpv6_data[ICMPV6_CODE_OFFSET] != 0 {
        return None;
    }
    
    // Extract target address from NS message
    let target_bytes = &icmpv6_data[ND_NS_TARGET_OFFSET..ND_NS_TARGET_OFFSET + 16];
    let mut tgt_bytes = [0u8; 16];
    tgt_bytes.copy_from_slice(target_bytes);
    let target_addr = Ipv6Addr::from(tgt_bytes);
    
    Some((src_mac, target_addr))
}

/// Parse an ICMPv6 Neighbor Solicitation packet and extract both source and target addresses
pub fn parse_ns_packet_with_source(packet: &[u8]) -> Option<(Ipv6Addr, Ipv6Addr)> {
    // Check if packet is large enough to contain IPv6 + ICMPv6 header + NS target
    if packet.len() < IPV6_HEADER_SIZE + ND_NS_TARGET_OFFSET + 16 {
        return None;
    }

    // Verify IPv6 version
    if (packet[0] >> 4) != 6 {
        return None;
    }

    // Check if next header is ICMPv6 (58)
    if packet[6] != 58 {
        return None;
    }

    // Extract source IPv6 address from IPv6 header
    let src_addr_bytes = &packet[IPV6_SRC_ADDR_OFFSET..IPV6_SRC_ADDR_OFFSET + 16];
    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(src_addr_bytes);
    let src_addr = Ipv6Addr::from(src_bytes);

    // Skip IPv6 header to get to ICMPv6 data
    let icmpv6_data = &packet[IPV6_HEADER_SIZE..];

    // Check if this is a Neighbor Solicitation message
    if icmpv6_data[ICMPV6_TYPE_OFFSET] != ND_NEIGHBOR_SOLICIT ||
        icmpv6_data[ICMPV6_CODE_OFFSET] != 0 {
        return None;
    }

    // Extract target address from NS message
    let target_bytes = &icmpv6_data[ND_NS_TARGET_OFFSET..ND_NS_TARGET_OFFSET + 16];
    let mut tgt_bytes = [0u8; 16];
    tgt_bytes.copy_from_slice(target_bytes);
    let target_addr = Ipv6Addr::from(tgt_bytes);

    Some((src_addr, target_addr))
}

/// Parse an ICMPv6 Neighbor Solicitation packet and extract only the target address
pub fn parse_ns_packet(packet: &[u8]) -> Option<Ipv6Addr> {
    parse_ns_packet_with_source(packet).map(|(_, target)| target)
}