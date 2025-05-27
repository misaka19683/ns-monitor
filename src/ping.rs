use std::net::Ipv6Addr;
use std::os::fd::AsRawFd;
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use log::{info, error, debug};
use pnet::datalink::MacAddr;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::icmpv6::{MutableIcmpv6Packet, Icmpv6Types, checksum};
use pnet::packet::MutablePacket;
use crate::interface::{get_interface_mac, get_interface_ipv6_link_local};

pub fn send_ping6(interface: &str, target: &Ipv6Addr) -> Result<()> {
    debug!("send_ping6 called with interface: {}, target: {}", interface, target);
    
    // Get source MAC address from interface
    let src_mac = get_interface_mac(interface)
        .context("Failed to get interface MAC address")?;
    debug!("Interface {} MAC address: {}", interface, src_mac);
    
    // Create a raw packet socket for sending Ethernet frames
    let socket = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(libc::ETH_P_ALL)))
        .context("Failed to create packet socket")?;
    debug!("Raw packet socket created successfully");
    
    // Get interface index
    let if_index = nix::net::if_::if_nametoindex(interface)
        .context("Failed to get interface index")?;
    debug!("Interface {} has index: {}", interface, if_index);
    
    // Bind to interface
    let sll = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
        sll_ifindex: if_index as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    
    unsafe {
        let addr_ptr = &sll as *const libc::sockaddr_ll as *const libc::sockaddr;
        let addr_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        if libc::bind(socket.as_raw_fd(), addr_ptr, addr_len) < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    debug!("Socket bound to interface: {}", interface);
    
    // Use a multicast MAC address as destination since we don't know the target's MAC
    // This follows ICMPv6 neighbor discovery behavior
    let dst_mac = MacAddr::new(0x33, 0x33, 
                              target.octets()[12], 
                              target.octets()[13],
                              target.octets()[14], 
                              target.octets()[15]);
    debug!("Destination MAC address: {}", dst_mac);
    
    // Create buffer for full Ethernet frame
    // Ethernet (14) + IPv6 (40) + ICMPv6 (8) + payload (24) = 86 bytes
    let mut buffer = [0u8; 86];
    
    // Construct Ethernet header
    {
        let mut eth_packet = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        eth_packet.set_destination(dst_mac);
        eth_packet.set_source(src_mac);
        eth_packet.set_ethertype(EtherTypes::Ipv6);
    }
    
    let src_addr = get_interface_ipv6_link_local(interface)
            .context("Failed to get interface IPv6 link-local address")?;
    debug!("Source IPv6 link-local address: {}", src_addr);

    // Construct IPv6 header
    {
        let mut ipv6_packet = MutableIpv6Packet::new(&mut buffer[14..]).unwrap();
        ipv6_packet.set_version(6);
        ipv6_packet.set_traffic_class(0);
        ipv6_packet.set_flow_label(0);
        ipv6_packet.set_payload_length(32); // ICMPv6 header (8) + payload (24)
        ipv6_packet.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
        ipv6_packet.set_hop_limit(64);
        
        // Get the actual IPv6 link-local address from the interface
        ipv6_packet.set_source(src_addr);
        ipv6_packet.set_destination(*target);
    }
    
    // Construct ICMPv6 Echo Request
    {
        let mut icmpv6_packet = MutableIcmpv6Packet::new(&mut buffer[54..]).unwrap();
        icmpv6_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
        icmpv6_packet.set_icmpv6_code(pnet::packet::icmpv6::Icmpv6Code::new(0));
        
        // Set identifier and sequence number
        let identifier = std::process::id() as u16;
        let sequence = 1u16;
        let payload = icmpv6_packet.payload_mut();
        payload[0] = (identifier >> 8) as u8;
        payload[1] = (identifier & 0xff) as u8;
        payload[2] = (sequence >> 8) as u8;
        payload[3] = (sequence & 0xff) as u8;
        
        // Add some payload data
        for i in 4..24 {
            payload[i] = (i - 4) as u8;
        }
        
        // Calculate checksum using the actual source address
        
        let checksum_val = checksum(&icmpv6_packet.to_immutable(), &src_addr, target);
        icmpv6_packet.set_checksum(checksum_val);
    }
    
    debug!("ICMPv6 Echo Request packet constructed: identifier={}, sequence=1", std::process::id() as u16);
    
    // Send the packet
    match socket.send(&buffer) {
        Ok(sent) => {
            info!("Sent {} bytes to {} via {} (link-layer)", sent, target, interface);
        },
        Err(e) => {
            error!("Failed to send ICMPv6 Echo Request to {} via {}: {}", target, interface, e);
            return Err(e.into());
        }
    }
    
    Ok(())
}