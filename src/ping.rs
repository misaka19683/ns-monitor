use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

pub fn send_ping6(interface: &str, target: &Ipv6Addr) -> Result<()> {
    // Create a raw ICMPv6 socket
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
        .context("Failed to create raw socket")?;

    // Bind to the interface
    socket.bind_device(Some(interface.as_bytes()))?;

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

    for (i, item) in packet.iter_mut().enumerate().take(32).skip(8) {
        *item = (i - 8) as u8;
    }

    // Destination address
    let dest = SocketAddr::V6(SocketAddrV6::new(*target, 0, 0, 0));

    // Send the packet (only the relevant portion)
    socket.send_to(&packet[0..32], &dest.into())?;

    Ok(())
}
