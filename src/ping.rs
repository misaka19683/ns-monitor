use std::net::{Ipv6Addr, SocketAddrV6};
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type, SockAddr};
use log::{info, error, debug};
use nix::net::if_::if_nametoindex;
use rtnetlink::{new_connection, RouteMessageBuilder};

/// ICMPv6 Echo Request header
#[repr(C)]
struct Icmp6Hdr {
    icmp6_type: u8,
    icmp6_code: u8,
    icmp6_checksum: u16,
    icmp6_dataun: [u8; 4],
}

/// Setup or remove a temporary IPv6 host route using rtnetlink
/// This mimics odhcpd's approach for ping6 destination routing
async fn setup_route(addr: &Ipv6Addr, interface: &str, add: bool) -> Result<()> {
    // Get interface index from name
    let if_index = if_nametoindex(interface)
        .with_context(|| format!("Failed to get index for interface {}", interface))?;

    debug!("setup_route: {} route for IPv6 address {} via interface {} (index {})", 
           if add { "Adding" } else { "Removing" }, addr, interface, if_index);

    // Create netlink connection
    let (connection, handle, _) = new_connection()
        .with_context(|| "Failed to create netlink connection")?;
    
    // Spawn the connection in a separate task
    let conn_handle = tokio::spawn(connection);

    // Create IPv6 route message
    let route = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(*addr, 128)  // /128 host route
        .output_interface(if_index)
        .priority(128)  // Use priority 128 like odhcpd (metric)
        .build();

    let operation = if add { "add" } else { "remove" };
    
    let result = if add {
        debug!("setup_route: Adding IPv6 route for {} via interface {} (index {})", addr, interface, if_index);
        handle.route().add(route).execute().await
            .with_context(|| format!("Failed to add route for {} via {}", addr, interface))
    } else {
        debug!("setup_route: Removing IPv6 route for {} via interface {} (index {})", addr, interface, if_index);
        handle.route().del(route).execute().await
            .with_context(|| format!("Failed to remove route for {} via {}", addr, interface))
    };

    // Clean up the connection
    conn_handle.abort();

    match result {
        Ok(_) => {
            debug!("setup_route: Successfully {}ed route for {} via {}", operation, addr, interface);
            Ok(())
        },
        Err(e) => {
            // Handle common cases that are not critical errors
            let error_msg = format!("{}", e);
            if add && error_msg.contains("File exists") {
                debug!("setup_route: Route for {} via {} already exists, continuing", addr, interface);
                Ok(())
            } else if !add && (error_msg.contains("No such") || error_msg.contains("not found")) {
                debug!("setup_route: Route for {} via {} does not exist, continuing", addr, interface);
                Ok(())
            } else {
                error!("setup_route: Failed to {} route for {} via {}: {}", operation, addr, interface, e);
                Err(e)
            }
        }
    }
}

pub async fn send_ping6(interface: &str, target: &Ipv6Addr) -> Result<()> {
    debug!("send_ping6 called with interface: {}, target: {}", interface, target);
    
    // Get interface index
    let if_index = if_nametoindex(interface)
        .context("Failed to get interface index")?;
    debug!("Interface {} has index: {}", interface, if_index);
    
    // Create a raw ICMPv6 socket
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
        .context("Failed to create ICMPv6 socket")?;
    debug!("Raw ICMPv6 socket created successfully");
    
    // Bind socket to the specific interface
    socket.bind_device(Some(interface.as_bytes()))
        .context("Failed to bind socket to interface")?;
    debug!("Socket bound to interface: {}", interface);
    
    // Construct destination address
    let dest_addr = SocketAddrV6::new(*target, 0, 0, 0);
    let dest_sockaddr = SockAddr::from(dest_addr);
    
    // Construct ICMPv6 Echo Request packet
    let mut icmp_packet = Icmp6Hdr {
        icmp6_type: 128, // ICMP6_ECHO_REQUEST
        icmp6_code: 0,
        icmp6_checksum: 0, // Will be calculated by kernel
        icmp6_dataun: [0; 4],
    };
    
    // Set identifier and sequence number in dataun field
    let identifier = std::process::id() as u16;
    let sequence = 1u16;
    icmp_packet.icmp6_dataun[0] = (identifier >> 8) as u8;
    icmp_packet.icmp6_dataun[1] = (identifier & 0xff) as u8;
    icmp_packet.icmp6_dataun[2] = (sequence >> 8) as u8;
    icmp_packet.icmp6_dataun[3] = (sequence & 0xff) as u8;
    
    // Convert to bytes
    let packet_bytes = unsafe {
        std::slice::from_raw_parts(
            &icmp_packet as *const Icmp6Hdr as *const u8,
            std::mem::size_of::<Icmp6Hdr>(),
        )
    };
    
    debug!("ICMPv6 Echo Request packet constructed: identifier={}, sequence=1", identifier);
    
    // Setup temporary route (similar to odhcpd's approach)
    setup_route(target, interface, true).await
        .context("Failed to setup temporary route")?;
    
    // Send the packet
    let result = socket.send_to(packet_bytes, &dest_sockaddr);
    
    // Remove temporary route
    if let Err(e) = setup_route(target, interface, false).await {
        debug!("Warning: Failed to remove temporary route: {}", e);
    }
    
    match result {
        Ok(sent) => {
            info!("Sent {} bytes ICMPv6 Echo Request to {} via {}", sent, target, interface);
        },
        Err(e) => {
            error!("Failed to send ICMPv6 Echo Request to {} via {}: {}", target, interface, e);
            return Err(e.into());
        }
    }
    
    Ok(())
}