use std::net::{Ipv6Addr, SocketAddrV6};
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type, SockAddr};
use log::{info, error, debug};
use nix::net::if_::if_nametoindex;

/// ICMPv6 Echo Request header
#[repr(C)]
struct Icmp6Hdr {
    icmp6_type: u8,
    icmp6_code: u8,
    icmp6_checksum: u16,
    icmp6_dataun: [u8; 4],
}

/// Setup or remove a temporary route for the target address
/// This implementation mimics odhcpd's approach but uses system commands for simplicity
fn setup_route(addr: &Ipv6Addr, interface: &str, add: bool) -> Result<()> {
    use std::process::Command;
    
    debug!("setup_route: Starting {} route for IPv6 address {} via interface {}", 
           if add { "addition" } else { "removal" }, addr, interface);
    
    let if_index = if_nametoindex(interface)
        .context("Failed to get interface index")?;
    
    debug!("setup_route: {} route to {} via interface {} (index: {})", 
           if add { "Adding" } else { "Removing" }, addr, interface, if_index);
    
    let addr_str = addr.to_string();
    debug!("setup_route: IPv6 address string representation: {}", addr_str);
    
    if add {
        // Construct command
        let route_cmd = format!("ip -6 route add {}/128 dev {} metric 128", addr_str, interface);
        debug!("setup_route: Executing command: {}", route_cmd);
        
        // Add route: ip -6 route add <addr>/128 dev <interface> metric 128
        let output = Command::new("ip")
            .args(&["-6", "route", "add", &format!("{}/128", addr_str), "dev", interface, "metric", "128"])
            .output()
            .context("Failed to add route")?;
        
        debug!("setup_route: Command executed, status: {}", output.status);
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            debug!("setup_route: Command stderr: {}", stderr);
            
            // Route may already exist, which is fine (RTNETLINK answers: File exists)
            if stderr.contains("File exists") || stderr.contains("EEXIST") {
                debug!("setup_route: Route to {} via {} already exists", addr, interface);
            } else {
                debug!("setup_route: Route add warning: {}", stderr);
            }
        } else {
            let stdout = String::from_utf8_lossy(&output.stdout);
            debug!("setup_route: Command stdout: {}", stdout);
            debug!("setup_route: Successfully added route to {} via {}", addr, interface);
        }
    } else {
        // Construct command
        let route_cmd = format!("ip -6 route del {}/128 dev {}", addr_str, interface);
        debug!("setup_route: Executing command: {}", route_cmd);
        
        // Delete route: ip -6 route del <addr>/128 dev <interface>
        let output = Command::new("ip")
            .args(&["-6", "route", "del", &format!("{}/128", addr_str), "dev", interface])
            .output()
            .context("Failed to remove route")?;
        
        debug!("setup_route: Command executed, status: {}", output.status);
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            debug!("setup_route: Command stderr: {}", stderr);
            
            // Route may not exist, which is fine
            if stderr.contains("No such process") || 
               stderr.contains("No such file or directory") ||
               stderr.contains("ESRCH") ||
               stderr.contains("ENOENT") {
                debug!("setup_route: Route to {} via {} does not exist", addr, interface);
            } else {
                debug!("setup_route: Route delete warning: {}", stderr);
            }
        } else {
            let stdout = String::from_utf8_lossy(&output.stdout);
            debug!("setup_route: Command stdout: {}", stdout);
            debug!("setup_route: Successfully removed route to {} via {}", addr, interface);
        }
    }
    
    Ok(())
}

pub fn send_ping6(interface: &str, target: &Ipv6Addr) -> Result<()> {
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
    setup_route(target, interface, true)
        .context("Failed to setup temporary route")?;
    
    // Send the packet
    let result = socket.send_to(packet_bytes, &dest_sockaddr);
    
    // Remove temporary route
    if let Err(e) = setup_route(target, interface, false) {
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