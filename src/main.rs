use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;
use std::os::fd::AsRawFd;
use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, error, info, warn};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::Mutex;
use tokio::time::sleep;
use tokio::signal;
use pnet::datalink::MacAddr;

mod bpf;
mod ndp;
mod ping;
mod interface;


#[derive(Parser, Debug)]
#[clap(author, version, about = "IPv6 Neighbor Solicitation monitor and ping6 forwarder")]
#[clap(long_about = "NS-Monitor listens for outgoing IPv6 Neighbor Solicitation packets on a master interface and forwards ping6 requests to configured slave interfaces to help with IPv6 neighbor discovery across multiple network interfaces.")]
struct Args {
    /// Master interface to monitor for outgoing NS packets
    #[clap(short, long)]
    master: String,

    /// Slave interfaces to send ping6 packets to
    #[clap(short, long, use_value_delimiter = true, value_delimiter = ',')]
    slaves: Vec<String>,

    /// Log level (error, warn, info, debug, trace)
    #[clap(short, long, default_value = "info")]
    log_level: String,

    /// Daemonize the process
    #[clap(short, long)]
    daemon: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Setup logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&args.log_level))
        .init();

    // Validate interfaces exist
    validate_interface(&args.master)?;
    for slave in &args.slaves {
        validate_interface(slave)?;
    }

    // Daemonize if requested
    if args.daemon {
        daemonize::Daemonize::new()
            .pid_file("/var/run/ns-monitor.pid")
            .chown_pid_file(true)
            .start()
            .context("Failed to daemonize")?;
    }

    info!("Starting outbound NS monitor on {} and forwarding to {:?}", args.master, args.slaves);

    // Get master interface MAC address for source filtering
    let master_mac_addr = interface::get_interface_mac(&args.master)?;
    info!("Master interface MAC address: {}", master_mac_addr);

    // Create shared state
    let state = Arc::new(Mutex::new(AppState {
        slaves: args.slaves.clone(),
        master_mac: master_mac_addr,
        ns_counter: 0,
        ping_counter: 0,
    }));

    // Setup socket for monitoring NS packets
    let socket = setup_ns_monitor_socket(&args.master)
        .context("Failed to setup NS monitor socket")?;

    // Start the main monitoring loop with signal handling
    tokio::select! {
        result = monitor_ns_packets(socket, state) => {
            result
        }
        _ = signal::ctrl_c() => {
            info!("Received SIGINT, shutting down gracefully");
            Ok(())
        }
    }
}

struct AppState {
    slaves: Vec<String>,
    master_mac: MacAddr,
    ns_counter: u64,
    ping_counter: u64,
}

fn validate_interface(interface: &str) -> Result<()> {
    // Use nix to check if the interface exists by name
    match nix::net::if_::if_nametoindex(interface) {
        Ok(_) => Ok(()),
        Err(_) => anyhow::bail!("Interface {} does not exist", interface),
    }
}


fn setup_ns_monitor_socket(interface: &str) -> Result<Socket> {
    debug!("Creating packet socket for interface: {}", interface);
    
    // Create packet socket to capture ALL ethernet frames (not just IPv6) to see outgoing packets
    let socket = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(libc::ETH_P_ALL)))
        .context("Failed to create packet socket")?;
    debug!("Successfully created packet socket");

    // Set socket options
    socket.set_nonblocking(true)
        .context("Failed to set socket non-blocking")?;
    debug!("Set socket to non-blocking mode");

    // Bind to the interface
    let if_index = nix::net::if_::if_nametoindex(interface)
        .context("Failed to get interface index")?;
    debug!("Interface {} has index: {}", interface, if_index);

    // Bind to interface - use ETH_P_ALL to catch all packets including outgoing
    let sll = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
        sll_ifindex: if_index as i32,
        sll_hatype: 0,
        sll_pkttype: 0,  // Accept all packet types (incoming and outgoing)
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    
    debug!("Binding socket to interface {} (index: {})", interface, if_index);
    debug!("sockaddr_ll: family={}, protocol={}, ifindex={}", 
           sll.sll_family, u16::from_be(sll.sll_protocol), sll.sll_ifindex);

    unsafe {
        let ret = libc::bind(
            socket.as_raw_fd(),
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        );

        if ret < 0 {
            let error = std::io::Error::last_os_error();
            error!("Failed to bind socket to interface {}: {}", interface, error);
            return Err(error.into());
        }
    }
    debug!("Successfully bound socket to interface {}", interface);

    // Apply BPF filter for NS packets only using manual setsockopt
    debug!("Creating BPF filter for NS packets");
    let filter = bpf::create_ns_filter();
    debug!("BPF filter created with {} instructions", filter.len());
    
    let filter_prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    
    debug!("Applying BPF filter to socket");
    unsafe {
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &filter_prog as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        );
        if ret < 0 {
            let error = std::io::Error::last_os_error();
            error!("Failed to attach BPF filter: {}", error);
            return Err(error.into());
        }
    }
    debug!("Successfully applied BPF filter");
    
    Ok(socket)
}

async fn monitor_ns_packets(socket: Socket, state: Arc<Mutex<AppState>>) -> Result<()> {
    // Use AsyncFd to wrap the raw socket
    let async_fd = tokio::io::unix::AsyncFd::new(socket)?;
    
    // Receive buffer - use standard Ethernet MTU size
    const MAX_PACKET_SIZE: usize = 1500;
    let mut buf = [0u8; MAX_PACKET_SIZE];
    
    loop {
        // Wait for socket to become readable
        let mut guard = async_fd.readable().await?;
        
        // Try to read packet data
        match guard.try_io(|inner| {
            let fd = inner.get_ref().as_raw_fd();
            let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut addr_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            
            let len = unsafe {
                libc::recvfrom(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    &mut addr as *mut _ as *mut libc::sockaddr,
                    &mut addr_len,
                )
            };
            
            if len < 0 {
                return Err(std::io::Error::last_os_error());
            }
            
            // Validate packet size
            if len > MAX_PACKET_SIZE as isize {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData, 
                    format!("Packet too large: {} bytes", len)
                ));
            }
            
            Ok((len as usize, addr))
        }) {
            Ok(Ok((len, addr))) => {
                // Check packet type - we're specifically looking for outgoing packets
                let packet_type = addr.sll_pkttype;
                debug!("Received {} bytes, packet type: {}", len, packet_type);
                
                // PACKET_OUTGOING = 4, PACKET_HOST = 0
                // We want outgoing packets (type 4) from our interface
                if packet_type == 4 { // PACKET_OUTGOING
                    debug!("Processing outgoing packet ({} bytes)", len);
                    
                    // Use improved pnet-based NS packet validation
                    if let Some((source_mac, target)) = ndp::validate_outgoing_ns_packet(&buf[..len]) {
                        let state_guard = state.lock().await;
                        
                        // Compare source MAC address with master interface MAC address
                        if source_mac == state_guard.master_mac {
                            // Validate target address
                            if target.is_multicast() {
                                debug!("Ignoring NS packet for multicast target {}", target);
                            } else if target.is_loopback() {
                                debug!("Ignoring NS packet for loopback target {}", target);
                            } else if target.is_unspecified() {
                                debug!("Ignoring NS packet for unspecified target {}", target);
                            } else {
                                // This is a valid outgoing NS packet from our interface - promote to INFO level
                                info!("📡 Detected outgoing NS packet from {} for target {} - forwarding to slave interfaces", 
                                      source_mac, target);
                                
                                drop(state_guard); // Release lock before async call
                                handle_ns_packet(&target, state.clone()).await?;
                            }
                        } else {
                            debug!("Ignoring outgoing NS packet from different MAC {} (expected {})", 
                                   source_mac, state_guard.master_mac);
                        }
                    } else {
                        debug!("Outgoing packet is not a valid NS packet");
                    }
                } else {
                    debug!("Ignoring packet type {} (not outgoing)", packet_type);
                }
            },
            Ok(Err(e)) => {
                error!("Error receiving packet: {}", e);
                // Exponential backoff to avoid spinning on persistent errors
                sleep(Duration::from_millis(100)).await;
            },
            Err(_would_block) => {
                // Socket is temporarily unreadable, wait for it to become ready again
                continue;
            }
        }
    }
}

async fn handle_ns_packet(target: &Ipv6Addr, state: Arc<Mutex<AppState>>) -> Result<()> {
    // Clone slaves list to avoid holding lock during ping operations
    let (slaves, ns_count) = {
        let mut state_guard = state.lock().await;
        state_guard.ns_counter += 1;
        let ns_count = state_guard.ns_counter;
        let slaves = state_guard.slaves.clone();
        (slaves, ns_count)
    };
    
    info!("🔄 Processing NS packet #{} for target {} - forwarding to {} slave interface(s)", 
          ns_count, target, slaves.len());

    // Send ping6 to each slave interface without holding the lock
    let mut ping_counter_increment = 0;
    let mut successful_forwards = Vec::new();
    let mut failed_forwards = Vec::new();

    for slave in &slaves {
        match ping::send_ping6(slave, target) {
            Ok(_) => {
                ping_counter_increment += 1;
                successful_forwards.push(slave.clone());
                debug!("✅ Sent ping6 to {} on interface {}", target, slave);
            }
            Err(e) => {
                failed_forwards.push((slave.clone(), e.to_string()));
                error!("❌ Failed to send ping6 on {}: {}", slave, e);
            }
        }
    }

    // Log summary of forwarding results
    if !successful_forwards.is_empty() {
        info!("✅ Successfully forwarded ping6 to {} interface(s): {}", 
              successful_forwards.len(), successful_forwards.join(", "));
    }
    if !failed_forwards.is_empty() {
        warn!("⚠️  Failed to forward ping6 to {} interface(s): {}", 
              failed_forwards.len(), 
              failed_forwards.iter().map(|(iface, _)| iface.as_str()).collect::<Vec<_>>().join(", "));
    }

    // Update ping counter after all operations
    {
        let mut state_guard = state.lock().await;
        state_guard.ping_counter += ping_counter_increment;
        let total_pings = state_guard.ping_counter;
        info!("📊 Statistics - Total NS packets: {}, Total successful pings: {}", 
              state_guard.ns_counter, total_pings);
    }

    Ok(())
}
