use std::net::Ipv6Addr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use std::collections::HashSet;
use std::os::fd::AsRawFd;
use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, error, info};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::Mutex;
use tokio::time::sleep;

mod bpf;
mod ndp;
mod ping;
mod interface;


#[derive(Parser, Debug)]
#[clap(author, version, about = "NS monitor and ping6 forwarder")]
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

    // Get interface local addresses for source filtering
    let local_addrs = interface::get_interface_addresses(&args.master)?;
    info!("Local addresses on {}: {:?}", args.master, local_addrs);

    // Create shared state
    let state = Arc::new(Mutex::new(AppState {
        master: args.master.clone(),
        slaves: args.slaves.clone(),
        local_addrs,
        ns_counter: 0,
        ping_counter: 0,
    }));

    // Setup socket for monitoring NS packets
    let socket = setup_ns_monitor_socket(&args.master)
        .context("Failed to setup NS monitor socket")?;

    // Start the main monitoring loop
    monitor_ns_packets(socket, state).await
}

struct AppState {
    master: String,
    slaves: Vec<String>,
    local_addrs: HashSet<Ipv6Addr>,
    ns_counter: u64,
    ping_counter: u64,
}

fn validate_interface(interface: &str) -> Result<()> {
    let output = Command::new("ip")
        .args(["link", "show", interface])
        .output()
        .context("Failed to execute ip command")?;

    if !output.status.success() {
        anyhow::bail!("Interface {} does not exist", interface);
    }

    Ok(())
}

fn setup_ns_monitor_socket(interface: &str) -> Result<Socket> {
    // Create raw ICMPv6 socket
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
        .context("Failed to create raw socket")?;

    // Set socket options
    socket.set_nonblocking(true)?;

    // Bind to the interface
    let if_index = nix::net::if_::if_nametoindex(interface)
        .context("Failed to get interface index")?;

    socket.bind_device(Some(interface.as_bytes()))?;

    // Apply BPF filter for NS packets only
    let filter = bpf::create_ns_filter();
    socket.attach_filter(&filter)?;


    // Join all-nodes multicast group (ff02::1) to receive NS packets
    let all_nodes = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    join_multicast_group(&socket, &all_nodes, if_index as u32)?;

    Ok(socket)
}

fn join_multicast_group(socket: &Socket, addr: &Ipv6Addr, if_index: u32) -> Result<()> {
    let mreq = libc::ipv6_mreq {
        ipv6mr_multiaddr: ipv6_addr_to_libc(addr),
        ipv6mr_interface: if_index,
    };

    unsafe {
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_ADD_MEMBERSHIP,
            &mreq as *const _ as *const libc::c_void,
            size_of::<libc::ipv6_mreq>() as libc::socklen_t,
        );

        if ret < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }

    Ok(())
}

fn ipv6_addr_to_libc(addr: &Ipv6Addr) -> libc::in6_addr {
    let segments = addr.segments();
    let mut bytes = [0u8; 16];

    for i in 0..8 {
        bytes[i*2] = (segments[i] >> 8) as u8;
        bytes[i*2+1] = segments[i] as u8;
    }

    libc::in6_addr { s6_addr: bytes }
}

async fn monitor_ns_packets(socket: Socket, state: Arc<Mutex<AppState>>) -> Result<()> {
    // Convert to tokio socket
    let socket = tokio::net::UdpSocket::from_std(socket.into())
        .context("Failed to convert socket to tokio socket")?;

    // Buffer for receiving packets
    let mut buf = [0u8; 1500];

    loop {
        // Receive packet
        match socket.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                debug!("Received {} bytes from {}", len, addr);

                // Parse NS packet and check if it's from our local address
                if let Some((source, target)) = ndp::parse_ns_packet_with_source(&buf[..len]) {
                    let state_guard = state.lock().await;

                    // Only process packets from our local addresses
                    if state_guard.local_addrs.contains(&source) {
                        debug!("Outgoing NS packet from {} to {}", source, target);
                        drop(state_guard); // Release lock before async call
                        handle_ns_packet(&target, state.clone()).await?;
                    } else {
                        debug!("Ignoring NS packet from non-local address: {}", source);
                    }
                }
            }
            Err(e) => {
                error!("Error receiving packet: {}", e);
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle_ns_packet(target: &Ipv6Addr, state: Arc<Mutex<AppState>>) -> Result<()> {
    let mut state_guard = state.lock().await;
    state_guard.ns_counter += 1;

    info!("Outgoing NS packet for target {}", target);

    // Send ping6 to each slave interface
    let mut ping_counter_increment = 0;

    for slave in &state_guard.slaves {
        match ping::send_ping6(slave, target) {
            Ok(_) => {
                ping_counter_increment += 1;
                info!("Sent ping6 to {} on interface {}", target, slave);
            }
            Err(e) => {
                error!("Failed to send ping6 on {}: {}", slave, e);
            }
        }
    }

    state_guard.ping_counter += ping_counter_increment;

    Ok(())
}