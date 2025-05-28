// 标准库导入
use std::mem::MaybeUninit;
use std::net::Ipv6Addr;
use std::os::fd::AsRawFd;
use std::sync::Arc;

// 日志相关导入
use log::{debug, error, info, warn};

// CLI 解析相关导入
use clap::Parser;

// 错误处理相关导入
use anyhow::{Context, Result};

// 网络协议相关导入
use pnet::datalink::MacAddr;
use pnet::packet::{
    Packet,
    ethernet::{EtherTypes, EthernetPacket},
    icmpv6::{Icmpv6Packet, Icmpv6Types},
    ip::IpNextHeaderProtocols,
    ipv6::Ipv6Packet,
};

// 套接字相关导入
use socket2::{Domain, Protocol, Socket, Type};

// 异步任务和信号处理相关导入
use tokio::signal;
use tokio::sync::Mutex;

mod bpf;
mod interface;
mod ping;

#[derive(Parser, Debug)]
#[clap(
    author,
    version,
    about = "IPv6 Neighbor Solicitation monitor and ping6 forwarder"
)]
#[clap(
    long_about = "NS-Monitor listens for outgoing IPv6 Neighbor Solicitation packets on a master interface and forwards ping6 requests to configured slave interfaces to help with IPv6 neighbor discovery across multiple network interfaces."
)]
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

    info!(
        "Starting outbound NS monitor on {} and forwarding to {:?}",
        args.master, args.slaves
    );

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
    let socket =
        setup_ns_monitor_socket(&args.master).context("Failed to setup NS monitor socket")?;

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
    let socket = Socket::new(
        Domain::PACKET,
        Type::RAW,
        Some(Protocol::from(libc::ETH_P_ALL)),
    )
    .context("Failed to create packet socket")?;
    debug!("Successfully created packet socket");

    // Set socket options
    socket
        .set_nonblocking(true)
        .context("Failed to set socket non-blocking")?;
    debug!("Set socket to non-blocking mode");

    // Bind to the interface
    let if_index =
        nix::net::if_::if_nametoindex(interface).context("Failed to get interface index")?;
    debug!("Interface {} has index: {}", interface, if_index);

    // Bind to interface - use ETH_P_ALL to catch all packets including outgoing
    let sll = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
        sll_ifindex: if_index as i32,
        sll_hatype: 0,
        sll_pkttype: 0, // Accept all packet types (incoming and outgoing)
        sll_halen: 0,
        sll_addr: [0; 8],
    };

    debug!(
        "Binding socket to interface {} (index: {})",
        interface, if_index
    );
    debug!(
        "sockaddr_ll: family={}, protocol={}, ifindex={}",
        sll.sll_family,
        u16::from_be(sll.sll_protocol),
        sll.sll_ifindex
    );

    unsafe {
        let ret = libc::bind(
            socket.as_raw_fd(),
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        );

        if ret < 0 {
            let error = std::io::Error::last_os_error();
            error!(
                "Failed to bind socket to interface {}: {}",
                interface, error
            );
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

/// 接收并处理网络数据包
async fn monitor_ns_packets(socket: Socket, state: Arc<Mutex<AppState>>) -> Result<()> {
    let mut buf = [MaybeUninit::zeroed(); 1500]; // 标准以太网 MTU

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received SIGINT, shutting down gracefully");
                return Ok(());
            }
            result = async {
                let Ok(len) = socket.recv(&mut buf) else {
                    return Ok::<(), anyhow::Error>(());
                };
                debug!("Received packet of {} bytes", len);

                let buf_slice = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, len) };

                // 解析以太网帧
                if let Some(ethernet_packet) = EthernetPacket::new(buf_slice) {
                    if ethernet_packet.get_source() != state.lock().await.master_mac {
                        debug!("Ignoring packet from non-master MAC: {}", ethernet_packet.get_source());
                        return Ok(());
                    }

                    if ethernet_packet.get_ethertype() != EtherTypes::Ipv6 {
                        debug!("Ignoring non-IPv6 packet");
                        return Ok(());
                    }

                    // 解析 IPv6 数据包
                    if let Some(ipv6_packet) = Ipv6Packet::new(ethernet_packet.payload()) {
                        if ipv6_packet.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
                            debug!("Ignoring non-ICMPv6 packet");
                            return Ok(());
                        }

                        // 解析 ICMPv6 数据包
                        if let Some(icmpv6_packet) = Icmpv6Packet::new(ipv6_packet.payload()) {
                            if icmpv6_packet.get_icmpv6_type() == Icmpv6Types::NeighborSolicit {
                                debug!("Detected Neighbor Solicitation packet");

                                // 提取目标地址
                                let target = extract_target_address(&icmpv6_packet)?;
                                handle_ns_packet(&target, state.clone()).await?;
                            } else {
                                debug!("Ignoring non-NS ICMPv6 packet");
                            }
                        } else {
                            debug!("Invalid ICMPv6 packet");
                        }
                    } else {
                        debug!("Invalid IPv6 packet");
                    }
                } else {
                    debug!("Invalid Ethernet packet");
                }
                Ok(())
            } => {
                if let Err(e) = result {
                    error!("Error processing packet: {}", e);
                }
            }
        }
    }
}

/// 提取 Neighbor Solicitation 数据包的目标地址
fn extract_target_address(icmpv6_packet: &Icmpv6Packet) -> Result<Ipv6Addr> {
    // 这里可以进一步解析 ICMPv6 数据包的内容
    // 假设目标地址存储在固定的偏移量处
    let payload = icmpv6_packet.payload();
    if payload.len() >= 16 {
        let target_bytes: [u8; 16] = payload[..16].try_into()?;
        Ok(Ipv6Addr::from(target_bytes))
    } else {
        Err(anyhow::anyhow!("Invalid NS packet payload"))
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

    info!(
        "🔄 Processing NS packet #{} for target {} - forwarding to {} slave interface(s)",
        ns_count,
        target,
        slaves.len()
    );

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
        info!(
            "✅ Successfully forwarded ping6 to {} interface(s): {}",
            successful_forwards.len(),
            successful_forwards.join(", ")
        );
    }
    if !failed_forwards.is_empty() {
        warn!(
            "⚠️  Failed to forward ping6 to {} interface(s): {}",
            failed_forwards.len(),
            failed_forwards
                .iter()
                .map(|(iface, _)| iface.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Update ping counter after all operations
    {
        let mut state_guard = state.lock().await;
        state_guard.ping_counter += ping_counter_increment;
        let total_pings = state_guard.ping_counter;
        info!(
            "📊 Statistics - Total NS packets: {}, Total successful pings: {}",
            state_guard.ns_counter, total_pings
        );
    }

    Ok(())
}
