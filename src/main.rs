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

    // Get master interface MAC address for source filtering
    let master_mac = interface::get_interface_mac(&args.master)?;
    info!("Master interface MAC address: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
          master_mac[0], master_mac[1], master_mac[2], master_mac[3], master_mac[4], master_mac[5]);

    // Create shared state
    let state = Arc::new(Mutex::new(AppState {
        master: args.master.clone(),
        slaves: args.slaves.clone(),
        master_mac,
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
    master_mac: [u8; 6],
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

/// 生成仅允许 ICMPv6 Neighbor Solicitation 的 BPF 字节码数组
fn create_ns_filter() -> Vec<libc::sock_filter> {
    vec![
        libc::sock_filter { code: 0x30, jt: 0, jf: 0, k: 6 },
        libc::sock_filter { code: 0x15, jt: 0, jf: 5, k: 58 },
        libc::sock_filter { code: 0x30, jt: 0, jf: 0, k: 40 },
        libc::sock_filter { code: 0x15, jt: 0, jf: 3, k: 135 },
        libc::sock_filter { code: 0x6, jt: 0, jf: 0, k: 0xffff_ffff },
        libc::sock_filter { code: 0x6, jt: 0, jf: 0, k: 0 },
    ]
}

fn setup_ns_monitor_socket(interface: &str) -> Result<Socket> {
    // Create packet socket to capture ethernet frames
    let socket = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(libc::ETH_P_IPV6)))?;

    // Set socket options
    socket.set_nonblocking(true)?;

    // Bind to the interface
    let if_index = nix::net::if_::if_nametoindex(interface)
        .context("Failed to get interface index")?;

    // Bind to interface
    let sll = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (libc::ETH_P_IPV6 as u16).to_be(),
        sll_ifindex: if_index as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };

    unsafe {
        let ret = libc::bind(
            socket.as_raw_fd(),
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        );

        if ret < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }

    // Apply BPF filter for NS packets only
    let filter = create_ns_filter();
    socket.attach_filter(&filter)?;
    
    Ok(socket)
}

async fn monitor_ns_packets(socket: Socket, state: Arc<Mutex<AppState>>) -> Result<()> {
    // 使用AsyncFd包装原始套接字，而不是转换为UdpSocket
    let async_fd = tokio::io::unix::AsyncFd::new(socket)?;
    
    // 接收缓冲区
    let mut buf = [0u8; 1500];
    
    loop {
        // 等待套接字可读
        let mut guard = async_fd.readable().await?;
        
        // 尝试读取数据包
        match guard.try_io(|inner| {
            let fd = inner.get_ref().as_raw_fd();
            let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            
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
            
            Ok(len as usize)
        }) {
            Ok(Ok(len)) => {
                debug!("Received {} bytes", len);
                
                // 解析包含以太网头部的NS数据包
                if let Some((source_mac, target)) = ndp::parse_ethernet_ns_packet(&buf[..len]) {
                    let state_guard = state.lock().await;
                    
                    // 比较源MAC地址与master接口的MAC地址
                    if source_mac == state_guard.master_mac {
                        debug!("Outgoing NS packet from our MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} for target {}",
                               source_mac[0], source_mac[1], source_mac[2], 
                               source_mac[3], source_mac[4], source_mac[5], target);
                        
                        drop(state_guard); // 在异步调用前释放锁
                        handle_ns_packet(&target, state.clone()).await?;
                    } else {
                        debug!("Ignoring NS packet from MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                               source_mac[0], source_mac[1], source_mac[2], 
                               source_mac[3], source_mac[4], source_mac[5]);
                    }
                }
            },
            Ok(Err(e)) => {
                error!("Error receiving packet: {}", e);
                sleep(Duration::from_millis(100)).await;
            },
            Err(_would_block) => {
                // 套接字暂时不可读，继续等待
                continue;
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