# NS-Monitor 技术报告

*作者: CalunVier*  
*日期: 2025-05-26*

## 1. 背景与目标

### 1.1 IPv6邻居发现协议概述

IPv6邻居发现协议(NDP)是IPv6协议栈中的一个核心组件，它替代了IPv4中的ARP协议，负责处理链路层地址解析、下一跳确定、前缀发现等功能。NDP依赖于ICMPv6消息，其中Neighbor Solicitation(NS)和Neighbor Advertisement(NA)消息对用于地址解析。

当IPv6节点需要发送数据包到某个目标地址时，它首先需要确定该地址对应的链路层(如MAC)地址。这时节点会发送一个NS消息，询问"谁拥有这个IPv6地址"。拥有该地址的节点则通过NA消息回应。

### 1.2 多网卡环境中的问题

在多网卡环境中，当一个网卡发出NS请求时，其他网卡并不会自动知道这一请求。这导致了一个常见问题：虽然一个设备通过多个网卡连接到相同或不同的网络，但某个网卡上的邻居发现不会传播到其他网卡。

这在如下场景中尤为明显：
- 路由器/防火墙设备需要在多个网络接口间转发流量
- 代理服务器连接到多个网络
- 网络虚拟化环境中的虚拟网卡

### 1.3 NS-Monitor的目标

NS-Monitor旨在解决上述问题，通过：
1. 监听从master网卡发出的NS请求
2. 在配置的slave网卡上发送ping6请求，促使Linux内核建立相应的邻居表项
3. 使用高效的实现，最小化资源消耗

## 2. 技术实现

### 2.1 系统架构

NS-Monitor采用模块化设计，主要包含以下组件：

1. **原始套接字监听器**：捕获和过滤ICMPv6 NS数据包
2. **数据包解析器**：提取NS数据包中的源地址和目标地址
3. **地址过滤器**：确定NS是否来自本机
4. **转发执行器**：向slave接口发送ping6请求
5. **命令行界面**：提供用户友好的配置接口

![系统架构图](https://via.placeholder.com/800x400?text=NS-Monitor+Architecture)

### 2.2 关键技术

#### 2.2.1 原始套接字与BPF过滤器

为高效捕获NS数据包，NS-Monitor使用原始套接字配合BPF(Berkeley Packet Filter)过滤器：

```rust
fn setup_ns_monitor_socket(interface: &str) -> Result<Socket> {
    // 创建原始ICMPv6套接字
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
        .context("Failed to create raw socket")?;
    
    // 设置非阻塞模式
    socket.set_nonblocking(true)?;
    
    // 绑定到指定接口
    socket.bind_device(Some(interface.as_bytes()))?;
    
    // 应用BPF过滤器
    let filter = bpf::create_ns_filter()?;
    socket.attach_filter(&filter)?;
    
    // 加入全节点多播组
    let all_nodes = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    join_multicast_group(&socket, &all_nodes, if_index as u32)?;
    
    Ok(socket)
}
```

BPF过滤器配置为只通过ICMPv6类型为135(Neighbor Solicitation)的数据包，这样大大减少了需要在用户空间处理的数据包数量：

```rust
pub fn create_ns_filter() -> Result<Vec<BpfInsn>> {
    let filter = vec![
        // 检查IPv6版本
        BpfInsn::new(libc::BPF_LD as u16 | libc::BPF_B as u16 | libc::BPF_ABS as u16, 0, 0, 0),
        BpfInsn::new(libc::BPF_ALU as u16 | libc::BPF_AND as u16 | libc::BPF_K as u16, 0, 0, 0xf0),
        BpfInsn::new(libc::BPF_JMP as u16 | libc::BPF_JEQ as u16 | libc::BPF_K as u16, 0, 5, 0x60),
        
        // 检查下一个头部是否为ICMPv6
        BpfInsn::new(libc::BPF_LD as u16 | libc::BPF_B as u16 | libc::BPF_ABS as u16, 0, 0, 6),
        BpfInsn::new(libc::BPF_JMP as u16 | libc::BPF_JEQ as u16 | libc::BPF_K as u16, 0, 3, IPPROTO_ICMPV6 as u32),
        
        // 检查ICMPv6类型是否为NS
        BpfInsn::new(libc::BPF_LD as u16 | libc::BPF_B as u16 | libc::BPF_ABS as u16, 0, 0, 40),
        BpfInsn::new(libc::BPF_JMP as u16 | libc::BPF_JEQ as u16 | libc::BPF_K as u16, 0, 1, ND_NEIGHBOR_SOLICIT as u32),
        
        // 返回值
        BpfInsn::new(libc::BPF_RET as u16 | libc::BPF_K as u16, 0, 0, 0xffffffff),
        BpfInsn::new(libc::BPF_RET as u16 | libc::BPF_K as u16, 0, 0, 0),
    ];
    
    Ok(filter)
}
```

#### 2.2.2 本地源地址过滤

NS-Monitor需要精确识别从本机发出的NS请求，而不是其他设备发送的请求。为此，程序在启动时获取master接口的所有IPv6地址，并用于过滤接收到的NS数据包：

```rust
// 获取接口的IPv6地址
let local_addrs = interface::get_interface_addresses(&args.master)?;

// 解析NS数据包并检查源地址
if let Some((source, target)) = ndp::parse_ns_packet_with_source(&buf[..len]) {
    // 只处理从本机地址发出的NS数据包
    if state_guard.local_addrs.contains(&source) {
        handle_ns_packet(&target, state.clone()).await?;
    }
}
```

#### 2.2.3 异步事件驱动架构

NS-Monitor使用Tokio提供异步运行时，实现高效的事件驱动架构，避免在I/O操作上阻塞：

```rust
#[tokio::main]
async fn main() -> Result<()> {
    // ...初始化代码...
    
    // 异步监听循环
    monitor_ns_packets(socket, state).await
}

async fn monitor_ns_packets(socket: Socket, state: Arc<Mutex<AppState>>) -> Result<()> {
    let socket = tokio::net::UdpSocket::from_std(socket.into())?;
    
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                // 异步处理数据包
                // ...
            }
            Err(e) => {
                // 错误处理
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
```

### 2.3 数据包解析

NS数据包解析是程序的核心功能，需要从原始数据包中提取IPv6源地址和目标地址：

```rust
pub fn parse_ns_packet_with_source(packet: &[u8]) -> Option<(Ipv6Addr, Ipv6Addr)> {
    // 检查数据包长度
    if packet.len() < IPV6_HEADER_SIZE + ND_NS_TARGET_OFFSET + 16 {
        return None;
    }
    
    // 验证IPv6版本
    if (packet[0] >> 4) != 6 {
        return None;
    }
    
    // 检查下一个头部是否为ICMPv6
    if packet[6] != 58 {
        return None;
    }
    
    // 提取IPv6源地址
    let src_addr_bytes = &packet[IPV6_SRC_ADDR_OFFSET..IPV6_SRC_ADDR_OFFSET + 16];
    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(src_addr_bytes);
    let src_addr = Ipv6Addr::from(src_bytes);
    
    // 检查ICMPv6类型是否为NS
    let icmpv6_data = &packet[IPV6_HEADER_SIZE..];
    if icmpv6_data[ICMPV6_TYPE_OFFSET] != ND_NEIGHBOR_SOLICIT || 
       icmpv6_data[ICMPV6_CODE_OFFSET] != 0 {
        return None;
    }
    
    // 提取目标地址
    let target_bytes = &icmpv6_data[ND_NS_TARGET_OFFSET..ND_NS_TARGET_OFFSET + 16];
    let mut tgt_bytes = [0u8; 16];
    tgt_bytes.copy_from_slice(target_bytes);
    let target_addr = Ipv6Addr::from(tgt_bytes);
    
    Some((src_addr, target_addr))
}
```

### 2.4 Ping6转发

检测到来自本机的NS请求后，程序会向所有配置的slave接口发送ping6请求：

```rust
pub fn send_ping6(interface: &str, target: &Ipv6Addr) -> Result<()> {
    // 格式化地址
    let addr_str = format!("{}", target);
    
    // 使用ping6命令发送单个数据包
    let status = Command::new("ping6")
        .args(["-c", "1", "-W", "1", "-I", interface, &addr_str])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("Failed to execute ping6 command")?;
    
    if !status.success() {
        anyhow::bail!("ping6 command failed with status: {}", status);
    }
    
    Ok(())
}
```

## 3. 性能考虑

### 3.1 内核级过滤

使用BPF过滤器在内核级别过滤数据包是NS-Monitor的关键性能优化。这大大减少了需要在用户空间处理的数据包数量，降低CPU使用率和上下文切换开销。

### 3.2 内存使用

NS-Monitor的内存占用非常小：
- 只维护必要的状态(本地地址列表、计数器等)
- 使用固定大小的缓冲区接收数据包
- 没有复杂的数据结构

### 3.3 CPU使用率

程序设计中的多项因素有助于保持低CPU使用率：
- 事件驱动架构避免忙等待
- 精确的BPF过滤减少处理的数据包数量
- 最小化数据包解析，只提取必要信息

## 4. 与其他工具的比较

### 4.1 odhcpd

OpenWrt的odhcpd实现了类似的功能，但NS-Monitor与它相比有几个不同点：

| 特性 | NS-Monitor | odhcpd |
|------|------------|--------|
| 专注功能 | 只监听NS数据包并转发ping6 | 完整的DHCP/RA/NDP服务器 |
| 资源使用 | 轻量级，最小依赖 | 相对较重，功能更多 |
| 配置简便性 | 简单的命令行接口 | 需要更复杂的配置 |
| 跨平台性 | 可在各种Linux系统上运行 | 主要针对OpenWrt优化 |

### 4.2 ndppd

ndppd是另一个提供NDP代理功能的工具：

| 特性 | NS-Monitor | ndppd |
|------|------------|-------|
| 工作方式 | 监听本机发出的NS并在其他接口发送ping6 | 完整的NDP代理，重写数据包 |
| 复杂性 | 简单，单一功能 | 更复杂，配置更灵活 |
| 需要内核支持 | 不需要特殊内核选项 | 可能需要开启内核NDP代理支持 |

## 5. 未来改进方向

### 5.1 直接发送ICMPv6数据包

目前NS-Monitor使用系统的ping6命令发送请求，未来可以实现直接构造和发送ICMPv6数据包，减少fork进程的开销。

### 5.2 更智能的转发策略

可以实现更智能的转发策略，例如：
- 基于目标地址前缀的选择性转发
- 根据接口配置的子网自动决定是否转发
- 支持IPv6地址过滤规则

### 5.3 监控和统计

添加更详细的监控和统计功能，如：
- 接口级别的数据包计数
- 周期性报告和状态导出
- 与监控系统集成的指标输出

### 5.4 配置文件支持

除命令行选项外，添加配置文件支持，允许更复杂的设置。

## 6. 结论

NS-Monitor提供了一个轻量级解决方案，用于解决多网卡环境中IPv6邻居发现的传播问题。它采用与odhcpd类似的技术原理，但更专注于单一功能，使其更易于理解和部署。

通过高效的实现和精确的过滤，NS-Monitor在资源有限的设备上也能表现良好。它的简单命令行接口使其易于集成到各种网络环境中。

虽然还有改进空间，但NS-Monitor已经是一个实用的工具，可以解决特定的IPv6网络挑战。

## 参考资料

1. RFC 4861 - Neighbor Discovery for IP version 6 (IPv6)
2. RFC 4862 - IPv6 Stateless Address Autoconfiguration
3. Berkeley Packet Filter (BPF) documentation
4. odhcpd source code: https://git.openwrt.org/project/odhcpd.git
5. Rust socket2 crate documentation: https://docs.rs/socket2/