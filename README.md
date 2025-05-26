# NS-Monitor

一个高效的IPv6 Neighbor Solicitation监听和转发工具。

## 功能概述

NS-Monitor是一个轻量级工具，用于：

- 监听指定master网卡发出的IPv6 Neighbor Solicitation数据包
- 向配置的slave网卡发送ping6请求，帮助Linux内核发现路由
- 使用高效的原始套接字和BPF过滤器实现

这个工具可以解决多网卡环境下IPv6邻居发现无法跨网卡传播的问题，特别适用于路由器、代理服务器等多网卡设备。

## 安装

### 从源码编译

确保已安装Rust工具链和必要的依赖：

```bash
# 安装Rust (如果尚未安装)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 克隆仓库
git clone https://github.com/CalunVier/ns-monitor.git
cd ns-monitor

# 编译
cargo build --release

# 安装 (可选)
sudo cp target/release/ns-monitor /usr/local/bin/
```

### 依赖项

- Rust 1.56.0+
- libpcap-dev
- libc6-dev

在Debian/Ubuntu系统上安装依赖：

```bash
sudo apt install libpcap-dev libc6-dev
```

## 使用方法

NS-Monitor需要root权限才能创建原始套接字：

```bash
sudo ns-monitor -m <master接口> -s <slave接口1>,<slave接口2>,...
```

### 命令行参数

```
选项:
  -m, --master <INTERFACE>     指定要监听NS包的master网卡
  -s, --slaves <INTERFACES>    指定要发送ping6的slave网卡(以逗号分隔)
  -l, --log-level <LEVEL>      日志级别 [默认: info] [可选: error, warn, info, debug, trace]
  -d, --daemon                 以守护进程模式运行
  -h, --help                   显示帮助信息
  -V, --version                显示版本信息
```

### 示例

```bash
# 监听eth0上发出的NS数据包，向eth1和eth2发送ping6
sudo ns-monitor -m eth0 -s eth1,eth2

# 以守护进程模式运行，并设置详细日志
sudo ns-monitor -m eth0 -s eth1,eth2 -l debug -d
```

## 工作原理

NS-Monitor使用原始套接字捕获IPv6 Neighbor Solicitation数据包，并通过BPF过滤器高效过滤。当检测到本机通过master接口发出NS请求时，程序会向所有配置的slave接口发送ping6请求，以帮助Linux内核在这些接口上发现目标地址的路由。

## 许可证

MIT License

## 作者

CalunVier (https://github.com/CalunVier)

## 贡献

欢迎提交问题和Pull Request！