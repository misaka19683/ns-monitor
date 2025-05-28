# NS-Monitor

[English](README.md) | [简体中文](README_ZH.md)

A high-efficiency IPv6 Neighbor Solicitation monitoring and forwarding tool.

## Overview

NS-Monitor is a lightweight tool designed to:

- Listen for IPv6 Neighbor Solicitation packets sent from a specified master network interface
- Send ping6 requests via configured slave interfaces to help the Linux kernel discover routes
- Utilize efficient raw sockets and BPF filters

This tool solves the problem where IPv6 neighbor discovery cannot propagate across interfaces in multi-NIC environments. It is especially suitable for routers, proxy servers, and other multi-interface devices.

## Installation

### Build from Source

Ensure you have the Rust toolchain and necessary dependencies installed:

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone the repository
git clone https://github.com/CalunVier/ns-monitor.git
cd ns-monitor

# Build
cargo build --release

# Or build with musl
target
cargo build --release --target x86_64-unknown-linux-musl

# Install (optional)
sudo cp target/release/ns-monitor /usr/local/bin/
```

### Dependencies

- Rust 1.56.0+
- libc6-dev
- ip command-line tool

On Debian/Ubuntu systems, install dependencies with:

```bash
sudo apt install libc6-dev
```

## Usage

NS-Monitor requires root privileges to create raw sockets:

```bash
sudo ns-monitor -m <master interface> -s <slave1>,<slave2>,...
```

### Command Line Options

```
Options:
  -m, --master <INTERFACE>     Specify the master interface to listen for NS packets
  -s, --slaves <INTERFACES>    Specify slave interfaces to send ping6 (comma-separated)
  -l, --log-level <LEVEL>      Log level [default: info] [options: error, warn, info, debug, trace]
  -d, --daemon                 Run as a daemon
  -h, --help                   Show help
  -V, --version                Show version
```

### Examples

```bash
# Listen for NS packets on eth0 and send ping6 via eth1 and eth2
sudo ns-monitor -m eth0 -s eth1,eth2

# Run as a daemon with debug log level
sudo ns-monitor -m eth0 -s eth1,eth2 -l debug -d
```

## How It Works

NS-Monitor uses raw sockets to capture IPv6 Neighbor Solicitation packets and applies BPF filters for efficiency. When a local NS request is detected on the master interface, the program sends ping6 requests via all configured slave interfaces to help the Linux kernel discover routes to the target address on those interfaces.

## License

MIT License

## Author

CalunVier (https://github.com/CalunVier)

## Contributing

Issues and Pull Requests are welcome!
