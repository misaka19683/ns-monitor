use std::net::Ipv6Addr;
use std::process::Command;
use anyhow::{Context, Result};

/// Send a ping6 packet to the specified address on the given interface
pub fn send_ping6(interface: &str, target: &Ipv6Addr) -> Result<()> {
    // Format the address for ping6
    let addr_str = format!("{}", target);

    // Use the ping6 command to send a single packet
    // -c 1: send just one packet
    // -W 1: wait at most 1 second for a reply
    // -I: specify the interface
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