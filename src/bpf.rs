use anyhow::{Result, Context};
use std::os::unix::io::AsRawFd;

/// 生成仅允许 ICMPv6 Neighbor Solicitation 的 BPF 字节码数组
pub fn create_ns_filter() -> Vec<libc::sock_filter> {
    vec![
        libc::sock_filter { code: 0x30, jt: 0, jf: 0, k: 6 },
        libc::sock_filter { code: 0x15, jt: 0, jf: 5, k: 58 },
        libc::sock_filter { code: 0x30, jt: 0, jf: 0, k: 40 },
        libc::sock_filter { code: 0x15, jt: 0, jf: 3, k: 135 },
        libc::sock_filter { code: 0x6, jt: 0, jf: 0, k: 0xffff_ffff },
        libc::sock_filter { code: 0x6, jt: 0, jf: 0, k: 0 },
    ]
}

pub trait AttachBpf {
    fn attach_filter(&self, filter: &mut [libc::sock_filter]) -> Result<()>;
}

impl<T: AsRawFd> AttachBpf for T {
    fn attach_filter(&self, filter: &mut [libc::sock_filter]) -> Result<()> {
        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(), // <--- 这里要用 as_mut_ptr()
        };
        let ret = unsafe {
            libc::setsockopt(
                self.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &prog as *const _ as *const libc::c_void,
                size_of::<libc::sock_fprog>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            Err(std::io::Error::last_os_error())
                .context("setsockopt SO_ATTACH_FILTER failed")
        } else {
            Ok(())
        }
    }
}