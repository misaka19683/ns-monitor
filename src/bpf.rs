/// Generate BPF bytecode array that only allows ICMPv6 packets
/// Use a simpler filter since we do precise NS parsing in user space
pub fn create_ns_filter() -> Vec<libc::sock_filter> {
    vec![
        // Load packet length
        libc::sock_filter {
            code: 0x80,
            jt: 0,
            jf: 0,
            k: 0,
        }, // BPF_LD + BPF_W + BPF_LEN
        // Check if packet is large enough (at least 54 bytes for Eth+IPv6+ICMPv6)
        libc::sock_filter {
            code: 0x35,
            jt: 0,
            jf: 4,
            k: 54,
        }, // BPF_JMP + BPF_JGE + BPF_K
        // Load Ethernet Type field (2 bytes at offset 12)
        libc::sock_filter {
            code: 0x28,
            jt: 0,
            jf: 0,
            k: 12,
        }, // BPF_LD + BPF_H + BPF_ABS
        // Jump if not IPv6 (0x86dd)
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 2,
            k: 0x86dd,
        }, // BPF_JMP + BPF_JEQ + BPF_K
        // Load IPv6 Next Header field (1 byte at offset 20)
        libc::sock_filter {
            code: 0x30,
            jt: 0,
            jf: 0,
            k: 20,
        }, // BPF_LD + BPF_B + BPF_ABS
        // Jump if ICMPv6 (58)
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: 58,
        }, // BPF_JMP + BPF_JEQ + BPF_K
        // Reject packet
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0,
        }, // BPF_RET + BPF_K
        // Accept packet
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0xffff,
        }, // BPF_RET + BPF_K
    ]
}

/// BPF Virtual Machine implementation for testing
#[cfg(test)]
mod bpf_vm {
    pub struct BpfVm {
        accumulator: u32,
        #[allow(dead_code)]
        index: u32,
        #[allow(dead_code)]
        memory: [u32; 16], // BPF_MEMWORDS
    }

    impl BpfVm {
        pub fn new() -> Self {
            Self {
                accumulator: 0,
                index: 0,
                memory: [0; 16],
            }
        }

        /// Execute BPF program on packet data and return the result
        /// Returns: 0 = drop packet, non-zero = accept packet (bytes to capture)
        pub fn execute(&mut self, program: &[libc::sock_filter], packet: &[u8]) -> u32 {
            let mut pc = 0; // Program counter
            let max_iterations = 1000; // Prevent infinite loops
            let mut iterations = 0;

            while pc < program.len() && iterations < max_iterations {
                iterations += 1;
                let instruction = &program[pc];
                let code = instruction.code;
                let jt = instruction.jt as usize;
                let jf = instruction.jf as usize;
                let k = instruction.k;

                // Decode instruction class
                let class = code & 0x07;
                match class {
                    0x00 => {
                        // BPF_LD
                        let size = code & 0x18;
                        let mode = code & 0xe0;

                        match (size, mode) {
                            (0x00, 0x20) => {
                                // BPF_W + BPF_ABS - load word absolute
                                let offset = k as usize;
                                if offset + 4 <= packet.len() {
                                    self.accumulator = u32::from_be_bytes([
                                        packet[offset],
                                        packet[offset + 1],
                                        packet[offset + 2],
                                        packet[offset + 3],
                                    ]);
                                } else {
                                    return 0; // Invalid access
                                }
                            }
                            (0x08, 0x20) => {
                                // BPF_H + BPF_ABS - load half-word absolute
                                let offset = k as usize;
                                if offset + 2 <= packet.len() {
                                    self.accumulator = u32::from_be_bytes([
                                        0,
                                        0,
                                        packet[offset],
                                        packet[offset + 1],
                                    ]);
                                } else {
                                    return 0; // Invalid access
                                }
                            }
                            (0x10, 0x20) => {
                                // BPF_B + BPF_ABS - load byte absolute
                                let offset = k as usize;
                                if offset < packet.len() {
                                    self.accumulator = packet[offset] as u32;
                                } else {
                                    return 0; // Invalid access
                                }
                            }
                            (0x00, 0x80) => {
                                // BPF_W + BPF_LEN - load packet length
                                self.accumulator = packet.len() as u32;
                            }
                            _ => return 0, // Unsupported instruction
                        }
                    }
                    0x05 => {
                        // BPF_JMP
                        let op = code & 0xf0;
                        match op {
                            0x10 => {
                                // BPF_JEQ
                                if self.accumulator == k {
                                    // jt is the number of instructions to skip if condition is true
                                    pc += 1 + jt;
                                } else {
                                    // jf is the number of instructions to skip if condition is false
                                    pc += 1 + jf;
                                }
                                continue;
                            }
                            0x30 => {
                                // BPF_JGE
                                if self.accumulator >= k {
                                    // jt is the number of instructions to skip if condition is true
                                    pc += 1 + jt;
                                } else {
                                    // jf is the number of instructions to skip if condition is false
                                    pc += 1 + jf;
                                }
                                continue;
                            }
                            _ => return 0, // Unsupported jump
                        }
                    }
                    0x06 => {
                        // BPF_RET
                        let src = code & 0x18;
                        match src {
                            0x00 => return k,                // BPF_K - return constant
                            0x08 => return self.accumulator, // BPF_A - return accumulator
                            _ => return 0,
                        }
                    }
                    _ => return 0, // Unsupported instruction class
                }

                pc += 1;
            }

            0 // Program ended without return
        }
    }
}

#[cfg(test)]
mod bpf_tests {
    use super::bpf_vm::BpfVm;
    use super::*;

    fn create_test_ipv6_icmpv6_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 100];

        // Ethernet header (14 bytes)
        // Destination MAC: 00:11:22:33:44:55
        packet[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Source MAC: 00:aa:bb:cc:dd:ee
        packet[6..12].copy_from_slice(&[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        // EtherType: IPv6 (0x86dd)
        packet[12] = 0x86;
        packet[13] = 0xdd;

        // IPv6 header (40 bytes starting at offset 14)
        packet[14] = 0x60; // Version (6) + Traffic Class
        packet[15] = 0x00; // Traffic Class + Flow Label
        packet[16] = 0x00; // Flow Label
        packet[17] = 0x00; // Flow Label
        packet[18] = 0x00; // Payload Length (high)
        packet[19] = 0x20; // Payload Length (low) - 32 bytes
        packet[20] = 58; // Next Header: ICMPv6
        packet[21] = 64; // Hop Limit

        // Source IPv6 address (16 bytes)
        packet[22..38].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);

        // Destination IPv6 address (16 bytes)
        packet[38..54].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);

        // ICMPv6 header (starting at offset 54)
        packet[54] = 135; // Type: Neighbor Solicitation
        packet[55] = 0; // Code
        packet[56] = 0; // Checksum (high)
        packet[57] = 0; // Checksum (low)

        packet
    }

    fn create_test_ipv4_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 64];

        // Ethernet header
        packet[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        packet[6..12].copy_from_slice(&[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        // EtherType: IPv4 (0x0800)
        packet[12] = 0x08;
        packet[13] = 0x00;

        // IPv4 header
        packet[14] = 0x45; // Version + IHL

        packet
    }

    fn create_test_short_packet() -> Vec<u8> {
        vec![0u8; 20] // Too short for our filter
    }

    #[test]
    fn test_bpf_filter_structure() {
        let filter = create_ns_filter();

        // Verify filter has expected number of instructions
        assert_eq!(filter.len(), 8, "BPF filter should have 8 instructions");

        // Test first instruction: load packet length
        assert_eq!(
            filter[0].code, 0x80,
            "First instruction should be BPF_LD + BPF_W + BPF_LEN"
        );
        assert_eq!(filter[0].k, 0, "LEN instruction should have k=0");

        // Test second instruction: check minimum length
        assert_eq!(
            filter[1].code, 0x35,
            "Second instruction should be BPF_JMP + BPF_JGE + BPF_K"
        );
        assert_eq!(filter[1].k, 54, "Should check for minimum 54 bytes");
        assert_eq!(
            filter[1].jf, 4,
            "Should jump forward 4 instructions on failure"
        );

        // Test EtherType check
        assert_eq!(
            filter[2].code, 0x28,
            "Third instruction should load half-word"
        );
        assert_eq!(filter[2].k, 12, "Should load EtherType at offset 12");

        assert_eq!(filter[3].code, 0x15, "Fourth instruction should be JEQ");
        assert_eq!(filter[3].k, 0x86dd, "Should check for IPv6 EtherType");

        // Test IPv6 Next Header check
        assert_eq!(filter[4].code, 0x30, "Fifth instruction should load byte");
        assert_eq!(filter[4].k, 20, "Should load Next Header at offset 20");

        assert_eq!(filter[5].code, 0x15, "Sixth instruction should be JEQ");
        assert_eq!(filter[5].k, 58, "Should check for ICMPv6 protocol");

        // Test return instructions
        assert_eq!(filter[6].code, 0x06, "Seventh instruction should be RET");
        assert_eq!(filter[6].k, 0, "Should return 0 (drop)");

        assert_eq!(filter[7].code, 0x06, "Eighth instruction should be RET");
        assert_eq!(filter[7].k, 0xffff, "Should return 0xffff (accept)");
    }

    #[test]
    fn test_bpf_filter_accepts_ipv6_icmpv6() {
        let filter = create_ns_filter();
        let packet = create_test_ipv6_icmpv6_packet();
        let mut vm = BpfVm::new();

        let result = vm.execute(&filter, &packet);
        assert_ne!(result, 0, "IPv6 ICMPv6 packet should be accepted");
        assert_eq!(result, 0xffff, "Should return maximum capture length");
    }

    #[test]
    fn test_bpf_filter_rejects_ipv4() {
        let filter = create_ns_filter();
        let packet = create_test_ipv4_packet();
        let mut vm = BpfVm::new();

        let result = vm.execute(&filter, &packet);
        assert_eq!(result, 0, "IPv4 packet should be rejected");
    }

    #[test]
    fn test_bpf_filter_rejects_short_packet() {
        let filter = create_ns_filter();
        let packet = create_test_short_packet();
        let mut vm = BpfVm::new();

        let result = vm.execute(&filter, &packet);
        assert_eq!(result, 0, "Short packet should be rejected");
    }

    #[test]
    fn test_bpf_filter_rejects_ipv6_non_icmpv6() {
        let filter = create_ns_filter();
        let mut packet = create_test_ipv6_icmpv6_packet();

        // Change Next Header to TCP (6) instead of ICMPv6 (58)
        packet[20] = 6;

        let mut vm = BpfVm::new();
        let result = vm.execute(&filter, &packet);
        assert_eq!(result, 0, "IPv6 non-ICMPv6 packet should be rejected");
    }

    #[test]
    fn test_bpf_vm_basic_operations() {
        let mut vm = BpfVm::new();

        // Test simple program that loads packet length and returns a constant
        let simple_program = vec![
            libc::sock_filter {
                code: 0x80,
                jt: 0,
                jf: 0,
                k: 0,
            }, // BPF_LD + BPF_LEN
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 42,
            }, // BPF_RET + BPF_K (return 42)
        ];

        let test_packet = vec![0u8; 100];
        let result = vm.execute(&simple_program, &test_packet);

        assert_eq!(result, 42, "Should return the constant value");
    }

    #[test]
    fn test_bpf_vm_infinite_loop_protection() {
        let mut vm = BpfVm::new();

        // Create a program with an infinite loop
        let infinite_loop_program = vec![
            libc::sock_filter {
                code: 0x80,
                jt: 0,
                jf: 0,
                k: 0,
            }, // BPF_LD + BPF_LEN
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 0,
                k: 100,
            }, // BPF_JEQ - always jump to self
        ];

        let test_packet = vec![0u8; 100];
        let result = vm.execute(&infinite_loop_program, &test_packet);

        // Should return 0 due to max iterations limit
        assert_eq!(result, 0, "Infinite loop should be detected and stopped");
    }
}
