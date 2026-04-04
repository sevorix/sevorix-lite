// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

//! Shared types between eBPF programs and userspace.
//!
//! This crate provides common data structures used by both the kernel-space
//! eBPF programs and the userspace daemon.
//!
//! # Features
//!
//! - `user`: Enable userspace support with aya crate
//! - `kernel`: Enable kernel-space support with aya-ebpf crate

// For kernel (eBPF) mode, we need no_std
#![cfg_attr(feature = "kernel", no_std)]

#[cfg(feature = "user")]
use zerocopy::{FromBytes, IntoBytes, KnownLayout};

/// Syscall event data sent from eBPF to userspace via ring buffer.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "user", derive(FromBytes, IntoBytes, KnownLayout))]
#[repr(C)]
pub struct SyscallEvent {
    /// Event type: 1 = syscall entry.
    pub event_type: u32,
    /// Process ID (kernel tgid).
    pub pid: u32,
    /// Thread ID (kernel pid).
    pub tid: u32,
    /// Padding to align to 8 bytes.
    pub _padding0: u32,
    /// Syscall number.
    pub syscall_nr: u64,
    /// Timestamp (nanoseconds since boot).
    pub timestamp: u64,
    /// First 6 arguments of the syscall.
    pub args: [u64; 6],
    /// cgroup v2 ID (inode of the cgroup directory) of the process at syscall time.
    /// Set by bpf_get_current_cgroup_id(); used for session routing without procfs.
    pub cgroup_id: u64,
    /// Reserved for future use.
    pub _reserved: u64,
}

/// Network connection event data sent from eBPF to userspace.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "user", derive(FromBytes, IntoBytes, KnownLayout))]
#[repr(C)]
pub struct NetworkEvent {
    /// Event type: 2 = network connect.
    pub event_type: u32,
    /// Process ID.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Padding to align to 8 bytes.
    pub _padding0: u32,
    /// Destination IPv4 address (network byte order).
    pub dst_ip: u32,
    /// Destination port (network byte order).
    pub dst_port: u16,
    /// Protocol (TCP=6, UDP=17, etc).
    pub protocol: u8,
    /// Socket operation type (connect=0, bind=1, etc).
    pub op: u8,
    /// Timestamp (nanoseconds since boot).
    pub timestamp: u64,
    /// Source IPv4 address (network byte order).
    pub src_ip: u32,
    /// Source port (network byte order).
    pub src_port: u16,
    /// Address family (AF_INET=2, AF_INET6=10).
    pub family: u16,
    /// cgroup v2 ID (inode of the cgroup directory) of the process at event time.
    /// Set by bpf_get_current_cgroup_id(); used for session routing without procfs.
    pub cgroup_id: u64,
    /// Reserved for future use.
    pub _reserved: u64,
}

/// Policy decision from userspace to eBPF.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "user", derive(FromBytes, IntoBytes, KnownLayout))]
#[repr(C)]
pub struct PolicyDecision {
    /// Process ID this decision applies to.
    pub pid: u32,
    /// Action: 0=allow, 1=deny, 2=audit.
    pub action: u32,
    /// Syscall number or 0 for network.
    pub syscall_nr: u64,
}

/// Network policy key for IP:port allow/deny maps.
/// Key: (dst_ip, dst_port) tuple for network filtering.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "user", derive(FromBytes, IntoBytes, KnownLayout))]
#[repr(C)]
pub struct NetworkKey {
    /// Destination IPv4 address (network byte order).
    pub dst_ip: u32,
    /// Destination port (network byte order).
    pub dst_port: u16,
    /// Protocol (TCP=6, UDP=17, 0=any).
    pub protocol: u8,
    /// Padding to 8-byte boundary.
    pub _padding: u8,
}

/// Per-process network policy key.
/// Key: (pid, dst_ip, dst_port) tuple for process-specific network filtering.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "user", derive(FromBytes, IntoBytes, KnownLayout))]
#[repr(C)]
pub struct ProcessNetworkKey {
    /// Process ID.
    pub pid: u32,
    /// Destination IPv4 address (network byte order).
    pub dst_ip: u32,
    /// Destination port (network byte order).
    pub dst_port: u16,
    /// Protocol (TCP=6, UDP=17, 0=any).
    pub protocol: u8,
    /// Padding to 8-byte boundary.
    pub _padding: u8,
}

/// Map keys for policy maps.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "user", derive(FromBytes, IntoBytes, KnownLayout))]
#[repr(C)]
pub struct PolicyKey {
    /// Process ID.
    pub pid: u32,
    /// Padding to align to 8 bytes.
    pub _padding: u32,
    /// Syscall number or connection identifier.
    pub id: u64,
}

impl SyscallEvent {
    /// Event type constant for syscall entry events.
    pub const EVENT_TYPE: u32 = 1;
    /// Event type constant for syscall exit events.
    pub const EVENT_TYPE_EXIT: u32 = 3;
    /// Size of the event in bytes.
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl NetworkEvent {
    /// Event type constant for network events.
    pub const EVENT_TYPE: u32 = 2;
    /// Size of the event in bytes.
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    // =========================================================================
    // SyscallEvent tests
    // =========================================================================

    #[test]
    fn test_syscall_event_constants() {
        assert_eq!(SyscallEvent::EVENT_TYPE, 1);
        assert_eq!(SyscallEvent::EVENT_TYPE_EXIT, 3);
    }

    #[test]
    fn test_syscall_event_size_is_nonzero() {
        assert!(SyscallEvent::SIZE > 0);
        assert_eq!(SyscallEvent::SIZE, mem::size_of::<SyscallEvent>());
    }

    #[test]
    fn test_syscall_event_creation() {
        let event = SyscallEvent {
            event_type: SyscallEvent::EVENT_TYPE,
            pid: 1234,
            tid: 1235,
            _padding0: 0,
            syscall_nr: 59, // execve
            timestamp: 1_000_000_000,
            args: [0u64; 6],
            cgroup_id: 0,
            _reserved: 0,
        };

        assert_eq!(event.event_type, 1);
        assert_eq!(event.pid, 1234);
        assert_eq!(event.tid, 1235);
        assert_eq!(event.syscall_nr, 59);
        assert_eq!(event.timestamp, 1_000_000_000);
    }

    #[test]
    fn test_syscall_event_clone() {
        let event = SyscallEvent {
            event_type: 1,
            pid: 42,
            tid: 43,
            _padding0: 0,
            syscall_nr: 0,
            timestamp: 999,
            args: [1u64, 2, 3, 4, 5, 6],
            cgroup_id: 0,
            _reserved: 0,
        };
        let cloned = event;
        assert_eq!(cloned.pid, event.pid);
        assert_eq!(cloned.args, event.args);
    }

    #[test]
    fn test_syscall_event_args_all_six() {
        let event = SyscallEvent {
            event_type: 1,
            pid: 100,
            tid: 101,
            _padding0: 0,
            syscall_nr: 2,
            timestamp: 0,
            args: [10, 20, 30, 40, 50, 60],
            cgroup_id: 0,
            _reserved: 0,
        };
        assert_eq!(event.args[0], 10);
        assert_eq!(event.args[5], 60);
    }

    // =========================================================================
    // NetworkEvent tests
    // =========================================================================

    #[test]
    fn test_network_event_constant() {
        assert_eq!(NetworkEvent::EVENT_TYPE, 2);
    }

    #[test]
    fn test_network_event_size_is_nonzero() {
        assert!(NetworkEvent::SIZE > 0);
        assert_eq!(NetworkEvent::SIZE, mem::size_of::<NetworkEvent>());
    }

    #[test]
    fn test_network_event_creation() {
        let event = NetworkEvent {
            event_type: NetworkEvent::EVENT_TYPE,
            pid: 5678,
            tid: 5679,
            _padding0: 0,
            dst_ip: 0x08080808u32.to_be(), // 8.8.8.8 in network order
            dst_port: 443u16.to_be(),
            protocol: 6, // TCP
            op: 0,       // connect
            timestamp: 2_000_000_000,
            src_ip: 0x7f000001u32.to_be(), // 127.0.0.1
            src_port: 54321u16.to_be(),
            family: 2, // AF_INET
            cgroup_id: 0,
            _reserved: 0,
        };

        assert_eq!(event.event_type, 2);
        assert_eq!(event.pid, 5678);
        assert_eq!(event.protocol, 6);
        assert_eq!(event.op, 0);
    }

    #[test]
    fn test_network_event_clone() {
        let event = NetworkEvent {
            event_type: 2,
            pid: 200,
            tid: 201,
            _padding0: 0,
            dst_ip: 0,
            dst_port: 80,
            protocol: 6,
            op: 0,
            timestamp: 123,
            src_ip: 0,
            src_port: 12345,
            family: 2,
            cgroup_id: 0,
            _reserved: 0,
        };
        let cloned = event;
        assert_eq!(cloned.pid, event.pid);
        assert_eq!(cloned.dst_port, event.dst_port);
    }

    // =========================================================================
    // PolicyDecision tests
    // =========================================================================

    #[test]
    fn test_policy_decision_creation() {
        let decision = PolicyDecision {
            pid: 1234,
            action: 0, // allow
            syscall_nr: 59,
        };

        assert_eq!(decision.pid, 1234);
        assert_eq!(decision.action, 0);
        assert_eq!(decision.syscall_nr, 59);
    }

    #[test]
    fn test_policy_decision_deny() {
        let decision = PolicyDecision {
            pid: 5678,
            action: 1, // deny
            syscall_nr: 0,
        };
        assert_eq!(decision.action, 1);
    }

    #[test]
    fn test_policy_decision_audit() {
        let decision = PolicyDecision {
            pid: 9999,
            action: 2, // audit
            syscall_nr: 42,
        };
        assert_eq!(decision.action, 2);
    }

    #[test]
    fn test_policy_decision_clone() {
        let decision = PolicyDecision {
            pid: 111,
            action: 0,
            syscall_nr: 5,
        };
        let cloned = decision;
        assert_eq!(cloned.pid, decision.pid);
        assert_eq!(cloned.syscall_nr, decision.syscall_nr);
    }

    // =========================================================================
    // NetworkKey tests
    // =========================================================================

    #[test]
    fn test_network_key_creation() {
        let key = NetworkKey {
            dst_ip: 0x08080808,
            dst_port: 443,
            protocol: 6,
            _padding: 0,
        };

        assert_eq!(key.dst_ip, 0x08080808);
        assert_eq!(key.dst_port, 443);
        assert_eq!(key.protocol, 6);
    }

    #[test]
    fn test_network_key_equality() {
        let key1 = NetworkKey {
            dst_ip: 0x01020304,
            dst_port: 80,
            protocol: 6,
            _padding: 0,
        };
        let key2 = NetworkKey {
            dst_ip: 0x01020304,
            dst_port: 80,
            protocol: 6,
            _padding: 0,
        };
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_network_key_inequality() {
        let key1 = NetworkKey {
            dst_ip: 0x01020304,
            dst_port: 80,
            protocol: 6,
            _padding: 0,
        };
        let key2 = NetworkKey {
            dst_ip: 0x01020304,
            dst_port: 443,
            protocol: 6,
            _padding: 0,
        };
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_network_key_hash() {
        use core::hash::{Hash, Hasher};

        struct SimpleHasher(u64);
        impl Hasher for SimpleHasher {
            fn finish(&self) -> u64 {
                self.0
            }
            fn write(&mut self, bytes: &[u8]) {
                for &b in bytes {
                    self.0 = self.0.wrapping_mul(31).wrapping_add(b as u64);
                }
            }
        }

        let key1 = NetworkKey {
            dst_ip: 0x08080808,
            dst_port: 53,
            protocol: 17,
            _padding: 0,
        };
        let key2 = NetworkKey {
            dst_ip: 0x08080404,
            dst_port: 53,
            protocol: 17,
            _padding: 0,
        };

        let mut h1 = SimpleHasher(0);
        let mut h2 = SimpleHasher(0);
        key1.hash(&mut h1);
        key2.hash(&mut h2);
        // Different IPs must produce different hashes
        assert_ne!(h1.finish(), h2.finish());
    }

    // =========================================================================
    // ProcessNetworkKey tests
    // =========================================================================

    #[test]
    fn test_process_network_key_creation() {
        let key = ProcessNetworkKey {
            pid: 1234,
            dst_ip: 0x08080808,
            dst_port: 443,
            protocol: 6,
            _padding: 0,
        };

        assert_eq!(key.pid, 1234);
        assert_eq!(key.dst_ip, 0x08080808);
        assert_eq!(key.dst_port, 443);
    }

    #[test]
    fn test_process_network_key_equality() {
        let key1 = ProcessNetworkKey {
            pid: 100,
            dst_ip: 0x01020304,
            dst_port: 80,
            protocol: 6,
            _padding: 0,
        };
        let key2 = ProcessNetworkKey {
            pid: 100,
            dst_ip: 0x01020304,
            dst_port: 80,
            protocol: 6,
            _padding: 0,
        };
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_process_network_key_inequality_by_pid() {
        let key1 = ProcessNetworkKey {
            pid: 100,
            dst_ip: 0x01020304,
            dst_port: 80,
            protocol: 6,
            _padding: 0,
        };
        let key2 = ProcessNetworkKey {
            pid: 200,
            dst_ip: 0x01020304,
            dst_port: 80,
            protocol: 6,
            _padding: 0,
        };
        assert_ne!(key1, key2);
    }

    // =========================================================================
    // PolicyKey tests
    // =========================================================================

    #[test]
    fn test_policy_key_creation() {
        let key = PolicyKey {
            pid: 1234,
            _padding: 0,
            id: 59,
        };

        assert_eq!(key.pid, 1234);
        assert_eq!(key.id, 59);
    }

    #[test]
    fn test_policy_key_equality() {
        let key1 = PolicyKey {
            pid: 100,
            _padding: 0,
            id: 42,
        };
        let key2 = PolicyKey {
            pid: 100,
            _padding: 0,
            id: 42,
        };
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_policy_key_inequality() {
        let key1 = PolicyKey {
            pid: 100,
            _padding: 0,
            id: 42,
        };
        let key2 = PolicyKey {
            pid: 100,
            _padding: 0,
            id: 43,
        };
        assert_ne!(key1, key2);
    }

    // =========================================================================
    // Size sanity checks (repr(C) alignment)
    // =========================================================================

    #[test]
    fn test_repr_c_sizes_are_reasonable() {
        // These are C-compatible structs — sanity check sizes
        assert!(mem::size_of::<SyscallEvent>() >= 64);
        assert!(mem::size_of::<NetworkEvent>() >= 32);
        assert!(mem::size_of::<PolicyDecision>() >= 16);
        assert!(mem::size_of::<NetworkKey>() >= 8);
        assert!(mem::size_of::<ProcessNetworkKey>() >= 12);
        assert!(mem::size_of::<PolicyKey>() >= 16);
    }
}

// Implement aya::Pod for userspace when the user feature is enabled
#[cfg(feature = "user")]
unsafe impl aya::Pod for SyscallEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NetworkEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyDecision {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NetworkKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessNetworkKey {}
