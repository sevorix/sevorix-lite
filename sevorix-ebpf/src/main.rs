//! Sevorix eBPF Programs
//!
//! This crate contains eBPF programs for syscall and network interception.
//!
//! # Architecture
//!
//! - `sys_enter`: Tracepoint for syscall entry
//! - `sys_exit`: Tracepoint for syscall exit (return values)
//! - `sock_ops`: cgroup/sockops for connect() interception
//! - Ring buffer for async event delivery to userspace
//! - Hash maps for policy decisions

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_SOCK_OPS_TCP_CONNECT_CB,
    cty::c_long,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, sock_ops, tracepoint},
    programs::{SockOpsContext, TracePointContext},
};
use aya_ebpf_bindings::helpers::bpf_get_current_cgroup_id;
use sevorix_ebpf_common::{NetworkEvent, NetworkKey, ProcessNetworkKey, SyscallEvent};

/// Ring buffer for sending events to userspace.
/// Events are consumed asynchronously by the userspace daemon.
#[map(name = "EVENTS")]
static mut EVENTS: aya_ebpf::maps::RingBuf = aya_ebpf::maps::RingBuf::with_byte_size(1 << 24, 0);

// ============================================================================
// SYSCALL LAYER
// ============================================================================

/// Map of allowed syscalls per process.
/// Key: (pid, syscall_nr), Value: 1 if allowed.
#[map(name = "SYSCALL_ALLOWLIST")]
static mut SYSCALL_ALLOWLIST: aya_ebpf::maps::HashMap<(u32, u64), u8> =
    aya_ebpf::maps::HashMap::with_max_entries(10240, 0);

/// Map of denied syscalls per process.
/// Key: (pid, syscall_nr), Value: error code to return.
#[map(name = "SYSCALL_DENYLIST")]
static mut SYSCALL_DENYLIST: aya_ebpf::maps::HashMap<(u32, u64), i32> =
    aya_ebpf::maps::HashMap::with_max_entries(10240, 0);

/// Global syscall denylist (applies to all processes).
/// Key: syscall_nr, Value: error code.
#[map(name = "GLOBAL_DENYLIST")]
static mut GLOBAL_DENYLIST: aya_ebpf::maps::HashMap<u64, i32> =
    aya_ebpf::maps::HashMap::with_max_entries(256, 0);

/// Global syscall allowlist (applies to all processes).
/// Syscalls in this list are not monitored.
#[map(name = "GLOBAL_ALLOWLIST")]
static mut GLOBAL_ALLOWLIST: aya_ebpf::maps::HashMap<u64, u8> =
    aya_ebpf::maps::HashMap::with_max_entries(256, 0);

/// Set of active sevorix session cgroup IDs.
///
/// Key: cgroup ID (u64, equals the inode number of the cgroup directory in cgroupfs v2).
/// Value: 1 (present = active session).
///
/// The userspace daemon populates this by scanning /sys/fs/cgroup/sevorix/ and
/// inserting each session subdirectory's inode. Processes whose current cgroup ID
/// is NOT in this map are silently dropped before reaching the ring buffer.
///
/// When the map is empty (no active sessions), ALL processes are dropped — the
/// ring buffer stays idle and CPU usage is negligible.
#[map(name = "SEVORIX_CGROUP_IDS")]
static mut SEVORIX_CGROUP_IDS: aya_ebpf::maps::HashMap<u64, u8> =
    aya_ebpf::maps::HashMap::with_max_entries(256, 0);

/// Tracepoint handler for syscall entry.
///
/// This is attached to `syscalls:sys_enter` and intercepts all syscall
/// entries. It checks allowlists/denylists and sends events to userspace
/// for policy evaluation.
#[tracepoint(name = "sys_enter", category = "raw_syscalls")]
pub fn sys_enter(ctx: TracePointContext) -> u32 {
    unsafe {
        // The tracepoint context contains the syscall number at offset 8
        // and arguments starting at offset 16.
        // See: /sys/kernel/debug/tracing/events/syscalls/sys_enter/format

        // Read syscall number (offset 8 in the tracepoint data)
        let syscall_nr: u64 = match ctx.read_at(8) {
            Ok(nr) => nr,
            Err(_) => return 0,
        };

        // Read first 6 arguments (offsets 16, 24, 32, 40, 48, 56)
        let args: [u64; 6] = [
            ctx.read_at(16).unwrap_or(0),
            ctx.read_at(24).unwrap_or(0),
            ctx.read_at(32).unwrap_or(0),
            ctx.read_at(40).unwrap_or(0),
            ctx.read_at(48).unwrap_or(0),
            ctx.read_at(56).unwrap_or(0),
        ];

        // Get PID/TID
        let pid_tgid = bpf_get_current_pid_tgid();
        let pid = (pid_tgid >> 32) as u32;
        let tid = pid_tgid as u32;

        // Cgroup filter: only monitor processes inside an active sevorix session.
        // bpf_get_current_cgroup_id() returns the cgroup v2 ID (= inode of the cgroup dir).
        // If the map is empty (no active sessions) or the cgroup isn't registered,
        // drop immediately — zero ring buffer writes, near-zero CPU.
        let cgroup_id = bpf_get_current_cgroup_id();
        if SEVORIX_CGROUP_IDS.get(&cgroup_id).is_none() {
            return 0;
        }

        // Fast path: check global allowlist
        if GLOBAL_ALLOWLIST.get(&syscall_nr).is_some() {
            return 0; // Allow immediately, no event
        }

        // Check global denylist
        if let Some(&error_code) = GLOBAL_DENYLIST.get(&syscall_nr) {
            // Log the denial event
            let event = SyscallEvent {
                event_type: SyscallEvent::EVENT_TYPE,
                pid,
                tid,
                _padding0: 0,
                syscall_nr,
                timestamp: bpf_ktime_get_ns(),
                args,
                _reserved: [0; 2],
            };

            // Try to send event (ignore failure - kernel doesn't wait)
            let _ = EVENTS.output(&event, 0);

            // Return error to deny syscall
            return error_code as u32;
        }

        // Check per-process denylist
        if let Some(&error_code) = SYSCALL_DENYLIST.get(&(pid, syscall_nr)) {
            let event = SyscallEvent {
                event_type: SyscallEvent::EVENT_TYPE,
                pid,
                tid,
                _padding0: 0,
                syscall_nr,
                timestamp: bpf_ktime_get_ns(),
                args,
                _reserved: [0; 2],
            };

            let _ = EVENTS.output(&event, 0);

            return error_code as u32;
        }

        // Check per-process allowlist
        if SYSCALL_ALLOWLIST.get(&(pid, syscall_nr)).is_some() {
            return 0; // Allow, no event
        }

        // Unknown syscall - send to userspace for policy evaluation
        let event = SyscallEvent {
            event_type: SyscallEvent::EVENT_TYPE,
            pid,
            tid,
            _padding0: 0,
            syscall_nr,
            timestamp: bpf_ktime_get_ns(),
            args,
            _reserved: [0; 2],
        };

        let _ = EVENTS.output(&event, 0);

        // Allow by default (userspace can update denylist)
        0
    }
}

/// Tracepoint handler for syscall exit.
///
/// This is attached to `syscalls:sys_exit` and captures return values.
/// Used for logging syscall results and tracking completed syscalls.
#[tracepoint(name = "sys_exit", category = "raw_syscalls")]
pub fn sys_exit(ctx: TracePointContext) -> u32 {
    unsafe {
        // The tracepoint context for sys_exit contains:
        // - offset 8: syscall number
        // - offset 16: return value (long)

        // Read syscall number
        let syscall_nr: u64 = match ctx.read_at(8) {
            Ok(nr) => nr,
            Err(_) => return 0,
        };

        // Read return value
        let ret_value: i64 = match ctx.read_at(16) {
            Ok(v) => v,
            Err(_) => return 0,
        };

        // Get PID/TID
        let pid_tgid = bpf_get_current_pid_tgid();
        let pid = (pid_tgid >> 32) as u32;
        let tid = pid_tgid as u32;

        // Cgroup filter: drop if not in an active sevorix session.
        let cgroup_id = bpf_get_current_cgroup_id();
        if SEVORIX_CGROUP_IDS.get(&cgroup_id).is_none() {
            return 0;
        }

        // Send exit event - userspace can filter if needed
        let event = SyscallEvent {
            event_type: SyscallEvent::EVENT_TYPE_EXIT,
            pid,
            tid,
            _padding0: 0,
            syscall_nr,
            timestamp: bpf_ktime_get_ns(),
            args: [ret_value as u64, 0, 0, 0, 0, 0], // First arg is return value
            _reserved: [0; 2],
        };

        let _ = EVENTS.output(&event, 0);

        0
    }
}

// ============================================================================
// NETWORK LAYER
// ============================================================================

/// Global network allowlist (IP:port tuples).
/// Key: NetworkKey (dst_ip, dst_port, protocol), Value: 1 if allowed.
#[map(name = "NET_ALLOWLIST")]
static mut NET_ALLOWLIST: aya_ebpf::maps::HashMap<NetworkKey, u8> =
    aya_ebpf::maps::HashMap::with_max_entries(10240, 0);

/// Global network denylist (IP:port tuples).
/// Key: NetworkKey (dst_ip, dst_port, protocol), Value: error code (EPERM=1).
#[map(name = "NET_DENYLIST")]
static mut NET_DENYLIST: aya_ebpf::maps::HashMap<NetworkKey, i32> =
    aya_ebpf::maps::HashMap::with_max_entries(10240, 0);

/// Per-process network allowlist.
/// Key: ProcessNetworkKey (pid, dst_ip, dst_port, protocol), Value: 1 if allowed.
#[map(name = "PROCESS_NET_ALLOWLIST")]
static mut PROCESS_NET_ALLOWLIST: aya_ebpf::maps::HashMap<ProcessNetworkKey, u8> =
    aya_ebpf::maps::HashMap::with_max_entries(10240, 0);

/// Per-process network denylist.
/// Key: ProcessNetworkKey (pid, dst_ip, dst_port, protocol), Value: error code.
#[map(name = "PROCESS_NET_DENYLIST")]
static mut PROCESS_NET_DENYLIST: aya_ebpf::maps::HashMap<ProcessNetworkKey, i32> =
    aya_ebpf::maps::HashMap::with_max_entries(10240, 0);

/// Socket operations handler for connect() interception.
///
/// This is attached to a cgroup and intercepts all socket operations.
/// We focus on BPF_SOCK_OPS_TCP_CONNECT_CB for outgoing TCP connections.
#[sock_ops]
pub fn sock_ops(ctx: SockOpsContext) -> u32 {
    unsafe { try_sock_ops(ctx) }
}

#[inline(always)]
unsafe fn try_sock_ops(ctx: SockOpsContext) -> u32 {
    let op = ctx.op();

    // We only care about TCP connect operations
    if op != BPF_SOCK_OPS_TCP_CONNECT_CB {
        return 1; // Allow other operations
    }

    // Get destination IP and port
    let dst_ip = ctx.remote_ip4();
    let dst_port = ctx.remote_port() as u16; // Convert u32 to u16
    let src_ip = ctx.local_ip4();
    let src_port = ctx.local_port() as u16; // Convert u32 to u16
    let family = ctx.family() as u16;

    // Note: bpf_get_current_pid_tgid is not available in sock_ops context on all kernels.
    // Use 0 as a fallback; per-process network policy checks will be skipped.
    let pid: u32 = 0;
    let tid: u32 = 0;

    // Build network key (protocol 6 = TCP)
    let key_tcp = NetworkKey {
        dst_ip,
        dst_port,
        protocol: 6, // TCP
        _padding: 0,
    };
    let key_any = NetworkKey {
        dst_ip,
        dst_port,
        protocol: 0, // Any protocol
        _padding: 0,
    };

    // Build per-process key
    let proc_key_tcp = ProcessNetworkKey {
        pid,
        dst_ip,
        dst_port,
        protocol: 6, // TCP
        _padding: 0,
    };
    let proc_key_any = ProcessNetworkKey {
        pid,
        dst_ip,
        dst_port,
        protocol: 0, // Any protocol
        _padding: 0,
    };

    // Fast path: check global allowlist (any protocol first, then specific)
    if NET_ALLOWLIST.get(&key_any).is_some() || NET_ALLOWLIST.get(&key_tcp).is_some() {
        return 1; // Allow
    }

    // Check per-process allowlist
    if PROCESS_NET_ALLOWLIST.get(&proc_key_any).is_some()
        || PROCESS_NET_ALLOWLIST.get(&proc_key_tcp).is_some()
    {
        return 1; // Allow
    }

    // Check global denylist
    if let Some(&_err) = NET_DENYLIST.get(&key_any).or_else(|| NET_DENYLIST.get(&key_tcp)) {
        // Log the denial event
        let event = NetworkEvent {
            event_type: NetworkEvent::EVENT_TYPE,
            pid,
            tid,
            _padding0: 0,
            dst_ip,
            dst_port,
            protocol: 6, // TCP
            op: 0,       // connect
            timestamp: bpf_ktime_get_ns(),
            src_ip,
            src_port,
            family,
            _reserved: [0; 2],
        };

        let _ = EVENTS.output(&event, 0);

        return 0; // Deny (will return EPERM)
    }

    // Check per-process denylist
    if let Some(&_err) = PROCESS_NET_DENYLIST.get(&proc_key_any)
        .or_else(|| PROCESS_NET_DENYLIST.get(&proc_key_tcp))
    {
        let event = NetworkEvent {
            event_type: NetworkEvent::EVENT_TYPE,
            pid,
            tid,
            _padding0: 0,
            dst_ip,
            dst_port,
            protocol: 6, // TCP
            op: 0,       // connect
            timestamp: bpf_ktime_get_ns(),
            src_ip,
            src_port,
            family,
            _reserved: [0; 2],
        };

        let _ = EVENTS.output(&event, 0);

        return 0; // Deny
    }

    // Unknown connection - send event to userspace for policy evaluation
    let event = NetworkEvent {
        event_type: NetworkEvent::EVENT_TYPE,
        pid,
        tid,
        _padding0: 0,
        dst_ip,
        dst_port,
        protocol: 6, // TCP
        op: 0,       // connect
        timestamp: bpf_ktime_get_ns(),
        src_ip,
        src_port,
        family,
        _reserved: [0; 2],
    };

    let _ = EVENTS.output(&event, 0);

    // Allow by default (userspace can update denylist)
    1
}

/// Panic handler for eBPF programs (no-std).
/// Gated on cfg(not(test)) because cargo test links std, which provides its own panic handler.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn _begin() {}
