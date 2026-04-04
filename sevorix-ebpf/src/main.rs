// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

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
    helpers::{
        bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_user,
    },
    macros::{lsm, map, sock_ops, tracepoint},
    programs::{LsmContext, SockOpsContext, TracePointContext},
};
use aya_ebpf_bindings::helpers::bpf_get_current_cgroup_id;
use sevorix_ebpf_common::{NetworkEvent, NetworkKey, PolicyKey, ProcessNetworkKey, SyscallEvent};

/// Ring buffer for sending events to userspace.
/// Events are consumed asynchronously by the userspace daemon.
#[map(name = "EVENTS")]
static mut EVENTS: aya_ebpf::maps::RingBuf = aya_ebpf::maps::RingBuf::with_byte_size(1 << 24, 0);

// ============================================================================
// SYSCALL LAYER
// ============================================================================

/// Map of denied syscalls per process.
/// Key: PolicyKey { pid, syscall_nr }, Value: error code to return.
#[map(name = "SYSCALL_DENYLIST")]
static mut SYSCALL_DENYLIST: aya_ebpf::maps::HashMap<PolicyKey, i32> =
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

/// Per-process cgroup ID cache.
///
/// Key: pid (u32), Value: cgroup_id (u64).
///
/// Populated by the sys_enter tracepoint (which has reliable cgroup_id access)
/// so that the sock_ops hook can look up the cgroup_id for the connecting process.
/// This lets sock_ops route network events correctly even though
/// bpf_get_current_cgroup_id() is unreliable in BPF_PROG_TYPE_SOCK_OPS context.
/// Entries are overwritten on each syscall, keeping the cached value fresh.
#[map(name = "PID_CGROUP_MAP")]
static mut PID_CGROUP_MAP: aya_ebpf::maps::HashMap<u32, u64> =
    aya_ebpf::maps::HashMap::with_max_entries(4096, 0);

/// Tracepoint handler for syscall entry.
///
/// This is attached to `syscalls:sys_enter` and fires on every syscall entry
/// inside a registered sevorix session cgroup. It sends events to userspace
/// via the ring buffer for policy evaluation and audit logging.
///
/// # Enforcement note
///
/// `BPF_PROG_TYPE_TRACEPOINT` return values are **ignored by the kernel** —
/// this program cannot block syscalls regardless of what it returns. It is
/// purely observational. The SYSCALL_DENYLIST map is checked here to avoid
/// redundant ring-buffer writes for already-known denials (fast-path).
///
/// Real syscall enforcement is provided by:
///   1. Per-session seccomp filter applied by `sevsh` at session startup
///      (`apply_syscall_deny_filter()` in sevorix-core).
///   2. BPF LSM hooks (`BPF_PROG_TYPE_LSM`) — available when the kernel is
///      booted with `lsm=...,bpf` (requires `CONFIG_BPF_LSM=y`).
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

        // Update the pid→cgroup_id cache so sock_ops can route network events.
        // We write on every syscall (cheap overwrite) to keep the entry fresh.
        // sock_ops cannot call bpf_get_current_cgroup_id() reliably, so it reads
        // this map instead.
        let _ = PID_CGROUP_MAP.insert(&pid, &cgroup_id, 0);

        // Fast path: check global allowlist
        if GLOBAL_ALLOWLIST.get(&syscall_nr).is_some() {
            return 0; // Allow immediately, no event
        }

        // Check global denylist — log the attempt for audit, but cannot block
        // (tracepoint return values are ignored; see enforcement note on this fn).
        if GLOBAL_DENYLIST.get(&syscall_nr).is_some() {
            let event = SyscallEvent {
                event_type: SyscallEvent::EVENT_TYPE,
                pid,
                tid,
                _padding0: 0,
                syscall_nr,
                timestamp: bpf_ktime_get_ns(),
                args,
                cgroup_id,
                _reserved: 0,
            };
            let _ = EVENTS.output(&event, 0);
            return 0;
        }

        // Check per-process denylist — log the attempt for audit, but cannot block.
        let policy_key = PolicyKey {
            pid,
            _padding: 0,
            id: syscall_nr,
        };
        if SYSCALL_DENYLIST.get(&policy_key).is_some() {
            let event = SyscallEvent {
                event_type: SyscallEvent::EVENT_TYPE,
                pid,
                tid,
                _padding0: 0,
                syscall_nr,
                timestamp: bpf_ktime_get_ns(),
                args,
                cgroup_id,
                _reserved: 0,
            };
            let _ = EVENTS.output(&event, 0);
            return 0;
        }

        // Intercept connect() (syscall 42 on x86-64) to emit NetworkEvents.
        //
        // connect(fd, *sockaddr, addrlen): args[1] is a userspace pointer to sockaddr.
        // We read it with bpf_probe_read_user to get the destination IP/port with the
        // correct cgroup_id — solving the routing problem that sock_ops has
        // (it cannot call bpf_get_current_cgroup_id on this kernel).
        //
        // syscall 42 = connect (x86-64 ABI, see /usr/include/asm/unistd_64.h)
        if syscall_nr == 42 {
            // connect(fd, sockaddr_ptr, addrlen): args[1] is a userspace pointer.
            // Read the sockaddr_in structure fields using integer-addressed reads
            // to avoid pointer-arithmetic-based derived pointers that the BPF
            // verifier may reject as type violations.
            let base: u64 = args[1];
            let family_ptr = base as *const u16;
            let port_ptr = (base + 2) as *const u16;
            let addr_ptr = (base + 4) as *const u32;

            let family_res = bpf_probe_read_user(family_ptr);
            let port_res = bpf_probe_read_user(port_ptr);
            let addr_res = bpf_probe_read_user(addr_ptr);

            if let (Ok(family), Ok(dst_port_be), Ok(dst_ip)) = (family_res, port_res, addr_res) {
                // AF_INET == 2; skip AF_UNIX, AF_INET6, etc.
                if family == 2 {
                    let net_event = NetworkEvent {
                        event_type: NetworkEvent::EVENT_TYPE,
                        pid,
                        tid,
                        _padding0: 0,
                        dst_ip,
                        dst_port: dst_port_be, // already BE; userspace applies from_be()
                        protocol: 6,
                        op: 0,
                        timestamp: bpf_ktime_get_ns(),
                        src_ip: 0,
                        src_port: 0,
                        family,
                        cgroup_id,
                        _reserved: 0,
                    };
                    let _ = EVENTS.output(&net_event, 0);
                }
            }
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
            cgroup_id,
            _reserved: 0,
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
            cgroup_id,
            _reserved: 0,
        };

        let _ = EVENTS.output(&event, 0);

        0
    }
}

// ============================================================================
// BPF LSM LAYER (Advanced tier — requires lsm=...,bpf in kernel boot params)
// ============================================================================

/// BPF LSM hook for exec security check.
///
/// Fires before execve/execveat. Checks whether this PID has been denied
/// execve by policy (GLOBAL_DENYLIST[59] or SYSCALL_DENYLIST[(pid,59)]).
/// Returns negative errno to block, 0 to allow.
///
/// Unlike tracepoints, LSM hook return values ARE enforced by the kernel.
/// This program only has effect on kernels with `bpf` in their active LSM
/// list (`/sys/kernel/security/lsm`). On Standard-tier kernels it loads
/// successfully but is not attached.
///
/// # Hook signature
///
/// `bprm_check_security(struct linux_binprm *bprm) -> int`
/// Plus the implicit `retval: int` appended by BPF LSM.
#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    unsafe { try_bprm_check_security(ctx) }
}

#[inline(always)]
unsafe fn try_bprm_check_security(ctx: LsmContext) -> i32 {
    // Defer to a previous LSM program's decision if it already denied.
    // bprm_check_security args: (struct linux_binprm*, int retval)
    let retval: i32 = ctx.arg(1);
    if retval != 0 {
        return retval;
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Cgroup filter: only enforce within active sevorix sessions.
    let cgroup_id = bpf_get_current_cgroup_id();
    if SEVORIX_CGROUP_IDS.get(&cgroup_id).is_none() {
        return 0;
    }

    // execve syscall number on x86-64
    let execve_nr: u64 = 59;

    // Check global denylist first.
    if let Some(&errno) = GLOBAL_DENYLIST.get(&execve_nr) {
        return -errno; // LSM hooks need negative errno to block
    }

    // Check per-process denylist.
    let key = PolicyKey {
        pid,
        _padding: 0,
        id: execve_nr,
    };
    if let Some(&errno) = SYSCALL_DENYLIST.get(&key) {
        return -errno;
    }

    0 // Allow
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

/// BPF LSM hook for socket connect security check.
///
/// Fires before any socket connect() call. For AF_INET (IPv4) connections,
/// reads the destination IP and port from the sockaddr and checks NET_DENYLIST.
/// Returns negative errno to block, 0 to allow.
///
/// Complements the existing sock_ops handler (which only covers TCP after the
/// BPF_SOCK_OPS_TCP_CONNECT_CB callback fires). This hook fires earlier, at the
/// LSM security boundary, and covers all socket families and protocols.
///
/// # Hook signature
///
/// `socket_connect(struct socket *sock, struct sockaddr *address, int addrlen) -> int`
/// Plus the implicit `retval: int` appended by BPF LSM.
#[lsm(hook = "socket_connect")]
pub fn lsm_socket_connect(ctx: LsmContext) -> i32 {
    unsafe { try_lsm_socket_connect(ctx) }
}

#[inline(always)]
unsafe fn try_lsm_socket_connect(ctx: LsmContext) -> i32 {
    // Defer to a previous LSM program's decision if it already denied.
    // socket_connect args: (struct socket*, struct sockaddr*, int addrlen, int retval)
    let retval: i32 = ctx.arg(3);
    if retval != 0 {
        return retval;
    }

    // Cgroup filter: only enforce within active sevorix sessions.
    let cgroup_id = bpf_get_current_cgroup_id();
    if SEVORIX_CGROUP_IDS.get(&cgroup_id).is_none() {
        return 0;
    }

    // Read the sockaddr pointer (arg 1).
    let sockaddr_ptr: *const u8 = ctx.arg(1);
    if sockaddr_ptr.is_null() {
        return 0;
    }

    // Read sa_family (first 2 bytes of sockaddr) from kernel memory.
    let family: u16 = match bpf_probe_read_kernel(sockaddr_ptr as *const u16) {
        Ok(f) => f,
        Err(_) => return 0,
    };

    // Only handle AF_INET (IPv4 = 2) for now.
    if family != 2 {
        return 0;
    }

    // sockaddr_in layout: sa_family(2B) + sin_port(2B BE) + sin_addr(4B)
    let port_ptr = sockaddr_ptr.add(2) as *const u16;
    let addr_ptr = sockaddr_ptr.add(4) as *const u32;

    let dst_port_be: u16 = match bpf_probe_read_kernel(port_ptr) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let dst_ip: u32 = match bpf_probe_read_kernel(addr_ptr) {
        Ok(a) => a,
        Err(_) => return 0,
    };

    // Store dst_port_be (network byte order) in the event so that the userspace
    // daemon's u16::from_be() conversion yields the correct host-order port.
    // Also use the host-order value for denylist key lookups.
    let dst_port_host = u16::from_be(dst_port_be);

    // Check NET_DENYLIST (protocol=0 for any, protocol=6 for TCP).
    let key_any = NetworkKey {
        dst_ip,
        dst_port: dst_port_host,
        protocol: 0,
        _padding: 0,
    };
    let key_tcp = NetworkKey {
        dst_ip,
        dst_port: dst_port_host,
        protocol: 6,
        _padding: 0,
    };

    // Emit a NetworkEvent for all connections from active sevorix sessions.
    // cgroup_id is embedded here (available in LSM context) so userspace can
    // route the event to the correct per-session Watchtower. src_ip/src_port
    // are 0 because the socket has not been bound yet at LSM time — that is
    // expected and acceptable; dst_ip/dst_port are the policy-relevant fields.
    let pid_tgid = bpf_get_current_pid_tgid();
    let event = NetworkEvent {
        event_type: NetworkEvent::EVENT_TYPE,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        _padding0: 0,
        dst_ip,
        dst_port: dst_port_be, // network byte order; userspace applies from_be()
        protocol: 6,           // TCP
        op: 0,                 // connect
        timestamp: bpf_ktime_get_ns(),
        src_ip: 0,
        src_port: 0,
        family,
        cgroup_id,
        _reserved: 0,
    };
    let _ = EVENTS.output(&event, 0);

    // Block if the destination is in the denylist.
    if let Some(&errno) = NET_DENYLIST
        .get(&key_any)
        .or_else(|| NET_DENYLIST.get(&key_tcp))
    {
        return -errno; // LSM hooks need negative errno to block
    }

    0 // Allow
}

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

    // Variables read to satisfy the sock_ops API; currently unused since network
    // events are emitted exclusively from the sys_enter tracepoint (connect=42).
    let _dst_ip = ctx.remote_ip4();
    let _dst_port = ctx.remote_port() as u16;
    let _src_ip = ctx.local_ip4();
    let _src_port = ctx.local_port() as u16;
    let _family = ctx.family() as u16;

    // Note: bpf_get_current_pid_tgid() is NOT available in BPF_PROG_TYPE_SOCK_OPS
    // on this kernel (verifier rejects it). bpf_get_current_cgroup_id() is similarly
    // unavailable. Network events are instead captured by the sys_enter tracepoint
    // at connect() (syscall 42), which has full access to both helpers and emits
    // NetworkEvents with correct cgroup_id for per-session routing.
    // This hook is kept for denylist enforcement only (allow-list fast path).

    1 // Allow (sock_ops TCP_CONNECT_CB return value is informational only)
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
