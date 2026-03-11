# Sevorix eBPF Programs

eBPF programs for Sevorix syscall and network interception.

## Overview

This crate contains eBPF programs that run in the Linux kernel to intercept
syscalls and network connections. These programs work with the userspace
daemon (`sevorix-ebpf-daemon`) to enforce security policies.

## Architecture

### Why eBPF Instead of seccomp-unotify?

The original seccomp-unotify approach had fundamental issues:
- **Synchronous blocking**: The kernel blocks waiting for userspace decisions
- **Deadlock potential**: Policy evaluation requires I/O (HTTP, file access) which can be blocked by seccomp itself
- **No network interception**: seccomp only handles syscalls

eBPF solves these by:
- **Asynchronous events**: Ring buffer delivers events without blocking kernel
- **Fast-path filtering**: Allow/deny lists in kernel space for instant decisions
- **No deadlock**: Userspace daemon can make HTTP calls without recursion issues

### Layer 4: Syscall Interception

```
Application                Kernel                  Userspace Daemon
    │                         │                           │
    │ syscall()               │                           │
    │ ─────────────────────────►                           │
    │                         │                           │
    │                 eBPF program                         │
    │                 checks local                         │
    │                 allow/deny map                       │
    │                         │                           │
    │                    (allowed?)                       │
    │                         │                           │
    │                    ┌────┴────┐                      │
    │                    │         │                      │
    │                 allowed   blocked                  │
    │                    │         │                      │
    │                (continue)  (return error)          │
    │                    │                                │
    │                    │  event to ring buffer ─────────►│
    │                    │                                │
    │                    │                        async policy
    │                    │                        evaluation
    │                    │                        (HTTP, DB, etc.)
    │                    │                                │
    │ ◄────────────────────                               │
    │ (syscall returns)                                   │
```

### Maps

| Map Name | Type | Purpose |
|----------|------|---------|
| `EVENTS` | RingBuf | Events sent to userspace |
| `SYSCALL_ALLOWLIST` | HashMap | Per-process syscall allowlist |
| `SYSCALL_DENYLIST` | HashMap | Per-process syscall denylist |
| `GLOBAL_ALLOWLIST` | HashMap | Global syscall allowlist (all processes) |
| `GLOBAL_DENYLIST` | HashMap | Global syscall denylist (all processes) |
| `TRACKED_PIDS` | HashMap | PIDs being monitored |
| `NETWORK_ALLOWLIST` | HashMap | Network connection allowlist |
| `NETWORK_DENYLIST` | HashMap | Network connection denylist |

### Event Types

#### SyscallEvent (type=1)

Sent when a syscall is intercepted:

```c
struct SyscallEvent {
    u32 event_type;    // 1
    u32 pid;           // Process ID
    u32 tid;           // Thread ID
    u32 _padding0;
    u64 syscall_nr;    // Syscall number
    u64 timestamp;      // Nanoseconds since boot
    u64 args[6];        // Syscall arguments
    u64 _reserved[2];
};
```

#### NetworkEvent (type=2)

Sent when a network connection is intercepted:

```c
struct NetworkEvent {
    u32 event_type;    // 2
    u32 pid;           // Process ID
    u32 tid;           // Thread ID
    u32 _padding0;
    u32 dst_ip;        // Destination IP (network byte order)
    u16 dst_port;      // Destination port (network byte order)
    u8 protocol;       // Protocol (TCP=6, UDP=17)
    u8 _padding1;
    u64 timestamp;     // Nanoseconds since boot
    u64 _reserved[4];
};
```

## Building

eBPF programs require the nightly Rust toolchain and a special compilation target.

```bash
# Install nightly toolchain
rustup install nightly

# Add the bpf target to nightly
rustup target add bpfel-unknown-none --toolchain nightly

# Build the eBPF program with nightly
cargo +nightly build -p sevorix-ebpf --release -Z build-std=core
```

The compiled eBPF object will be at:
`target/bpfel-unknown-none/release/sevorix-ebpf`

## Running

1. Build the eBPF program (see above)
2. Build the daemon with eBPF feature:

```bash
cargo build --features ebpf --release --bin sevorix-ebpf-daemon
```

3. Run with root privileges (requires CAP_BPF, CAP_NET_ADMIN, CAP_SYS_ADMIN):

```bash
sudo ./target/release/sevorix-ebpf-daemon
```

## Integration with Watchtower

The eBPF daemon connects to the Watchtower HTTP API for policy decisions:

1. eBPF program captures syscall event
2. Event sent to userspace via ring buffer
3. Daemon queries `POST /analyze-syscall` on Watchtower
4. Watchtower returns `allow`, `deny`, or `kill` decision
5. (Future) Daemon updates eBPF maps with decision for fast-path

## Security Model

### Fast Path (Kernel Space)

- `GLOBAL_ALLOWLIST`: Syscalls that always pass (no event)
- `GLOBAL_DENYLIST`: Syscalls that always fail (log event)
- Per-process allow/deny lists for cached decisions

### Slow Path (Userspace)

- Unknown syscalls → event to daemon → policy evaluation
- Policy can use arbitrary I/O (HTTP, database, etc.)
- Decisions can be cached in eBPF maps for future fast-path

### No Circular Dependency

Unlike seccomp-unotify:
- eBPF daemon runs as a separate process
- It's NOT subject to eBPF interception (only traced processes are)
- No deadlock when making HTTP calls to Watchtower

## Next Steps

1. **Network interception** (Phase 3): cgroup/sockops for connect() tracking
2. **Policy caching**: Update eBPF maps with decisions from userspace
3. **Process tracking**: Implement PID filtering via TRACKED_PIDS map
4. **Tests**: Integration tests for eBPF program behavior