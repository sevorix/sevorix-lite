// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

//! Sevorix eBPF Daemon
//!
//! Userspace daemon that loads eBPF programs and processes events.
//!
//! # Architecture
//!
//! 1. Loads eBPF programs (syscall tracepoints, network sockops)
//! 2. Attaches to tracepoints and cgroups
//! 3. Consumes events from ring buffer
//! 4. Evaluates policy via HTTP to Watchtower
//! 5. Updates eBPF maps with policy decisions (enforcing future syscalls/connections)
//!
//! # Enforcement Model
//!
//! Syscall enforcement uses a caching/reactive model: the first occurrence of an
//! unknown syscall by a PID passes through while Watchtower evaluates it async.
//! On a BLOCK decision, the (pid, syscall_nr) pair is inserted into SYSCALL_DENYLIST
//! so all future occurrences are rejected at the kernel level without a userspace
//! round-trip.
//!
//! Network enforcement via sock_ops is synchronous for known entries (pre-populated
//! in NET_DENYLIST). Unknown connections pass through on first occurrence and are
//! blocked for future attempts after Watchtower returns a BLOCK decision.
//!
//! # Usage
//!
//! This binary is only functional when the `ebpf` feature is enabled:
//! ```sh
//! cargo build --features ebpf --bin sevorix-ebpf-daemon
//! ```

#[cfg(not(feature = "ebpf"))]
fn main() {
    eprintln!("Error: sevorix-ebpf-daemon requires the 'ebpf' feature.");
    eprintln!("Build with: cargo build --features ebpf --bin sevorix-ebpf-daemon");
    std::process::exit(1);
}

#[cfg(feature = "ebpf")]
mod ebpf_impl {
    use std::net::IpAddr;
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    use anyhow::{Context, Result};
    use aya::maps::RingBuf;
    use aya::programs::lsm::LsmLink;
    use aya::programs::{CgroupAttachMode, Lsm, SockOps, TracePoint};
    use aya::{Btf, Ebpf};
    use directories::ProjectDirs;
    use sevorix_core::{detect_enforcement_tier, EnforcementTier};
    use sevorix_ebpf_common::{NetworkEvent, NetworkKey, PolicyKey, SyscallEvent};
    use tokio::sync::{broadcast, Mutex};
    use tracing::{error, info, warn};

    /// Syscall numbers considered interesting enough to forward to Watchtower.
    /// Excludes high-frequency noise (read, write, futex, poll, etc.).
    const INTERESTING_SYSCALLS: &[u64] = &[
        2,   // open
        3,   // close
        56,  // clone
        57,  // fork
        58,  // vfork
        59,  // execve
        41,  // socket
        42,  // connect
        43,  // accept
        44,  // sendto
        87,  // unlink
        257, // openat
        263, // unlinkat
        322, // execveat
    ];

    fn syscall_name(nr: u64) -> String {
        match nr {
            0 => "read",
            1 => "write",
            2 => "open",
            3 => "close",
            4 => "stat",
            5 => "fstat",
            6 => "lstat",
            7 => "poll",
            8 => "lseek",
            9 => "mmap",
            10 => "mprotect",
            11 => "munmap",
            12 => "brk",
            20 => "writev",
            21 => "access",
            22 => "pipe",
            32 => "dup",
            33 => "dup2",
            39 => "getpid",
            41 => "socket",
            42 => "connect",
            43 => "accept",
            44 => "sendto",
            45 => "recvfrom",
            49 => "bind",
            50 => "listen",
            56 => "clone",
            57 => "fork",
            58 => "vfork",
            59 => "execve",
            60 => "exit",
            61 => "wait4",
            62 => "kill",
            63 => "uname",
            72 => "fcntl",
            79 => "getcwd",
            80 => "chdir",
            81 => "fchdir",
            82 => "rename",
            83 => "mkdir",
            84 => "rmdir",
            85 => "creat",
            86 => "link",
            87 => "unlink",
            88 => "symlink",
            89 => "readlink",
            90 => "chmod",
            92 => "chown",
            99 => "sysinfo",
            102 => "getuid",
            104 => "getgid",
            105 => "setuid",
            106 => "setgid",
            186 => "gettid",
            202 => "futex",
            218 => "set_tid_address",
            231 => "exit_group",
            257 => "openat",
            258 => "mkdirat",
            261 => "futimesat",
            263 => "unlinkat",
            264 => "renameat",
            265 => "linkat",
            266 => "symlinkat",
            267 => "readlinkat",
            268 => "fchmodat",
            269 => "faccessat",
            316 => "renameat2",
            318 => "getrandom",
            322 => "execveat",
            _ => "",
        }
        .to_string()
        .pipe(|s| {
            if s.is_empty() {
                format!("syscall_{}", nr)
            } else {
                s
            }
        })
    }

    /// Shared HTTP client — created once, reused for all policy query calls.
    static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

    fn http_client() -> &'static reqwest::Client {
        HTTP_CLIENT.get_or_init(reqwest::Client::new)
    }

    /// Semaphore limiting concurrent HTTP evaluations.
    ///
    /// Each `evaluate_and_enforce_syscall` / `evaluate_and_enforce_network` call opens
    /// a TCP socket (1 FD). Without a cap, a burst of ring-buffer events spawns unbounded
    /// tasks, quickly exhausting the process's 1024-FD soft limit and causing EMFILE.
    /// 64 permits leaves ~960 FDs headroom for eBPF maps, program links, tokio internals,
    /// the log file, and the Unix socket.
    static EVAL_SEM: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();

    fn eval_sem() -> &'static Arc<tokio::sync::Semaphore> {
        EVAL_SEM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(64)))
    }

    trait Pipe: Sized {
        fn pipe<F: FnOnce(Self) -> T, T>(self, f: F) -> T {
            f(self)
        }
    }
    impl<T> Pipe for T {}

    /// Policy decision returned by Watchtower's /analyze-syscall endpoint.
    #[derive(Debug, Clone, serde::Deserialize)]
    struct WatchtowerDecision {
        /// "allow", "block", or "kill"
        pub action: String,
        /// errno to return when blocking (e.g. EPERM=1, EACCES=13). Defaults to EPERM.
        #[serde(default)]
        pub errno: Option<i32>,
    }

    /// Structured policy rules returned by `GET /policies/ebpf`.
    #[derive(Debug, serde::Deserialize)]
    struct SyscallRule {
        syscall_nr: u64,
        errno: i32,
    }

    #[derive(Debug, serde::Deserialize)]
    struct EbpfPolicies {
        syscall_rules: Vec<SyscallRule>,
        // net_rules reserved for future use
        #[allow(dead_code)]
        net_rules: Vec<serde_json::Value>,
    }

    /// Shared, mutable handles to eBPF enforcement maps.
    ///
    /// Cloning is cheap — all fields are Arc-wrapped.
    #[derive(Clone)]
    struct PolicyMaps {
        syscall_denylist: Arc<Mutex<aya::maps::Map>>,
        net_denylist: Arc<Mutex<aya::maps::Map>>,
        global_denylist: Arc<Mutex<aya::maps::Map>>,
    }

    impl PolicyMaps {
        /// Insert (pid, syscall_nr) → errno into SYSCALL_DENYLIST.
        /// Future occurrences of this syscall by this PID will be rejected at the kernel level.
        ///
        /// Uses PolicyKey (repr(C) with explicit padding) as the map key — this has the same
        /// byte layout as the kernel-side (u32, u64) key and implements aya::Pod.
        async fn deny_syscall(&self, pid: u32, syscall_nr: u64, errno: i32) {
            let key = PolicyKey {
                pid,
                _padding: 0,
                id: syscall_nr,
            };
            let mut guard = self.syscall_denylist.lock().await;
            match aya::maps::HashMap::<_, PolicyKey, i32>::try_from(&mut *guard) {
                Ok(mut map) => match map.insert(key, errno, 0) {
                    Ok(_) => info!(
                        "eBPF: denied pid={} syscall={} errno={}",
                        pid, syscall_nr, errno
                    ),
                    Err(e) => warn!("eBPF: SYSCALL_DENYLIST insert failed: {}", e),
                },
                Err(e) => warn!("eBPF: failed to access SYSCALL_DENYLIST: {}", e),
            }
        }

        /// Insert dst_ip:dst_port → errno into NET_DENYLIST.
        /// Future TCP connections to this destination will be rejected by sock_ops.
        async fn deny_network(&self, dst_ip: u32, dst_port: u16, errno: i32) {
            let mut guard = self.net_denylist.lock().await;
            match aya::maps::HashMap::<_, NetworkKey, i32>::try_from(&mut *guard) {
                Ok(mut map) => {
                    let key = NetworkKey {
                        dst_ip,
                        dst_port,
                        protocol: 6,
                        _padding: 0,
                    };
                    match map.insert(key, errno, 0) {
                        Ok(_) => info!(
                            "eBPF: denied network dst_ip={} dst_port={}",
                            dst_ip, dst_port
                        ),
                        Err(e) => warn!("eBPF: NET_DENYLIST insert failed: {}", e),
                    }
                }
                Err(e) => warn!("eBPF: failed to access NET_DENYLIST: {}", e),
            }
        }
    }

    /// Query Watchtower for a policy decision on a syscall, then enforce via eBPF maps.
    ///
    /// On BLOCK: inserts into SYSCALL_DENYLIST so future calls are rejected in-kernel.
    /// On ALLOW: no map update — every occurrence is evaluated (correctness > fast-path).
    /// On KILL:  sends SIGKILL to the process and also denies the syscall.
    async fn evaluate_and_enforce_syscall(
        watchtower_url: String,
        pid: u32,
        syscall_nr: u64,
        args: [u64; 6],
        maps: PolicyMaps,
    ) {
        let name = syscall_name(syscall_nr);
        let args_str: Vec<String> = args.iter().map(|a| format!("0x{:x}", a)).collect();
        let payload = serde_json::json!({
            "syscall_name": name,
            "syscall_number": syscall_nr as i64,
            "args": args_str,
            "pid": pid,
            "ppid": 0,
            "timestamp": chrono::Local::now().to_rfc3339(),
        });

        let resp = match http_client()
            .post(format!("{}/analyze-syscall", watchtower_url))
            .header("X-Sevorix-Internal", "true")
            .json(&payload)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to query Watchtower for syscall: {}", e);
                return;
            }
        };

        let decision: WatchtowerDecision = match resp.json().await {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to parse Watchtower syscall decision: {}", e);
                return;
            }
        };

        match decision.action.as_str() {
            "block" => {
                let errno = decision.errno.unwrap_or(libc::EPERM);
                maps.deny_syscall(pid, syscall_nr, errno).await;
            }
            "kill" => {
                let errno = decision.errno.unwrap_or(libc::EPERM);
                unsafe {
                    if libc::kill(pid as libc::pid_t, libc::SIGKILL) != 0 {
                        warn!("Failed to SIGKILL pid={}", pid);
                    } else {
                        info!("eBPF: sent SIGKILL to pid={} for policy violation", pid);
                    }
                }
                maps.deny_syscall(pid, syscall_nr, errno).await;
            }
            "allow" => {
                // No map update — SYSCALL_ALLOWLIST removed to prevent stale
                // fast-path entries causing missed logs after PID reuse.
            }
            other => {
                warn!(
                    "Unknown Watchtower action '{}' for syscall; defaulting to allow",
                    other
                );
            }
        }
    }

    /// Query Watchtower for a policy decision on a network connection, then enforce via eBPF maps.
    ///
    /// Formats the connection as a "connect" syscall event to reuse the existing
    /// /analyze-syscall endpoint. On BLOCK/KILL, inserts into NET_DENYLIST so future
    /// connections to the same destination are rejected by sock_ops in-kernel.
    async fn evaluate_and_enforce_network(
        watchtower_url: String,
        pid: u32,
        dst_ip_str: String,
        dst_ip: u32,
        dst_port: u16,
        maps: PolicyMaps,
    ) {
        let payload = serde_json::json!({
            "syscall_name": "connect",
            "syscall_number": 42i64,
            "args": [format!("{}:{}", dst_ip_str, dst_port), "TCP"],
            "pid": pid,
            "ppid": 0,
            "timestamp": chrono::Local::now().to_rfc3339(),
        });

        let resp = match http_client()
            .post(format!("{}/analyze-syscall", watchtower_url))
            .header("X-Sevorix-Internal", "true")
            .json(&payload)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to query Watchtower for network event: {}", e);
                return;
            }
        };

        let decision: WatchtowerDecision = match resp.json().await {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to parse Watchtower network decision: {}", e);
                return;
            }
        };

        match decision.action.as_str() {
            "block" | "kill" => {
                let errno = decision.errno.unwrap_or(libc::EPERM);
                maps.deny_network(dst_ip, dst_port, errno).await;

                // Log blocked network event to Watchtower for audit trail
                let log_payload = serde_json::json!({
                    "event_type": "network",
                    "verdict": "BLOCK",
                    "lane": "RED",
                    "layer": "network",
                    "payload": format!("connect to {}:{}", dst_ip_str, dst_port),
                    "timestamp": chrono::Local::now().to_rfc3339(),
                    "latency": 0,
                    "reason": format!("Network connection blocked (errno={})", errno),
                    "confidence": "Policy Match",
                    "context": "Network",
                    "pid": pid,
                    "destination": format!("{}:{}", dst_ip_str, dst_port),
                });

                if let Err(e) = http_client()
                    .post(format!("{}/api/ebpf-event", watchtower_url))
                    .header("X-Sevorix-Internal", "true")
                    .json(&log_payload)
                    .send()
                    .await
                {
                    warn!("Failed to log blocked network event to Watchtower: {}", e);
                }
            }
            _ => {} // allow / unknown: no map update needed
        }
    }

    /// Fetch policy rules from Watchtower and pre-populate eBPF enforcement maps.
    ///
    /// Handle a single cgroup registration connection on the eBPF Unix socket.
    ///
    /// Reads a JSON line `{"cgroup_path":"..."}`, stats the path for its inode,
    /// inserts it into `SEVORIX_CGROUP_IDS`, prefills policy maps, and sends ACK.
    async fn handle_cgroup_registration(
        stream: tokio::net::UnixStream,
        map: Arc<tokio::sync::Mutex<aya::maps::Map>>,
        pmaps: PolicyMaps,
        wt_url: String,
    ) {
        use aya::maps::HashMap;
        use std::os::unix::fs::MetadataExt;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let (reader, mut writer) = stream.into_split();
        let line = match BufReader::new(reader).lines().next_line().await {
            Ok(Some(l)) => l,
            _ => return,
        };
        let v: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => return,
        };
        let path = match v["cgroup_path"].as_str() {
            Some(p) => p,
            None => return,
        };
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                warn!("eBPF socket: stat({}) failed: {}", path, e);
                let _ = writer.write_all(b"{\"ok\":false}\n").await;
                return;
            }
        };
        let ino = meta.ino();
        let mut guard = map.lock().await;
        match HashMap::<_, u64, u8>::try_from(&mut *guard) {
            Ok(mut ids_map) => match ids_map.insert(ino, 1u8, 0) {
                Ok(_) => {
                    info!("eBPF socket: registered cgroup path={} ino={}", path, ino);
                    drop(guard);
                    prefill_policy_maps(&wt_url, &pmaps).await;
                    let _ = writer.write_all(b"{\"ok\":true}\n").await;
                }
                Err(e) => {
                    warn!("eBPF socket: SEVORIX_CGROUP_IDS insert failed: {}", e);
                    let _ = writer.write_all(b"{\"ok\":false}\n").await;
                }
            },
            Err(e) => {
                warn!("eBPF socket: failed to access SEVORIX_CGROUP_IDS: {}", e);
                let _ = writer.write_all(b"{\"ok\":false}\n").await;
            }
        }
    }

    /// Called at daemon startup and on each new session cgroup creation to close the
    /// first-occurrence gap: without pre-population, the first forbidden syscall passes
    /// through (triggering the feedback loop for future calls). With pre-population,
    /// GLOBAL_DENYLIST is filled before any session process runs.
    async fn prefill_policy_maps(watchtower_url: &str, maps: &PolicyMaps) {
        let resp = match http_client()
            .get(format!("{}/policies/ebpf", watchtower_url))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!("Policy prefill: failed to fetch /policies/ebpf: {}", e);
                return;
            }
        };

        let policies: EbpfPolicies = match resp.json().await {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    "Policy prefill: failed to parse /policies/ebpf response: {}",
                    e
                );
                return;
            }
        };

        if policies.syscall_rules.is_empty() {
            info!("Policy prefill: no syscall rules to populate");
            return;
        }

        let mut guard = maps.global_denylist.lock().await;
        match aya::maps::HashMap::<_, u64, i32>::try_from(&mut *guard) {
            Ok(mut map) => {
                for rule in &policies.syscall_rules {
                    match map.insert(rule.syscall_nr, rule.errno, 0) {
                        Ok(_) => info!(
                            "Policy prefill: GLOBAL_DENYLIST[syscall={}] = errno={}",
                            rule.syscall_nr, rule.errno
                        ),
                        Err(e) => warn!(
                            "Policy prefill: GLOBAL_DENYLIST insert failed for syscall={}: {}",
                            rule.syscall_nr, e
                        ),
                    }
                }
                info!(
                    "Policy prefill complete: {} syscall rules applied to GLOBAL_DENYLIST",
                    policies.syscall_rules.len()
                );
            }
            Err(e) => warn!("Policy prefill: failed to access GLOBAL_DENYLIST: {}", e),
        }
    }

    fn write_pid_file() -> Result<()> {
        let proj_dirs = ProjectDirs::from("com", "sevorix", "sevorix")
            .ok_or_else(|| anyhow::anyhow!("Could not determine project directories"))?;
        let state_dir = proj_dirs
            .state_dir()
            .unwrap_or_else(|| proj_dirs.cache_dir());
        std::fs::create_dir_all(state_dir)?;
        let pid_path = state_dir.join("sevorix-ebpf.pid");
        std::fs::write(&pid_path, std::process::id().to_string())?;
        Ok(())
    }

    /// Event received from eBPF program (used for dashboard broadcast).
    // Fields are written via broadcast::Sender and will be consumed by future dashboard subscribers.
    #[allow(dead_code)]
    #[derive(Debug, Clone)]
    pub struct EbpfEvent {
        pub event_type: EventType,
        pub pid: u32,
        pub tid: u32,
        pub timestamp: u64,
        pub data: serde_json::Value,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EventType {
        SyscallEntry,
        SyscallExit,
        Network,
    }

    /// Daemon configuration.
    #[derive(Debug, Clone)]
    pub struct DaemonConfig {
        pub watchtower_url: String,
        pub cgroup_path: String,
    }

    impl Default for DaemonConfig {
        fn default() -> Self {
            Self {
                watchtower_url: "http://localhost:3000".to_string(),
                cgroup_path: "/sys/fs/cgroup".to_string(),
            }
        }
    }

    /// Load and attach eBPF programs.
    /// Load and attach all eBPF programs.
    ///
    /// Returns any LSM links that must stay alive for the program lifetime.
    /// Dropping an `LsmLink` detaches the program from the kernel.
    pub fn load_and_attach(
        bpf: &mut Ebpf,
        cgroup_path: &str,
        tier: EnforcementTier,
    ) -> Result<Vec<LsmLink>> {
        info!("Attaching eBPF programs (tier: {})...", tier);

        let sys_enter: &mut TracePoint = bpf
            .program_mut("sys_enter")
            .context("Failed to get sys_enter program")?
            .try_into()
            .context("Failed to convert sys_enter to TracePoint")?;
        sys_enter.load()?;
        sys_enter.attach("raw_syscalls", "sys_enter")?;
        info!("sys_enter tracepoint attached");

        let sys_exit: &mut TracePoint = bpf
            .program_mut("sys_exit")
            .context("Failed to get sys_exit program")?
            .try_into()
            .context("Failed to convert sys_exit to TracePoint")?;
        sys_exit.load()?;
        sys_exit.attach("raw_syscalls", "sys_exit")?;
        info!("sys_exit tracepoint attached");

        let sock_ops: &mut SockOps = bpf
            .program_mut("sock_ops")
            .context("Failed to get sock_ops program")?
            .try_into()
            .context("Failed to convert sock_ops to SockOps")?;
        sock_ops.load()?;

        let cgroup_file = std::fs::File::open(cgroup_path)
            .with_context(|| format!("Failed to open cgroup: {}", cgroup_path))?;
        sock_ops.attach(cgroup_file, CgroupAttachMode::Single)?;
        info!("Sockops attached to cgroup: {}", cgroup_path);

        // On Advanced tier: load and attach BPF LSM programs.
        // These provide true enforcement (unlike tracepoints, LSM hook returns are enforced).
        // Failure is non-fatal — log a warning and continue with Standard-tier enforcement.
        let mut lsm_links: Vec<LsmLink> = Vec::new();
        if tier == EnforcementTier::Advanced {
            match Btf::from_sys_fs() {
                Ok(btf) => {
                    attach_lsm(bpf, "bprm_check_security", &btf, &mut lsm_links);
                    attach_lsm(bpf, "lsm_socket_connect", &btf, &mut lsm_links);
                    if lsm_links.is_empty() {
                        warn!("Advanced tier: no LSM programs attached — falling back to Standard-tier enforcement");
                    } else {
                        info!("Advanced tier: {} LSM program(s) attached", lsm_links.len());
                    }
                }
                Err(e) => {
                    warn!("Advanced tier: BTF unavailable ({}), falling back to Standard-tier enforcement", e);
                }
            }
        }

        info!("eBPF programs loaded and attached successfully");
        Ok(lsm_links)
    }

    /// Attempt to load and attach a single BPF LSM program by name.
    ///
    /// On success, takes ownership of the link and pushes it into `links`.
    /// On failure, logs a warning and returns — non-fatal.
    fn attach_lsm(bpf: &mut Ebpf, prog_name: &str, btf: &Btf, links: &mut Vec<LsmLink>) {
        // The hook name passed to lsm.load() is the kernel LSM hook name,
        // which matches the aya #[lsm(hook = "...")] attribute.
        // prog_name may differ from hook_name (e.g. "lsm_socket_connect" → "socket_connect").
        let hook_name = prog_name.trim_start_matches("lsm_");

        let prog: &mut Lsm = match bpf.program_mut(prog_name).and_then(|p| p.try_into().ok()) {
            Some(p) => p,
            None => {
                warn!("LSM program '{}' not found in eBPF object", prog_name);
                return;
            }
        };

        if let Err(e) = prog.load(hook_name, btf) {
            warn!("Failed to load LSM program '{}': {}", prog_name, e);
            return;
        }

        match prog.attach() {
            Ok(link_id) => match prog.take_link(link_id) {
                Ok(link) => {
                    info!("LSM program '{}' attached (hook: {})", prog_name, hook_name);
                    links.push(link);
                }
                Err(e) => warn!("Failed to take LSM link for '{}': {}", prog_name, e),
            },
            Err(e) => warn!("Failed to attach LSM program '{}': {}", prog_name, e),
        }
    }

    /// Process a single event from the ring buffer.
    fn process_event(
        data: &[u8],
        event_tx: &broadcast::Sender<EbpfEvent>,
        watchtower_url: &str,
        maps: &PolicyMaps,
    ) -> Result<()> {
        if data.len() < 4 {
            warn!("Event data too short: {} bytes", data.len());
            return Ok(());
        }

        let event_type = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);

        match event_type {
            SyscallEvent::EVENT_TYPE => {
                if data.len() < std::mem::size_of::<SyscallEvent>() {
                    warn!("SyscallEvent data too short: {} bytes", data.len());
                    return Ok(());
                }
                let event = parse_syscall_event(data)?;
                handle_syscall_event(
                    event,
                    event_tx,
                    EventType::SyscallEntry,
                    watchtower_url,
                    maps,
                )?;
            }
            SyscallEvent::EVENT_TYPE_EXIT => {
                if data.len() < std::mem::size_of::<SyscallEvent>() {
                    warn!("SyscallEvent (exit) data too short: {} bytes", data.len());
                    return Ok(());
                }
                let event = parse_syscall_event(data)?;
                handle_syscall_event(
                    event,
                    event_tx,
                    EventType::SyscallExit,
                    watchtower_url,
                    maps,
                )?;
            }
            NetworkEvent::EVENT_TYPE => {
                if data.len() < std::mem::size_of::<NetworkEvent>() {
                    warn!("NetworkEvent data too short: {} bytes", data.len());
                    return Ok(());
                }
                let event = parse_network_event(data)?;
                handle_network_event(event, event_tx, watchtower_url, maps)?;
            }
            _ => {
                warn!("Unknown event type: {}", event_type);
            }
        }

        Ok(())
    }

    fn parse_syscall_event(data: &[u8]) -> Result<SyscallEvent> {
        if data.len() < std::mem::size_of::<SyscallEvent>() {
            anyhow::bail!("SyscallEvent data too short");
        }
        Ok(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const SyscallEvent) })
    }

    fn parse_network_event(data: &[u8]) -> Result<NetworkEvent> {
        if data.len() < std::mem::size_of::<NetworkEvent>() {
            anyhow::bail!("NetworkEvent data too short");
        }
        Ok(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const NetworkEvent) })
    }

    /// Handle a syscall event: broadcast to dashboard and spawn policy evaluation if interesting.
    fn handle_syscall_event(
        event: SyscallEvent,
        event_tx: &broadcast::Sender<EbpfEvent>,
        event_type: EventType,
        watchtower_url: &str,
        maps: &PolicyMaps,
    ) -> Result<()> {
        let ebpf_event = EbpfEvent {
            event_type,
            pid: event.pid,
            tid: event.tid,
            timestamp: event.timestamp,
            data: serde_json::json!({
                "syscall_nr": event.syscall_nr,
                "args": event.args,
            }),
        };

        if event_type == EventType::SyscallEntry && INTERESTING_SYSCALLS.contains(&event.syscall_nr)
        {
            info!(
                "Syscall entry: pid={}, syscall={}",
                event.pid,
                syscall_name(event.syscall_nr)
            );
            if let Ok(permit) = eval_sem().clone().try_acquire_owned() {
                let url = watchtower_url.to_string();
                let maps = maps.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    evaluate_and_enforce_syscall(
                        url,
                        event.pid,
                        event.syscall_nr,
                        event.args,
                        maps,
                    )
                    .await;
                });
            } else {
                tracing::trace!(
                    "eval semaphore full — dropping syscall event pid={} nr={}",
                    event.pid,
                    event.syscall_nr
                );
            }
        }

        let _ = event_tx.send(ebpf_event);
        Ok(())
    }

    /// Handle a network event: broadcast to dashboard and spawn policy evaluation.
    fn handle_network_event(
        event: NetworkEvent,
        event_tx: &broadcast::Sender<EbpfEvent>,
        watchtower_url: &str,
        maps: &PolicyMaps,
    ) -> Result<()> {
        let dst_ip = u32::from_be(event.dst_ip);
        let src_ip = u32::from_be(event.src_ip);
        let dst_ip_addr = IpAddr::from(std::net::Ipv4Addr::from(dst_ip));
        let src_ip_addr = IpAddr::from(std::net::Ipv4Addr::from(src_ip));
        let dst_port = u16::from_be(event.dst_port);
        let src_port = u16::from_be(event.src_port);

        // Fix 1: Drop LSM pre-bind events. When src_port=0 the socket hasn't been
        // bound yet — a duplicate sock_ops event with full port info always follows.
        if src_port == 0 {
            return Ok(());
        }

        // Fix 2: Skip internal control-plane traffic destined for Watchtower itself.
        // These are loopback connections from sevsh (health checks, session mgmt) and
        // from this daemon (event logging), and would otherwise create a feedback loop.
        let watchtower_port = watchtower_url
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(3000);
        if dst_ip_addr.is_loopback() && dst_port == watchtower_port {
            return Ok(());
        }

        info!(
            "Network event: pid={}, dst={}:{} (protocol={})",
            event.pid, dst_ip_addr, dst_port, event.protocol
        );

        let ebpf_event = EbpfEvent {
            event_type: EventType::Network,
            pid: event.pid,
            tid: event.tid,
            timestamp: event.timestamp,
            data: serde_json::json!({
                "dst_ip": dst_ip_addr.to_string(),
                "dst_port": dst_port,
                "src_ip": src_ip_addr.to_string(),
                "src_port": src_port,
                "protocol": event.protocol,
                "op": event.op,
            }),
        };

        // Log network event to Watchtower for audit trail (async, non-blocking)
        let log_url = watchtower_url.to_string();
        let log_dst_ip = dst_ip_addr.to_string();
        let log_pid = event.pid;
        tokio::spawn(async move {
            let log_payload = serde_json::json!({
                "event_type": "network",
                "verdict": "EVENT",
                "lane": "GREEN",
                "layer": "network",
                "payload": format!("connect to {}:{} (protocol={})", log_dst_ip, dst_port, event.protocol),
                "timestamp": chrono::Local::now().to_rfc3339(),
                "latency": 0,
                "reason": "Network connection observed",
                "confidence": "N/A",
                "context": "Network",
                "pid": log_pid,
                "destination": format!("{}:{}", log_dst_ip, dst_port),
            });

            if let Err(e) = http_client()
                .post(format!("{}/api/ebpf-event", log_url))
                .header("X-Sevorix-Internal", "true")
                .json(&log_payload)
                .send()
                .await
            {
                tracing::trace!("Failed to log network event to Watchtower: {}", e);
            }
        });

        // Spawn policy evaluation. The first connection to an unknown destination
        // passes through; on BLOCK, the destination is added to NET_DENYLIST so
        // future connections are rejected by sock_ops in-kernel.
        if let Ok(permit) = eval_sem().clone().try_acquire_owned() {
            let url = watchtower_url.to_string();
            let maps = maps.clone();
            let dst_ip_str = dst_ip_addr.to_string();
            tokio::spawn(async move {
                let _permit = permit;
                evaluate_and_enforce_network(
                    url,
                    event.pid,
                    dst_ip_str,
                    event.dst_ip,
                    dst_port,
                    maps,
                )
                .await;
            });
        } else {
            tracing::trace!(
                "eval semaphore full — dropping network event pid={} dst={}:{}",
                event.pid,
                dst_ip_addr,
                dst_port
            );
        }

        let _ = event_tx.send(ebpf_event);
        Ok(())
    }

    /// Write a diagnostic line before tracing is initialized.
    fn diag(msg: &str) {
        let line = format!("[{}] {}\n", std::process::id(), msg);
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/sevorix-ebpf-daemon-diag.log")
        {
            let _ = f.write_all(line.as_bytes());
        }
    }

    pub fn run() -> Result<()> {
        diag("run() entered");

        write_pid_file().context("Failed to write eBPF daemon PID file")?;
        diag("PID file written");

        let log_path = std::env::var("SEVORIX_EBPF_LOG")
            .unwrap_or_else(|_| "/tmp/sevorix-ebpf-daemon.log".to_string());
        diag(&format!("log path = {}", log_path));
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .unwrap_or_else(|_| {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("/tmp/sevorix-ebpf-daemon-fallback.log")
                    .expect("cannot open any log file")
            });
        tracing_subscriber::fmt()
            .with_writer(std::sync::Mutex::new(log_file))
            .init();
        diag("tracing initialized");

        tokio::runtime::Runtime::new()
            .context("Failed to create tokio runtime")?
            .block_on(async {
                info!("Sevorix eBPF Daemon starting...");

                let tier = detect_enforcement_tier();
                info!("Enforcement tier: {}", tier);
                if tier == EnforcementTier::Standard {
                    info!("  (BPF LSM unavailable — 'bpf' not in /sys/kernel/security/lsm)");
                }

                let config = DaemonConfig::default();
                let (event_tx, _) = broadcast::channel(1024);

                info!("Loading eBPF programs...");

                let ebpf_path = std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(|d| d.join("sevorix-ebpf")))
                    .filter(|p| p.exists())
                    .unwrap_or_else(|| {
                        std::path::PathBuf::from(
                            "target/bpfel-unknown-none/release/sevorix-ebpf",
                        )
                    });

                let mut bpf = if ebpf_path.exists() {
                    let bytes = std::fs::read(&ebpf_path)
                        .context("Failed to read eBPF binary")?;
                    Ebpf::load(&bytes)?
                } else {
                    warn!("eBPF binary not found at {:?}", ebpf_path);
                    warn!("Please compile the eBPF program first:");
                    warn!("  cargo build --target bpfel-unknown-none -Zbuild-std --release -p sevorix-ebpf");
                    anyhow::bail!("eBPF binary not found");
                };

                // _lsm_links must stay alive for the duration of the daemon.
                // Dropping them would detach the BPF LSM programs from the kernel.
                let _lsm_links = load_and_attach(&mut bpf, &config.cgroup_path, tier)?;

                // Extract enforcement maps before taking the ring buffer.
                // Wrapped in Arc<Mutex<>> so they can be shared across async tasks.
                let policy_maps = PolicyMaps {
                    syscall_denylist: Arc::new(Mutex::new(
                        bpf.take_map("SYSCALL_DENYLIST")
                            .context("SYSCALL_DENYLIST map not found in eBPF object")?,
                    )),
                    net_denylist: Arc::new(Mutex::new(
                        bpf.take_map("NET_DENYLIST")
                            .context("NET_DENYLIST map not found in eBPF object")?,
                    )),
                    global_denylist: Arc::new(Mutex::new(
                        bpf.take_map("GLOBAL_DENYLIST")
                            .context("GLOBAL_DENYLIST map not found in eBPF object")?,
                    )),
                };
                info!("eBPF enforcement maps acquired");

                // Pre-populate maps at startup so any already-running sessions get
                // the current policy set applied without waiting for first occurrence.
                prefill_policy_maps(&config.watchtower_url, &policy_maps).await;

                let sevorix_cgroup_base = "/sys/fs/cgroup/sevorix";
                if let Err(e) = std::fs::create_dir_all(sevorix_cgroup_base) {
                    warn!(
                        "Could not create sevorix cgroup base {}: {}",
                        sevorix_cgroup_base, e
                    );
                }

                let cgroup_ids_map = bpf.take_map("SEVORIX_CGROUP_IDS");
                let events_map = bpf.map("EVENTS").context("Failed to get EVENTS map")?;
                let mut ring_buf = RingBuf::try_from(events_map)
                    .context("Failed to create RingBuf from EVENTS map")?;

                // Background task: sync active sevorix session cgroup IDs into the BPF map.
                if let Some(cgroup_map_raw) = cgroup_ids_map {
                    // Wrap in Arc<Mutex> so both the inotify task and the fast-poll task can share it.
                    let shared_cgroup_map = Arc::new(Mutex::new(cgroup_map_raw));
                    let cgroup_maps = policy_maps.clone();
                    let cgroup_watchtower_url = config.watchtower_url.clone();

                    // Unix socket listener: synchronous cgroup registration.
                    // Watchtower's session_register handler connects here immediately after
                    // creating the cgroup, sends {"cgroup_path":"..."}, and waits for ACK.
                    // This ensures SEVORIX_CGROUP_IDS is updated before sevsh runs the child.
                    {
                        use tokio::net::UnixListener;
                        use sevorix_watchtower::EBPF_SOCK_PATH;

                        let _ = std::fs::remove_file(EBPF_SOCK_PATH);
                        let socket_cgroup_map = shared_cgroup_map.clone();
                        let socket_policy_maps = policy_maps.clone();
                        let socket_watchtower_url = config.watchtower_url.clone();

                        match UnixListener::bind(EBPF_SOCK_PATH) {
                            Ok(listener) => {
                                // Make socket world-writable so unprivileged watchtower can connect.
                                let _ = std::fs::set_permissions(
                                    EBPF_SOCK_PATH,
                                    std::os::unix::fs::PermissionsExt::from_mode(0o666),
                                );
                                info!("Unix socket listener bound at {}", EBPF_SOCK_PATH);
                                tokio::spawn(async move {
                                    loop {
                                        match listener.accept().await {
                                            Ok((stream, _)) => {
                                                let map = socket_cgroup_map.clone();
                                                let pmaps = socket_policy_maps.clone();
                                                let wt_url = socket_watchtower_url.clone();
                                                tokio::spawn(handle_cgroup_registration(stream, map, pmaps, wt_url));
                                            }
                                            Err(e) => {
                                                warn!("eBPF socket: accept error: {}", e);
                                                tokio::time::sleep(Duration::from_millis(1)).await;
                                            }
                                        }
                                    }
                                });
                            }
                            Err(e) => warn!("eBPF socket: failed to bind {}: {} — synchronous registration disabled", EBPF_SOCK_PATH, e),
                        }
                    }

                    // Fast-poll task: polls /api/active-sessions every 200ms and syncs
                    // SEVORIX_CGROUP_IDS from the returned paths. This closes the race
                    // condition where fast commands complete before the inotify watcher
                    // detects the new cgroup.
                    let fast_poll_map = shared_cgroup_map.clone();
                    let fast_poll_url = config.watchtower_url.clone();
                    let fast_poll_maps = policy_maps.clone();
                    tokio::spawn(async move {
                        use aya::maps::HashMap;
                        use std::collections::HashSet;
                        use std::os::unix::fs::MetadataExt;

                        let mut known: HashSet<u64> = HashSet::new();
                        loop {
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            // Fetch active sessions from Watchtower
                            let sessions: Vec<String> = match http_client()
                                .get(format!("{}/api/active-sessions", fast_poll_url))
                                .send()
                                .await
                            {
                                Ok(resp) => resp
                                    .json::<serde_json::Value>()
                                    .await
                                    .ok()
                                    .and_then(|v| v["sessions"].as_array().cloned())
                                    .unwrap_or_default()
                                    .into_iter()
                                    .filter_map(|s| s.as_str().map(str::to_string))
                                    .collect(),
                                Err(_) => continue,
                            };

                            // Stat each path to get its inode (cgroup ID)
                            let active: HashSet<u64> = sessions
                                .iter()
                                .filter_map(|p| std::fs::metadata(p).ok().map(|m| m.ino()))
                                .collect();

                            // Sync map
                            let mut any_new = false;
                            let mut guard = fast_poll_map.lock().await;
                            if let Ok(mut ids_map) = HashMap::<_, u64, u8>::try_from(&mut *guard) {
                                for &id in active.difference(&known) {
                                    if ids_map.insert(id, 1u8, 0).is_ok() {
                                        tracing::info!(
                                            "eBPF fast-poll: added session cgroup id={}",
                                            id
                                        );
                                        any_new = true;
                                    }
                                }
                                for &id in known.difference(&active) {
                                    let _ = ids_map.remove(&id);
                                    tracing::info!(
                                        "eBPF fast-poll: removed session cgroup id={}",
                                        id
                                    );
                                }
                            }
                            drop(guard);
                            known = active;
                            if any_new {
                                prefill_policy_maps(&fast_poll_url, &fast_poll_maps).await;
                            }
                        }
                    });

                    let cgroup_map_arc = shared_cgroup_map;
                    let cgroup_maps = cgroup_maps;
                    let cgroup_watchtower_url = cgroup_watchtower_url;
                    tokio::spawn(async move {
                        use aya::maps::HashMap;
                        use inotify::{Inotify, WatchMask};
                        use std::collections::HashSet;
                        use std::os::unix::fs::MetadataExt;

                        fn scan_cgroup_ids(base: &str) -> HashSet<u64> {
                            let mut ids = HashSet::new();
                            if let Ok(rd) = std::fs::read_dir(base) {
                                for entry in rd.flatten() {
                                    if let Ok(meta) = entry.metadata() {
                                        if meta.is_dir() {
                                            ids.insert(meta.ino());
                                        }
                                    }
                                }
                            }
                            ids
                        }

                        /// Returns true if any new session cgroups were added.
                        fn sync_map(
                            cgroup_map: &mut aya::maps::Map,
                            known: &mut HashSet<u64>,
                            active: &HashSet<u64>,
                        ) -> bool {
                            let mut any_new = false;
                            if let Ok(mut ids_map) =
                                HashMap::<_, u64, u8>::try_from(&mut *cgroup_map)
                            {
                                for &id in active.difference(known) {
                                    if ids_map.insert(id, 1u8, 0).is_ok() {
                                        tracing::info!(
                                            "eBPF cgroup filter: added session cgroup id={}",
                                            id
                                        );
                                        any_new = true;
                                    }
                                }
                                for &id in known.difference(active) {
                                    let _ = ids_map.remove(&id);
                                    tracing::info!(
                                        "eBPF cgroup filter: removed session cgroup id={}",
                                        id
                                    );
                                }
                            }
                            *known = active.clone();
                            any_new
                        }

                        let mut known: HashSet<u64> = HashSet::new();
                        let active = scan_cgroup_ids(sevorix_cgroup_base);
                        // Initial sync — any already-running sessions are covered by the
                        // startup prefill call in run(), so we don't re-prefill here.
                        {
                            let mut guard = cgroup_map_arc.lock().await;
                            sync_map(&mut *guard, &mut known, &active);
                        }

                        let inotify_result = Inotify::init().and_then(|mut i| {
                            i.add_watch(
                                sevorix_cgroup_base,
                                WatchMask::CREATE | WatchMask::DELETE,
                            )?;
                            Ok(i)
                        });

                        let mut buf = [0u8; 4096];

                        match inotify_result {
                            Ok(inotify) => {
                                use std::os::unix::io::AsRawFd;
                                use tokio::io::unix::AsyncFd;

                                let fd = inotify.as_raw_fd();
                                unsafe {
                                    libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
                                }

                                let async_fd = match AsyncFd::new(inotify) {
                                    Ok(a) => a,
                                    Err(e) => {
                                        warn!(
                                            "AsyncFd init failed ({}), falling back to polling",
                                            e
                                        );
                                        loop {
                                            tokio::time::sleep(Duration::from_millis(500)).await;
                                            let any_new = {
                                                let mut guard = cgroup_map_arc.lock().await;
                                                sync_map(
                                                    &mut *guard,
                                                    &mut known,
                                                    &scan_cgroup_ids(sevorix_cgroup_base),
                                                )
                                            };
                                            if any_new {
                                                prefill_policy_maps(&cgroup_watchtower_url, &cgroup_maps).await;
                                            }
                                        }
                                    }
                                };

                                let mut rescan =
                                    tokio::time::interval(Duration::from_secs(5));
                                rescan.tick().await;

                                loop {
                                    tokio::select! {
                                        ready = async_fd.readable() => {
                                            if let Ok(mut guard) = ready {
                                                guard.clear_ready();
                                                unsafe {
                                                    libc::read(
                                                        fd,
                                                        buf.as_mut_ptr() as *mut _,
                                                        buf.len(),
                                                    );
                                                }
                                            }
                                            tokio::time::sleep(Duration::from_millis(10)).await;
                                            let any_new = {
                                                let mut guard = cgroup_map_arc.lock().await;
                                                sync_map(
                                                    &mut *guard,
                                                    &mut known,
                                                    &scan_cgroup_ids(sevorix_cgroup_base),
                                                )
                                            };
                                            if any_new {
                                                prefill_policy_maps(&cgroup_watchtower_url, &cgroup_maps).await;
                                            }
                                        },
                                        _ = rescan.tick() => {
                                            let mut guard = cgroup_map_arc.lock().await;
                                            sync_map(
                                                &mut *guard,
                                                &mut known,
                                                &scan_cgroup_ids(sevorix_cgroup_base),
                                            );
                                        },
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "inotify unavailable ({}), falling back to 500ms polling",
                                    e
                                );
                                loop {
                                    tokio::time::sleep(Duration::from_millis(500)).await;
                                    let any_new = {
                                        let mut guard = cgroup_map_arc.lock().await;
                                        sync_map(
                                            &mut *guard,
                                            &mut known,
                                            &scan_cgroup_ids(sevorix_cgroup_base),
                                        )
                                    };
                                    if any_new {
                                        prefill_policy_maps(&cgroup_watchtower_url, &cgroup_maps).await;
                                    }
                                }
                            }
                        }
                    });
                } else {
                    warn!("SEVORIX_CGROUP_IDS map not found — cgroup filtering disabled");
                }

                info!("Ring buffer ready, waiting for sevorix session events...");

                loop {
                    let mut processed = 0u32;
                    while let Some(event) = ring_buf.next() {
                        if let Err(e) = process_event(
                            &event,
                            &event_tx,
                            &config.watchtower_url,
                            &policy_maps,
                        ) {
                            error!("Failed to process event: {}", e);
                        }
                        processed += 1;
                        if processed % 64 == 0 {
                            tokio::task::yield_now().await;
                        }
                    }

                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
    }
}

#[cfg(feature = "ebpf")]
fn main() {
    if let Err(e) = ebpf_impl::run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "ebpf")]
    use super::ebpf_impl::*;

    #[cfg(feature = "ebpf")]
    #[test]
    fn test_daemon_config_default() {
        let config = DaemonConfig::default();
        assert_eq!(config.watchtower_url, "http://localhost:3000");
        assert_eq!(config.cgroup_path, "/sys/fs/cgroup");
    }
}
