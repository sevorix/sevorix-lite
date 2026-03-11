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
//! 5. Updates eBPF maps with policy decisions
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
    use std::sync::OnceLock;
    use std::time::Duration;

    use anyhow::{Context, Result};
    use aya::maps::RingBuf;
    use aya::programs::{CgroupAttachMode, SockOps, TracePoint};
    use aya::Ebpf;
    use directories::ProjectDirs;
    use sevorix_ebpf_common::{NetworkEvent, SyscallEvent};
    use tokio::sync::broadcast;
    use tracing::{error, info, warn};

    /// Syscall numbers considered interesting enough to forward to watchtower.
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
            0 => "read", 1 => "write", 2 => "open", 3 => "close",
            4 => "stat", 5 => "fstat", 6 => "lstat", 7 => "poll",
            8 => "lseek", 9 => "mmap", 10 => "mprotect", 11 => "munmap",
            12 => "brk", 20 => "writev", 21 => "access", 22 => "pipe",
            32 => "dup", 33 => "dup2", 39 => "getpid", 41 => "socket",
            42 => "connect", 43 => "accept", 44 => "sendto", 45 => "recvfrom",
            49 => "bind", 50 => "listen", 56 => "clone", 57 => "fork",
            58 => "vfork", 59 => "execve", 60 => "exit", 61 => "wait4",
            62 => "kill", 63 => "uname", 72 => "fcntl", 79 => "getcwd",
            80 => "chdir", 81 => "fchdir", 82 => "rename", 83 => "mkdir",
            84 => "rmdir", 85 => "creat", 86 => "link", 87 => "unlink",
            88 => "symlink", 89 => "readlink", 90 => "chmod", 92 => "chown",
            99 => "sysinfo", 102 => "getuid", 104 => "getgid", 105 => "setuid",
            106 => "setgid", 186 => "gettid", 202 => "futex", 218 => "set_tid_address",
            231 => "exit_group", 257 => "openat", 258 => "mkdirat", 261 => "futimesat",
            263 => "unlinkat", 264 => "renameat", 265 => "linkat", 266 => "symlinkat",
            267 => "readlinkat", 268 => "fchmodat", 269 => "faccessat",
            316 => "renameat2", 318 => "getrandom", 322 => "execveat",
            _ => "",
        }
        .to_string()
        .pipe(|s| if s.is_empty() { format!("syscall_{}", nr) } else { s })
    }

    /// Shared HTTP client — created once, reused for all forwarding calls.
    /// reqwest::Client uses connection pooling internally, so reusing it avoids
    /// the per-event TCP handshake overhead that caused the 17-second backlog.
    static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

    fn http_client() -> &'static reqwest::Client {
        HTTP_CLIENT.get_or_init(reqwest::Client::new)
    }

    trait Pipe: Sized {
        fn pipe<F: FnOnce(Self) -> T, T>(self, f: F) -> T { f(self) }
    }
    impl<T> Pipe for T {}

    async fn forward_syscall_to_watchtower(
        watchtower_url: String,
        pid: u32,
        syscall_nr: u64,
        args: [u64; 6],
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

        let url = format!("{}/analyze-syscall", watchtower_url);
        if let Err(e) = http_client().post(&url).json(&payload).send().await {
            warn!("Failed to forward syscall to watchtower: {}", e);
        }
    }

    fn write_pid_file() -> Result<()> {
        let proj_dirs = ProjectDirs::from("com", "sevorix", "sevorix")
            .ok_or_else(|| anyhow::anyhow!("Could not determine project directories"))?;
        let state_dir = proj_dirs.state_dir().unwrap_or_else(|| proj_dirs.cache_dir());
        std::fs::create_dir_all(state_dir)?;
        let pid_path = state_dir.join("sevorix-ebpf.pid");
        std::fs::write(&pid_path, std::process::id().to_string())?;
        Ok(())
    }

    /// Event received from eBPF program.
    #[derive(Debug, Clone)]
    pub struct EbpfEvent {
        /// Event type (syscall or network).
        pub event_type: EventType,
        /// Process ID.
        pub pid: u32,
        /// Thread ID.
        pub tid: u32,
        /// Timestamp (ns since boot).
        pub timestamp: u64,
        /// Event-specific data.
        pub data: serde_json::Value,
    }

    /// Type of eBPF event.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EventType {
        SyscallEntry,
        SyscallExit,
        Network,
    }

    /// Daemon configuration.
    #[derive(Debug, Clone)]
    pub struct DaemonConfig {
        /// Watchtower HTTP endpoint for policy decisions.
        pub watchtower_url: String,
        /// Cgroup path for network interception.
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
    pub fn load_and_attach(bpf: &mut Ebpf, cgroup_path: &str) -> Result<()> {
        info!("Attaching eBPF programs...");

        // Attach syscall tracepoint (sys_enter)
        info!("Attaching sys_enter tracepoint...");
        let sys_enter: &mut TracePoint = bpf
            .program_mut("sys_enter")
            .context("Failed to get sys_enter program")?
            .try_into()
            .context("Failed to convert sys_enter to TracePoint")?;
        sys_enter.load()?;
        sys_enter.attach("raw_syscalls", "sys_enter")?;
        info!("sys_enter tracepoint attached");

        // Attach syscall tracepoint (sys_exit)
        info!("Attaching sys_exit tracepoint...");
        let sys_exit: &mut TracePoint = bpf
            .program_mut("sys_exit")
            .context("Failed to get sys_exit program")?
            .try_into()
            .context("Failed to convert sys_exit to TracePoint")?;
        sys_exit.load()?;
        sys_exit.attach("raw_syscalls", "sys_exit")?;
        info!("sys_exit tracepoint attached");

        // Attach sockops for network interception
        info!("Attaching sockops for network interception...");
        let sock_ops: &mut SockOps = bpf
            .program_mut("sock_ops")
            .context("Failed to get sock_ops program")?
            .try_into()
            .context("Failed to convert sock_ops to SockOps")?;
        sock_ops.load()?;

        // Attach to cgroup
        let cgroup_file = std::fs::File::open(cgroup_path)
            .with_context(|| format!("Failed to open cgroup: {}", cgroup_path))?;
        sock_ops.attach(cgroup_file, CgroupAttachMode::Single)?;
        info!("Sockops attached to cgroup: {}", cgroup_path);

        info!("eBPF programs loaded and attached successfully");
        Ok(())
    }

    /// Process a single event from the ring buffer.
    fn process_event(data: &[u8], event_tx: &broadcast::Sender<EbpfEvent>, watchtower_url: &str) -> Result<()> {
        if data.len() < 4 {
            warn!("Event data too short: {} bytes", data.len());
            return Ok(());
        }

        // Read event type from first 4 bytes
        let event_type = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);

        match event_type {
            SyscallEvent::EVENT_TYPE => {
                if data.len() < std::mem::size_of::<SyscallEvent>() {
                    warn!("SyscallEvent data too short: {} bytes", data.len());
                    return Ok(());
                }
                // Parse the event manually to avoid lifetime issues
                let event = parse_syscall_event(data)?;
                handle_syscall_event(event, event_tx, EventType::SyscallEntry, watchtower_url)?;
            }
            SyscallEvent::EVENT_TYPE_EXIT => {
                if data.len() < std::mem::size_of::<SyscallEvent>() {
                    warn!("SyscallEvent (exit) data too short: {} bytes", data.len());
                    return Ok(());
                }
                let event = parse_syscall_event(data)?;
                handle_syscall_event(event, event_tx, EventType::SyscallExit, watchtower_url)?;
            }
            NetworkEvent::EVENT_TYPE => {
                if data.len() < std::mem::size_of::<NetworkEvent>() {
                    warn!("NetworkEvent data too short: {} bytes", data.len());
                    return Ok(());
                }
                // Parse the event manually to avoid lifetime issues
                let event = parse_network_event(data)?;
                handle_network_event(event, event_tx)?;
            }
            _ => {
                warn!("Unknown event type: {}", event_type);
            }
        }

        Ok(())
    }

    /// Parse a SyscallEvent from raw bytes.
    fn parse_syscall_event(data: &[u8]) -> Result<SyscallEvent> {
        // Ensure we have enough data
        if data.len() < std::mem::size_of::<SyscallEvent>() {
            anyhow::bail!("SyscallEvent data too short");
        }

        // Use unsafe to transmute the bytes to the struct
        // This is safe because we've verified the size and the struct is repr(C)
        Ok(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const SyscallEvent) })
    }

    /// Parse a NetworkEvent from raw bytes.
    fn parse_network_event(data: &[u8]) -> Result<NetworkEvent> {
        // Ensure we have enough data
        if data.len() < std::mem::size_of::<NetworkEvent>() {
            anyhow::bail!("NetworkEvent data too short");
        }

        // Use unsafe to transmute the bytes to the struct
        // This is safe because we've verified the size and the struct is repr(C)
        Ok(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const NetworkEvent) })
    }

    /// Check if a PID belongs to a process inside the sevorix cgroup hierarchy.
    ///
    /// Reads `/proc/<pid>/cgroup` (cgroup v2 single-hierarchy format) and checks
    /// whether the cgroup path contains `/sevorix/`, indicating it was placed there
    /// by sevsh's session cgroup setup.
    fn is_pid_in_sevorix_cgroup(pid: u32) -> bool {
        let path = format!("/proc/{}/cgroup", pid);
        std::fs::read_to_string(&path)
            .map(|s| s.contains("/sevorix/"))
            .unwrap_or(false)
    }

    /// Handle a syscall event.
    fn handle_syscall_event(
        event: SyscallEvent,
        event_tx: &broadcast::Sender<EbpfEvent>,
        event_type: EventType,
        watchtower_url: &str,
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

        match event_type {
            EventType::SyscallEntry => {
                // Only forward syscalls from processes inside a sevsh session cgroup.
                // This prevents flooding watchtower with unrelated system activity.
                // The kernel already filtered to sevorix-cgroup processes only.
                // Forward interesting syscalls to watchtower for policy evaluation.
                if INTERESTING_SYSCALLS.contains(&event.syscall_nr) {
                    info!(
                        "Syscall entry (sevorix): pid={}, tid={}, syscall={}",
                        event.pid, event.tid, event.syscall_nr
                    );
                    let url = watchtower_url.to_string();
                    let (pid, nr, args) = (event.pid, event.syscall_nr, event.args);
                    tokio::spawn(async move {
                        forward_syscall_to_watchtower(url, pid, nr, args).await;
                    });
                }
            }
            EventType::SyscallExit => {}
            _ => {}
        }

        // Broadcast to subscribers
        let _ = event_tx.send(ebpf_event);

        Ok(())
    }

    /// Handle a network event.
    fn handle_network_event(event: NetworkEvent, event_tx: &broadcast::Sender<EbpfEvent>) -> Result<()> {
        // Convert IP from network byte order to human-readable
        let dst_ip = u32::from_be(event.dst_ip);
        let src_ip = u32::from_be(event.src_ip);
        let dst_ip_addr = IpAddr::from(std::net::Ipv4Addr::from(dst_ip));
        let src_ip_addr = IpAddr::from(std::net::Ipv4Addr::from(src_ip));
        let dst_port = u16::from_be(event.dst_port);
        let src_port = u16::from_be(event.src_port);

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

        info!(
            "Network event: pid={}, dst={}:{} ({})",
            event.pid, dst_ip_addr, dst_port, event.protocol
        );

        // Broadcast to subscribers
        let _ = event_tx.send(ebpf_event);

        // TODO: Perform DNS reverse lookup for enrichment
        // tokio::spawn(async move {
        //     if let Some(hostname) = reverse_dns_lookup(dst_ip_addr).await {
        //         info!("DNS enrichment: {} -> {}", dst_ip_addr, hostname);
        //     }
        // });

        Ok(())
    }

    /// Policy decision from Watchtower.
    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct PolicyDecision {
        pub action: String,
        pub reason: String,
        #[serde(default)]
        pub confidence: f32,
    }

    /// Query watchtower for policy decision.
    pub async fn query_policy(
        watchtower_url: &str,
        event: &EbpfEvent,
    ) -> Result<PolicyDecision> {
        let response = http_client()
            .post(format!("{}/analyze-syscall", watchtower_url))
            .json(&serde_json::json!({
                "event_type": match event.event_type {
                    EventType::SyscallEntry => "syscall_entry",
                    EventType::SyscallExit => "syscall_exit",
                    EventType::Network => "network",
                },
                "pid": event.pid,
                "tid": event.tid,
                "data": event.data,
            }))
            .send()
            .await
            .context("Failed to query Watchtower")?;

        let decision: PolicyDecision = response
            .json()
            .await
            .context("Failed to parse Watchtower response")?;

        Ok(decision)
    }

    /// Perform DNS reverse lookup for an IP address.
    pub async fn reverse_dns_lookup(ip: IpAddr) -> Option<String> {
        // Use spawn_blocking for synchronous DNS lookup
        let handle = tokio::task::spawn_blocking(move || {
            dns_lookup::lookup_addr(&ip).ok()
        });
        handle.await.ok().flatten()
    }

    /// Write a diagnostic line to /tmp/sevorix-ebpf-daemon-diag.log (world-writable path).
    fn diag(msg: &str) {
        let line = format!("[{}] {}\n", std::process::id(), msg);
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("/tmp/sevorix-ebpf-daemon-diag.log") {
            let _ = f.write_all(line.as_bytes());
        }
    }

    pub fn run() -> Result<()> {
        diag("run() entered");

        // Write PID file so EbpfDaemonManager::is_running() can detect us.
        write_pid_file().context("Failed to write eBPF daemon PID file")?;
        diag("PID file written");

        // Initialize logging — write to the dedicated log file passed via an env var
        // (set by watchtower before spawning us), falling back to stdout.
        let log_path = std::env::var("SEVORIX_EBPF_LOG")
            .unwrap_or_else(|_| "/tmp/sevorix-ebpf-daemon.log".to_string());
        diag(&format!("log path = {}", log_path));
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .unwrap_or_else(|_| {
                // Last resort: /tmp
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

                let config = DaemonConfig::default();

                // Create event broadcast channel
                let (event_tx, _) = broadcast::channel(1024);

                info!("Loading eBPF programs...");

                // Load the eBPF object file
                // Note: In production, this would load the compiled .o file
                // The eBPF program must be compiled separately using:
                // cargo build --target bpfel-unknown-none -Zbuild-std --release
                //
                // For now, we'll try to load from the expected location
                // In a proper setup, this would be included at compile time when the eBPF
                // target is available

                // Look for the eBPF bytecode alongside this binary, then fall back
                // to the build output path (for development).
                let ebpf_path = std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(|d| d.join("sevorix-ebpf")))
                    .filter(|p| p.exists())
                    .unwrap_or_else(|| std::path::PathBuf::from("target/bpfel-unknown-none/release/sevorix-ebpf"));

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

                // Attach programs
                load_and_attach(&mut bpf, &config.cgroup_path)?;

                // Ensure the sevorix cgroup base directory exists.
                // All session sub-cgroups live under it; the eBPF map tracks their IDs.
                let sevorix_cgroup_base = "/sys/fs/cgroup/sevorix";
                if let Err(e) = std::fs::create_dir_all(sevorix_cgroup_base) {
                    warn!("Could not create sevorix cgroup base {}: {}", sevorix_cgroup_base, e);
                }

                info!("Starting eBPF event processor");

                // Take ownership of the SEVORIX_CGROUP_IDS map so we can move it into the
                // background sync task (aya's HashMap requires &mut Map for writes).
                let cgroup_ids_map = bpf.take_map("SEVORIX_CGROUP_IDS");

                // Get the ring buffer (must be done after take_map).
                let events_map = bpf.map("EVENTS").context("Failed to get EVENTS map")?;
                let mut ring_buf = RingBuf::try_from(events_map)
                    .context("Failed to create RingBuf from EVENTS map")?;

                // Background task: sync active sevorix session cgroup IDs into the BPF map.
                //
                // Uses inotify to detect new session cgroup directories the instant they are
                // created by the cgroup helper, eliminating the race condition where fast
                // commands (like `ls`) complete before a polling loop can register the cgroup.
                //
                // A periodic re-scan every 5s acts as a safety net for missed events (e.g.
                // if the cgroup base was created after the watch was set up).
                if let Some(mut cgroup_map) = cgroup_ids_map {
                    tokio::spawn(async move {
                        use aya::maps::HashMap;
                        use inotify::{EventMask, Inotify, WatchMask};
                        use std::collections::HashSet;
                        use std::os::unix::fs::MetadataExt;

                        /// Scan the sevorix cgroup directory and return the inode of every
                        /// sub-cgroup directory (= cgroup ID in cgroupfs v2).
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

                        /// Push differences between `known` and `active` into the BPF map.
                        fn sync_map(
                            cgroup_map: &mut aya::maps::Map,
                            known: &mut HashSet<u64>,
                            active: &HashSet<u64>,
                        ) {
                            if let Ok(mut ids_map) = HashMap::<_, u64, u8>::try_from(&mut *cgroup_map) {
                                for &id in active.difference(known) {
                                    if ids_map.insert(id, 1u8, 0).is_ok() {
                                        tracing::info!("eBPF cgroup filter: added session cgroup id={}", id);
                                    }
                                }
                                for &id in known.difference(active) {
                                    let _ = ids_map.remove(&id);
                                    tracing::info!("eBPF cgroup filter: removed session cgroup id={}", id);
                                }
                            }
                            *known = active.clone();
                        }

                        let mut known: HashSet<u64> = HashSet::new();

                        // Perform an initial scan so sessions that existed before the daemon
                        // started (or before the watch is ready) are registered immediately.
                        let active = scan_cgroup_ids(sevorix_cgroup_base);
                        sync_map(&mut cgroup_map, &mut known, &active);

                        // Set up inotify on the sevorix cgroup base directory.
                        // Wrap inotify in AsyncFd for non-blocking use in tokio.
                        // Falls back to 500ms polling if inotify is unavailable.
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
                                // Use AsyncFd so we can await readability without blocking tokio.
                                use tokio::io::unix::AsyncFd;
                                use std::os::unix::io::AsRawFd;

                                // Set inotify fd to non-blocking.
                                let fd = inotify.as_raw_fd();
                                unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK); }

                                // Safety: we own the inotify instance and it lives for the task.
                                let async_fd = match AsyncFd::new(inotify) {
                                    Ok(a) => a,
                                    Err(e) => {
                                        warn!("AsyncFd init failed ({}), falling back to polling", e);
                                        loop {
                                            tokio::time::sleep(Duration::from_millis(500)).await;
                                            sync_map(&mut cgroup_map, &mut known, &scan_cgroup_ids(sevorix_cgroup_base));
                                        }
                                    }
                                };

                                // Periodic re-scan ticker (safety net for missed events).
                                let mut rescan = tokio::time::interval(Duration::from_secs(5));
                                rescan.tick().await; // consume immediate tick

                                loop {
                                    tokio::select! {
                                        // inotify signals a directory was created or deleted.
                                        ready = async_fd.readable() => {
                                            if let Ok(mut guard) = ready {
                                                guard.clear_ready();
                                                // Drain events via the raw fd; we only care
                                                // that something changed, not what.
                                                unsafe {
                                                    libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len());
                                                }
                                            }
                                            // Small delay so the cgroup helper finishes writing
                                            // cgroup.procs before we stat the directory.
                                            tokio::time::sleep(Duration::from_millis(10)).await;
                                            sync_map(&mut cgroup_map, &mut known, &scan_cgroup_ids(sevorix_cgroup_base));
                                        },
                                        _ = rescan.tick() => {
                                            sync_map(&mut cgroup_map, &mut known, &scan_cgroup_ids(sevorix_cgroup_base));
                                        },
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("inotify unavailable ({}), falling back to 500ms polling", e);
                                loop {
                                    tokio::time::sleep(Duration::from_millis(500)).await;
                                    sync_map(&mut cgroup_map, &mut known, &scan_cgroup_ids(sevorix_cgroup_base));
                                }
                            }
                        }
                    });
                } else {
                    warn!("SEVORIX_CGROUP_IDS map not found — cgroup filtering disabled");
                }

                info!("Ring buffer ready, waiting for sevorix session events...");

                loop {
                    // Poll for events with a short yield to keep tokio responsive.
                    let mut processed = 0u32;
                    while let Some(event) = ring_buf.next() {
                        if let Err(e) = process_event(&event, &event_tx, &config.watchtower_url) {
                            error!("Failed to process event: {}", e);
                        }
                        processed += 1;
                        // Yield every 64 events to let tokio schedule the cgroup sync task.
                        if processed % 64 == 0 {
                            tokio::task::yield_now().await;
                        }
                    }

                    // Buffer empty — sleep before next poll.
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
