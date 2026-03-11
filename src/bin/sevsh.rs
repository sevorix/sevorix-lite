use clap::Parser;
use sevorix_core::{PtyMultiplexer, PtyMultiplexerConfig};
use serde_json::json;
use std::env;
use std::process::{exit, Command, Stdio};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use uuid::Uuid;

const PROXY_URL: &str = "http://localhost:3000";
/// Sevorix Watchtower Shell - Secure shell with syscall interception via eBPF
///
/// Syscall interception is handled automatically by the eBPF daemon running
/// in the background. Commands are executed in a network-isolated sandbox
/// with the Watchtower proxy for security monitoring.
#[derive(Parser, Debug)]
#[command(name = "sevsh", about = "Sevorix Watchtower Shell", version)]
struct SevshArgs {
    /// Publish a port mapping (HOST:CONTAINER)
    #[arg(short = 'p', long = "publish")]
    port_mappings: Vec<String>,

    /// Disable proxy environment variables
    #[arg(long)]
    no_proxy: bool,

    /// Disable sandbox isolation
    #[arg(long)]
    no_sandbox: bool,

    /// Command to execute (optional - if omitted, starts interactive shell)
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw_args: Vec<String> = env::args().collect();

    // Internal Sandbox entry point (Child mode)
    // This is called by the parent process after unshare()
    if let Some(sock_path) = get_arg_value(&raw_args, "--internal-sandbox") {
        return run_internal_agent(&raw_args, &sock_path).await;
    }

    // Parse arguments with clap
    let args = SevshArgs::parse();

    // Generate unique session ID for this sevsh session
    let session_id = format!("sevsh-{}", Uuid::new_v4());

    // Fail-closed: Check daemon availability before proceeding
    if !args.no_sandbox {
        // Check if Watchtower is reachable
        match check_watchtower_reachable().await {
            Ok(()) => {},
            Err(e) => {
                eprintln!("[SEVSH] Error: Watchtower not reachable: {}", e);
                eprintln!("[SEVSH] Fail-closed: Cannot proceed without Watchtower.");
                std::process::exit(1);
            }
        }

        // Check if eBPF daemon is running
        if !is_ebpf_daemon_running() {
            eprintln!("[SEVSH] Error: eBPF daemon is not running.");
            eprintln!("[SEVSH] Fail-closed: Cannot proceed without eBPF daemon.");
            eprintln!("[SEVSH] Start with: sevorix start");
            std::process::exit(1);
        }
    }

    // Create cgroup for this session (for eBPF process filtering)
    let cgroup_created = match create_session_cgroup(&session_id) {
        Ok(created) => {
            // Add current process to the cgroup
            if let Err(e) = add_process_to_cgroup(&session_id) {
                eprintln!("[SEVSH] Warning: Could not add process to cgroup: {}", e);
                false
            } else {
                created
            }
        }
        Err(e) => {
            // Non-fatal: cgroup creation may fail if we don't have permissions
            // or cgroup v2 is not available
            if !args.command.is_empty() {
                eprintln!("[SEVSH] Warning: Could not create cgroup: {}. Process isolation limited.", e);
            }
            false
        }
    };

    // Set session ID in environment for child processes and eBPF tagging
    env::set_var("SEVORIX_SESSION_ID", &session_id);

    // Build command args for sandbox mode
    let mut command_args = Vec::new();
    if !raw_args.is_empty() {
        command_args.push(raw_args[0].clone());
    }
    command_args.extend(args.command.iter().cloned());

    // Check availability of sandbox tools
    let has_unshare = Command::new("unshare").arg("--version").output().is_ok();
    let has_ip = Command::new("ip").arg("-V").output().is_ok();

    // Determine isolation mode
    let exit_code: i32 = if !args.no_sandbox && has_unshare && has_ip {
        match run_parent_bridge(
            &command_args,
            &args.port_mappings,
            args.no_proxy,
            &session_id,
        )
        .await
        {
            Ok(code) => code,
            Err(e) => {
                // Check if this is a namespace exhaustion error
                let err_str = e.to_string();
                if err_str.contains("No space left on device")
                    || err_str.contains("unshare failed")
                    || err_str.contains("Resource temporarily unavailable")
                {
                    eprintln!("[SEVSH] Warning: Namespace isolation unavailable ({}). Falling back to simple environment variable isolation. Port forwarding will be disabled.", err_str);
                    // Fall through to handle_single_command below
                    -1 // sentinel: indicates fallthrough
                } else {
                    if cgroup_created { cleanup_session_cgroup(&session_id); }
                    return Err(e);
                }
            }
        }
    } else {
        if !args.no_sandbox && (!has_unshare || !has_ip) && !args.command.is_empty() {
            eprintln!("[SEVSH] Warning: Sandbox tools (unshare/ip) not found. Falling back to simple environment variable isolation. Port forwarding will be disabled.");
        }
        -1 // sentinel: fall through to below
    };

    // If sandbox path returned a real exit code, clean up and exit now.
    if exit_code >= 0 {
        if cgroup_created { cleanup_session_cgroup(&session_id); }
        exit(exit_code);
    }

    // Fallback: Standard execution (Env vars only)
    let exit_code = if !args.command.is_empty() {
        handle_single_command(&args.command, !args.no_proxy, &session_id).await?
    } else {
        // PTY multiplexer mode (full terminal support)
        run_pty_interactive_shell_code(!args.no_proxy, &session_id)?
    };

    // Cleanup cgroup on exit
    if cgroup_created {
        cleanup_session_cgroup(&session_id);
    }

    exit(exit_code);
}

fn get_arg_value(args: &[String], key: &str) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == key {
            return iter.next().cloned();
        }
    }
    None
}

// -----------------------------------------------------------------------------
// Daemon Reachability Checks (Fail-Closed)
// -----------------------------------------------------------------------------

/// Check if Watchtower is reachable.
/// Returns Ok(()) if reachable, Err if not.
async fn check_watchtower_reachable() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()?;

    let resp = client
        .get("http://localhost:3000/health")
        .send()
        .await?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("Watchtower health check failed: {}", resp.status()).into())
    }
}

/// Check if eBPF daemon is running.
/// Returns Ok(()) if running, Err if not.
fn check_ebpf_daemon_running() -> Result<(), Box<dyn std::error::Error>> {
    use sevorix_watchtower::EbpfDaemonManager;

    let manager = EbpfDaemonManager::new()?;
    if manager.is_running() {
        Ok(())
    } else {
        Err("eBPF daemon is not running".into())
    }
}

/// Convenience function to check if eBPF daemon is running.
fn is_ebpf_daemon_running() -> bool {
    check_ebpf_daemon_running().is_ok()
}

// -----------------------------------------------------------------------------
// Cgroup Management
// -----------------------------------------------------------------------------

const CGROUP_HELPER: &str = "/usr/local/bin/sevorix-cgroup-helper";

/// Create a session cgroup and add the current process to it.
///
/// Uses a privileged helper via `sudo -n` because cgroup v2 only allows
/// root to migrate processes across unrelated cgroup subtrees.
/// The helper is installed by install.sh with a NOPASSWD sudoers rule.
fn create_session_cgroup(session_id: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let pid = std::process::id();

    // Step 1: create the session sub-cgroup (root needed to create & set base ownership)
    let create_status = std::process::Command::new("sudo")
        .args(["-n", CGROUP_HELPER, "create", session_id])
        .stderr(std::process::Stdio::null())
        .status()?;

    if !create_status.success() {
        return Err(format!(
            "cgroup helper 'create' failed (exit {}). Run ./install.sh to set up the cgroup sudoers rule.",
            create_status.code().unwrap_or(-1)
        ).into());
    }

    // Step 2: add current PID — root required due to cross-hierarchy migration restriction
    let add_status = std::process::Command::new("sudo")
        .args(["-n", CGROUP_HELPER, "add-pid", session_id, &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()?;

    if !add_status.success() {
        return Err(format!(
            "cgroup helper 'add-pid' failed (exit {})",
            add_status.code().unwrap_or(-1)
        ).into());
    }

    Ok(true)
}

/// Add a process to the session cgroup.
fn add_process_to_cgroup(session_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pid = std::process::id();
    let status = std::process::Command::new("sudo")
        .args(["-n", CGROUP_HELPER, "add-pid", session_id, &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()?;

    if !status.success() {
        return Err(format!(
            "cgroup helper 'add-pid' failed (exit {})",
            status.code().unwrap_or(-1)
        ).into());
    }
    Ok(())
}

/// Clean up session cgroup.
fn cleanup_session_cgroup(session_id: &str) {
    let _ = std::process::Command::new("sudo")
        .args(["-n", CGROUP_HELPER, "cleanup", session_id])
        .stderr(std::process::Stdio::null())
        .status();
}

// -----------------------------------------------------------------------------
// Parent Bridge Logic (Host)
// -----------------------------------------------------------------------------
async fn run_parent_bridge(
    args: &[String],
    port_mappings: &[String],
    no_proxy: bool,
    session_id: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    // 1. Create Unix Socket for bridging
    let pid = std::process::id();
    let sock_path = format!("/tmp/sevorix_bridge_{}.sock", pid);

    // Remove if exists
    let _ = std::fs::remove_file(&sock_path);

    let listener = UnixListener::bind(&sock_path)?;

    // 2. Setup Port Forwarding Listeners (Host Side)
    // We need to pass the socket paths to the child
    let mut fwd_args = Vec::new();

    // Keep track of resources to clean up
    let mut fwd_sockets = Vec::new();

    for mapping in port_mappings {
        // Format: HOST:CONTAINER (e.g., 8080:80)
        let parts: Vec<&str> = mapping.split(':').collect();
        if parts.len() != 2 {
            eprintln!("[SEVSH] Invalid port mapping: {}", mapping);
            continue;
        }
        let host_port = parts[0];
        let container_port = parts[1];

        let fwd_sock_path = format!("/tmp/sevorix_fwd_{}_{}.sock", pid, host_port);
        let _ = std::fs::remove_file(&fwd_sock_path);

        fwd_sockets.push(fwd_sock_path.clone());

        // Spawn Host TCP Listener
        let addr = format!("127.0.0.1:{}", host_port);
        let path = fwd_sock_path.clone();

        // We expect the CHILD to listen on this Unix socket.
        // HOST connects to it.
        // So we don't bind UnixListener here. Child binds it.

        // Spawn TCP Listener task
        tokio::spawn(async move {
            let listener = match TcpListener::bind(&addr).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[SEVSH] Failed to bind host port {}: {}", addr, e);
                    return;
                }
            };

            while let Ok((tcp_stream, _)) = listener.accept().await {
                let p = path.clone();
                tokio::spawn(async move {
                    // Connect to Unix socket (Child listening)
                    // Retry a few times if child is slow startup?
                    let mut attempts = 0;
                    loop {
                        match UnixStream::connect(&p).await {
                            Ok(mut unix_stream) => {
                                let mut tcp = tcp_stream;
                                if tokio::io::copy_bidirectional(
                                    &mut tcp,
                                    &mut unix_stream,
                                )
                                .await
                                .is_err()
                                {
                                    // Ignore
                                }
                                break;
                            }
                            Err(_) => {
                                attempts += 1;
                                if attempts > 5 {
                                    break;
                                }
                                tokio::time::sleep(std::time::Duration::from_millis(100))
                                    .await;
                            }
                        }
                    }
                });
            }
        });

        // Pass config to child: --internal-forward-sock PATH:PORT
        fwd_args.push("--internal-forward-sock".to_string());
        fwd_args.push(format!("{}:{}", fwd_sock_path, container_port));
    }

    // 3. Spawn Child in Network Namespace
    let sevsh_bin = env::current_exe()?;
    let sevsh_bin_str = sevsh_bin.to_string_lossy().to_string();

    let mut child_cmd_args = vec![
        "--net".to_string(),
        "--map-root-user".to_string(),
        sevsh_bin_str,
        "--internal-sandbox".to_string(),
        sock_path.clone(),
    ];

    // Add forward args
    child_cmd_args.extend(fwd_args);

    // Pass proxy flag to child
    if no_proxy {
        child_cmd_args.push("--no-proxy".to_string());
    }

    // Pass session ID to child
    child_cmd_args.push("--session-id".to_string());
    child_cmd_args.push(session_id.to_string());

    // Append original args (skip binary name)
    if args.len() > 1 {
        child_cmd_args.extend_from_slice(&args[1..]);
    }

    let mut child = Command::new("unshare")
        .args(&child_cmd_args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    // 4. Proxy Loop (Host Side)
    // Accept connection on Unix socket -> Proxy to Localhost:3000
    let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();

    let bridge_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut rx => break,
                res = listener.accept() => {
                    match res {
                        Ok((unix_stream, _)) => {
                            tokio::spawn(async move {
                                 if let Err(_e) = proxy_unix_to_tcp(unix_stream).await {
                                     // Silent fail
                                 }
                            });
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });

    // Wait for child to exit
    let status = child.wait()?;

    // Cleanup
    let _ = tx.send(());
    let _ = bridge_task.await;
    let _ = std::fs::remove_file(&sock_path);
    for s in fwd_sockets {
        let _ = std::fs::remove_file(&s);
    }

    Ok(status.code().unwrap_or(1))
}

async fn proxy_unix_to_tcp(mut unix: UnixStream) -> std::io::Result<()> {
    // Connect to Host Daemon
    let mut tcp = TcpStream::connect("127.0.0.1:3000").await?;
    tokio::io::copy_bidirectional(&mut unix, &mut tcp).await?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Child Internal Logic (Inside Sandbox)
// -----------------------------------------------------------------------------
async fn run_internal_agent(
    args: &[String],
    sock_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup Loopback Interface
    let status = Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .output()?;

    if !status.status.success() {
        eprintln!(
            "[SEVSH] Failed to bring up loopback: {}",
            String::from_utf8_lossy(&status.stderr)
        );
    }

    // 2. Start TCP Bridge (127.0.0.1:3000 -> sock_path)
    let listener = TcpListener::bind("127.0.0.1:3000").await?;
    let sock_path_owned = sock_path.to_string();

    tokio::spawn(async move {
        while let Ok((tcp_stream, _)) = listener.accept().await {
            let path = sock_path_owned.clone();
            tokio::spawn(async move {
                let mut tcp = tcp_stream;
                if let Ok(mut unix) = UnixStream::connect(&path).await {
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut unix).await;
                }
            });
        }
    });

    // 3. Setup Port Forwarding Listeners (Child Side - Reverse)
    // Iterate args for --internal-forward-sock PATH:PORT
    let mut arg_iter = args.iter();
    while let Some(arg) = arg_iter.next() {
        if arg == "--internal-forward-sock" {
            if let Some(val) = arg_iter.next() {
                let parts: Vec<&str> = val.split(':').collect();
                if parts.len() == 2 {
                    let path = parts[0].to_string();
                    let port = parts[1].to_string();

                    // Bind Unix Listener
                    // Ensure cleanup of previous if reusing pid?
                    let _ = std::fs::remove_file(&path);

                    if let Ok(unix_listener) = UnixListener::bind(&path) {
                        let target_addr = format!("127.0.0.1:{}", port);

                        tokio::spawn(async move {
                            while let Ok((unix_stream, _)) = unix_listener.accept().await {
                                let addr = target_addr.clone();
                                tokio::spawn(async move {
                                    // Connect to INTERNAL service
                                    if let Ok(mut tcp) = TcpStream::connect(&addr).await {
                                        let mut unix = unix_stream;
                                        let _ = tokio::io::copy_bidirectional(
                                            &mut tcp, &mut unix,
                                        )
                                        .await;
                                    }
                                });
                            }
                        });
                    }
                }
            }
        }
    }

    // 4. Prepare Args for Actual Logic
    // Find where real args start (after all internal flags)
    // We need to filter out --internal-sandbox <val> AND --internal-forward-sock <val>
    // Just construct clean args by iterating

    // NOTE: We intentionally skip args[0] (binary path) to avoid recursive sevsh calls.
    // The payload should contain only the command to execute, not the sevsh binary path.
    let mut real_args = Vec::new();

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--internal-sandbox" || arg == "--internal-forward-sock" || arg == "--session-id" {
            i += 2;
        } else if arg == "--no-proxy" {
            // Filter out this flag as it's handled via bool param
            i += 1;
        } else {
            real_args.push(arg.clone());
            i += 1;
        }
    }

    // Re-check no-proxy based on raw args (before filtering)
    let no_proxy = args.iter().any(|arg| arg == "--no-proxy");

    // Extract session ID from args
    let session_id = get_arg_value(args, "--session-id")
        .unwrap_or_else(|| format!("sevsh-{}", Uuid::new_v4()));

    // Set session ID in environment
    env::set_var("SEVORIX_SESSION_ID", &session_id);

    // Call logic (eBPF daemon handles syscall interception)
    // PTY multiplexer is now the default and only interactive mode
    let code = if !real_args.is_empty() {
        handle_single_command(&real_args, !no_proxy, &session_id).await?
    } else {
        run_pty_interactive_shell_code(!no_proxy, &session_id)?
    };
    exit(code);
}

async fn handle_single_command(
    args: &[String],
    use_proxy: bool,
    session_id: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());

    let (payload, final_cmd_args) = if args[0] == "-c" {
        // Case: sevsh -c "ls -la"
        if args.len() > 1 {
            let cmd = args[1].clone();
            (cmd.clone(), vec!["-c".to_string(), cmd])
        } else {
            eprintln!("Error: -c requires an argument");
            return Ok(1);
        }
    } else {
        // Case: sevsh ls -la
        let cmd = args.join(" ");
        (cmd.clone(), vec!["-c".to_string(), cmd])
    };

    // Validate
    let verdict = validate_command(&payload).await?;

    if verdict.allowed {
        if verdict.status == "FLAG" {
            eprintln!(
                "SEVORIX WARNING: {} (Confidence: {})",
                verdict.reason, verdict.confidence
            );
        }

        // Build environment variables for proxy if needed
        let mut env_vars: Vec<(String, String)> = if use_proxy {
            vec![
                ("HTTP_PROXY".to_string(), PROXY_URL.to_string()),
                ("http_proxy".to_string(), PROXY_URL.to_string()),
                ("HTTPS_PROXY".to_string(), PROXY_URL.to_string()),
                ("https_proxy".to_string(), PROXY_URL.to_string()),
                ("ALL_PROXY".to_string(), PROXY_URL.to_string()),
                ("all_proxy".to_string(), PROXY_URL.to_string()),
                ("NO_PROXY".to_string(), "localhost,127.0.0.1,::1".to_string()),
                ("no_proxy".to_string(), "localhost,127.0.0.1,::1".to_string()),
            ]
        } else {
            vec![]
        };

        // Add session ID to environment for eBPF tagging
        env_vars.push(("SEVORIX_SESSION_ID".to_string(), session_id.to_string()));

        // Use standard Command execution - eBPF daemon handles syscall interception
        let mut command = Command::new(&shell);
        command.args(&final_cmd_args);
        for (key, value) in env_vars {
            command.env(key, value);
        }
        let status = command.status()?;

        Ok(status.code().unwrap_or(1))
    } else {
        eprintln!("SEVORIX BLOCKED: {}", verdict.reason);
        Ok(1)
    }
}

/// Run interactive shell using PTY multiplexer with command validation.
///
/// This mode provides full terminal support including:
/// - Tab completion (forwarded to bash)
/// - Arrow key history (forwarded to bash)
/// - Raw mode passthrough for vim/less/etc.
/// - Command validation via Watchtower before execution
fn run_pty_interactive_shell_code(use_proxy: bool, session_id: &str) -> Result<i32, Box<dyn std::error::Error>> {
    let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());

    // Set session ID in environment
    env::set_var("SEVORIX_SESSION_ID", session_id);

    if use_proxy {
        println!("[SEVSH] Auto-Proxy Enabled: {}", PROXY_URL);
    }
    println!("[SEVSH] Session ID: {}", session_id);
    println!("[SEVSH] PTY Multiplexer Mode - Full terminal support");
    println!("[SEVSH] Type 'exit' or press Ctrl+D to leave.");

    // Build environment variables for proxy if needed
    let mut env_vars: Vec<(String, String)> = if use_proxy {
        vec![
            ("HTTP_PROXY".to_string(), PROXY_URL.to_string()),
            ("http_proxy".to_string(), PROXY_URL.to_string()),
            ("HTTPS_PROXY".to_string(), PROXY_URL.to_string()),
            ("https_proxy".to_string(), PROXY_URL.to_string()),
            ("ALL_PROXY".to_string(), PROXY_URL.to_string()),
            ("all_proxy".to_string(), PROXY_URL.to_string()),
            ("NO_PROXY".to_string(), "localhost,127.0.0.1,::1".to_string()),
            ("no_proxy".to_string(), "localhost,127.0.0.1,::1".to_string()),
        ]
    } else {
        vec![]
    };

    // Add session ID to environment
    env_vars.push(("SEVORIX_SESSION_ID".to_string(), session_id.to_string()));

    let config = PtyMultiplexerConfig {
        shell,
        env_vars,
        passthrough_commands: PtyMultiplexerConfig::default().passthrough_commands,
        watchtower_url: PROXY_URL.to_string(),
        validation_timeout_ms: 5000,
    };

    let mut multiplexer = PtyMultiplexer::new(config)?;
    let exit_status = multiplexer.run()?;
    Ok(exit_status.code().unwrap_or(1))
}

struct Verdict {
    allowed: bool,
    status: String,
    reason: String,
    confidence: String,
}

async fn validate_command(cmd: &str) -> Result<Verdict, Box<dyn std::error::Error>> {
    // Use the async client explicitly
    let client = reqwest::Client::new();
    let url = "http://localhost:3000/analyze";

    // Fail-safe: if we can't connect, we must fail closed (or exit process),
    // but returning error here lets the caller decide.
    // The plan says: "If Watchtower is unreachable, default to blocking execution".

    let resp = client
        .post(url)
        .json(&json!({
            "payload": cmd,
            "agent": "sevsh-repl",
            "context": "Shell"
        }))
        .send()
        .await;

    match resp {
        Ok(r) => {
            if !r.status().is_success() {
                return Ok(Verdict {
                    allowed: false,
                    status: "ERROR".to_string(),
                    reason: format!("API Error {}", r.status()),
                    confidence: "100%".to_string(),
                });
            }

            let json_resp: serde_json::Value = r.json().await?;
            let status = json_resp["status"]
                .as_str()
                .unwrap_or("UNKNOWN")
                .to_string();
            let reason = json_resp["reason"]
                .as_str()
                .unwrap_or("Policy Violation")
                .to_string();
            // Confidence comes as a string like "99.8%" or "High Consensus", or null
            let confidence = json_resp["confidence"]
                .as_str()
                .unwrap_or("Unknown")
                .to_string();

            // Map status to allowed
            let allowed = status == "ALLOW" || status == "FLAG"; // Plan says "If ALLOW/FLAG: Execute"

            Ok(Verdict {
                allowed,
                status,
                reason,
                confidence,
            })
        }
        Err(e) => {
            // Unreachable -> Block
            Ok(Verdict {
                allowed: false,
                status: "UNREACHABLE".to_string(),
                reason: format!("Watchtower unreachable: {}", e),
                confidence: "100%".to_string(),
            })
        }
    }
}
