// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

use clap::Parser;
use serde_json::json;
#[cfg(target_os = "linux")]
use sevorix_core::{
    apply_syscall_deny_filter, apply_syscall_notify_filter, run_seccomp_notify_supervisor,
    SyscallInfo,
};
use sevorix_core::{PtyMultiplexer, PtyMultiplexerConfig};
use std::env;
use std::os::unix::process::CommandExt;
use std::process::{exit, Command, Stdio};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use uuid::Uuid;

/// Return the Watchtower proxy URL.
/// Resolved proxy URL, set once at process startup and never changed.
static RESOLVED_PROXY_URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn proxy_url() -> &'static str {
    RESOLVED_PROXY_URL
        .get()
        .map(|s| s.as_str())
        .unwrap_or("http://localhost:3000")
}

/// Resolve the Watchtower proxy URL for this sevsh invocation.
///
/// Resolution order:
///   1. `SEVORIX_PORT` env var — use that port directly
///   2. `SEVORIX_SESSION` env var — look up port from session metadata
///   3. Auto-detect — if exactly one session is running, use its port
///   4. Fallback — port 3000
///
/// The resolved URL is stored as a plain Rust value and `SEVORIX_SESSION` /
/// `SEVORIX_PORT` are stripped from the child environment so that nested
/// sevsh invocations cannot inherit an agent-injected override.
fn resolve_proxy_url() -> String {
    // Priority 1: direct port override
    if let Ok(port_str) = std::env::var("SEVORIX_PORT") {
        if let Ok(port) = port_str.parse::<u16>() {
            return format!("http://localhost:{}", port);
        }
    }

    // Priority 2 & 3: look up session metadata
    let sessions_dir = directories::ProjectDirs::from("com", "sevorix", "sevorix").map(|d| {
        d.state_dir()
            .unwrap_or_else(|| d.cache_dir())
            .join("sessions")
    });

    if let Some(sdir) = sessions_dir {
        let target_name = std::env::var("SEVORIX_SESSION").ok();
        let mut found_port: Option<u16> = None;
        let mut running_count: usize = 0;

        if let Ok(entries) = std::fs::read_dir(&sdir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("json") {
                    continue;
                }
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(info) = serde_json::from_str::<serde_json::Value>(&content) {
                        let pid = info["pid"].as_i64().unwrap_or(0) as i32;
                        let alive = pid > 0 && unsafe { libc::kill(pid, 0) } == 0;
                        if !alive {
                            continue;
                        }
                        let port = info["port"].as_u64().unwrap_or(3000) as u16;
                        let name = info["name"].as_str().unwrap_or("").to_string();
                        running_count += 1;
                        if let Some(ref wanted) = target_name {
                            if &name == wanted {
                                found_port = Some(port);
                                break;
                            }
                        } else {
                            // remember last running port for auto-detect
                            found_port = Some(port);
                        }
                    }
                }
            }
        }

        if let Some(ref wanted) = target_name {
            if let Some(p) = found_port {
                return format!("http://localhost:{}", p);
            }
            // Named session requested but not found — warn loudly so the user
            // can see why traffic is being dropped instead of silently routing
            // to the wrong session.
            eprintln!(
                "[SEVSH] WARNING: session '{}' not found in running sessions. \
                 Is the session started? Falling back to http://localhost:3000 \
                 — traffic may go to the wrong session.",
                wanted
            );
        } else if running_count == 1 {
            if let Some(p) = found_port {
                return format!("http://localhost:{}", p);
            }
        } else if running_count > 1 {
            // Multiple sessions running with no SEVORIX_SESSION specified.
            // Refuse the ambiguous fallback — require an explicit session name.
            eprintln!(
                "[SEVSH] ERROR: {} sessions are running but SEVORIX_SESSION is not set. \
                 Set SEVORIX_SESSION=<name> or SEVORIX_PORT=<port> to target a specific session.",
                running_count
            );
            std::process::exit(1);
        }
    }

    // Fallback: no sessions running (or session dir unreadable). Use default port.
    "http://localhost:3000".to_string()
}

// -----------------------------------------------------------------------------
// Bash-compatible argument parsing
// -----------------------------------------------------------------------------

/// Represents a parsed bash-compatible invocation.
///
/// Sevsh is bind-mounted over /bin/bash when used with the Claude Code
/// integration, so it must accept every form of invocation that bash accepts.
#[derive(Debug, PartialEq, Default)]
pub struct BashInvocation {
    /// Command string from `-c STRING`.
    pub command: Option<String>,
    /// Script file to execute (`bash script.sh`).
    pub script_file: Option<String>,
    /// Positional args: after `--` in `-c` mode, or after the script name.
    /// These become `$0`, `$1`, … inside the command string.
    pub positional_args: Vec<String>,
    /// Single-char set options (`-e`, `-x`, `-v`, `-u`, `-n`, `-l`, `-r`).
    /// Collected and forwarded to the inner bash invocation.
    pub set_options: Vec<String>,
    /// Long options (`--norc`, `--noprofile`, `--login`, `--rcfile FILE`, …).
    /// Collected and forwarded to the inner bash invocation.
    pub extra_options: Vec<String>,
    /// `-i` flag: caller wants an interactive shell (no command or script).
    pub interactive: bool,
}

impl BashInvocation {
    /// Build the argument list to pass to the real bash binary.
    ///
    /// For command-string mode: `[set_opts…, extra_opts…, "-c", cmd, positional…]`
    /// For script-file mode:    `[set_opts…, extra_opts…, script, args…]`
    /// For interactive mode:    `[set_opts…, extra_opts…]`
    pub fn to_bash_args(&self) -> Vec<String> {
        let mut args: Vec<String> = Vec::new();
        args.extend(self.set_options.iter().cloned());
        args.extend(self.extra_options.iter().cloned());
        if let Some(ref cmd) = self.command {
            args.push("-c".to_string());
            args.push(cmd.clone());
            args.extend(self.positional_args.iter().cloned());
        } else if let Some(ref script) = self.script_file {
            args.push(script.clone());
            args.extend(self.positional_args.iter().cloned());
        }
        args
    }

    /// The payload to send to Watchtower for validation.
    pub fn payload(&self) -> Option<String> {
        if let Some(ref cmd) = self.command {
            Some(cmd.clone())
        } else {
            self.script_file.clone()
        }
    }
}

/// Parse a bash-compatible argument list into a `BashInvocation`.
///
/// Handles all common bash invocation forms:
/// - `bash -c 'cmd'`
/// - `bash -c 'cmd' -- arg0 arg1`
/// - `bash -e -x -c 'cmd'`
/// - `bash --norc --noprofile -c 'cmd'`
/// - `bash script.sh arg1 arg2`
/// - `bash -i`
/// - `bash` (no args → interactive)
///
/// Unknown flags are passed through in `extra_options` rather than rejected,
/// matching bash's behaviour of erroring on them at execution time.
pub fn parse_bash_invocation(args: &[String]) -> BashInvocation {
    let mut inv = BashInvocation::default();
    let mut i = 0;

    // Single-char flags that bash accepts at invocation and that we pass through.
    // -i (interactive) is handled specially.
    const SET_OPTION_CHARS: &str = "eilnrsTuvx";

    while i < args.len() {
        let arg = &args[i];

        // End of options: everything after is positional.
        if arg == "--" {
            i += 1;
            inv.positional_args.extend_from_slice(&args[i..]);
            break;
        }

        // `-c COMMAND_STRING`
        if arg == "-c" {
            i += 1;
            if i < args.len() {
                inv.command = Some(args[i].clone());
                i += 1;
                // Optional `--` then positional args ($0, $1, …)
                if i < args.len() && args[i] == "--" {
                    i += 1;
                }
                inv.positional_args.extend_from_slice(&args[i..]);
            }
            break;
        }

        // Long options
        if arg.starts_with("--") {
            match arg.as_str() {
                "--login" | "--restricted" | "--norc" | "--noprofile" | "--noediting"
                | "--posix" | "--debugger" => {
                    inv.extra_options.push(arg.clone());
                }
                "--rcfile" | "--init-file" => {
                    inv.extra_options.push(arg.clone());
                    i += 1;
                    if i < args.len() {
                        inv.extra_options.push(args[i].clone());
                    }
                }
                _ if arg == "--no-sandbox"
                    || arg == "--no-proxy"
                    || arg.starts_with("--no-sandbox=")
                    || arg.starts_with("--no-proxy=") =>
                {
                    // Sevsh modifier flags — consumed by sevsh, not passed to bash.
                }
                _ => {
                    // Unknown long option — pass through.
                    inv.extra_options.push(arg.clone());
                }
            }
            i += 1;
            continue;
        }

        // Short option cluster starting with `-`
        if arg.starts_with('-') && arg.len() > 1 {
            // Special-case: `-i` alone means interactive.
            // In a cluster like `-ei`, treat each char individually.
            let chars: Vec<char> = arg[1..].chars().collect();
            let mut handled = true;
            for ch in &chars {
                match ch {
                    'i' => {
                        inv.interactive = true;
                    }
                    c if SET_OPTION_CHARS.contains(*c) => {
                        inv.set_options.push(format!("-{}", c));
                    }
                    _ => {
                        // Unknown short option — pass through the whole arg.
                        inv.extra_options.push(arg.clone());
                        handled = false;
                        break;
                    }
                }
            }
            if !handled {
                // Already added the whole arg above; skip re-adding.
            }
            i += 1;
            continue;
        }

        // First non-option argument: script file.
        inv.script_file = Some(arg.clone());
        i += 1;
        inv.positional_args.extend_from_slice(&args[i..]);
        break;
    }

    inv
}

/// Returns true if the arg list contains any sevsh-specific flags, meaning
/// the invocation should be handled by clap rather than the bash-compat path.
fn has_sevsh_flags(args: &[String]) -> bool {
    // Only structural flags force the clap path. Modifier flags (--no-sandbox,
    // --no-proxy) are also valid alongside bash-compat flags like -c, so they
    // must not trigger the clap path — the bash-compat path reads them directly
    // from raw_args when needed.
    //
    // `"--"` signals direct binary execution (sevsh -- cmd args); it must
    // route through clap so args.command is populated correctly.
    args.iter().any(|a| {
        matches!(
            a.as_str(),
            "--internal-sandbox" | "--internal-forward-sock" | "--session-id" | "--"
        ) || a.starts_with("--publish")
            || a == "-p"
    })
}

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
    // Resolve the proxy URL once from env/session metadata, then strip the
    // session env vars so nested sevsh invocations cannot inherit an agent-injected override.
    RESOLVED_PROXY_URL.get_or_init(resolve_proxy_url);
    env::remove_var("SEVORIX_SESSION");
    env::remove_var("SEVORIX_PORT");

    let raw_args: Vec<String> = env::args().collect();

    // Internal Sandbox entry point (Child mode)
    // This is called by the parent process after unshare()
    if let Some(sock_path) = get_arg_value(&raw_args, "--internal-sandbox") {
        return run_internal_agent(&raw_args, &sock_path).await;
    }

    // Bash-compat path: if no sevsh-specific flags are present, treat this
    // invocation as a bash replacement and parse with parse_bash_invocation()
    // rather than clap.  This handles -c, -e, -x, --norc, script.sh, etc.
    let user_args = &raw_args[1..]; // strip argv[0]
    if !has_sevsh_flags(user_args) {
        let inv = parse_bash_invocation(user_args);
        let session_id = format!("sevsh-{}", Uuid::new_v4());
        // Guard: if SEVORIX_SESSION_ID is already set we are nested inside an
        // existing sevsh session — skip cgroup creation to prevent recursive spawning.
        let already_in_session = env::var("SEVORIX_SESSION_ID").is_ok();
        env::set_var("SEVORIX_SESSION_ID", &session_id);

        // Set up cgroup for eBPF syscall tracking. Best-effort: if cgroup
        // creation fails (e.g. helper not installed), proceed without isolation.
        let cgroup_created = if already_in_session {
            false
        } else {
            create_session_cgroup(&session_id).unwrap_or_default()
        };
        if cgroup_created {
            if let Err(e) = add_process_to_cgroup(&session_id) {
                eprintln!("[SEVSH] Warning: Could not add process to cgroup: {}", e);
            }
            let path = format!("/sys/fs/cgroup/sevorix/{}", session_id);
            let url = proxy_url().to_string();
            let _ = reqwest::Client::builder()
                .no_proxy()
                .build()
                .unwrap_or_default()
                .post(format!("{}/api/session/register", url))
                .header("X-Sevorix-Internal", "true")
                .json(&serde_json::json!({"cgroup_path": path}))
                .send()
                .await;
        }

        if inv.command.is_none() && inv.script_file.is_none() {
            let stdin_is_tty = unsafe { libc::isatty(0) != 0 };
            if stdin_is_tty || inv.interactive {
                // Real interactive session: intercept typed commands via PTY.
                let exit_code = run_pty_interactive_shell_code(true, &session_id)?;
                if cgroup_created {
                    let _ = reqwest::Client::builder().no_proxy().build().unwrap_or_default()
                        .post(format!("{}/api/session/unregister", proxy_url()))
                        .header("X-Sevorix-Internal", "true")
                        .json(&serde_json::json!({"cgroup_path": format!("/sys/fs/cgroup/sevorix/{}", session_id)}))
                        .send().await;
                    cleanup_session_cgroup(&session_id);
                }
                exit(exit_code);
            } else {
                // Non-interactive with no command (e.g. `bash -l` for profile
                // sourcing): nothing to intercept, pass straight through.
                let shell = real_shell();
                let status = Command::new(&shell).args(inv.to_bash_args()).status()?;
                if cgroup_created {
                    let _ = reqwest::Client::builder().no_proxy().build().unwrap_or_default()
                        .post(format!("{}/api/session/unregister", proxy_url()))
                        .header("X-Sevorix-Internal", "true")
                        .json(&serde_json::json!({"cgroup_path": format!("/sys/fs/cgroup/sevorix/{}", session_id)}))
                        .send().await;
                    cleanup_session_cgroup(&session_id);
                }
                exit(status.code().unwrap_or(1));
            }
        }

        // Non-interactive: validate and execute.
        // For -c invocations, route through the namespace sandbox (unshare)
        // to enforce network isolation, matching the sevsh-specific path.
        let no_sandbox_flag = raw_args.iter().any(|a| a == "--no-sandbox");
        let has_unshare = Command::new("unshare").arg("--version").output().is_ok();
        let has_ip = Command::new("ip").arg("-V").output().is_ok();

        // Record the real agent PID (our PPID) before the sandbox adds intermediaries.
        // The sandbox (unshare) exec()s into the inner sevsh, making getppid() inside
        // the sandbox return the outer sevsh's PID rather than the actual agent's PID.
        let agent_pid = unsafe { libc::getppid() };
        env::set_var("SEVORIX_AGENT_PID", agent_pid.to_string());

        let exit_code = if (inv.command.is_some() || inv.script_file.is_some())
            && !no_sandbox_flag
            && has_unshare
            && has_ip
        {
            // Route through the namespace-isolated sandbox path.
            let mut command_args = Vec::new();
            if !raw_args.is_empty() {
                command_args.push(raw_args[0].clone());
            }
            command_args.extend(inv.to_bash_args());
            match run_parent_bridge(&command_args, &[], false, &session_id).await {
                Ok(code) => code,
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("No space left on device")
                        || err_str.contains("unshare failed")
                        || err_str.contains("Resource temporarily unavailable")
                    {
                        eprintln!("[SEVSH] Warning: Namespace isolation unavailable ({}). Falling back to simple environment variable isolation. Port forwarding will be disabled.", err_str);
                        handle_bash_invocation(inv, true, &session_id).await?
                    } else {
                        if cgroup_created {
                            let _ = reqwest::Client::builder().no_proxy().build().unwrap_or_default()
                                .post(format!("{}/api/session/unregister", proxy_url()))
                                .header("X-Sevorix-Internal", "true")
                                .json(&serde_json::json!({"cgroup_path": format!("/sys/fs/cgroup/sevorix/{}", session_id)}))
                                .send().await;
                            cleanup_session_cgroup(&session_id);
                        }
                        return Err(e);
                    }
                }
            }
        } else if (inv.command.is_some() || inv.script_file.is_some())
            && !no_sandbox_flag
            && (!has_unshare || !has_ip)
        {
            // Fail-closed: sandbox tools unavailable and --no-sandbox not set.
            eprintln!("[SEVSH] Error: Sandbox tools (unshare/ip) not available for -c/-script invocation.");
            eprintln!("[SEVSH] Fail-closed: Use --no-sandbox to allow unsandboxed execution.");
            if cgroup_created {
                let _ = reqwest::Client::builder().no_proxy().build().unwrap_or_default()
                    .post(format!("{}/api/session/unregister", proxy_url()))
                    .header("X-Sevorix-Internal", "true")
                    .json(&serde_json::json!({"cgroup_path": format!("/sys/fs/cgroup/sevorix/{}", session_id)}))
                    .send().await;
                cleanup_session_cgroup(&session_id);
            }
            std::process::exit(1);
        } else {
            // --no-sandbox set, or script-file invocation: fall back to env-var isolation.
            handle_bash_invocation(inv, true, &session_id).await?
        };
        if cgroup_created {
            let _ = reqwest::Client::builder().no_proxy().build().unwrap_or_default()
                .post(format!("{}/api/session/unregister", proxy_url()))
                .header("X-Sevorix-Internal", "true")
                .json(&serde_json::json!({"cgroup_path": format!("/sys/fs/cgroup/sevorix/{}", session_id)}))
                .send().await;
            cleanup_session_cgroup(&session_id);
        }
        exit(exit_code);
    }

    // Parse arguments with clap (sevsh-specific invocation)
    let args = SevshArgs::parse();

    // Generate unique session ID for this sevsh session
    let session_id = format!("sevsh-{}", Uuid::new_v4());

    // Fail-closed: Check daemon availability before proceeding
    if !args.no_sandbox {
        // Check if Watchtower is reachable
        match check_watchtower_reachable().await {
            Ok(()) => {}
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

    // Guard: if SEVORIX_SESSION_ID is already set we are nested inside an
    // existing sevsh session — skip cgroup creation to prevent recursive spawning.
    let already_in_session = env::var("SEVORIX_SESSION_ID").is_ok();

    // Create cgroup for this session (for eBPF process filtering)
    let cgroup_created = if already_in_session {
        false
    } else {
        match create_session_cgroup(&session_id) {
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
                    eprintln!(
                        "[SEVSH] Warning: Could not create cgroup: {}. Process isolation limited.",
                        e
                    );
                }
                false
            }
        }
    };

    // Register session with Watchtower for synchronous eBPF cgroup ID sync
    if cgroup_created {
        let _ = reqwest::Client::new()
            .post(format!("{}/api/session/register", proxy_url()))
            .header("X-Sevorix-Internal", "true")
            .json(&serde_json::json!({"cgroup_path": format!("/sys/fs/cgroup/sevorix/{}", session_id)}))
            .send()
            .await;
    }

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
                    if cgroup_created {
                        cleanup_session_cgroup(&session_id);
                    }
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
        if cgroup_created {
            let _ = reqwest::Client::new()
                .post(format!("{}/api/session/unregister", proxy_url()))
                .header("X-Sevorix-Internal", "true")
                .json(&serde_json::json!({"cgroup_path": format!("/sys/fs/cgroup/sevorix/{}", session_id)}))
                .send()
                .await;
            cleanup_session_cgroup(&session_id);
        }
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
        let _ = reqwest::Client::new()
            .post(format!("{}/api/session/unregister", proxy_url()))
            .json(&serde_json::json!({"cgroup_path": format!("/sys/fs/cgroup/sevorix/{}", session_id)}))
            .send()
            .await;
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
        .get(format!("{}/health", proxy_url()))
        .header("X-Sevorix-Internal", "true")
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
        )
        .into());
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
        )
        .into());
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
                                if tokio::io::copy_bidirectional(&mut tcp, &mut unix_stream)
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
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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

    // Re-raise any signal that killed the sandbox child so the sandbox is transparent
    // to signal-based termination. Without this, a SIGKILL received by the inner process
    // would be swallowed here and the real agent (our parent) would never see it.
    use std::os::unix::process::ExitStatusExt;
    if let Some(signal) = status.signal() {
        let ppid = unsafe { libc::getppid() };
        if ppid > 1 {
            unsafe { libc::kill(ppid, signal as libc::c_int) };
        }
    }

    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)))
}

fn resolved_proxy_port() -> u16 {
    let url = proxy_url();
    // Parse port from "http://localhost:PORT" or "http://localhost:PORT/..."
    url.split(':')
        .nth(2)
        .and_then(|s| s.split('/').next())
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(3000)
}

async fn proxy_unix_to_tcp(mut unix: UnixStream) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Inject X-Sevorix-Pid / X-Sevorix-Ppid into the first HTTP request's
    // headers so the proxy can tag network events with the sevsh process ID.
    // Advisory only — not a security control.
    const MAX_HEADER_BYTES: usize = 65_536;

    // --- Read HTTP headers byte-by-byte, looking for the end-of-headers marker ---
    let mut header_buf: Vec<u8> = Vec::with_capacity(4096);

    // 4-byte window for \r\n\r\n detection
    let mut window4 = [0u8; 4];
    // 2-byte window for bare-LF \n\n detection (HTTP/1.0 style)
    let mut last2 = [0u8; 2];

    loop {
        // Reject oversized headers: fail-closed with a proper HTTP error response.
        if header_buf.len() >= MAX_HEADER_BYTES {
            eprintln!(
                "[SEVSH] proxy_unix_to_tcp: request headers exceed {} bytes; rejecting connection",
                MAX_HEADER_BYTES
            );
            let _ = unix
                .write_all(
                    b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            return Ok(());
        }

        let mut byte = [0u8; 1];
        let n = unix.read(&mut byte).await?;
        if n == 0 {
            // Client closed connection before we saw end-of-headers.
            return Ok(());
        }

        header_buf.push(byte[0]);

        // Slide the 4-byte window
        window4[0] = window4[1];
        window4[1] = window4[2];
        window4[2] = window4[3];
        window4[3] = byte[0];

        // Slide the 2-byte window
        last2[0] = last2[1];
        last2[1] = byte[0];

        if window4 == *b"\r\n\r\n" {
            break;
        }
        if last2 == *b"\n\n" {
            break;
        }
    }

    // --- Inject X-Sevorix-Pid / X-Sevorix-Ppid headers before the terminator ---
    let pid = std::process::id();
    #[cfg(unix)]
    let ppid = unsafe { libc::getppid() } as u32;
    #[cfg(not(unix))]
    let ppid = 0u32;

    let injected = format!("X-Sevorix-Pid: {}\r\nX-Sevorix-Ppid: {}\r\n", pid, ppid);

    // Split at the blank line only (not the last header's \r\n).
    // The terminator \r\n\r\n is: "\r\n" (end of last header) + "\r\n" (blank line).
    // We keep the last header's "\r\n" in headers_part so the injected headers
    // are appended as new header lines rather than concatenated onto the last value.
    let last4: &[u8] = &header_buf[header_buf.len().saturating_sub(4)..];
    let (headers_part, blank_line): (&[u8], &[u8]) = if last4 == b"\r\n\r\n" {
        // Strip only the 2-byte blank line; keep the last header's "\r\n".
        (&header_buf[..header_buf.len() - 2], b"\r\n")
    } else {
        // Bare-LF style: strip only the final "\n" blank line.
        (&header_buf[..header_buf.len() - 1], b"\n")
    };

    // --- Connect to the Watchtower daemon and forward the modified request ---
    let addr = format!("127.0.0.1:{}", resolved_proxy_port());
    let mut tcp = TcpStream::connect(&addr).await?;

    tcp.write_all(headers_part).await?;
    tcp.write_all(injected.as_bytes()).await?;
    tcp.write_all(blank_line).await?;

    // Proxy the remaining request body and response bidirectionally.
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
                                        let _ = tokio::io::copy_bidirectional(&mut tcp, &mut unix)
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
        if arg == "--internal-sandbox" || arg == "--internal-forward-sock" || arg == "--session-id"
        {
            i += 2;
        } else if arg == "--no-proxy" || arg == "--no-sandbox" {
            // Filter out these flags as they are handled via bool params
            i += 1;
        } else {
            real_args.push(arg.clone());
            i += 1;
        }
    }

    // Re-check no-proxy / no-sandbox based on raw args (before filtering)
    let no_proxy = args.iter().any(|arg| arg == "--no-proxy");
    let _no_sandbox = args.iter().any(|arg| arg == "--no-sandbox");

    // Extract session ID from args
    let session_id =
        get_arg_value(args, "--session-id").unwrap_or_else(|| format!("sevsh-{}", Uuid::new_v4()));

    // Set session ID in environment
    env::set_var("SEVORIX_SESSION_ID", &session_id);

    // Call logic (eBPF daemon handles syscall interception)
    let code = if !real_args.is_empty() {
        if real_args[0].starts_with('-') {
            // Bash-style invocation inside sandbox (e.g. -c "cmd")
            let inv = parse_bash_invocation(&real_args);
            handle_bash_invocation(inv, !no_proxy, &session_id).await?
        } else {
            // Direct command exec from `sevsh -- cmd args` — exec the binary
            // directly rather than via bash to avoid "cannot execute binary file".
            handle_direct_exec(&real_args, !no_proxy, &session_id).await?
        }
    } else {
        run_pty_interactive_shell_code(!no_proxy, &session_id)?
    };
    exit(code);
}

/// Thin wrapper: parse raw args into a BashInvocation and execute.
/// Used by the clap path (sevsh-specific flags already stripped).
async fn handle_single_command(
    args: &[String],
    use_proxy: bool,
    session_id: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    if args.first().map(|a| !a.starts_with('-')).unwrap_or(false) {
        // Direct binary (e.g. from `sevsh -- cmd` fallback path)
        return handle_direct_exec(args, use_proxy, session_id).await;
    }
    let inv = parse_bash_invocation(args);
    handle_bash_invocation(inv, use_proxy, session_id).await
}

/// Execute a binary directly (not via a shell) after Watchtower validation.
/// Used when `sevsh -- cmd args...` passes a real binary (not bash options).
async fn handle_direct_exec(
    args: &[String],
    use_proxy: bool,
    session_id: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Ok(0);
    }

    // Validation payload: join args for a human-readable command string.
    let payload = args.join(" ");
    let verdict = validate_command(&payload).await?;

    if verdict.allowed {
        if verdict.status == "FLAG" {
            eprintln!(
                "SEVORIX WARNING: {} (Confidence: {})",
                verdict.reason, verdict.confidence
            );
        }

        let mut cmd = Command::new(&args[0]);
        cmd.args(&args[1..]);

        if use_proxy {
            cmd.env("HTTP_PROXY", proxy_url())
                .env("http_proxy", proxy_url())
                .env("HTTPS_PROXY", proxy_url())
                .env("https_proxy", proxy_url())
                .env("ALL_PROXY", proxy_url())
                .env("all_proxy", proxy_url())
                .env("NO_PROXY", "localhost,127.0.0.1,::1")
                .env("no_proxy", "localhost,127.0.0.1,::1");
        }
        cmd.env("SEVORIX_SESSION_ID", session_id);

        // On Linux: apply seccomp notify/deny filter via the shared helper.
        #[cfg(target_os = "linux")]
        let status = spawn_with_seccomp(&mut cmd).await?;

        #[cfg(not(target_os = "linux"))]
        let status = cmd.status()?;

        Ok(status.code().unwrap_or(1))
    } else {
        eprintln!("SEVORIX BLOCKED: {}", verdict.reason);
        if verdict.kill {
            eprintln!("SEVORIX: kill=true — terminating agent process.");
            let pid = agent_pid();
            if pid > 1 {
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
            return Ok(137);
        }
        Ok(1)
    }
}

/// Core execution path for bash-compatible invocations.
async fn handle_bash_invocation(
    inv: BashInvocation,
    use_proxy: bool,
    session_id: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let shell = real_shell();

    let payload = match inv.payload() {
        Some(p) => p,
        None => {
            // Nothing to execute (e.g. -i with no command)
            return Ok(0);
        }
    };

    let final_cmd_args = inv.to_bash_args();

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
                ("HTTP_PROXY".to_string(), proxy_url().to_string()),
                ("http_proxy".to_string(), proxy_url().to_string()),
                ("HTTPS_PROXY".to_string(), proxy_url().to_string()),
                ("https_proxy".to_string(), proxy_url().to_string()),
                ("ALL_PROXY".to_string(), proxy_url().to_string()),
                ("all_proxy".to_string(), proxy_url().to_string()),
                (
                    "NO_PROXY".to_string(),
                    "localhost,127.0.0.1,::1".to_string(),
                ),
                (
                    "no_proxy".to_string(),
                    "localhost,127.0.0.1,::1".to_string(),
                ),
            ]
        } else {
            vec![]
        };

        // Add session ID to environment for eBPF tagging
        env_vars.push(("SEVORIX_SESSION_ID".to_string(), session_id.to_string()));

        let mut command = Command::new(&shell);
        command.args(&final_cmd_args);
        for (key, value) in env_vars {
            command.env(key, value);
        }

        // On Linux: fetch the syscall policy and apply a per-child seccomp notify filter
        // for synchronous kernel-level enforcement. On macOS seccomp is unavailable
        // so we skip the fetch and go straight to command execution.
        #[cfg(target_os = "linux")]
        let status = spawn_with_seccomp(&mut command).await?;

        #[cfg(not(target_os = "linux"))]
        let status = command.status()?;

        Ok(status.code().unwrap_or(1))
    } else {
        eprintln!("SEVORIX BLOCKED: {}", verdict.reason);
        if verdict.kill {
            eprintln!("SEVORIX: kill=true — terminating agent process.");
            let pid = agent_pid();
            if pid > 1 {
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
            return Ok(137); // 128 + SIGKILL(9)
        }
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
fn run_pty_interactive_shell_code(
    use_proxy: bool,
    session_id: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let shell = real_shell();

    // Set session ID in environment
    env::set_var("SEVORIX_SESSION_ID", session_id);

    if use_proxy {
        println!("[SEVSH] Auto-Proxy Enabled: {}", proxy_url());
    }
    println!("[SEVSH] Session ID: {}", session_id);
    println!("[SEVSH] PTY Multiplexer Mode - Full terminal support");
    println!("[SEVSH] Type 'exit' or press Ctrl+D to leave.");

    // Build environment variables for proxy if needed
    let mut env_vars: Vec<(String, String)> = if use_proxy {
        vec![
            ("HTTP_PROXY".to_string(), proxy_url().to_string()),
            ("http_proxy".to_string(), proxy_url().to_string()),
            ("HTTPS_PROXY".to_string(), proxy_url().to_string()),
            ("https_proxy".to_string(), proxy_url().to_string()),
            ("ALL_PROXY".to_string(), proxy_url().to_string()),
            ("all_proxy".to_string(), proxy_url().to_string()),
            (
                "NO_PROXY".to_string(),
                "localhost,127.0.0.1,::1".to_string(),
            ),
            (
                "no_proxy".to_string(),
                "localhost,127.0.0.1,::1".to_string(),
            ),
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
        watchtower_url: proxy_url().to_string(),
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
    /// If true, SIGKILL the parent process (the agent) in addition to blocking.
    kill: bool,
}

/// Return the path to the real bash binary to use for executing commands.
///
/// Prefers `SEVORIX_REAL_SHELL`, which the sevorix-claude-launcher sets to a
/// bind-mounted copy of the original /bin/bash captured before sevsh replaces
/// it.  Falls back to `SHELL`, and finally to `/usr/bin/bash`.  Never falls
/// back to `/bin/bash` because in the Claude Code integration that path IS
/// sevsh — using it would recurse infinitely.
fn real_shell() -> String {
    env::var("SEVORIX_REAL_SHELL")
        .or_else(|_| env::var("SHELL"))
        .unwrap_or_else(|_| "/usr/bin/bash".to_string())
}

/// Returns the PID of the real agent process to target for kill=true enforcement.
///
/// In the sandbox path (run_parent_bridge → unshare → inner sevsh), getppid() returns
/// the outer sevsh wrapper rather than the actual agent. The outer sevsh records its
/// own PPID as SEVORIX_AGENT_PID before entering the sandbox so the inner process can
/// target the correct PID. Falls back to getppid() for the direct --no-sandbox path.
fn agent_pid() -> i32 {
    env::var("SEVORIX_AGENT_PID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| unsafe { libc::getppid() })
}

/// Fetch the syscall policy from Watchtower and compile it into a local rule set.
///
/// Returns the compiled rule set together with the role name that was used for the
/// policy fetch. The role is read from `settings.json` (`sevsh.default_role`) and
/// defaults to `"default"` if unset. Both values are needed so that blocked-syscall
/// events posted to `/analyze-syscall` carry the correct role.
///
/// Falls back to an empty rule set on any error (non-fatal: enforcement degrades
/// gracefully to the eBPF tracepoint observe-only path).
#[cfg(target_os = "linux")]
async fn fetch_syscall_policy() -> (sevorix_core::CompiledRuleSet, String) {
    use sevorix_core::{CompiledRuleSet, SyscallRule};
    let role = sevorix_watchtower::settings::Settings::load()
        .sevsh
        .and_then(|s| s.default_role)
        .unwrap_or_else(|| "default".to_string());
    let client = reqwest::Client::new();
    let url = format!("{}/syscall-policy?role={}", proxy_url(), role);
    match client.get(&url).send().await {
        Ok(resp) => {
            let rules: Vec<SyscallRule> = resp
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|v| serde_json::from_value(v["rules"].clone()).ok())
                .unwrap_or_default();
            (CompiledRuleSet::from_rules(rules), role)
        }
        Err(e) => {
            eprintln!(
                "[SEVSH] Warning: Could not fetch syscall policy: {}. Seccomp filter not applied.",
                e
            );
            (CompiledRuleSet::from_rules(vec![]), role)
        }
    }
}

/// Spawn `command` with the full seccomp notify/deny filter applied.
///
/// Fetches the current syscall policy from Watchtower, then:
/// 1. If the rule set is non-empty: installs a seccomp notify filter in the
///    child via `pre_exec`, reads the notify fd back over a pipe, and starts a
///    blocking supervisor task that evaluates each intercepted syscall and logs
///    denials to Watchtower.
/// 2. If the notify filter setup fails: falls back to a deny-only filter (no
///    supervisor, syscalls receive EPERM but are not logged).
/// 3. If the rule set is empty: spawns the command without any seccomp filter.
///
/// Returns the child's exit status.
#[cfg(target_os = "linux")]
async fn spawn_with_seccomp(command: &mut Command) -> std::io::Result<std::process::ExitStatus> {
    let (rule_set, session_role) = fetch_syscall_policy().await;

    if !rule_set.is_empty() {
        // Create a pipe so the child's pre_exec can pass the seccomp notify_fd
        // number back to us. Both ends inherit across fork; O_CLOEXEC closes them
        // on exec (after the pre_exec write is already done).
        let mut pipe_fds = [0i32; 2];
        let pipe_ok = unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } == 0;

        if pipe_ok {
            let (pipe_read, pipe_write) = (pipe_fds[0], pipe_fds[1]);

            // SAFETY: pre_exec runs after fork, before exec. syscall_names is
            // moved into the closure. We use only async-signal-safe primitives.
            let syscall_names = rule_set.syscall_names.clone();
            unsafe {
                command.pre_exec(move || {
                    libc::close(pipe_read); // child doesn't need read end
                    match apply_syscall_notify_filter(&syscall_names) {
                        Ok(notify_fd) => {
                            let bytes = notify_fd.to_ne_bytes();
                            libc::write(pipe_write, bytes.as_ptr() as *const libc::c_void, 4);
                            libc::close(pipe_write);
                            Ok(())
                        }
                        Err(_) => {
                            // Notify filter unavailable — signal -1 to parent and
                            // fall back to the deny filter so syscalls still get EPERM.
                            let bytes = (-1i32).to_ne_bytes();
                            libc::write(pipe_write, bytes.as_ptr() as *const libc::c_void, 4);
                            libc::close(pipe_write);
                            apply_syscall_deny_filter(&syscall_names).map_err(|e| {
                                std::io::Error::other(format!("seccomp fallback: {}", e))
                            })
                        }
                    }
                });
            }

            let mut child = command.spawn()?;
            let child_pid = child.id();

            // Close parent's write end so the pipe read returns EOF after
            // the child writes its 4 bytes and execs.
            unsafe { libc::close(pipe_write) };

            // Read the notify_fd number the child wrote (blocking, 4 bytes).
            let mut fd_bytes = [0u8; 4];
            let mut nread = 0usize;
            while nread < 4 {
                let r = unsafe {
                    libc::read(
                        pipe_read,
                        fd_bytes[nread..].as_mut_ptr() as *mut libc::c_void,
                        4 - nread,
                    )
                };
                if r <= 0 {
                    break;
                }
                nread += r as usize;
            }
            unsafe { libc::close(pipe_read) };

            if nread == 4 {
                let child_notify_fd = i32::from_ne_bytes(fd_bytes);
                // child_notify_fd == -1 means notify filter failed and deny filter
                // was loaded as fallback — no supervisor needed.
                if child_notify_fd >= 0 {
                    // pidfd_open(2) = 434, pidfd_getfd(2) = 438 on x86_64.
                    #[cfg(target_arch = "x86_64")]
                    const SYS_PIDFD_OPEN: i64 = 434;
                    #[cfg(target_arch = "x86_64")]
                    const SYS_PIDFD_GETFD: i64 = 438;
                    #[cfg(not(target_arch = "x86_64"))]
                    const SYS_PIDFD_OPEN: i64 = libc::SYS_pidfd_open as i64;
                    #[cfg(not(target_arch = "x86_64"))]
                    const SYS_PIDFD_GETFD: i64 = libc::SYS_pidfd_getfd as i64;

                    let pidfd =
                        unsafe { libc::syscall(SYS_PIDFD_OPEN, child_pid as libc::pid_t, 0u32) }
                            as i32;
                    let parent_notify_fd = if pidfd >= 0 {
                        let fd =
                            unsafe { libc::syscall(SYS_PIDFD_GETFD, pidfd, child_notify_fd, 0u32) }
                                as i32;
                        unsafe { libc::close(pidfd) };
                        fd
                    } else {
                        -1
                    };

                    if parent_notify_fd >= 0 {
                        // Spawn a blocking supervisor: evaluates each intercepted syscall
                        // locally against the compiled rule set (zero-latency, no HTTP),
                        // then responds to the kernel. Denied syscalls are logged to
                        // Watchtower asynchronously on a fire-and-forget thread.
                        let log_url = proxy_url().to_string();
                        tokio::task::spawn_blocking(move || {
                            run_seccomp_notify_supervisor(
                                parent_notify_fd,
                                |info: &SyscallInfo| -> bool {
                                    let allow = rule_set.evaluate(info);
                                    if !allow {
                                        // Resolve the path NOW while the process is still
                                        // suspended by seccomp-unotify. After we return,
                                        // the pointer in args is no longer valid.
                                        let path = sevorix_core::resolve_syscall_path(info);
                                        let name = sevorix_core::syscall_name(info.syscall_nr);
                                        let args: Vec<String> = info
                                            .args
                                            .iter()
                                            .map(|a| format!("0x{:x}", a))
                                            .collect();
                                        let ppid_for_block = std::fs::read_to_string(format!(
                                            "/proc/{}/stat",
                                            info.pid
                                        ))
                                        .ok()
                                        .map(|s| parse_ppid_from_stat(&s))
                                        .unwrap_or(0);
                                        let payload = serde_json::json!({
                                            "syscall_name": name,
                                            "syscall_number": info.syscall_nr,
                                            "args": args,
                                            "pid": info.pid,
                                            "ppid": ppid_for_block,
                                            "timestamp": chrono::Local::now().to_rfc3339(),
                                            "path": path,
                                            "role": session_role,
                                        });
                                        // Log synchronously — we're already in spawn_blocking,
                                        // and the child is about to receive EPERM and exit,
                                        // so the added latency is acceptable. A fire-and-forget
                                        // thread would be killed when sevsh exits before the
                                        // HTTP call completes.
                                        if let Ok(client) = reqwest::blocking::Client::builder()
                                            .timeout(std::time::Duration::from_millis(50))
                                            .build()
                                        {
                                            let _ = client
                                                .post(format!("{}/analyze-syscall", &log_url))
                                                .json(&payload)
                                                .send();
                                        }
                                    }
                                    allow
                                },
                            );
                        });
                    } else {
                        // pidfd_getfd failed — we can't attach a supervisor, but the
                        // child's notify filter is already loaded. Without a supervisor,
                        // the first monitored syscall would deadlock waiting for a
                        // unotify response. Kill the child to surface the error cleanly.
                        eprintln!(
                            "[SEVSH] Error: could not attach seccomp supervisor (pidfd_getfd failed: {}). Aborting.",
                            std::io::Error::last_os_error()
                        );
                        unsafe { libc::kill(child_pid as libc::pid_t, libc::SIGKILL) };
                    }
                }
            }

            child.wait()
        } else {
            // Pipe creation failed; fall back to EPERM-only filter (no logging).
            let fallback_names = rule_set.syscall_names.clone();
            unsafe {
                command.pre_exec(move || {
                    apply_syscall_deny_filter(&fallback_names)
                        .map_err(|e| std::io::Error::other(format!("seccomp filter failed: {}", e)))
                });
            }
            command.status()
        }
    } else {
        command.status()
    }
}

async fn validate_command(cmd: &str) -> Result<Verdict, Box<dyn std::error::Error>> {
    let settings = sevorix_watchtower::settings::Settings::load();
    // The validation timeout must exceed the intervention timeout so that flagged
    // commands can wait for an operator decision without sevsh timing out first.
    // Use explicit validation_timeout_secs if set; otherwise derive from the
    // intervention timeout (default 30s) plus a 10s buffer.
    let timeout_secs = settings
        .sevsh
        .as_ref()
        .and_then(|s| s.validation_timeout_secs)
        .unwrap_or_else(|| {
            let intervention_secs = settings
                .intervention
                .as_ref()
                .map(|i| i.timeout_secs())
                .unwrap_or(30);
            intervention_secs + 10
        });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()?;
    let url = format!("{}/analyze", proxy_url());

    // Fail-safe: if we can't connect, we must fail closed (or exit process),
    // but returning error here lets the caller decide.
    // The plan says: "If Watchtower is unreachable, default to blocking execution".

    let pid = std::process::id();
    let ppid = unsafe { libc::getppid() } as u32;
    let resp = client
        .post(url)
        .json(&json!({
            "payload": cmd,
            "agent": "sevsh-repl",
            "context": "Shell",
            "pid": pid,
            "ppid": ppid,
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
                    kill: false,
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
            let kill = json_resp["kill"].as_bool().unwrap_or(false);

            // Map status to allowed
            let allowed = status == "ALLOW" || status == "FLAG"; // Plan says "If ALLOW/FLAG: Execute"

            Ok(Verdict {
                allowed,
                status,
                reason,
                confidence,
                kill,
            })
        }
        Err(e) => {
            // Unreachable -> Block
            Ok(Verdict {
                allowed: false,
                status: "UNREACHABLE".to_string(),
                reason: format!("Watchtower unreachable: {}", e),
                confidence: "100%".to_string(),
                kill: false,
            })
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// Parse the ppid (4th field) from a `/proc/<pid>/stat` file content.
///
/// The format is: `pid (comm) state ppid ...`
/// where `comm` may contain spaces and parentheses, so we locate the
/// *last* `)` to find where the fixed fields begin.
fn parse_ppid_from_stat(stat: &str) -> u32 {
    stat.rfind(')')
        .and_then(|close| {
            stat[close + 2..]
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u32>().ok())
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| s.to_string()).collect()
    }

    /// Shared lock so proxy_unix_to_tcp tests that mutate RESOLVED_PROXY_URL
    /// don't race against each other.
    static PORT_LOCK: Mutex<()> = Mutex::new(());

    // -------------------------------------------------------------------------
    // parse_ppid_from_stat
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_ppid_normal() {
        // Typical /proc/<pid>/stat line
        let stat = "1234 (bash) S 5678 1234 1234 0 -1 4194304 100 0 0 0 0 0 0 0 20 0 1";
        assert_eq!(parse_ppid_from_stat(stat), 5678);
    }

    #[test]
    fn test_parse_ppid_comm_with_parens() {
        // Process name that itself contains parentheses
        let stat = "42 (my (weird) proc) S 99 42 42 0 -1 0";
        assert_eq!(parse_ppid_from_stat(stat), 99);
    }

    #[test]
    fn test_parse_ppid_comm_with_spaces() {
        let stat = "7 (kworker/0:1H) I 2 0 0 0 -1 69238880";
        assert_eq!(parse_ppid_from_stat(stat), 2);
    }

    #[test]
    fn test_parse_ppid_no_closing_paren() {
        assert_eq!(parse_ppid_from_stat("1234 (bash"), 0);
    }

    #[test]
    fn test_parse_ppid_too_few_fields() {
        // Only state field after ')' — ppid field missing
        let stat = "1 (init) S";
        assert_eq!(parse_ppid_from_stat(stat), 0);
    }

    #[test]
    fn test_parse_ppid_non_numeric_ppid() {
        let stat = "1 (init) S notanumber rest";
        assert_eq!(parse_ppid_from_stat(stat), 0);
    }

    #[test]
    fn test_parse_ppid_matches_getppid_for_self() {
        // Smoke-test against the real /proc/self/stat on Linux.
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
        let parsed = parse_ppid_from_stat(&stat);
        let actual = unsafe { libc::getppid() } as u32;
        assert_eq!(
            parsed, actual,
            "parsed ppid from /proc/self/stat should match libc::getppid()"
        );
    }

    // -------------------------------------------------------------------------
    // parse_bash_invocation
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_empty() {
        let inv = parse_bash_invocation(&[]);
        assert_eq!(inv, BashInvocation::default());
        assert!(inv.command.is_none());
        assert!(inv.script_file.is_none());
        assert!(inv.positional_args.is_empty());
        assert!(!inv.interactive);
    }

    #[test]
    fn test_parse_c_basic() {
        let inv = parse_bash_invocation(&args(&["-c", "echo hello"]));
        assert_eq!(inv.command.as_deref(), Some("echo hello"));
        assert!(inv.script_file.is_none());
        assert!(inv.positional_args.is_empty());
        assert!(inv.set_options.is_empty());
    }

    #[test]
    fn test_parse_c_with_positional_args_after_dashdash() {
        let inv = parse_bash_invocation(&args(&["-c", "echo $0 $1", "--", "arg0", "arg1"]));
        assert_eq!(inv.command.as_deref(), Some("echo $0 $1"));
        assert_eq!(inv.positional_args, args(&["arg0", "arg1"]));
    }

    #[test]
    fn test_parse_c_with_positional_args_no_dashdash() {
        // bash -c 'cmd' arg0 arg1  (no explicit --)
        let inv = parse_bash_invocation(&args(&["-c", "echo $@", "arg0", "arg1"]));
        assert_eq!(inv.command.as_deref(), Some("echo $@"));
        assert_eq!(inv.positional_args, args(&["arg0", "arg1"]));
    }

    #[test]
    fn test_parse_set_option_e() {
        let inv = parse_bash_invocation(&args(&["-e", "-c", "cmd"]));
        assert!(inv.set_options.contains(&"-e".to_string()));
        assert_eq!(inv.command.as_deref(), Some("cmd"));
    }

    #[test]
    fn test_parse_multiple_set_options() {
        let inv = parse_bash_invocation(&args(&["-e", "-x", "-v", "-c", "cmd"]));
        assert!(inv.set_options.contains(&"-e".to_string()));
        assert!(inv.set_options.contains(&"-x".to_string()));
        assert!(inv.set_options.contains(&"-v".to_string()));
        assert_eq!(inv.command.as_deref(), Some("cmd"));
    }

    #[test]
    fn test_parse_set_option_cluster() {
        // bash -ex -c 'cmd' is valid — clusters of single-char options
        let inv = parse_bash_invocation(&args(&["-ex", "-c", "cmd"]));
        assert!(inv.set_options.contains(&"-e".to_string()));
        assert!(inv.set_options.contains(&"-x".to_string()));
        assert_eq!(inv.command.as_deref(), Some("cmd"));
    }

    #[test]
    fn test_parse_interactive_flag() {
        let inv = parse_bash_invocation(&args(&["-i"]));
        assert!(inv.interactive);
        assert!(inv.command.is_none());
        assert!(inv.script_file.is_none());
    }

    #[test]
    fn test_parse_interactive_in_cluster() {
        let inv = parse_bash_invocation(&args(&["-il"]));
        assert!(inv.interactive);
        assert!(inv.set_options.contains(&"-l".to_string()));
    }

    #[test]
    fn test_parse_long_option_norc() {
        let inv = parse_bash_invocation(&args(&["--norc", "-c", "cmd"]));
        assert!(inv.extra_options.contains(&"--norc".to_string()));
        assert_eq!(inv.command.as_deref(), Some("cmd"));
    }

    #[test]
    fn test_parse_long_option_noprofile() {
        let inv = parse_bash_invocation(&args(&["--noprofile", "-c", "cmd"]));
        assert!(inv.extra_options.contains(&"--noprofile".to_string()));
    }

    #[test]
    fn test_parse_long_option_login() {
        let inv = parse_bash_invocation(&args(&["--login", "-c", "cmd"]));
        assert!(inv.extra_options.contains(&"--login".to_string()));
    }

    #[test]
    fn test_parse_long_option_rcfile_with_value() {
        let inv = parse_bash_invocation(&args(&["--rcfile", "/etc/bashrc", "-c", "cmd"]));
        assert!(inv.extra_options.contains(&"--rcfile".to_string()));
        assert!(inv.extra_options.contains(&"/etc/bashrc".to_string()));
        assert_eq!(inv.command.as_deref(), Some("cmd"));
    }

    #[test]
    fn test_parse_long_option_init_file_with_value() {
        let inv = parse_bash_invocation(&args(&["--init-file", "/etc/bashrc", "-c", "cmd"]));
        assert!(inv.extra_options.contains(&"--init-file".to_string()));
        assert!(inv.extra_options.contains(&"/etc/bashrc".to_string()));
    }

    #[test]
    fn test_parse_script_file_mode() {
        let inv = parse_bash_invocation(&args(&["script.sh", "arg1", "arg2"]));
        assert_eq!(inv.script_file.as_deref(), Some("script.sh"));
        assert_eq!(inv.positional_args, args(&["arg1", "arg2"]));
        assert!(inv.command.is_none());
    }

    #[test]
    fn test_parse_script_file_with_set_options() {
        let inv = parse_bash_invocation(&args(&["-e", "script.sh", "arg1"]));
        assert!(inv.set_options.contains(&"-e".to_string()));
        assert_eq!(inv.script_file.as_deref(), Some("script.sh"));
        assert_eq!(inv.positional_args, args(&["arg1"]));
    }

    #[test]
    fn test_parse_dashdash_stops_option_processing() {
        // bash -- -c  →  tries to run a file named "-c"
        let inv = parse_bash_invocation(&args(&["--", "-c"]));
        assert!(inv.command.is_none());
        assert_eq!(inv.positional_args, args(&["-c"]));
    }

    #[test]
    fn test_parse_dashdash_with_script() {
        let inv = parse_bash_invocation(&args(&["--", "script.sh", "arg1"]));
        assert!(inv.command.is_none());
        assert_eq!(inv.positional_args, args(&["script.sh", "arg1"]));
    }

    #[test]
    fn test_parse_combined_full() {
        // bash -e -x --norc -c 'echo $0' -- myname arg1
        let inv = parse_bash_invocation(&args(&[
            "-e", "-x", "--norc", "-c", "echo $0", "--", "myname", "arg1",
        ]));
        assert!(inv.set_options.contains(&"-e".to_string()));
        assert!(inv.set_options.contains(&"-x".to_string()));
        assert!(inv.extra_options.contains(&"--norc".to_string()));
        assert_eq!(inv.command.as_deref(), Some("echo $0"));
        assert_eq!(inv.positional_args, args(&["myname", "arg1"]));
    }

    #[test]
    fn test_parse_unknown_long_option_passed_through() {
        let inv = parse_bash_invocation(&args(&["--some-unknown-flag", "-c", "cmd"]));
        assert!(inv
            .extra_options
            .contains(&"--some-unknown-flag".to_string()));
        assert_eq!(inv.command.as_deref(), Some("cmd"));
    }

    #[test]
    fn test_parse_c_empty_command_string() {
        let inv = parse_bash_invocation(&args(&["-c", ""]));
        assert_eq!(inv.command.as_deref(), Some(""));
    }

    #[test]
    fn test_parse_c_no_string_is_silent() {
        // -c with nothing after it — command stays None
        let inv = parse_bash_invocation(&args(&["-c"]));
        assert!(inv.command.is_none());
    }

    #[test]
    fn test_parse_dashdash_no_following_args() {
        let inv = parse_bash_invocation(&args(&["--"]));
        assert!(inv.positional_args.is_empty());
        assert!(inv.command.is_none());
        assert!(inv.script_file.is_none());
    }

    // -------------------------------------------------------------------------
    // BashInvocation::to_bash_args
    // -------------------------------------------------------------------------

    #[test]
    fn test_to_bash_args_command_string() {
        let inv = BashInvocation {
            command: Some("echo hello".to_string()),
            ..Default::default()
        };
        assert_eq!(inv.to_bash_args(), args(&["-c", "echo hello"]));
    }

    #[test]
    fn test_to_bash_args_command_with_positional() {
        let inv = BashInvocation {
            command: Some("echo $0 $1".to_string()),
            positional_args: args(&["myname", "arg1"]),
            ..Default::default()
        };
        assert_eq!(
            inv.to_bash_args(),
            args(&["-c", "echo $0 $1", "myname", "arg1"])
        );
    }

    #[test]
    fn test_to_bash_args_set_options_prepended() {
        let inv = BashInvocation {
            command: Some("cmd".to_string()),
            set_options: args(&["-e", "-x"]),
            ..Default::default()
        };
        assert_eq!(inv.to_bash_args(), args(&["-e", "-x", "-c", "cmd"]));
    }

    #[test]
    fn test_to_bash_args_extra_options_after_set() {
        let inv = BashInvocation {
            command: Some("cmd".to_string()),
            set_options: args(&["-e"]),
            extra_options: args(&["--norc"]),
            ..Default::default()
        };
        assert_eq!(inv.to_bash_args(), args(&["-e", "--norc", "-c", "cmd"]));
    }

    #[test]
    fn test_to_bash_args_script_file() {
        let inv = BashInvocation {
            script_file: Some("script.sh".to_string()),
            positional_args: args(&["arg1", "arg2"]),
            ..Default::default()
        };
        assert_eq!(inv.to_bash_args(), args(&["script.sh", "arg1", "arg2"]));
    }

    #[test]
    fn test_to_bash_args_script_file_with_set_options() {
        let inv = BashInvocation {
            script_file: Some("script.sh".to_string()),
            set_options: args(&["-e"]),
            ..Default::default()
        };
        assert_eq!(inv.to_bash_args(), args(&["-e", "script.sh"]));
    }

    #[test]
    fn test_to_bash_args_interactive_empty() {
        let inv = BashInvocation {
            interactive: true,
            ..Default::default()
        };
        assert!(inv.to_bash_args().is_empty());
    }

    // -------------------------------------------------------------------------
    // BashInvocation::payload
    // -------------------------------------------------------------------------

    #[test]
    fn test_payload_command() {
        let inv = BashInvocation {
            command: Some("echo hi".to_string()),
            ..Default::default()
        };
        assert_eq!(inv.payload().as_deref(), Some("echo hi"));
    }

    #[test]
    fn test_payload_script_file() {
        let inv = BashInvocation {
            script_file: Some("run.sh".to_string()),
            ..Default::default()
        };
        assert_eq!(inv.payload().as_deref(), Some("run.sh"));
    }

    #[test]
    fn test_payload_none_when_interactive() {
        let inv = BashInvocation {
            interactive: true,
            ..Default::default()
        };
        assert!(inv.payload().is_none());
    }

    // -------------------------------------------------------------------------
    // has_sevsh_flags
    // -------------------------------------------------------------------------

    #[test]
    fn test_has_sevsh_flags_no_proxy() {
        // --no-proxy is a modifier flag; does not force the clap path on its own
        assert!(!has_sevsh_flags(&args(&["--no-proxy", "-c", "cmd"])));
    }

    #[test]
    fn test_has_sevsh_flags_no_sandbox() {
        // --no-sandbox is a modifier flag; does not force the clap path on its own
        assert!(!has_sevsh_flags(&args(&["--no-sandbox"])));
    }

    #[test]
    fn test_has_sevsh_flags_internal_sandbox() {
        assert!(has_sevsh_flags(&args(&["--internal-sandbox", "/tmp/sock"])));
    }

    #[test]
    fn test_has_sevsh_flags_publish_long() {
        assert!(has_sevsh_flags(&args(&["--publish", "8080:80"])));
    }

    #[test]
    fn test_has_sevsh_flags_publish_short() {
        assert!(has_sevsh_flags(&args(&["-p", "8080:80"])));
    }

    #[test]
    fn test_has_sevsh_flags_none_for_bash_args() {
        assert!(!has_sevsh_flags(&args(&["-e", "-c", "echo hello"])));
    }

    #[test]
    fn test_has_sevsh_flags_none_for_script() {
        assert!(!has_sevsh_flags(&args(&["script.sh", "arg1"])));
    }

    #[test]
    fn test_has_sevsh_flags_none_for_empty() {
        assert!(!has_sevsh_flags(&[]));
    }

    #[test]
    fn test_has_sevsh_flags_double_dash() {
        // `sevsh -- curl ...` must route through the clap path, not bash-compat
        assert!(has_sevsh_flags(&args(&[
            "--",
            "curl",
            "-s",
            "http://example.com"
        ])));
    }

    // -------------------------------------------------------------------------
    // parse_bash_invocation: --flag=value stripping
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_no_sandbox_eq_value_consumed() {
        // --no-sandbox=value must be consumed by sevsh, NOT forwarded to bash.
        let inv = parse_bash_invocation(&args(&["--no-sandbox=true", "-c", "echo hello"]));
        assert_eq!(inv.command, Some("echo hello".to_string()));
        assert!(
            !inv.extra_options.iter().any(|o| o == "--no-sandbox=true"),
            "expected --no-sandbox=true to be consumed, not in extra_options"
        );
    }

    #[test]
    fn test_parse_no_proxy_eq_value_consumed() {
        // --no-proxy=value must be consumed by sevsh, NOT forwarded to bash.
        let inv = parse_bash_invocation(&args(&["--no-proxy=1", "-c", "cmd"]));
        assert_eq!(inv.command, Some("cmd".to_string()));
        assert!(
            !inv.extra_options.iter().any(|o| o == "--no-proxy=1"),
            "expected --no-proxy=1 to be consumed, not in extra_options"
        );
    }

    // -------------------------------------------------------------------------
    // proxy_unix_to_tcp: bare-LF header injection
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_proxy_unix_to_tcp_bare_lf_injection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        let _guard = PORT_LOCK.lock().unwrap();

        // Bind a TCP listener on a random port.
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp_listener.local_addr().unwrap().port();

        // Point RESOLVED_PROXY_URL at our listener.  The OnceLock may already
        // be initialised from a previous test run in this process; if so we
        // need to overwrite it.  We do this by temporarily putting the port
        // into SEVORIX_PORT and then calling resolved_proxy_port() which
        // parses from the OnceLock — but since the OnceLock is already set we
        // have to use a small workaround: override the OnceLock value with
        // unsafe memory manipulation would be unsound, so instead we force the
        // URL by using set_var and calling resolve_proxy_url() inline here,
        // then patching the OnceLock.  Because OnceLock doesn't allow
        // overwrite we use a different strategy: derive the port from the
        // env-var inside a helper and verify the listener receives the request.
        //
        // The cleanest approach that avoids OnceLock conflicts: write the
        // request to the unix socket directly, and inspect what arrives at the
        // TCP listener after spawning the task.  We temporarily set
        // SEVORIX_PORT so that resolved_proxy_port() picks up our port.
        // resolved_proxy_port() reads proxy_url() which reads RESOLVED_PROXY_URL.
        // If RESOLVED_PROXY_URL is uninitialised it falls back to env vars via
        // resolve_proxy_url().  We ensure RESOLVED_PROXY_URL is initialised to
        // our port by calling get_or_init before the task starts.
        RESOLVED_PROXY_URL.get_or_init(|| format!("http://localhost:{}", port));

        // If the OnceLock was already initialised to a different port we fall
        // back to whatever port it holds and bind a new listener on that port.
        let actual_port: u16 = {
            let url = RESOLVED_PROXY_URL.get().unwrap();
            url.split(':')
                .nth(2)
                .and_then(|s| s.split('/').next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(3000)
        };

        // Re-bind the listener on the actual port if it differs.
        let tcp_listener: tokio::net::TcpListener = if actual_port == port {
            tcp_listener
        } else {
            tokio::net::TcpListener::bind(format!("127.0.0.1:{}", actual_port))
                .await
                .unwrap()
        };

        // Create a Unix socket pair.  We pass the *server* side to
        // proxy_unix_to_tcp; we write the request to the *client* side.
        let (mut client_unix, server_unix) = UnixStream::pair().unwrap();

        // Spawn the proxy task.
        let proxy_task = tokio::spawn(proxy_unix_to_tcp(server_unix));

        // Write an HTTP request with bare-LF line endings.
        client_unix
            .write_all(b"GET / HTTP/1.0\nHost: example.com\n\n")
            .await
            .unwrap();

        // Accept the forwarded connection on the TCP listener.
        let (mut tcp_conn, _) = tcp_listener.accept().await.unwrap();

        // Read the forwarded request (up to 8 KiB).
        let mut buf = vec![0u8; 8192];
        let n = tcp_conn.read(&mut buf).await.unwrap();
        let forwarded = std::str::from_utf8(&buf[..n]).unwrap();

        assert!(
            forwarded.contains("X-Sevorix-Pid:"),
            "expected X-Sevorix-Pid header in forwarded request, got:\n{}",
            forwarded
        );
        assert!(
            forwarded.contains("X-Sevorix-Ppid:"),
            "expected X-Sevorix-Ppid header in forwarded request, got:\n{}",
            forwarded
        );
        // Structural check: Host header must be properly terminated before the
        // injected headers (no concatenation like "example.comX-Sevorix-Pid:").
        assert!(
            forwarded.contains("Host: example.com\n"),
            "Host header must be terminated with \\n before injected headers; got:\n{}",
            forwarded
        );
        // Verify the injected headers don't bleed into the Host value.
        assert!(
            !forwarded.contains("example.comX-Sevorix"),
            "injected headers must not be concatenated onto Host value; got:\n{}",
            forwarded
        );

        // Close the TCP connection so the bidirectional copy terminates.
        drop(tcp_conn);
        drop(client_unix);
        let _ = proxy_task.await;
    }

    // -------------------------------------------------------------------------
    // proxy_unix_to_tcp: CRLF header injection (standard HTTP/1.1)
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_proxy_unix_to_tcp_crlf_injection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        // Serialize with the bare-LF test so they don't race on RESOLVED_PROXY_URL.
        let _guard = PORT_LOCK.lock().unwrap();

        // Reuse the same port-discovery pattern as the bare-LF test.
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp_listener.local_addr().unwrap().port();

        RESOLVED_PROXY_URL.get_or_init(|| format!("http://localhost:{}", port));
        let actual_port: u16 = {
            let url = RESOLVED_PROXY_URL.get().unwrap();
            url.split(':')
                .nth(2)
                .and_then(|s| s.split('/').next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(3000)
        };
        let tcp_listener = if actual_port == port {
            tcp_listener
        } else {
            drop(tcp_listener);
            tokio::net::TcpListener::bind(format!("127.0.0.1:{}", actual_port))
                .await
                .unwrap()
        };

        let (mut client_unix, server_unix) = UnixStream::pair().unwrap();
        let proxy_task = tokio::spawn(proxy_unix_to_tcp(server_unix));

        // Standard CRLF HTTP/1.1 POST with a small JSON body.
        client_unix
            .write_all(
                b"POST /analyze HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            )
            .await
            .unwrap();

        let (mut tcp_conn, _) = tcp_listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let n = tcp_conn.read(&mut buf).await.unwrap();
        let forwarded = std::str::from_utf8(&buf[..n]).unwrap();

        // Injected headers must be present.
        assert!(
            forwarded.contains("X-Sevorix-Pid:"),
            "expected X-Sevorix-Pid header; got:\n{forwarded}"
        );
        assert!(
            forwarded.contains("X-Sevorix-Ppid:"),
            "expected X-Sevorix-Ppid header; got:\n{forwarded}"
        );
        // The Content-Length header must retain its own \r\n terminator and must
        // NOT be concatenated with the injected header name.
        assert!(
            forwarded.contains("Content-Length: 2\r\n"),
            "Content-Length must be properly terminated before injected headers; got:\n{forwarded}"
        );
        assert!(
            !forwarded.contains("2X-Sevorix"),
            "injected headers must not be concatenated onto Content-Length value; got:\n{forwarded}"
        );
        // There must be exactly one \r\n\r\n separating headers from body.
        let header_end = forwarded
            .find("\r\n\r\n")
            .expect("no \\r\\n\\r\\n found in forwarded request");
        assert!(
            !forwarded[header_end + 4..].contains("\r\n\r\n"),
            "forwarded request must have exactly one header terminator; got:\n{forwarded}"
        );

        drop(tcp_conn);
        drop(client_unix);
        let _ = proxy_task.await;
    }

    // -------------------------------------------------------------------------
    // proxy_unix_to_tcp: oversized headers → 431 rejection
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_proxy_unix_to_tcp_oversized_headers_431() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        // Create a Unix socket pair.
        let (mut client_unix, server_unix) = UnixStream::pair().unwrap();

        // Build a request whose headers exceed MAX_HEADER_BYTES (65536).
        // The header value consists of 66000 'a' bytes (no \r or \n embedded),
        // which pushes the buffer past 65536 before any terminator is seen.
        let mut big_request = b"GET / HTTP/1.1\r\nX-Padding: ".to_vec();
        big_request.extend(std::iter::repeat(b'a').take(66_000));
        big_request.extend_from_slice(b"\r\n\r\n");

        // Spawn the proxy function as a task first, then feed it data.
        // We read from the client concurrently so we capture the 431 response
        // before server_unix is dropped.
        let proxy_task = tokio::spawn(proxy_unix_to_tcp(server_unix));

        // Write the oversized request to the client side.
        client_unix.write_all(&big_request).await.unwrap();
        // Shut down the write half so the server sees EOF after writing the 431.
        client_unix.shutdown().await.unwrap();

        // Concurrently read back the 431 response from the server.
        let mut response = Vec::new();
        client_unix.read_to_end(&mut response).await.unwrap_or(0);

        // Wait for the proxy task to finish.
        let result = proxy_task.await.expect("proxy task panicked");
        assert!(result.is_ok(), "expected Ok(()), got: {:?}", result);

        let response_str = std::str::from_utf8(&response).unwrap_or("<non-utf8>");
        assert!(
            response_str.starts_with("HTTP/1.1 431"),
            "expected HTTP/1.1 431 response, got: {:?}",
            response_str
        );
    }
}
