// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

use clap::{CommandFactory, Parser};
use sevorix_watchtower::find_available_port;
use sevorix_watchtower::prime::print_prime;
use sevorix_watchtower::{
    handle_config, handle_integrations, handle_validate,
    logging::{init_logging, init_logging_with_session},
    run_server, validate_startup_config, Cli, Commands, DaemonManager, HubCommands,
};
use tracing::info;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Parse allowed roles from CLI
    let allowed_roles = cli.roles.as_ref().map(|s| {
        s.split(',')
            .map(|r| r.trim().to_string())
            .collect::<Vec<String>>()
    });

    match cli.command {
        Some(Commands::Start {
            watchtower_only,
            ebpf_only,
            name,
            port,
        }) => {
            // Handle mutually exclusive flags
            if watchtower_only && ebpf_only {
                eprintln!("Error: --watchtower-only and --ebpf-only are mutually exclusive");
                std::process::exit(1);
            }

            // Determine what to start
            let start_watchtower = !ebpf_only;
            let start_ebpf = !watchtower_only;

            // Pre-flight check: fail early if eBPF is requested but not available
            if start_ebpf {
                #[cfg(not(feature = "ebpf"))]
                {
                    eprintln!("Error: eBPF daemon not available. Reinstall with eBPF support.");
                    std::process::exit(1);
                }
            }

            // Start Watchtower if requested
            if start_watchtower {
                // Pre-flight: validate config before daemonizing so errors surface
                // to the user immediately rather than silently crashing the child.
                if let Err(e) = validate_startup_config() {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }

                // Lite: enforce single-session limit
                {
                    if let Ok(sessions) = DaemonManager::list_sessions() {
                        if let Some((info, _)) = sessions.iter().find(|(_, running)| *running) {
                            eprintln!(
                                "A session '{}' is already running on port {}.",
                                info.name, info.port
                            );
                            eprintln!("  sevorix stop        # stop the current session");
                            eprintln!("Upgrade to pro for multiple concurrent sessions.");
                            std::process::exit(1);
                        }
                    }
                }

                let session_id = uuid::Uuid::new_v4();
                let session_name = name.unwrap_or_else(|| session_id.to_string());
                let resolved_port = port.unwrap_or_else(|| find_available_port(3000));

                let start_role: Option<String> = None;

                let daemon = DaemonManager::new(&session_name)?;
                daemon.start(session_id, resolved_port, start_role.clone(), start_ebpf)?;
                let _guard = init_logging_with_session(session_id);
                info!("Watchtower daemon initialized. Session ID: {}", session_id);

                // Start eBPF daemon before blocking on the server
                if start_ebpf {
                    #[cfg(feature = "ebpf")]
                    {
                        info!("Starting eBPF daemon...");
                        if let Some(ebpf_process) = spawn_ebpf_daemon(resolved_port)? {
                            info!("eBPF daemon started with PID: {}", ebpf_process.id());
                        }
                    }
                }

                start_runtime(allowed_roles.clone(), session_id, resolved_port, start_role)?;
            } else if start_ebpf {
                // eBPF-only mode: spawn daemon and wait for it
                #[cfg(feature = "ebpf")]
                {
                    info!("Starting eBPF daemon...");
                    let ebpf_port = port.unwrap_or_else(|| find_available_port(3000));
                    if let Some(mut ebpf_process) = spawn_ebpf_daemon(ebpf_port)? {
                        info!("eBPF daemon started with PID: {}", ebpf_process.id());
                        let status = ebpf_process.wait()?;
                        if let Some(code) = status.code() {
                            std::process::exit(code);
                        }
                    }
                }
            }
        }
        Some(Commands::Stop {}) => {
            if let Err(e) = DaemonManager::stop_all() {
                eprintln!("Error stopping sessions: {}", e);
            }
            #[cfg(feature = "ebpf")]
            if let Err(e) = stop_ebpf_daemon() {
                eprintln!("Error stopping eBPF daemon: {}", e);
            }
        }
        Some(Commands::Restart) => {
            DaemonManager::stop_all()?;
            #[cfg(feature = "ebpf")]
            {
                let _ = stop_ebpf_daemon();
            }
            // Brief pause to ensure OS releases resources
            std::thread::sleep(std::time::Duration::from_millis(500));
            if let Err(e) = validate_startup_config() {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
            let session_id = uuid::Uuid::new_v4();
            let session_name = session_id.to_string();
            let resolved_port = 3000u16;
            let daemon = DaemonManager::new(&session_name)?;
            daemon.start(session_id, resolved_port, None, true)?;
            let _guard = init_logging_with_session(session_id);
            info!("Daemon restarted. Session ID: {}", session_id);
            #[cfg(feature = "ebpf")]
            {
                info!("Starting eBPF daemon...");
                if let Some(ebpf_process) = spawn_ebpf_daemon(resolved_port)? {
                    info!("eBPF daemon started with PID: {}", ebpf_process.id());
                }
            }
            start_runtime(allowed_roles.clone(), session_id, resolved_port, None)?;
        }
        Some(Commands::Status {}) => {
            print_all_sessions_status();
        }
        Some(Commands::Config { subcmd }) => handle_config(subcmd),
        Some(Commands::Hub { subcmd }) => handle_hub(subcmd),
        Some(Commands::Integrations { subcmd }) => handle_integrations(subcmd),
        Some(Commands::Validate {
            command,
            role,
            context,
        }) => handle_validate(command, role, context),
        Some(Commands::Prime { agent_type }) => print_prime(&agent_type),
        Some(Commands::Run) => {
            // Explicit foreground run
            let (_guard, session_id) = init_logging();
            info!("Running in foreground. Session ID: {}", session_id);
            start_runtime(allowed_roles, session_id, 3000, None)?;
        }
        None => {
            Cli::command().print_help()?;
            println!();
        }
    }
    Ok(())
}

fn start_runtime(
    allowed_roles: Option<Vec<String>>,
    session_id: uuid::Uuid,
    port: u16,
    initial_role: Option<String>,
) -> anyhow::Result<()> {
    // Initialize the Tokio runtime here, after potential daemonization
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run_server(allowed_roles, session_id, port, initial_role))
}

/// Spawn the eBPF daemon via `sudo -n` and write its PID to the state directory.
/// eBPF tracepoints need root-level access to tracefs regardless of file capabilities.
///
/// Returns `Ok(None)` if the eBPF daemon is already running — the new session will
/// self-register via the Unix socket cgroup notification, so no second daemon is needed.
#[cfg(feature = "ebpf")]
fn spawn_ebpf_daemon(port: u16) -> anyhow::Result<Option<std::process::Child>> {
    if sevorix_watchtower::daemon::is_ebpf_daemon_running() {
        tracing::info!(
            "eBPF daemon already running; session on port {} will register via Unix socket",
            port
        );
        return Ok(None);
    }

    let ebpf_binary = get_ebpf_daemon_path()?;
    let child = std::process::Command::new("sudo")
        .arg("-n")
        .arg(&ebpf_binary)
        .arg("--port")
        .arg(port.to_string())
        .spawn()
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to start eBPF daemon via sudo -n: {}. \
             Run ./install.sh to configure the required sudoers rule.",
                e
            )
        })?;

    // Write the PID file from here so EbpfDaemonManager can find it.
    // The sudo process PID is valid for the lifetime of the daemon.
    if let Some(proj_dirs) = directories::ProjectDirs::from("com", "sevorix", "sevorix") {
        let state_dir = proj_dirs
            .state_dir()
            .unwrap_or_else(|| proj_dirs.cache_dir());
        let _ = std::fs::create_dir_all(state_dir);
        let pid_path = state_dir.join("sevorix-ebpf.pid");
        let _ = std::fs::write(&pid_path, child.id().to_string());
    }

    Ok(Some(child))
}

/// Get the path to the eBPF daemon binary.
/// Looks for sevorix-ebpf-daemon in the same directory as the current binary,
/// or in the PATH.
#[cfg(feature = "ebpf")]
fn get_ebpf_daemon_path() -> anyhow::Result<std::path::PathBuf> {
    // First, try same directory as current executable
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let ebpf_path = exe_dir.join("sevorix-ebpf-daemon");
            if ebpf_path.exists() {
                return Ok(ebpf_path);
            }
        }
    }

    // Fall back to PATH lookup
    which::which("sevorix-ebpf-daemon").map_err(|_| {
        anyhow::anyhow!("Could not find sevorix-ebpf-daemon in PATH or alongside sevorix binary")
    })
}

/// Stop the eBPF daemon by reading its PID file and sending SIGTERM.
#[cfg(feature = "ebpf")]
fn stop_ebpf_daemon() -> anyhow::Result<()> {
    use directories::ProjectDirs;
    use std::fs;

    let proj_dirs = ProjectDirs::from("com", "sevorix", "sevorix")
        .ok_or_else(|| anyhow::anyhow!("Could not determine project directories"))?;

    let state_dir = proj_dirs
        .state_dir()
        .unwrap_or_else(|| proj_dirs.cache_dir());
    let pid_path = state_dir.join("sevorix-ebpf.pid");

    if let Ok(pid_str) = fs::read_to_string(&pid_path) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            let _ = fs::remove_file(&pid_path);
            println!("eBPF daemon stopped (PID: {})", pid);
        }
    } else {
        println!("eBPF daemon is not running.");
    }

    Ok(())
}

/// Print the status of the eBPF daemon.
#[cfg(feature = "ebpf")]
fn print_ebpf_daemon_status() {
    use directories::ProjectDirs;
    use std::fs;

    let proj_dirs = match ProjectDirs::from("com", "sevorix", "sevorix") {
        Some(d) => d,
        None => {
            println!("eBPF daemon status: Unable to determine state directory");
            return;
        }
    };

    let state_dir = proj_dirs
        .state_dir()
        .unwrap_or_else(|| proj_dirs.cache_dir());
    let pid_path = state_dir.join("sevorix-ebpf.pid");

    if let Ok(pid_str) = fs::read_to_string(&pid_path) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            let res = unsafe { libc::kill(pid, 0) };
            if res == 0 {
                println!("eBPF daemon is running (PID: {})", pid);
            } else {
                println!("eBPF daemon PID file exists but process is gone. Cleaning up.");
                let _ = fs::remove_file(&pid_path);
            }
        }
    } else {
        println!("eBPF daemon is NOT running.");
    }
}

fn handle_hub(cmd: HubCommands) {
    // Create a tokio runtime for async hub operations
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime");

    if let Err(e) = rt.block_on(handle_hub_async(cmd)) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn print_all_sessions_status() {
    let sessions = DaemonManager::list_sessions().unwrap_or_default();
    if sessions.is_empty() {
        println!("No running Watchtower sessions.");
    } else {
        println!(
            "{:<20} {:<38} {:<6} {:<12} STATUS",
            "NAME", "SESSION_ID", "PORT", "ROLE"
        );
        println!("{}", "-".repeat(90));
        for (info, running) in &sessions {
            let port_str = if info.port == 0 {
                "(unknown)".to_string()
            } else {
                info.port.to_string()
            };
            let id_str = if info.session_id.is_empty() {
                "(legacy)".to_string()
            } else {
                info.session_id.clone()
            };
            println!(
                "{:<20} {:<38} {:<10} {:<12} {}",
                info.name,
                id_str,
                port_str,
                info.role.as_deref().unwrap_or("(none)"),
                if *running { "running" } else { "stopped" }
            );
        }
    }
    #[cfg(feature = "ebpf")]
    print_ebpf_daemon_status();
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use sevorix_watchtower::{ConfigCommands, IntegrationsCommands};

    #[test]
    fn test_cli_default_command() {
        let cli = Cli::try_parse_from(["sevorix"]);
        assert!(cli.is_ok());
        assert!(cli.unwrap().command.is_none());
    }

    #[test]
    fn test_cli_start_command() {
        let cli = Cli::try_parse_from(["sevorix", "start"]);
        assert!(cli.is_ok());
        if let Some(Commands::Start {
            watchtower_only,
            ebpf_only,
            ..
        }) = cli.unwrap().command
        {
            assert!(!watchtower_only);
            assert!(!ebpf_only);
        } else {
            panic!("Expected Start command");
        }
    }

    #[test]
    fn test_cli_start_watchtower_only() {
        let cli = Cli::try_parse_from(["sevorix", "start", "--watchtower-only"]);
        assert!(cli.is_ok());
        if let Some(Commands::Start {
            watchtower_only,
            ebpf_only,
            ..
        }) = cli.unwrap().command
        {
            assert!(watchtower_only);
            assert!(!ebpf_only);
        } else {
            panic!("Expected Start command with watchtower_only flag");
        }
    }

    #[test]
    fn test_cli_start_ebpf_only() {
        let cli = Cli::try_parse_from(["sevorix", "start", "--ebpf-only"]);
        assert!(cli.is_ok());
        if let Some(Commands::Start {
            watchtower_only,
            ebpf_only,
            ..
        }) = cli.unwrap().command
        {
            assert!(!watchtower_only);
            assert!(ebpf_only);
        } else {
            panic!("Expected Start command with ebpf_only flag");
        }
    }

    #[test]
    fn test_cli_stop_command() {
        let cli = Cli::try_parse_from(["sevorix", "stop"]);
        assert!(cli.is_ok());
        assert!(matches!(cli.unwrap().command, Some(Commands::Stop { .. })));
    }

    #[test]
    fn test_cli_restart_command() {
        let cli = Cli::try_parse_from(["sevorix", "restart"]);
        assert!(cli.is_ok());
        assert!(matches!(cli.unwrap().command, Some(Commands::Restart)));
    }

    #[test]
    fn test_cli_status_command() {
        let cli = Cli::try_parse_from(["sevorix", "status"]);
        assert!(cli.is_ok());
        assert!(matches!(
            cli.unwrap().command,
            Some(Commands::Status { .. })
        ));
    }

    #[test]
    fn test_cli_run_command() {
        let cli = Cli::try_parse_from(["sevorix", "run"]);
        assert!(cli.is_ok());
        assert!(matches!(cli.unwrap().command, Some(Commands::Run)));
    }

    #[test]
    fn test_cli_config_check_command() {
        let cli = Cli::try_parse_from(["sevorix", "config", "check"]);
        assert!(cli.is_ok());
        if let Some(Commands::Config { subcmd }) = cli.unwrap().command {
            assert!(matches!(subcmd, ConfigCommands::Check));
        } else {
            panic!("Expected Config command");
        }
    }

    #[test]
    fn test_cli_validate_command() {
        let cli = Cli::try_parse_from(["sevorix", "validate", "echo hello"]);
        assert!(cli.is_ok());
        if let Some(Commands::Validate {
            command,
            role,
            context,
        }) = cli.unwrap().command
        {
            assert_eq!(command, "echo hello");
            assert!(role.is_none());
            assert_eq!(context, "Shell"); // default
        } else {
            panic!("Expected Validate command");
        }
    }

    #[test]
    fn test_cli_validate_with_options() {
        let cli = Cli::try_parse_from([
            "sevorix",
            "validate",
            "DROP TABLE",
            "-r",
            "admin",
            "-C",
            "All",
        ]);
        assert!(cli.is_ok());
        if let Some(Commands::Validate {
            command,
            role,
            context,
        }) = cli.unwrap().command
        {
            assert_eq!(command, "DROP TABLE");
            assert_eq!(role, Some("admin".to_string()));
            assert_eq!(context, "All");
        } else {
            panic!("Expected Validate command");
        }
    }

    #[test]
    fn test_cli_roles_flag() {
        let cli = Cli::try_parse_from(["sevorix", "--roles", "admin,dev", "run"]);
        assert!(cli.is_ok());
        let cli = cli.unwrap();
        assert_eq!(cli.roles, Some("admin,dev".to_string()));
    }

    #[test]
    fn test_cli_hub_login_command() {
        let cli = Cli::try_parse_from([
            "sevorix",
            "hub",
            "login",
            "-e",
            "test@example.com",
            "-p",
            "secret",
        ]);
        assert!(cli.is_ok());
        if let Some(Commands::Hub { subcmd }) = cli.unwrap().command {
            match subcmd {
                HubCommands::Login {
                    email, password, ..
                } => {
                    assert_eq!(email, Some("test@example.com".to_string()));
                    assert_eq!(password, Some("secret".to_string()));
                }
                _ => panic!("Expected Login subcommand"),
            }
        } else {
            panic!("Expected Hub command");
        }
    }

    #[test]
    fn test_cli_hub_logout_command() {
        let cli = Cli::try_parse_from(["sevorix", "hub", "logout"]);
        assert!(cli.is_ok());
        if let Some(Commands::Hub { subcmd }) = cli.unwrap().command {
            assert!(matches!(subcmd, HubCommands::Logout));
        } else {
            panic!("Expected Hub command");
        }
    }

    #[test]
    fn test_cli_hub_status_command() {
        let cli = Cli::try_parse_from(["sevorix", "hub", "status"]);
        assert!(cli.is_ok());
        if let Some(Commands::Hub { subcmd }) = cli.unwrap().command {
            assert!(matches!(subcmd, HubCommands::Status { hub_url: None }));
        } else {
            panic!("Expected Hub command");
        }
    }

    #[test]
    fn test_cli_hub_push_command() {
        let cli = Cli::try_parse_from([
            "sevorix",
            "hub",
            "push",
            "-n",
            "my-policy",
            "-v",
            "1.0.0",
            "-f",
            "/path/to/policy.json",
            "-d",
            "My policy description",
            "-t",
            "security",
            "-t",
            "blocking",
        ]);
        assert!(cli.is_ok());
        if let Some(Commands::Hub { subcmd }) = cli.unwrap().command {
            match subcmd {
                HubCommands::Push {
                    name,
                    version,
                    file,
                    description,
                    tag,
                    ..
                } => {
                    assert_eq!(name, "my-policy");
                    assert_eq!(version, "1.0.0");
                    assert_eq!(file, "/path/to/policy.json");
                    assert_eq!(description, Some("My policy description".to_string()));
                    assert_eq!(tag, vec!["security", "blocking"]);
                }
                _ => panic!("Expected Push subcommand"),
            }
        } else {
            panic!("Expected Hub command");
        }
    }

    #[test]
    fn test_cli_hub_pull_command() {
        let cli = Cli::try_parse_from([
            "sevorix",
            "hub",
            "pull",
            "my-policy",
            "1.0.0",
            "-o",
            "/tmp/policy.json",
        ]);
        assert!(cli.is_ok());
        if let Some(Commands::Hub { subcmd }) = cli.unwrap().command {
            match subcmd {
                HubCommands::Pull {
                    name,
                    version,
                    output,
                    ..
                } => {
                    assert_eq!(name, "my-policy");
                    assert_eq!(version, "1.0.0");
                    assert_eq!(output, Some("/tmp/policy.json".to_string()));
                }
                _ => panic!("Expected Pull subcommand"),
            }
        } else {
            panic!("Expected Hub command");
        }
    }

    #[test]
    fn test_cli_hub_search_command() {
        let cli = Cli::try_parse_from([
            "sevorix", "hub", "search", "-q", "security", "-t", "blocking", "-l", "50",
        ]);
        assert!(cli.is_ok());
        if let Some(Commands::Hub { subcmd }) = cli.unwrap().command {
            match subcmd {
                HubCommands::Search {
                    query, tag, limit, ..
                } => {
                    assert_eq!(query, Some("security".to_string()));
                    assert_eq!(tag, Some("blocking".to_string()));
                    assert_eq!(limit, 50);
                }
                _ => panic!("Expected Search subcommand"),
            }
        } else {
            panic!("Expected Hub command");
        }
    }

    #[test]
    fn test_cli_integrations_list_command() {
        let cli = Cli::try_parse_from(["sevorix", "integrations", "list"]);
        assert!(cli.is_ok());
        if let Some(Commands::Integrations { subcmd }) = cli.unwrap().command {
            assert!(matches!(subcmd, IntegrationsCommands::List));
        } else {
            panic!("Expected Integrations command");
        }
    }

    #[test]
    fn test_cli_integrations_install_command() {
        let cli = Cli::try_parse_from(["sevorix", "integrations", "install", "claude-code"]);
        assert!(cli.is_ok());
        if let Some(Commands::Integrations { subcmd }) = cli.unwrap().command {
            match subcmd {
                IntegrationsCommands::Install { name, .. } => {
                    assert_eq!(name, "claude-code");
                }
                _ => panic!("Expected Install subcommand"),
            }
        } else {
            panic!("Expected Integrations command");
        }
    }

    #[test]
    fn test_cli_integrations_uninstall_command() {
        let cli = Cli::try_parse_from(["sevorix", "integrations", "uninstall", "claude-code"]);
        assert!(cli.is_ok());
        if let Some(Commands::Integrations { subcmd }) = cli.unwrap().command {
            match subcmd {
                IntegrationsCommands::Uninstall { name } => {
                    assert_eq!(name, "claude-code");
                }
                _ => panic!("Expected Uninstall subcommand"),
            }
        } else {
            panic!("Expected Integrations command");
        }
    }

    #[test]
    fn test_cli_integrations_status_command() {
        let cli = Cli::try_parse_from(["sevorix", "integrations", "status", "claude-code"]);
        assert!(cli.is_ok());
        if let Some(Commands::Integrations { subcmd }) = cli.unwrap().command {
            match subcmd {
                IntegrationsCommands::Status { name } => {
                    assert_eq!(name, Some("claude-code".to_string()));
                }
                _ => panic!("Expected Status subcommand"),
            }
        } else {
            panic!("Expected Integrations command");
        }
    }

    // -------------------------------------------------------------------------
    // handle_hub_async tests — exercises functions defined in main.rs
    // Logout and Status are chosen because they are purely local operations
    // (read/remove a token file; no network calls).
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_handle_hub_async_logout_succeeds_when_not_logged_in() {
        // clear_token() is a no-op when no token file exists; must not panic
        let result = handle_hub_async(HubCommands::Logout).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_hub_async_status_when_unauthenticated() {
        // check_auth_status() reads the local token file — no network needed
        let result = handle_hub_async(HubCommands::Status { hub_url: None }).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_cli_hub_register_command() {
        let cli = Cli::try_parse_from([
            "sevorix",
            "hub",
            "register",
            "-e",
            "new@example.com",
            "-p",
            "password123",
        ]);
        assert!(cli.is_ok());
        if let Some(Commands::Hub { subcmd }) = cli.unwrap().command {
            match subcmd {
                HubCommands::Register {
                    email, password, ..
                } => {
                    assert_eq!(email, Some("new@example.com".to_string()));
                    assert_eq!(password, Some("password123".to_string()));
                }
                _ => panic!("Expected Register subcommand"),
            }
        } else {
            panic!("Expected Hub command");
        }
    }
}

async fn handle_hub_async(cmd: HubCommands) -> anyhow::Result<()> {
    use sevorix_watchtower::hub::{
        check_auth_status, check_executable_policy, clear_token, save_token, DependencyRef,
        HubClient, PushRequest,
    };

    match cmd {
        HubCommands::Register {
            hub_url,
            email,
            password,
        } => {
            use dialoguer::{Input, Password};

            println!("SevorixHub Registration\n");

            // Prompt for email if not provided
            let email = match email {
                Some(e) => e,
                None => Input::new()
                    .with_prompt("Email address")
                    .validate_with(|input: &String| -> Result<(), &str> {
                        if input.contains('@') && input.contains('.') {
                            Ok(())
                        } else {
                            Err("Please enter a valid email address")
                        }
                    })
                    .interact_text()?,
            };

            // Prompt for password if not provided
            let password = match password {
                Some(p) => p,
                None => {
                    let pwd = Password::new()
                        .with_prompt("Password")
                        .validate_with(|input: &String| -> Result<(), &str> {
                            if input.len() >= 8 {
                                Ok(())
                            } else {
                                Err("Password must be at least 8 characters")
                            }
                        })
                        .interact()?;
                    let confirm = Password::new().with_prompt("Confirm password").interact()?;
                    if pwd != confirm {
                        anyhow::bail!("Passwords do not match");
                    }
                    pwd
                }
            };

            let client = HubClient::new(hub_url.as_deref())?;
            let response = client.register(&email, &password).await?;

            println!("\n✓ Successfully registered user '{}'", response.email);
            println!("  User ID: {}", response.id);
            println!(
                "\nYou can now login with: sevorix hub login -e {}",
                response.email
            );
        }

        HubCommands::Login {
            hub_url,
            email,
            password,
        } => {
            use dialoguer::{Input, Password};

            println!("SevorixHub Login\n");

            // Prompt for email if not provided
            let email = match email {
                Some(e) => e,
                None => Input::new()
                    .with_prompt("Email address")
                    .validate_with(|input: &String| -> Result<(), &str> {
                        if input.contains('@') && input.contains('.') {
                            Ok(())
                        } else {
                            Err("Please enter a valid email address")
                        }
                    })
                    .interact_text()?,
            };

            // Prompt for password if not provided
            let password = match password {
                Some(p) => p,
                None => Password::new().with_prompt("Password").interact()?,
            };

            let client = HubClient::new(hub_url.as_deref())?;
            let response = client.login(&email, &password).await?;

            // Save the token
            save_token(&response.token)?;

            println!("\n✓ Logged in as '{}'", response.email);
            println!("  Token saved to ~/.sevorix/hub_token");
        }

        HubCommands::Push {
            hub_url,
            name,
            version,
            file,
            description,
            tag,
            artifact_type,
            dep,
            visibility,
        } => {
            // Read the policy file
            let content = std::fs::read_to_string(&file)
                .map_err(|e| anyhow::anyhow!("Failed to read file '{}': {}", file, e))?;

            // Validate it's valid JSON
            let _: serde_json::Value = serde_json::from_str(&content)
                .map_err(|e| anyhow::anyhow!("Invalid JSON in file: {}", e))?;

            let client = HubClient::new(hub_url.as_deref())?;

            let tags = if tag.is_empty() { None } else { Some(tag) };

            // Parse --dep name@version flags
            let dependencies = if dep.is_empty() {
                None
            } else {
                let mut deps = Vec::new();
                for d in &dep {
                    let parts: Vec<&str> = d.splitn(2, '@').collect();
                    if parts.len() != 2 {
                        anyhow::bail!("Invalid dependency '{}': must be in name@version format", d);
                    }
                    deps.push(DependencyRef {
                        name: parts[0].to_string(),
                        version: parts[1].to_string(),
                        required: true,
                    });
                }
                Some(deps)
            };

            let req = PushRequest {
                name,
                version,
                description,
                tags,
                content,
                visibility: Some(visibility),
                artifact_type: Some(artifact_type),
                dependencies,
            };

            let response = client.push(req).await?;

            println!(
                "Pushed artifact: {}@{} [{}]",
                response.name, response.version, response.artifact_type
            );
            println!("  ID: {}", response.id);
            println!("  Owner: {}", response.owner);
            println!("  Downloads: {}", response.downloads);
            if !response.dependencies.is_empty() {
                println!("  Dependencies:");
                for d in &response.dependencies {
                    println!(
                        "    - {}@{}{}",
                        d.name,
                        d.version,
                        if d.required { "" } else { " (optional)" }
                    );
                }
            }
        }

        HubCommands::Pull {
            hub_url,
            name,
            version,
            output,
        } => {
            let client = HubClient::new(hub_url.as_deref())?;
            let response = client.pull(&name, &version).await?;

            // Check for executable policy warnings
            let warnings = check_executable_policy(&response.content);
            if !warnings.is_empty() {
                eprintln!("\n⚠️  SECURITY WARNING:");
                for warning in &warnings {
                    eprintln!("  - {}", warning);
                }
                eprintln!("\nThis artifact contains policies that can execute arbitrary commands.");
                eprintln!("Review carefully before using in production.\n");
            }

            let content_str = serde_json::to_string_pretty(&response.content)?;

            match output {
                Some(path) => {
                    std::fs::write(&path, &content_str)?;
                    println!("Saved artifact to: {}", path);
                }
                None => {
                    println!("{}", content_str);
                }
            }

            println!(
                "\nArtifact: {}@{} [{}]",
                response.name, response.version, response.artifact_type
            );
            println!("Owner: {}", response.owner);
            println!("Downloads: {}", response.downloads);
            if let Some(desc) = response.description {
                println!("Description: {}", desc);
            }
            if !response.dependencies.is_empty() {
                println!("Dependencies:");
                for d in &response.dependencies {
                    println!(
                        "  - {}@{}{}",
                        d.name,
                        d.version,
                        if d.required { "" } else { " (optional)" }
                    );
                }
            }
        }

        HubCommands::Search {
            hub_url,
            query,
            tag,
            limit,
        } => {
            let client = HubClient::new(hub_url.as_deref())?;
            let response = client.search(query.as_deref(), tag.as_deref()).await?;

            if response.results.is_empty() {
                println!("No artifacts found.");
            } else {
                println!(
                    "Found {} artifact(s):\n",
                    response.results.len().min(limit as usize)
                );
                for artifact in response.results.iter().take(limit as usize) {
                    println!("  {}@{}", artifact.name, artifact.version);
                    if let Some(desc) = &artifact.description {
                        println!("    {}", desc);
                    }
                    println!(
                        "    Owner: {} | Downloads: {} | Tags: {}",
                        artifact.owner,
                        artifact.downloads,
                        artifact.tags.join(", ")
                    );
                    println!();
                }

                if response.total > limit {
                    println!("  ... and {} more results", response.total - limit);
                }
            }
        }

        HubCommands::Yank {
            hub_url,
            name,
            version,
            reason,
        } => {
            let client = HubClient::new(hub_url.as_deref())?;
            // Resolve the UUID via pull
            let artifact = client.pull(&name, &version).await.map_err(|e| {
                anyhow::anyhow!("Could not find artifact '{}@{}': {}", name, version, e)
            })?;
            client.yank(&artifact.id, reason.as_deref()).await?;
            println!("Yanked {}@{}", name, version);
            if let Some(r) = &reason {
                println!("  Reason: {}", r);
            }
        }

        HubCommands::Unyank {
            hub_url,
            name,
            version,
        } => {
            let client = HubClient::new(hub_url.as_deref())?;
            let artifact = client.pull(&name, &version).await.map_err(|e| {
                anyhow::anyhow!("Could not find artifact '{}@{}': {}", name, version, e)
            })?;
            client.unyank(&artifact.id).await?;
            println!("Unyanked {}@{}", name, version);
        }

        HubCommands::Logout => {
            clear_token()?;
            println!("✓ Logged out successfully.");
        }

        HubCommands::Status { hub_url } => {
            let status = check_auth_status(hub_url.as_deref());

            println!("SevorixHub Authentication Status\n");
            println!("  Hub URL: {}", status.hub_url);

            if status.logged_in {
                println!("  Status: Logged in");
                if let Some(email) = &status.email {
                    println!("  Email: {}", email);
                }
                if let Some(expires) = &status.expires_at {
                    println!("  Token expires: {}", expires);
                }
            } else {
                println!("  Status: Not logged in");
                println!("\n  Run 'sevorix hub login' to authenticate.");
            }
        }
    }

    Ok(())
}
