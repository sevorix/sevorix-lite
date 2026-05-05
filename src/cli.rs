// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "sevorix", about = "Sevorix Watchtower Security Proxy", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Comma-separated list of allowed roles to load (e.g. "admin,dev")
    #[arg(long, global = true)]
    pub roles: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the daemon (background)
    /// By default, starts both Watchtower and eBPF daemon
    /// Use flags to start specific components
    Start {
        /// Start only the Watchtower proxy (no eBPF monitoring)
        #[arg(long)]
        watchtower_only: bool,
        /// Start only the eBPF daemon (no Watchtower proxy)
        #[arg(long)]
        ebpf_only: bool,
        /// Session name (default: random UUID)
        #[arg(long)]
        name: Option<String>,
        /// Port to listen on (default: auto-assign starting at 3000)
        #[arg(long)]
        port: Option<u16>,
    },
    /// Stop the daemon(s)
    Stop {},
    /// Restart the daemon(s)
    Restart,
    /// Check daemon status
    Status {},
    /// Run in foreground (default)
    Run,
    /// Configuration commands
    Config {
        #[command(subcommand)]
        subcmd: ConfigCommands,
    },
    /// SevorixHub commands (login, push, pull, search)
    Hub {
        #[command(subcommand)]
        subcmd: HubCommands,
    },
    /// Integration management commands
    Integrations {
        #[command(subcommand)]
        subcmd: IntegrationsCommands,
    },
    /// Validate a command string for security (returns JSON with verdict)
    Validate {
        /// Command string to validate
        command: String,
        /// Optional role context for policy evaluation
        #[arg(short, long)]
        role: Option<String>,
        /// Context type: Shell, Network, or All (default: Shell)
        #[arg(short = 'C', long, default_value = "Shell")]
        context: String,
    },
    /// Print a context primer for a specific agent type (pipe into an AI agent's context)
    Prime {
        /// Agent type to prime: policy-manager (pm) or guarded-agent (guard)
        agent_type: String,
    },
    /// Session management commands
    Session {
        #[command(subcommand)]
        subcmd: SessionCommands,
    },
    /// CA certificate management (TLS MITM)
    Ca {
        #[command(subcommand)]
        subcmd: CaCommands,
    },
}

#[derive(Subcommand)]
pub enum SessionCommands {
    /// List all running sessions
    List,
    /// Set the active policy role for the current session
    SetRole {
        /// Role name to apply to this session
        role: String,
        /// Target session by name (required when multiple sessions are running)
        #[arg(long)]
        name: Option<String>,
    },
    /// Atomically kill all agent processes in the session cgroup tree
    Kill {
        /// Target session by name (required when multiple sessions are running)
        #[arg(long)]
        name: Option<String>,
    },
    /// Freeze all agent processes in the session cgroup (suspend without killing)
    Freeze {
        /// Target session by name (required when multiple sessions are running)
        #[arg(long)]
        name: Option<String>,
    },
    /// Unfreeze all agent processes in the session cgroup
    Unfreeze {
        /// Target session by name (required when multiple sessions are running)
        #[arg(long)]
        name: Option<String>,
    },
    /// Reload policies and roles from disk without restarting
    Reload {
        /// Target session by name (required when multiple sessions are running)
        #[arg(long)]
        name: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Check configuration validity
    Check,
}

#[derive(Subcommand)]
pub enum HubCommands {
    /// Register a new account on SevorixHub
    Register {
        /// SevorixHub server URL (default: http://localhost:8080)
        #[arg(long, env = "SEVORIX_HUB_URL")]
        hub_url: Option<String>,
        /// Email address for the new account (will prompt if not provided)
        #[arg(short, long)]
        email: Option<String>,
        /// Password for the new account (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Login to SevorixHub and store authentication token
    Login {
        /// SevorixHub server URL (default: http://localhost:8080)
        #[arg(long, env = "SEVORIX_HUB_URL")]
        hub_url: Option<String>,
        /// Email address for authentication (will prompt if not provided)
        #[arg(short, long)]
        email: Option<String>,
        /// Password for authentication (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Push a policy artifact to SevorixHub
    Push {
        /// SevorixHub server URL (default: http://localhost:8080)
        #[arg(long, env = "SEVORIX_HUB_URL")]
        hub_url: Option<String>,
        /// Artifact name (e.g., "my-policy")
        #[arg(short, long)]
        name: String,
        /// Artifact version (e.g., "1.0.0")
        #[arg(short, long)]
        version: String,
        /// Path to policy JSON file to upload
        #[arg(short, long)]
        file: String,
        /// Optional description
        #[arg(short, long)]
        description: Option<String>,
        /// Optional tags (can be specified multiple times)
        #[arg(short = 't', long)]
        tag: Vec<String>,
        /// Artifact type: "artifact" (default) or "set"
        #[arg(long, default_value = "artifact")]
        artifact_type: String,
        /// Declare a dependency as name@version (can be specified multiple times)
        #[arg(long = "dep", value_name = "NAME@VERSION")]
        dep: Vec<String>,
        /// Visibility: "public" (default), "private", or "draft"
        #[arg(long, default_value = "public")]
        visibility: String,
    },
    /// Pull a policy artifact from SevorixHub
    Pull {
        /// SevorixHub server URL (default: http://localhost:8080)
        #[arg(long, env = "SEVORIX_HUB_URL")]
        hub_url: Option<String>,
        /// Artifact name
        name: String,
        /// Artifact version
        version: String,
        /// Output file path (prints to stdout if not specified)
        #[arg(short, long)]
        output: Option<String>,
        /// Allow pulling artifacts that contain Executable policies (dangerous; requires explicit opt-in)
        #[arg(long)]
        allow_executable: bool,
    },
    /// Search for policy artifacts on SevorixHub
    Search {
        /// SevorixHub server URL (default: http://localhost:8080)
        #[arg(long, env = "SEVORIX_HUB_URL")]
        hub_url: Option<String>,
        /// Search query (searches name and description)
        #[arg(short, long)]
        query: Option<String>,
        /// Filter by tag
        #[arg(short = 't', long)]
        tag: Option<String>,
        /// Maximum number of results
        #[arg(short, long, default_value = "20")]
        limit: i64,
    },
    /// Yank an artifact by name and version (pulls the ID, then yanks)
    Yank {
        /// SevorixHub server URL
        #[arg(long, env = "SEVORIX_HUB_URL")]
        hub_url: Option<String>,
        /// Artifact name
        name: String,
        /// Artifact version
        version: String,
        /// Optional reason for yanking
        #[arg(short, long)]
        reason: Option<String>,
    },
    /// Unyank a previously yanked artifact
    Unyank {
        /// SevorixHub server URL
        #[arg(long, env = "SEVORIX_HUB_URL")]
        hub_url: Option<String>,
        /// Artifact name
        name: String,
        /// Artifact version
        version: String,
    },
    /// Logout from SevorixHub and remove stored authentication token
    Logout,
    /// Show authentication status
    Status {
        /// SevorixHub server URL (default: http://localhost:8080)
        #[arg(long, env = "SEVORIX_HUB_URL")]
        hub_url: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum IntegrationsCommands {
    /// Install an integration (verifies prerequisites are met)
    Install {
        /// Name of the integration to install (e.g. "Claude Code" or "claude")
        name: String,
    },
    /// Uninstall an integration
    Uninstall {
        /// Name of the integration to uninstall
        name: String,
    },
    /// List all available integrations
    List,
    /// Show status of integrations
    Status {
        /// Name of the integration (optional, shows all if not specified)
        name: Option<String>,
    },
    /// Start an integration session (e.g. launch Claude Code under Sevorix monitoring)
    Start {
        /// Name of the integration to start (e.g. "Claude Code" or "claude")
        name: String,
        /// Arguments forwarded to the underlying tool
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum CaCommands {
    /// Print the CA certificate PEM to stdout (pipe into trust-store tooling)
    Print,
    /// Print the path to the CA certificate file
    Path,
    /// Regenerate the CA certificate and key (invalidates all previously issued leaf certs)
    Regenerate,
}
