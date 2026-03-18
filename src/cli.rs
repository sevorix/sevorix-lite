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
    },
    /// Stop the daemon(s)
    Stop,
    /// Restart the daemon(s)
    Restart,
    /// Check daemon status
    Status,
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
}

#[derive(Subcommand)]
pub enum SessionCommands {
    /// Set the active policy role for the current session
    SetRole {
        /// Role name to apply to this session
        role: String,
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
