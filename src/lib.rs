use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use directories::{ProjectDirs, UserDirs};
use uuid;
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    process::Command,
    sync::{Arc, RwLock},
};
use dashmap::DashMap;
use tokio::sync::{broadcast, oneshot, watch, Mutex};

/// Unix socket path used for synchronous cgroup registration between
/// the Watchtower server and the eBPF daemon.
pub const EBPF_SOCK_PATH: &str = "/tmp/sevorix-ebpf.sock";

pub mod assets;
pub mod cli;
pub mod daemon;
pub mod hub;
pub mod integrations;
pub mod logging;
pub mod policy;
pub mod prime;
pub mod proxy;
pub mod scanner;
pub mod settings;

use assets::Assets;
pub use cli::{Cli, Commands, ConfigCommands, HubCommands, IntegrationsCommands, SessionCommands};
pub use daemon::{DaemonManager, EbpfDaemonManager, is_ebpf_daemon_running, is_watchtower_running};
pub use integrations::{IntegrationRegistry, Integration, IntegrationStatus, InstallResult, Manifest, claude_code::ClaudeCodeIntegration, codex::CodexIntegration, openclaw::OpenClawIntegration};
use policy::{Action, Engine, PolicyContext, PolicyType};
use proxy::proxy_handler;
use scanner::{log_threat, log_kill, scan_content, scan_for_poison, scan_syscall_with_engine, PoisonPill};
use sevorix_core::{detect_enforcement_tier, EnforcementTier, SyscallEvent, SeccompDecision};

/// Holds both channel halves for one pending intervention decision.
pub struct PendingEntry {
    /// Send `true` (allow) or `false` (block) to unblock the waiting handler.
    pub decision_tx: oneshot::Sender<bool>,
    /// Send `true` (paused) or `false` (running) to freeze/unfreeze the countdown.
    pub pause_tx: watch::Sender<bool>,
}

#[derive(Clone)]
pub struct AppState {
    pub tx: broadcast::Sender<String>,
    pub policy_engine: Arc<RwLock<Engine>>,
    pub traffic_log_path: std::path::PathBuf,
    pub log_dir: std::path::PathBuf,
    pub session_id: String,
    pub enforcement_tier: EnforcementTier,
    pub active_sessions: Arc<Mutex<std::collections::HashSet<String>>>,
    /// Pending intervention decisions keyed by event UUID.
    pub pending_decisions: Arc<DashMap<String, PendingEntry>>,
    /// Seconds before an unanswered intervention auto-resolves.
    pub intervention_timeout_secs: u64,
    /// If true, auto-allow on timeout; if false (default), auto-block.
    pub intervention_timeout_allow: bool,
    /// The active policy role for this daemon session. Loaded from
    /// settings.json `default_role` at startup; updated live via
    /// `POST /api/session/set-role`. Fail-closed if None.
    pub current_role: Arc<RwLock<Option<String>>>,
}

pub fn handle_config(cmd: ConfigCommands) {
    match cmd {
        ConfigCommands::Check => {
            if let Some(proj_dirs) = ProjectDirs::from("com", "sevorix", "sevorix") {
                let config_dir = proj_dirs.config_dir();
                let policy_path = config_dir.join("policies.json");
                println!("Config path: {}", policy_path.display());
                if policy_path.exists() {
                    println!("Status: File exists.");
                } else {
                    println!("Status: File MISSING.");
                }
            } else {
                println!("Could not determine config directory.");
            }
        }
    }
}

/// Resolve integration name aliases to canonical names.
/// Accepts "claude" and "claude-code" as aliases for "Claude Code".
fn resolve_integration_name(name: &str) -> &str {
    match name {
        "claude" | "claude-code" => "Claude Code",
        other => other,
    }
}

/// Handle integration commands
pub fn handle_integrations(cmd: IntegrationsCommands) {
    let mut registry = match IntegrationRegistry::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error initializing integration registry: {}", e);
            return;
        }
    };

    // Register built-in integrations
    if let Ok(claude_code) = ClaudeCodeIntegration::new() {
        registry.register(std::sync::Arc::new(claude_code));
    }
    if let Ok(codex) = CodexIntegration::new() {
        registry.register(std::sync::Arc::new(codex));
    }
    if let Ok(openclaw) = OpenClawIntegration::new() {
        registry.register(std::sync::Arc::new(openclaw));
    }

    match cmd {
        IntegrationsCommands::Install { name } => {
            let resolved = resolve_integration_name(&name);
            match registry.get(resolved) {
                Some(integration) => match integration.install() {
                    Ok(result) => {
                        println!("Successfully installed '{}'", resolved);
                        if !result.files_modified.is_empty() {
                            println!("Modified files:");
                            for f in &result.files_modified {
                                println!("  - {}", f);
                            }
                        }
                        println!("{}", result.message);
                    }
                    Err(e) => eprintln!("Failed to install '{}': {}", resolved, e),
                },
                None => {
                    eprintln!("Integration '{}' not found.", name);
                    println!("Use 'sevorix integrations list' to see available integrations.");
                }
            }
        }
        IntegrationsCommands::Uninstall { name } => {
            let resolved = resolve_integration_name(&name);
            match registry.get(resolved) {
                Some(integration) => {
                    match integration.uninstall() {
                        Ok(()) => println!("Successfully uninstalled '{}'", resolved),
                        Err(e) => eprintln!("Failed to uninstall '{}': {}", resolved, e),
                    }
                }
                None => {
                    eprintln!("Integration '{}' not found.", name);
                }
            }
        }
        IntegrationsCommands::Start { name, args } => {
            let resolved = resolve_integration_name(&name);
            match resolved {
                "Claude Code" => {
                    // Exec the mount-namespace launcher, replacing the current process.
                    // sudo is required; the launcher validates $SUDO_USER itself.
                    let mut cmd = std::process::Command::new("sudo");
                    cmd.arg("/usr/local/bin/sevorix-claude-launcher");
                    cmd.args(&args);
                    let err = {
                        use std::os::unix::process::CommandExt;
                        cmd.exec()
                    };
                    eprintln!("Failed to exec sevorix-claude-launcher: {}", err);
                    eprintln!("Is the launcher installed? Re-run the Sevorix installer.");
                    std::process::exit(1);
                }
                other => {
                    eprintln!("'start' is not supported for integration '{}'.", other);
                    std::process::exit(1);
                }
            }
        }
        IntegrationsCommands::List => {
            let integrations = registry.list();
            if integrations.is_empty() {
                println!("No integrations registered.");
                println!("\nNote: Integrations will be added in future phases:");
                println!("  - Claude Code (Phase 3)");
                println!("  - OpenClaw (Phase 4)");
                println!("  - Codex (Phase 4)");
            } else {
                println!("Available integrations:");
                for integration in integrations {
                    let status = if integration.is_installed() {
                        "installed"
                    } else {
                        "not installed"
                    };
                    println!("  {} - {} ({})", integration.name(), integration.description(), status);
                }
            }
        }
        IntegrationsCommands::Status { name } => {
            match name {
                Some(n) => {
                    let resolved = resolve_integration_name(&n);
                    match registry.get(resolved) {
                        Some(integration) => {
                            println!("Integration: {}", integration.name());
                            println!("Description: {}", integration.description());
                            println!("Status: {:?}", integration.status());
                        }
                        None => {
                            eprintln!("Integration '{}' not found.", n);
                        }
                    }
                }
                None => {
                    let integrations = registry.list();
                    if integrations.is_empty() {
                        println!("No integrations registered.");
                    } else {
                        println!("Integration Status:");
                        for integration in integrations {
                            println!("  {}: {:?}", integration.name(), integration.status());
                        }
                    }
                }
            }
        }
    }
}

/// Validate configuration files and policies
pub fn handle_validate_config() {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Primary store: ~/.sevorix/
    if let Some(user_dirs) = directories::UserDirs::new() {
        let sevorix_dir = user_dirs.home_dir().join(".sevorix");

        if sevorix_dir.exists() {
            println!("✓ ~/.sevorix/: Exists");
        } else {
            warnings.push("~/.sevorix/: Not found (will be created on first use)".to_string());
        }

        // Check primary policies directory
        let policy_dir = sevorix_dir.join("policies");
        if policy_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&policy_dir) {
                let count = entries.count();
                println!("✓ ~/.sevorix/policies/: {} policy file(s) found", count);
            }
        } else {
            warnings.push("~/.sevorix/policies/: Not found (optional — place .json policy files here)".to_string());
        }

        // Check primary roles directory
        let roles_dir = sevorix_dir.join("roles");
        if roles_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&roles_dir) {
                let count = entries.count();
                println!("✓ ~/.sevorix/roles/: {} role file(s) found", count);
            }
        } else {
            warnings.push("~/.sevorix/roles/: Not found (optional — place .json role files here)".to_string());
        }

        // Check hub token
        let token_path = sevorix_dir.join("hub_token");
        if token_path.exists() {
            println!("✓ ~/.sevorix/hub_token: Present");
        } else {
            warnings.push("~/.sevorix/hub_token: Not found (run 'sevorix hub login' to authenticate)".to_string());
        }
    }

    // Legacy fallback: ~/.config/sevorix/policies.json
    if let Some(proj_dirs) = ProjectDirs::from("com", "sevorix", "sevorix") {
        let legacy_policy = proj_dirs.config_dir().join("policies.json");
        if legacy_policy.exists() {
            match std::fs::read_to_string(&legacy_policy) {
                Ok(content) => {
                    match serde_json::from_str::<serde_json::Value>(&content) {
                        Ok(_) => println!("✓ ~/.config/sevorix/policies.json: Valid JSON (legacy fallback)"),
                        Err(e) => errors.push(format!("~/.config/sevorix/policies.json: Invalid JSON - {}", e)),
                    }
                }
                Err(e) => errors.push(format!("~/.config/sevorix/policies.json: Cannot read - {}", e)),
            }
        }
    }

    // Print warnings
    if !warnings.is_empty() {
        println!("\nWarnings:");
        for w in &warnings {
            println!("  ⚠ {}", w);
        }
    }

    // Print errors
    if !errors.is_empty() {
        println!("\nErrors:");
        for e in &errors {
            println!("  ✗ {}", e);
        }
        std::process::exit(1);
    }

    if errors.is_empty() && warnings.is_empty() {
        println!("\n✓ All validations passed");
    }
}

/// Validate a command string for security
/// Returns exit code 0 if allowed, 1 if blocked
/// Outputs JSON with verdict details
pub fn handle_validate(command: String, role: Option<String>, context: String) {
    // Parse context
    let policy_context = match context.as_str() {
        "Shell" => PolicyContext::Shell,
        "Network" => PolicyContext::Network,
        "Syscall" => PolicyContext::Syscall,
        "All" => PolicyContext::All,
        _ => {
            eprintln!("Error: Invalid context '{}'. Use Shell, Network, Syscall, or All.", context);
            std::process::exit(1);
        }
    };

    // Initialize policy engine
    let mut engine = Engine::new();

    // Load policies from standard locations
    let proj_dirs = match ProjectDirs::from("com", "sevorix", "sevorix") {
        Some(d) => d,
        None => {
            eprintln!("Error: Could not determine config directory");
            std::process::exit(1);
        }
    };

    let mut base_dirs = Vec::new();
    if let Some(user_dirs) = UserDirs::new() {
        base_dirs.push(user_dirs.home_dir().join(".sevorix"));
    }
    base_dirs.push(proj_dirs.config_dir().to_path_buf());
    base_dirs.push(std::path::PathBuf::from(".sevorix"));

    // Load policies from directories
    for base in &base_dirs {
        let policy_dir = base.join("policies");
        if policy_dir.exists() && policy_dir.is_dir() {
            let _ = engine.load_policies_from_dir(&policy_dir);
        }
    }

    // Load roles from directories
    for base in &base_dirs {
        let role_dir = base.join("roles");
        if role_dir.exists() && role_dir.is_dir() {
            let _ = engine.load_roles_from_dir(&role_dir);
        }
    }

    // Legacy fallback: try loading single policies.json
    for base in &base_dirs {
        let policy_path = base.join("policies.json");
        if policy_path.exists() {
            if let Ok(legacy_engine) = Engine::load_from_file(policy_path.to_str().unwrap_or("policies.json")) {
                engine.merge(legacy_engine);
                break;
            }
        }
    }

    // Perform the scan
    let result = scan_content(&command, role.as_deref(), &engine, policy_context);

    // Build output JSON
    let output = json!({
        "command": command,
        "verdict": result.verdict,
        "lane": result.lane,
        "reason": result.log_msg,
        "confidence": result.log_score,
        "context": context
    });

    // Output JSON
    println!("{}", serde_json::to_string_pretty(&output).unwrap());

    // Exit with appropriate code
    match result.verdict.as_str() {
        "BLOCK" => std::process::exit(1),
        _ => std::process::exit(0),
    }
}

/// Pre-flight validation run in the parent process before daemonizing.
/// Returns an error if configuration is invalid so `sevorix start` can exit
/// with a clear message before reporting success.
pub fn validate_startup_config() -> anyhow::Result<()> {
    use directories::UserDirs;
    use crate::policy::Engine;

    // Load roles from disk (same search path as run_server)
    let mut engine = Engine::new();
    let mut base_dirs: Vec<std::path::PathBuf> = Vec::new();
    if let Some(proj_dirs) = ProjectDirs::from("com", "sevorix", "sevorix") {
        base_dirs.push(proj_dirs.config_dir().to_path_buf());
    }
    if let Some(user_dirs) = UserDirs::new() {
        base_dirs.push(user_dirs.home_dir().join(".sevorix"));
    }
    for base in &base_dirs {
        let role_dir = base.join("roles");
        if role_dir.exists() && role_dir.is_dir() {
            let _ = engine.load_roles_from_dir(&role_dir);
        }
    }

    // Read settings and validate default_role
    let settings = settings::Settings::load();
    if let Some(role) = settings.sevsh.and_then(|s| s.default_role) {
        if !engine.roles.contains_key(role.as_str()) {
            anyhow::bail!(
                "settings.json specifies default_role '{}' but that role is not loaded. \
                 Check ~/.sevorix/roles/ and ensure the role file exists.",
                role
            );
        }
    }

    Ok(())
}

pub async fn run_server(allowed_roles: Option<Vec<String>>, session_id: uuid::Uuid) -> anyhow::Result<()> {
    // Setup paths
    let proj_dirs = ProjectDirs::from("com", "sevorix", "sevorix")
        .ok_or_else(|| anyhow::anyhow!("No home dir"))?;

    // Setup the shared state for the Dashboard + JuryConfig
    let (tx, _rx) = broadcast::channel(8192);



    // Initialize Engine
    let mut engine = Engine::new();

    // 1. Identify Config Base Dirs
    // Priority:
    // - ~/.sevorix/
    // - XDG Config Home (e.g. ~/.config/sevorix/)
    // - Local .sevorix/ (for dev)

    let mut base_dirs = Vec::new();
    if let Some(user_dirs) = UserDirs::new() {
        base_dirs.push(user_dirs.home_dir().join(".sevorix"));
    }
    base_dirs.push(proj_dirs.config_dir().to_path_buf());
    base_dirs.push(std::path::PathBuf::from(".sevorix"));

    // 2. Load Policies from directories
    let mut policies_loaded = false;
    for base in &base_dirs {
        let policy_dir = base.join("policies");
        if policy_dir.exists() && policy_dir.is_dir() {
            tracing::info!("Loading policies from directory: {}", policy_dir.display());
            if let Err(e) = engine.load_policies_from_dir(&policy_dir) {
                tracing::error!("Error loading policies from {}: {}", policy_dir.display(), e);
            } else {
                policies_loaded = true;
            }
        }
    }

    // 3. Load Roles from directories
    for base in &base_dirs {
        let role_dir = base.join("roles");
        if role_dir.exists() && role_dir.is_dir() {
            tracing::info!("Loading roles from directory: {}", role_dir.display());
            if let Err(e) = engine.load_roles_from_dir(&role_dir) {
                tracing::error!("Error loading roles from {}: {}", role_dir.display(), e);
            }
        }
    }

    // 4. Legacy / Single File Fallback (policies.json)
    // If no policies loaded via directory, try loading single file
    if !policies_loaded {
        let mut candidate_paths = vec![std::path::PathBuf::from(".sevorix/policies.json")];
        if let Some(user_dirs) = UserDirs::new() {
            candidate_paths.push(user_dirs.home_dir().join(".sevorix/policies.json"));
        }
        candidate_paths.push(proj_dirs.config_dir().join("policies.json"));
        candidate_paths.push(std::path::PathBuf::from("policies.json"));

        for path in &candidate_paths {
            if path.exists() {
                tracing::info!("Loading legacy policies from: {}", path.display());
                if let Ok(legacy_engine) =
                    Engine::load_from_file(path.to_str().unwrap_or("policies.json"))
                {
                    engine.merge(legacy_engine);
                    break;
                }
            }
        }
    }

    // 5. Apply Role Filtering
    if let Some(roles) = allowed_roles {
        tracing::info!("Filtering active roles to: {:?}", roles);
        engine.retain_roles(&roles);
    }

    if engine.policies.is_empty() {
        tracing::warn!("Warning: No policies loaded. Engine is empty.");
    }

    // Load settings from ~/.sevorix/settings.json (optional; missing = all defaults)
    let loaded_settings = base_dirs
        .first()
        .map(|d| d.join("settings.json"))
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str::<settings::Settings>(&s).ok())
        .unwrap_or_default();
    let intervention_settings = loaded_settings.intervention.unwrap_or_default();
    let default_role = loaded_settings.sevsh.and_then(|s| s.default_role);

    let enforcement_tier = detect_enforcement_tier();

    // Per-session traffic log: ~/.sevorix/logs/{session_id}-traffic.jsonl
    let log_dir = if let Some(user_dirs) = UserDirs::new() {
        user_dirs.home_dir().join(".sevorix").join("logs")
    } else {
        std::path::PathBuf::from(".sevorix/logs")
    };
    let _ = std::fs::create_dir_all(&log_dir);
    let session_id_str = session_id.to_string();
    let traffic_log_path = log_dir.join(format!("{}-traffic.jsonl", session_id_str));

    let app_state = Arc::new(AppState {
        tx,
        policy_engine: Arc::new(RwLock::new(engine)),
        traffic_log_path,
        log_dir: log_dir.clone(),
        session_id: session_id_str,
        enforcement_tier,
        active_sessions: Arc::new(Mutex::new(std::collections::HashSet::new())),
        pending_decisions: Arc::new(DashMap::new()),
        intervention_timeout_secs: intervention_settings.timeout_secs(),
        intervention_timeout_allow: intervention_settings.timeout_action_allow(),
        current_role: Arc::new(RwLock::new(default_role)),
    });

    // Define the Routes
    let app = Router::new()
        .route("/analyze", post(analyze_intent))
        .route("/analyze-syscall", post(analyze_syscall))
        .route("/syscall-policy", get(syscall_policy_handler))
        .route("/policies/ebpf", get(ebpf_policies_handler))
        .route("/api/ebpf-event", post(ebpf_event_handler))
        .route("/api/policies/reload", post(reload_policies_handler))
        .route("/ws", get(ws_handler))
        .route("/api/events", get(get_recent_events))
        .route("/api/decide", post(decide_handler))
        .route("/api/pause", post(pause_handler))
        .route("/api/stats", get(get_stats_handler))
        .route("/api/sessions", get(get_sessions_handler))
        .route("/dashboard/*file", get(static_handler))
        // also redirect /dashboard to /dashboard/index.html
        .route("/dashboard", get(dashboard_redirect))
        .route("/api/session/register", post(session_register))
        .route("/api/session/unregister", post(session_unregister))
        .route("/api/session/set-role", post(session_set_role))
        .route("/api/active-sessions", get(active_sessions_handler));


    let app = app
        .route("/health", get(health_handler))
        .route("/api/version", get(get_version))
        .fallback(proxy_handler)
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));

    tracing::info!("--------------------------------------------------");
    tracing::info!("🛡️  SEVORIX WATCHTOWER ACTIVE");
    tracing::info!("📡 API: http://localhost:3000/analyze");
    tracing::info!("📊 Dashboard: http://localhost:3000/dashboard/desktop.html");
    tracing::info!("🔒 Enforcement tier: {}", enforcement_tier);
    if enforcement_tier == EnforcementTier::Standard {
        tracing::info!("   (BPF LSM unavailable — 'bpf' not in /sys/kernel/security/lsm)");
    }
    if let Some(state_dir) = proj_dirs.state_dir() {
        tracing::info!("📝 Logging Threats to: {}/threat_log.txt", state_dir.display());
    }
    tracing::info!("--------------------------------------------------");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn session_register(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> impl IntoResponse {
    if let Some(path) = body["cgroup_path"].as_str() {
        state.active_sessions.lock().await.insert(path.to_string());

        // Synchronously notify the eBPF daemon so SEVORIX_CGROUP_IDS is updated
        // before sevsh runs the child process. Best-effort: if the daemon socket
        // is not available (e.g. non-ebpf build), we continue without blocking.
        notify_ebpf_daemon_cgroup(path).await;
    }
    StatusCode::OK
}

/// Send a cgroup registration message to the eBPF daemon over a Unix socket.
///
/// The daemon inserts the cgroup's inode into SEVORIX_CGROUP_IDS before returning ACK,
/// ensuring the BPF filter recognises the new session immediately.
/// Timeout is 200ms — if the daemon is not running or the socket is unavailable,
/// this returns promptly without blocking session startup.
async fn notify_ebpf_daemon_cgroup(cgroup_path: &str) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let msg = format!("{}\n", json!({"cgroup_path": cgroup_path}));

    let result = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        async {
            let stream = UnixStream::connect(EBPF_SOCK_PATH).await?;
            let (reader, mut writer) = stream.into_split();
            writer.write_all(msg.as_bytes()).await?;
            let mut lines = BufReader::new(reader).lines();
            let _ack = lines.next_line().await?;
            Ok::<_, std::io::Error>(())
        },
    )
    .await;

    match result {
        Ok(Ok(())) => {} // ACK received — cgroup ID is in the BPF map
        Ok(Err(e)) => tracing::debug!("eBPF socket notify failed: {}", e),
        Err(_) => tracing::debug!("eBPF socket notify timed out — daemon may not be running"),
    }
}

async fn active_sessions_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let sessions: Vec<String> = state.active_sessions.lock().await.iter().cloned().collect();
    Json(json!({ "sessions": sessions }))
}

async fn session_unregister(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> impl IntoResponse {
    if let Some(path) = body["cgroup_path"].as_str() {
        state.active_sessions.lock().await.remove(path);
    }
    StatusCode::OK
}

async fn session_set_role(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> impl IntoResponse {
    let Some(role) = body["role"].as_str() else {
        return (StatusCode::BAD_REQUEST, "Missing 'role' field").into_response();
    };
    if !state.policy_engine.read().unwrap().roles.contains_key(role) {
        return (
            StatusCode::BAD_REQUEST,
            format!("Role '{}' not found. Load it into ~/.sevorix/roles/ and reload policies.", role),
        ).into_response();
    }
    *state.current_role.write().unwrap() = Some(role.to_string());
    tracing::info!("Session role updated to '{}'", role);
    StatusCode::OK.into_response()
}

/// Hot-reload all policies and roles from disk without restarting the server.
///
/// Re-reads `~/.sevorix/policies/`, `~/.sevorix/roles/`, and the legacy
/// `~/.config/sevorix/policies.json` fallback, then atomically swaps the engine.
async fn reload_policies_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let proj_dirs = match ProjectDirs::from("com", "sevorix", "sevorix") {
        Some(d) => d,
        None => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "reason": "No home dir" })),
            )
                .into_response()
        }
    };

    let mut engine = Engine::new();

    let mut base_dirs = Vec::new();
    if let Some(user_dirs) = UserDirs::new() {
        base_dirs.push(user_dirs.home_dir().join(".sevorix"));
    }
    base_dirs.push(proj_dirs.config_dir().to_path_buf());
    base_dirs.push(std::path::PathBuf::from(".sevorix"));

    let mut policies_loaded = false;
    for base in &base_dirs {
        let policy_dir = base.join("policies");
        if policy_dir.exists() && policy_dir.is_dir() {
            if engine.load_policies_from_dir(&policy_dir).is_ok() {
                policies_loaded = true;
            }
        }
    }
    for base in &base_dirs {
        let role_dir = base.join("roles");
        if role_dir.exists() && role_dir.is_dir() {
            let _ = engine.load_roles_from_dir(&role_dir);
        }
    }

    if !policies_loaded {
        let mut candidate_paths = vec![std::path::PathBuf::from(".sevorix/policies.json")];
        if let Some(user_dirs) = UserDirs::new() {
            candidate_paths.push(user_dirs.home_dir().join(".sevorix/policies.json"));
        }
        candidate_paths.push(proj_dirs.config_dir().join("policies.json"));
        candidate_paths.push(std::path::PathBuf::from("policies.json"));
        for path in &candidate_paths {
            if path.exists() {
                if let Ok(legacy) = Engine::load_from_file(path.to_str().unwrap_or("policies.json")) {
                    engine.merge(legacy);
                    break;
                }
            }
        }
    }

    *state.policy_engine.write().unwrap() = engine;
    tracing::info!("Policies reloaded via API");
    Json(json!({ "status": "reloaded" })).into_response()
}


async fn dashboard_redirect() -> impl IntoResponse {
    axum::response::Redirect::permanent("/dashboard/index.html")
}

// Serves embedded assets
async fn static_handler(uri: Uri) -> impl IntoResponse {
    let mut path = uri.path().trim_start_matches('/').to_string();
    if path.starts_with("dashboard/") {
        path = path.replace("dashboard/", "");
    }
    if path.is_empty() {
        path = "index.html".to_string();
    }

    match Assets::get(&path) {
        Some(content) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            (
                [(axum::http::header::CONTENT_TYPE, mime.as_ref())],
                content.data,
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Await a user intervention decision, respecting a pause/resume signal.
///
/// - While paused: the timeout clock is frozen; only a decision or unpause can proceed.
/// - On timeout (unpaused): returns `timeout_allow`.
/// - On user decision: returns the decision value.
async fn await_decision_with_pause(
    mut decision_rx: oneshot::Receiver<bool>,
    mut pause_rx: watch::Receiver<bool>,
    timeout_secs: u64,
    timeout_allow: bool,
) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    loop {
        let paused = *pause_rx.borrow_and_update();
        if paused {
            // Frozen — wait indefinitely until a decision arrives or pause is lifted.
            tokio::select! {
                result = &mut decision_rx => return result.unwrap_or(timeout_allow),
                _ = pause_rx.changed() => continue,
            }
        } else {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return timeout_allow;
            }
            tokio::select! {
                result = &mut decision_rx => return result.unwrap_or(timeout_allow),
                _ = pause_rx.changed() => continue,
                _ = tokio::time::sleep(remaining) => return timeout_allow,
            }
        }
    }
}

#[derive(serde::Deserialize)]
struct DecidePayload {
    event_id: String,
    action: String,
}

#[derive(serde::Deserialize)]
struct PausePayload {
    event_id: String,
    paused: bool,
}

/// Receive a human decision (allow/block) for a pending intervention.
async fn decide_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DecidePayload>,
) -> Response {
    let event_id = body.event_id.clone();
    let allow = match body.action.to_lowercase().as_str() {
        "allow" => true,
        "block" => false,
        _ => {
            return (StatusCode::BAD_REQUEST, "action must be 'allow' or 'block'").into_response();
        }
    };

    match state.pending_decisions.remove(&event_id) {
        Some((_, entry)) => {
            let _ = entry.decision_tx.send(allow);
            let ev = json!({
                "type": "DECIDED",
                "event_id": event_id,
                "action": body.action.to_lowercase(),
                "timestamp": chrono::Local::now().to_rfc3339(),
            });
            let _ = state.tx.send(ev.to_string());
            Json(json!({ "status": "ok", "event_id": event_id })).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            "event_id not found or already decided",
        )
            .into_response(),
    }
}

/// Pause or resume the countdown timer for a pending intervention.
async fn pause_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PausePayload>,
) -> Response {
    let event_id = body.event_id.clone();
    match state.pending_decisions.get(&event_id) {
        Some(entry) => {
            let _ = entry.pause_tx.send(body.paused);
            let ev = json!({
                "type": "PAUSED",
                "event_id": event_id,
                "paused": body.paused,
                "timestamp": chrono::Local::now().to_rfc3339(),
            });
            let _ = state.tx.send(ev.to_string());
            Json(json!({ "status": "ok", "paused": body.paused })).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            "event_id not found or already decided",
        )
            .into_response(),
    }
}

async fn analyze_intent(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<Value>,
) -> Response {
    let start_time = std::time::Instant::now();
    let text = payload["payload"].as_str().unwrap_or("").to_string();
    let agent_id = payload["agent"].as_str().unwrap_or("Unknown-Agent");

    // Resolve the active role. Fail-closed if no role is configured.
    let resolved_role: Option<String> = state.current_role.read().unwrap().clone();
    let Some(ref resolved_role) = resolved_role else {
        return Json(json!({
            "status": "BLOCK",
            "reason": "No role configured for this session. Use `sevorix session set-role <role>` or set default_role in ~/.sevorix/settings.json.",
            "lane": "RED",
            "confidence": "100%",
        })).into_response();
    };

    // Parse context
    let context_str = payload["context"].as_str().unwrap_or("All");
    let context = match context_str {
        "Shell" => PolicyContext::Shell,
        "Network" => PolicyContext::Network,
        _ => PolicyContext::All,
    };

    // --- POISON PILL LOGIC ---
    let pill = PoisonPill::default_canary();
    if scan_for_poison(&payload, &pill) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "SEVORIX CRITICAL: Honey-Pot Triggered. Agent Compromised.".to_string(),
        )
            .into_response();
    }

    // --- DECISION RULES ---
    let mut scan = scan_content(&text, Some(resolved_role.as_str()), &state.policy_engine.read().unwrap(), context);


    // --- USER INTERVENTION for FLAG (shell channel) ---
    if scan.verdict == "FLAG" {
        let event_id = uuid::Uuid::new_v4().to_string();
        let (decision_tx, decision_rx) = oneshot::channel::<bool>();
        let (pause_tx, pause_rx) = watch::channel(false);
        state.pending_decisions.insert(event_id.clone(), PendingEntry { decision_tx, pause_tx });

        let pending_event = json!({
            "type": "PENDING",
            "event_id": event_id,
            "verdict": "FLAG",
            "lane": "YELLOW",
            "layer": "shell",
            "payload": &text,
            "timestamp": chrono::Local::now().to_rfc3339(),
            "reason": scan.log_msg,
            "context": context_str,
            "role": resolved_role,
            "timeout_secs": state.intervention_timeout_secs,
            "timeout_action": if state.intervention_timeout_allow { "allow" } else { "block" },
        });
        log_traffic_event(&state.traffic_log_path, &pending_event.to_string());
        let _ = state.tx.send(pending_event.to_string());

        let allowed = await_decision_with_pause(
            decision_rx,
            pause_rx,
            state.intervention_timeout_secs,
            state.intervention_timeout_allow,
        ).await;

        // Still in map → timeout fired (not resolved by user via decide_handler)
        if state.pending_decisions.remove(&event_id).is_some() {
            let decided_event = json!({
                "type": "DECIDED",
                "event_id": event_id,
                "action": if allowed { "allow" } else { "block" },
                "reason": "timeout",
                "timestamp": chrono::Local::now().to_rfc3339(),
            });
            let _ = state.tx.send(decided_event.to_string());
        }

        if !allowed {
            let elapsed = start_time.elapsed().as_millis() as u64;
            let block_event = json!({
                "verdict": "BLOCK",
                "lane": "RED",
                "layer": "shell",
                "payload": &text,
                "timestamp": chrono::Local::now().to_rfc3339(),
                "latency": elapsed,
                "reason": "Blocked by operator",
                "confidence": null,
                "context": context_str,
                "role": resolved_role,
            });
            let block_str = block_event.to_string();
            log_traffic_event(&state.traffic_log_path, &block_str);
            let _ = state.tx.send(block_str);
            return Json(json!({
                "status": "BLOCK",
                "latency_ms": elapsed,
                "lane": "RED",
                "reason": "Blocked by operator",
                "confidence": null,
            })).into_response();
        }

        // Operator allowed — update verdict so the event logs as ALLOW
        scan.verdict = "ALLOW".to_string();
        scan.lane = "GREEN".to_string();
        scan.log_msg = Some("Allowed by operator intervention".to_string());
        scan.delay = 0;
    }

    if let Some(msg) = &scan.log_msg {
        log_threat(
            agent_id,
            &text,
            msg,
            scan.log_score.as_deref().unwrap_or("Unknown"),
        );
    }

    if scan.delay > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(scan.delay)).await;
    }

    let elapsed = start_time.elapsed().as_millis() as u64;

    let event = json!({
        "verdict": scan.verdict,
        "lane": scan.lane,
        "layer": "shell",
        "payload": payload["payload"],
        "timestamp": chrono::Local::now().to_rfc3339(),
        "latency": elapsed,
        "reason": scan.log_msg,
        "confidence": scan.log_score,
        "context": context_str,
        "role": resolved_role,
    });
    let event_str = event.to_string();
    log_traffic_event(&state.traffic_log_path, &event_str);
    let _ = state.tx.send(event_str);

    Json(json!({
        "status": scan.verdict,
        "latency_ms": elapsed,
        "lane": scan.lane,
        "reason": scan.log_msg,
        "confidence": scan.log_score
    }))
    .into_response()
}

/// Analyze a syscall event and return a policy decision.
///
/// This endpoint is used by seccomp-unotify handlers to get policy decisions
/// for intercepted syscalls. The response includes the action to take
/// (allow, block, or kill) and the errno to return if blocking.
async fn analyze_syscall(
    State(state): State<Arc<AppState>>,
    Json(event): Json<SyscallEvent>,
) -> Response {
    let start_time = std::time::Instant::now();

    // Get decision from policy engine
    let decision = scan_syscall_with_engine(&event, &state.policy_engine.read().unwrap());

    // Determine verdict and lane
    let (verdict, lane) = match &decision {
        SeccompDecision::Allow => ("ALLOW", "GREEN"),
        SeccompDecision::Block { .. } => ("BLOCK", "RED"),
        SeccompDecision::Kill => ("KILL", "RED"),
    };

    // Build payload for logging
    let payload = format!("{}({})", event.syscall_name, event.args.join(", "));

    // Log if blocked or killed
    match &decision {
        SeccompDecision::Block { errno } => {
            log_threat(
                &format!("syscall-pid-{}", event.pid),
                &payload,
                &format!("Syscall blocked (errno={})", errno),
                "Policy Match",
            );
        }
        SeccompDecision::Kill => {
            log_kill(
                &event.syscall_name,
                event.pid,
                event.ppid,
                &event.args,
                "policy-match",
            );
        }
        SeccompDecision::Allow => {
            // No logging for allowed syscalls
        }
    }

    let elapsed = start_time.elapsed().as_millis() as u64;

    // Broadcast syscall event to dashboard for unified monitoring
    let syscall_event = json!({
        "verdict": verdict,
        "lane": lane,
        "layer": "syscall",
        "payload": payload,
        "timestamp": chrono::Local::now().to_rfc3339(),
        "latency": elapsed,
        "reason": match &decision {
            SeccompDecision::Block { errno } => Some(format!("Syscall blocked (errno={})", errno)),
            SeccompDecision::Kill => Some("Critical violation - process killed".to_string()),
            SeccompDecision::Allow => None,
        },
        "confidence": "Policy Match",
        "context": "Syscall",
        "syscall_name": event.syscall_name,
        "syscall_number": event.syscall_number,
        "pid": event.pid,
        "ppid": event.ppid
    });
    let event_str = syscall_event.to_string();
    log_traffic_event(&state.traffic_log_path, &event_str);
    let _ = state.tx.send(event_str);

    // Build response
    let (action, errno) = match &decision {
        SeccompDecision::Allow => ("allow", None),
        SeccompDecision::Block { errno } => ("block", Some(*errno)),
        SeccompDecision::Kill => ("kill", None),
    };

    Json(json!({
        "action": action,
        "errno": errno,
        "syscall": event.syscall_name,
        "pid": event.pid,
        "latency_ms": elapsed
    }))
    .into_response()
}

/// Query parameters for role-scoped policy endpoints.
#[derive(Deserialize, Default)]
struct RoleQuery {
    /// Role name to scope policies by (defaults to "default").
    role: Option<String>,
}

/// Return the list of syscall names that should be denied for the current policy set.
///
/// Used by `sevsh` at session startup to build a per-session seccomp filter. Only
/// `Simple`-pattern policies with `context: Syscall` (or `All`) and `action: Block`
/// contribute to this list — regex and executable patterns cannot be safely mapped
/// to individual syscall names at filter-build time.
///
/// Policies are scoped to the role specified by the `?role=` query parameter, or
/// the "default" role if not provided. If the role does not exist, returns an empty list.
async fn syscall_policy_handler(
    State(state): State<Arc<AppState>>,
    Query(q): Query<RoleQuery>,
) -> impl IntoResponse {
    let engine = state.policy_engine.read().unwrap();
    let role_name = q.role.as_deref().unwrap_or("default");
    let policy_ids = match engine.roles.get(role_name) {
        Some(role) => role.policies.clone(),
        None => return Json(json!({ "deny_names": [] })),
    };

    let deny_names: Vec<String> = policy_ids
        .iter()
        .filter_map(|id| engine.policies.get(id))
        .filter(|p| {
            (p.context == PolicyContext::Syscall || p.context == PolicyContext::All)
                && p.action == Action::Block
        })
        .filter_map(|p| match &p.match_type {
            PolicyType::Simple(pattern) => Some(pattern.clone()),
            _ => None,
        })
        .collect();

    Json(json!({ "deny_names": deny_names }))
}

/// Map syscall name to x86-64 syscall number.
fn syscall_nr_by_name(name: &str) -> Option<u64> {
    match name {
        "read" => Some(0), "write" => Some(1), "open" => Some(2), "close" => Some(3),
        "stat" => Some(4), "fstat" => Some(5), "lstat" => Some(6),
        "mmap" => Some(9), "mprotect" => Some(10), "munmap" => Some(11),
        "brk" => Some(12), "pipe" => Some(22),
        "dup" => Some(32), "dup2" => Some(33),
        "socket" => Some(41), "connect" => Some(42), "accept" => Some(43),
        "sendto" => Some(44), "recvfrom" => Some(45),
        "bind" => Some(49), "listen" => Some(50),
        "clone" => Some(56), "fork" => Some(57), "vfork" => Some(58),
        "execve" => Some(59), "exit" => Some(60), "wait4" => Some(61),
        "kill" => Some(62), "uname" => Some(63),
        "fcntl" => Some(72), "getcwd" => Some(79),
        "chdir" => Some(80), "fchdir" => Some(81),
        "rename" => Some(82), "mkdir" => Some(83), "rmdir" => Some(84),
        "creat" => Some(85), "link" => Some(86), "unlink" => Some(87),
        "symlink" => Some(88), "readlink" => Some(89),
        "chmod" => Some(90), "chown" => Some(92),
        "ptrace" => Some(101), "getuid" => Some(102), "getgid" => Some(104),
        "setuid" => Some(105), "setgid" => Some(106),
        "mount" => Some(165), "umount2" => Some(166),
        "openat" => Some(257), "mkdirat" => Some(258),
        "unlinkat" => Some(263), "renameat" => Some(264),
        "fchmodat" => Some(268), "faccessat" => Some(269),
        "renameat2" => Some(316), "execveat" => Some(322),
        _ => None,
    }
}

/// Return structured eBPF policy rules for map pre-population.
///
/// The eBPF daemon calls this at startup and on each new session to pre-populate
/// GLOBAL_DENYLIST and NET_DENYLIST before any session process runs, closing the
/// first-occurrence gap in reactive enforcement.
///
/// Returns:
/// - `syscall_rules`: `[{syscall_nr, errno}]` for all Simple/Block/Syscall policies
/// - `net_rules`: reserved, always empty until network policies support IP/port matching
///
/// Policies are scoped to the role specified by the `?role=` query parameter, or
/// the "default" role if not provided. If the role does not exist, returns empty lists.
async fn ebpf_policies_handler(
    State(state): State<Arc<AppState>>,
    Query(q): Query<RoleQuery>,
) -> impl IntoResponse {
    let engine = state.policy_engine.read().unwrap();
    let role_name = q.role.as_deref().unwrap_or("default");
    let policy_ids = match engine.roles.get(role_name) {
        Some(role) => role.policies.clone(),
        None => return Json(json!({ "syscall_rules": [], "net_rules": [] })),
    };

    let syscall_rules: Vec<Value> = policy_ids
        .iter()
        .filter_map(|id| engine.policies.get(id))
        .filter(|p| {
            (p.context == PolicyContext::Syscall || p.context == PolicyContext::All)
                && p.action == Action::Block
        })
        .filter_map(|p| match &p.match_type {
            PolicyType::Simple(name) => syscall_nr_by_name(name.trim()).map(|nr| {
                json!({ "syscall_nr": nr, "errno": libc::EPERM })
            }),
            _ => None,
        })
        .collect();

    Json(json!({
        "syscall_rules": syscall_rules,
        "net_rules": [],
    }))
}

/// Handle eBPF events from the eBPF daemon.
///
/// This endpoint receives events from the eBPF daemon (syscall and network events)
/// and logs them to the unified traffic log. Events are also broadcast to the
/// dashboard for real-time monitoring.
///
/// Event types:
/// - "syscall": Syscall interception events
/// - "network": Network connection events
async fn ebpf_event_handler(
    State(state): State<Arc<AppState>>,
    Json(event): Json<Value>,
) -> Response {
    // Extract event type
    let event_type = event["event_type"].as_str().unwrap_or("unknown");
    let layer = match event_type {
        "syscall" => "syscall",
        "network" => "network",
        _ => "ebpf",
    };

    // Build unified event format
    let unified_event = json!({
        "verdict": event["verdict"].as_str().unwrap_or("ALLOW"),
        "lane": event["lane"].as_str().unwrap_or("GREEN"),
        "layer": layer,
        "payload": event["payload"].as_str().unwrap_or(""),
        "timestamp": chrono::Local::now().to_rfc3339(),
        "latency": event["latency"].as_u64().unwrap_or(0),
        "reason": event["reason"].as_str().unwrap_or(""),
        "confidence": event["confidence"].as_str().unwrap_or("N/A"),
        "context": event["context"].as_str().unwrap_or(layer),
        // Preserve original event details
        "details": event
    });

    let event_str = unified_event.to_string();

    // Log to traffic events
    log_traffic_event(&state.traffic_log_path, &event_str);

    // Broadcast to dashboard
    let _ = state.tx.send(event_str);

    // Log based on verdict
    if event["verdict"].as_str() == Some("BLOCK") {
        if let Some(syscall) = event["syscall_name"].as_str() {
            tracing::warn!(
                "[eBPF] BLOCK: {} syscall blocked (pid={})",
                syscall,
                event["pid"].as_u64().unwrap_or(0)
            );
        } else if let Some(dst) = event["destination"].as_str() {
            tracing::warn!("[eBPF] BLOCK: Network connection blocked to {}", dst);
        }
    }

    Json(json!({
        "status": "ok",
        "event_type": event_type,
        "layer": layer
    }))
    .into_response()
}


async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    use tokio::sync::broadcast::error::RecvError;
    let mut rx = state.tx.subscribe();
    loop {
        match rx.recv().await {
            Ok(msg) => {
                if socket.send(Message::Text(msg)).await.is_err() {
                    break;
                }
            }
            // Receiver fell behind — skip missed messages and keep going.
            Err(RecvError::Lagged(_)) => continue,
            // Sender dropped (server shutting down).
            Err(RecvError::Closed) => break,
        }
    }
}

/// Log a traffic event to the persistent JSONL file
pub fn log_traffic_event(path: &std::path::Path, event: &str) {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{}", event);
    }
}

/// Query parameters for the event log endpoint.
#[derive(Deserialize, Default)]
struct EventQuery {
    /// Comma-separated layer filter: "shell", "syscall", "network".
    /// Omit to include all layers.
    layer: Option<String>,
    /// Full-text search across payload, verdict, lane, reason, context, syscall_name.
    search: Option<String>,
    /// Lane filter: "RED", "YELLOW", "GREEN".
    lane: Option<String>,
    /// 1-indexed page number (default 1).
    page: Option<usize>,
    /// Results per page (default 50, max 500).
    limit: Option<usize>,
    /// Optional session UUID to query a past session's traffic file.
    /// Use "legacy" to query the old global traffic_events.jsonl.
    session: Option<String>,
}

/// Query the traffic event log with server-side filtering, search, and pagination.
///
/// Reads the JSONL file once, applies all filters, then returns a single page.
/// The abstraction is intentionally thin so the reader can later be swapped
/// for a cloud logging backend (e.g. Datadog, CloudWatch) behind a trait.
async fn get_recent_events(
    State(state): State<Arc<AppState>>,
    Query(q): Query<EventQuery>,
) -> Response {
    let limit = q.limit.unwrap_or(50).min(500);
    let page = q.page.unwrap_or(1).max(1);

    // Parse layer filter into a set of accepted layer strings.
    let layer_filter: Option<Vec<String>> = q.layer.map(|s| {
        s.split(',').map(|l| l.trim().to_lowercase()).collect()
    });

    let lane_filter: Option<String> = q.lane.map(|s| s.to_uppercase());

    let search_term: Option<String> = q.search
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty());

    // Resolve which session's traffic file to read.
    let traffic_path: std::path::PathBuf = if q.session.as_deref() == Some("legacy") {
        if let Some(proj_dirs) = ProjectDirs::from("com", "sevorix", "sevorix") {
            proj_dirs.state_dir()
                .unwrap_or_else(|| proj_dirs.cache_dir())
                .join("traffic_events.jsonl")
        } else {
            state.traffic_log_path.clone()
        }
    } else if let Some(ref sid) = q.session {
        if uuid::Uuid::parse_str(sid).is_ok() {
            state.log_dir.join(format!("{}-traffic.jsonl", sid))
        } else {
            return Json(json!({
                "events": [],
                "total": 0,
                "page": 1,
                "limit": limit,
                "total_pages": 0,
                "error": "invalid session id"
            })).into_response();
        }
    } else {
        state.traffic_log_path.clone()
    };

    let mut matched: Vec<Value> = Vec::new();

    if let Ok(file) = std::fs::File::open(&traffic_path) {
        use std::io::{BufRead, BufReader};
        let reader = BufReader::new(file);

        for line in reader.lines().map_while(Result::ok) {
            let Ok(event) = serde_json::from_str::<Value>(&line) else { continue };

            // Layer filter.
            if let Some(ref layers) = layer_filter {
                let event_layer = event.get("layer").and_then(|v| v.as_str()).unwrap_or("shell");
                if !layers.iter().any(|l| l == event_layer) {
                    continue;
                }
            }

            // Lane filter
            if let Some(ref lane) = lane_filter {
                let event_lane = event.get("lane").and_then(|v| v.as_str()).unwrap_or("");
                if event_lane != lane {
                    continue;
                }
            }

            // Full-text search
            if let Some(ref term) = search_term {
                let haystack = ["payload", "verdict", "lane", "layer", "reason", "context", "syscall_name"]
                    .iter()
                    .filter_map(|k| event.get(k).and_then(|v| v.as_str()))
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_lowercase();
                if !haystack.contains(term.as_str()) {
                    continue;
                }
            }

            matched.push(event);
        }
    }

    // Sort newest-first (RFC3339 timestamps sort lexicographically).
    matched.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let tb = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        tb.cmp(ta)
    });

    let total = matched.len();
    let total_pages = total.div_ceil(limit);
    let offset = (page - 1) * limit;
    let events: Vec<Value> = matched.into_iter().skip(offset).take(limit).collect();

    Json(json!({
        "events": events,
        "total": total,
        "page": page,
        "limit": limit,
        "total_pages": total_pages,
    })).into_response()
}

/// Compute aggregate stats from a traffic log file.
async fn get_stats_handler(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StatsQuery>,
) -> impl IntoResponse {
    let traffic_path: std::path::PathBuf = if q.session.as_deref() == Some("legacy") {
        if let Some(proj_dirs) = ProjectDirs::from("com", "sevorix", "sevorix") {
            proj_dirs.state_dir()
                .unwrap_or_else(|| proj_dirs.cache_dir())
                .join("traffic_events.jsonl")
        } else {
            state.traffic_log_path.clone()
        }
    } else if let Some(ref sid) = q.session {
        if uuid::Uuid::parse_str(sid).is_ok() {
            state.log_dir.join(format!("{}-traffic.jsonl", sid))
        } else {
            state.traffic_log_path.clone()
        }
    } else {
        state.traffic_log_path.clone()
    };

    let mut total: u64 = 0;
    let mut blocked: u64 = 0;
    let mut latency_sum: u64 = 0;
    let mut latency_count: u64 = 0;
    let mut shell: u64 = 0;
    let mut syscall: u64 = 0;
    let mut network: u64 = 0;

    if let Ok(file) = std::fs::File::open(&traffic_path) {
        use std::io::{BufRead, BufReader};
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            let Ok(event) = serde_json::from_str::<Value>(&line) else { continue };
            total += 1;

            if event.get("lane").and_then(|v| v.as_str()) == Some("RED") {
                blocked += 1;
            }
            if let Some(ms) = event.get("latency").and_then(|v| v.as_u64()) {
                latency_sum += ms;
                latency_count += 1;
            }

            let layer = event.get("layer").and_then(|v| v.as_str()).unwrap_or("shell");
            match layer {
                "syscall" => syscall += 1,
                "network" => network += 1,
                _ => shell += 1,
            }
        }
    }

    let avg_latency = if latency_count > 0 { latency_sum / latency_count } else { 0 };

    Json(json!({
        "total": total,
        "blocked": blocked,
        "avg_latency": avg_latency,
        "shell": shell,
        "syscall": syscall,
        "network": network,
    }))
}

#[derive(Deserialize, Default)]
struct StatsQuery {
    session: Option<String>,
}

/// List all traffic log sessions found in the log directory.
async fn get_sessions_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut sessions: Vec<Value> = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&state.log_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let fname = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            if !fname.ends_with("-traffic.jsonl") {
                continue;
            }
            let uuid_part = &fname[..fname.len() - "-traffic.jsonl".len()];
            if uuid::Uuid::parse_str(uuid_part).is_err() {
                continue;
            }
            let is_current = uuid_part == state.session_id;
            let (event_count, first_ts, last_ts) = summarize_traffic_file(&path);
            let size_bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            sessions.push(json!({
                "session_id": uuid_part,
                "is_current": is_current,
                "event_count": event_count,
                "started_at": first_ts,
                "last_event_at": last_ts,
                "size_bytes": size_bytes,
            }));
        }
    }

    // Expose legacy global file if it exists and has events.
    if let Some(proj_dirs) = ProjectDirs::from("com", "sevorix", "sevorix") {
        let legacy_path = proj_dirs
            .state_dir()
            .unwrap_or_else(|| proj_dirs.cache_dir())
            .join("traffic_events.jsonl");
        if legacy_path.exists() {
            let (event_count, first_ts, last_ts) = summarize_traffic_file(&legacy_path);
            if event_count > 0 {
                let size_bytes = std::fs::metadata(&legacy_path).map(|m| m.len()).unwrap_or(0);
                sessions.push(json!({
                    "session_id": "legacy",
                    "is_current": false,
                    "event_count": event_count,
                    "started_at": first_ts,
                    "last_event_at": last_ts,
                    "size_bytes": size_bytes,
                }));
            }
        }
    }

    // Sort newest-first by last_event_at.
    sessions.sort_by(|a, b| {
        let ta = a["last_event_at"].as_str().unwrap_or("");
        let tb = b["last_event_at"].as_str().unwrap_or("");
        tb.cmp(ta)
    });

    Json(json!({
        "current_session": state.session_id,
        "sessions": sessions,
    }))
}

/// Scan a traffic JSONL file and return (event_count, first_timestamp, last_timestamp).
fn summarize_traffic_file(path: &std::path::Path) -> (usize, Option<String>, Option<String>) {
    use std::io::{BufRead, BufReader};
    let Ok(file) = std::fs::File::open(path) else {
        return (0, None, None);
    };
    let reader = BufReader::new(file);
    let mut count = 0usize;
    let mut first_ts: Option<String> = None;
    let mut last_ts: Option<String> = None;
    for line in reader.lines().map_while(Result::ok) {
        let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
        count += 1;
        let ts = v["timestamp"].as_str().map(String::from);
        if first_ts.is_none() {
            first_ts = ts.clone();
        }
        last_ts = ts;
    }
    (count, first_ts, last_ts)
}

/// Get version and edition info
async fn health_handler() -> impl IntoResponse {
    StatusCode::OK
}

async fn get_version(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    #[cfg(not(feature = "pro"))]
    let edition = "lite";

    let tier = match state.enforcement_tier {
        EnforcementTier::Standard => "standard",
        EnforcementTier::Advanced => "advanced",
    };

    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "edition": edition,
        "enforcement_tier": tier,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Action, Policy, PolicyType, Role};
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn test_log_traffic_event_creates_file() {
        let dir = tempdir().expect("Failed to create temp dir");
        let path = dir.path().join("traffic.jsonl");

        log_traffic_event(&path, r#"{"test": "event"}"#);

        assert!(path.exists());
        let content = std::fs::read_to_string(&path).expect("Failed to read file");
        assert!(content.contains("test"));
    }

    #[test]
    fn test_log_traffic_event_appends() {
        let dir = tempdir().expect("Failed to create temp dir");
        let path = dir.path().join("traffic.jsonl");

        log_traffic_event(&path, r#"{"id": 1}"#);
        log_traffic_event(&path, r#"{"id": 2}"#);

        let content = std::fs::read_to_string(&path).expect("Failed to read file");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_log_traffic_event_creates_parent_dirs() {
        let dir = tempdir().expect("Failed to create temp dir");
        let path = dir.path().join("nested/deep/dir/traffic.jsonl");

        log_traffic_event(&path, r#"{"test": "nested"}"#);

        assert!(path.exists());
    }

    fn create_test_app_state() -> Arc<AppState> {
        let (tx, _) = broadcast::channel(100);
        Arc::new(AppState {
            tx,
            policy_engine: Arc::new(RwLock::new(Engine::new())),
            traffic_log_path: PathBuf::from("/tmp/test_traffic.jsonl"),
            log_dir: PathBuf::from("/tmp"),
            session_id: "00000000-0000-0000-0000-000000000000".to_string(),
            enforcement_tier: EnforcementTier::Standard,
            active_sessions: Arc::new(Mutex::new(std::collections::HashSet::new())),
            pending_decisions: Arc::new(DashMap::new()),
            intervention_timeout_secs: 30,
            intervention_timeout_allow: false,
            current_role: Arc::new(RwLock::new(None)),
        })
    }

    #[allow(dead_code)]
    fn create_test_app_state_with_path(path: PathBuf) -> Arc<AppState> {
        let (tx, _) = broadcast::channel(100);
        Arc::new(AppState {
            tx,
            policy_engine: Arc::new(RwLock::new(Engine::new())),
            traffic_log_path: path,
            log_dir: PathBuf::from("/tmp"),
            session_id: "00000000-0000-0000-0000-000000000000".to_string(),
            enforcement_tier: EnforcementTier::Standard,
            active_sessions: Arc::new(Mutex::new(std::collections::HashSet::new())),
            pending_decisions: Arc::new(DashMap::new()),
            intervention_timeout_secs: 30,
            intervention_timeout_allow: false,
            current_role: Arc::new(RwLock::new(None)),
        })
    }

    fn create_test_app_state_with_engine(engine: Engine) -> Arc<AppState> {
        let (tx, _) = broadcast::channel(100);
        Arc::new(AppState {
            tx,
            policy_engine: Arc::new(RwLock::new(engine)),
            traffic_log_path: PathBuf::from("/tmp/test_traffic.jsonl"),
            log_dir: PathBuf::from("/tmp"),
            session_id: "00000000-0000-0000-0000-000000000000".to_string(),
            enforcement_tier: EnforcementTier::Standard,
            active_sessions: Arc::new(Mutex::new(std::collections::HashSet::new())),
            pending_decisions: Arc::new(DashMap::new()),
            intervention_timeout_secs: 30,
            intervention_timeout_allow: false,
            current_role: Arc::new(RwLock::new(None)),
        })
    }

    #[test]
    fn test_handle_validate_config_missing_files() {
        // This test just verifies the function doesn't panic
        // when config files don't exist
        handle_validate_config();
    }

    #[test]
    fn test_handle_config_check() {
        // This test verifies handle_config doesn't panic
        handle_config(ConfigCommands::Check);
    }

    #[test]
    fn test_app_state_cloning() {
        let state = create_test_app_state();
        let cloned = state.clone();
        assert!(Arc::ptr_eq(&state, &cloned));
    }

    #[test]
    fn test_handle_integrations_list() {
        // Just verify it doesn't panic
        handle_integrations(IntegrationsCommands::List);
    }

    #[test]
    fn test_handle_integrations_status_all() {
        // Just verify it doesn't panic
        handle_integrations(IntegrationsCommands::Status { name: None });
    }

    // Test scan_content via the scanner module
    #[test]
    fn test_scan_content_integration() {
        let mut engine = Engine::new();
        engine.policies.insert("test_block".to_string(), Policy {
            id: "test_block".to_string(),
            match_type: PolicyType::Simple("BLOCKME".to_string()),
            action: Action::Block,
            context: PolicyContext::All,
            kill: false,
        });
        engine.roles.insert("default".to_string(), Role {
            name: "default".to_string(),
            policies: vec!["test_block".to_string()],
            is_dynamic: false,
        });

        let result = scan_content("BLOCKME", Some("default"), &engine, PolicyContext::All);
        assert_eq!(result.verdict, "BLOCK");
    }

    #[test]
    fn test_scan_for_poison_integration() {
        let pill = PoisonPill::default_canary();
        let payload = json!({
            "AWS_SECRET": pill.value
        });

        assert!(scan_for_poison(&payload, &pill));
    }

    #[test]
    fn test_scan_syscall_with_engine_integration() {
        let mut engine = Engine::new();
        engine.roles.insert("default".to_string(), Role {
            name: "default".to_string(),
            policies: vec![],
            is_dynamic: false,
        });
        let event = SyscallEvent {
            syscall_name: "read".to_string(),
            syscall_number: 0,
            args: vec!["3".to_string()],
            pid: 1234,
            ppid: 1,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
        };

        let decision = scan_syscall_with_engine(&event, &engine);
        assert_eq!(decision, SeccompDecision::Allow);
    }

    #[test]
    fn test_app_state_with_custom_engine() {
        let mut engine = Engine::new();
        engine.policies.insert("test".to_string(), Policy {
            id: "test".to_string(),
            match_type: PolicyType::Simple("pattern".to_string()),
            action: Action::Block,
            context: PolicyContext::All,
            kill: false,
        });

        let state = create_test_app_state_with_engine(engine);
        assert!(state.policy_engine.read().unwrap().policies.contains_key("test"));
    }

    #[test]
    fn test_scan_content_with_role() {
        let mut engine = Engine::new();
        engine.policies.insert("role_test".to_string(), Policy {
            id: "role_test".to_string(),
            match_type: PolicyType::Simple("DANGEROUS".to_string()),
            action: Action::Block,
            context: PolicyContext::All,
            kill: false,
        });
        engine.roles.insert("custom_role".to_string(), Role {
            name: "custom_role".to_string(),
            policies: vec!["role_test".to_string()],
            is_dynamic: false,
        });

        let result = scan_content("DANGEROUS content", Some("custom_role"), &engine, PolicyContext::All);
        assert_eq!(result.verdict, "BLOCK");
    }

    #[test]
    fn test_scan_content_flag_action() {
        let mut engine = Engine::new();
        engine.policies.insert("flag_test".to_string(), Policy {
            id: "flag_test".to_string(),
            match_type: PolicyType::Simple("SUSPICIOUS".to_string()),
            action: Action::Flag,
            context: PolicyContext::All,
            kill: false,
        });
        engine.roles.insert("default".to_string(), Role {
            name: "default".to_string(),
            policies: vec!["flag_test".to_string()],
            is_dynamic: false,
        });

        let result = scan_content("SUSPICIOUS content", Some("default"), &engine, PolicyContext::All);
        assert_eq!(result.verdict, "FLAG");
        assert_eq!(result.lane, "YELLOW");
        assert_eq!(result.delay, 500);
    }

    #[test]
    fn test_scan_content_with_kill_flag() {
        let mut engine = Engine::new();
        engine.policies.insert("kill_test".to_string(), Policy {
            id: "kill_test".to_string(),
            match_type: PolicyType::Simple("KILLME".to_string()),
            action: Action::Block,
            context: PolicyContext::All,
            kill: true,
        });
        engine.roles.insert("default".to_string(), Role {
            name: "default".to_string(),
            policies: vec!["kill_test".to_string()],
            is_dynamic: false,
        });

        let result = scan_content("KILLME now", Some("default"), &engine, PolicyContext::All);
        assert_eq!(result.verdict, "BLOCK");
        assert!(result.kill);
    }

    #[test]
    fn test_log_traffic_event_to_nested_path() {
        let dir = tempdir().expect("Failed to create temp dir");
        let nested_path = dir.path().join("deep").join("nested").join("traffic.jsonl");

        log_traffic_event(&nested_path, r#"{"test": "nested"}"#);

        assert!(nested_path.exists());
        let content = std::fs::read_to_string(&nested_path).expect("Failed to read");
        assert!(content.contains("nested"));
    }

    #[test]
    fn test_scan_for_poison_in_payload_field() {
        let pill = PoisonPill::default_canary();
        let payload = json!({
            "other_key": "value",
            "payload": format!("Some text with {} embedded", pill.value)
        });

        assert!(scan_for_poison(&payload, &pill));
    }

    #[test]
    fn test_scan_for_poison_not_present() {
        let pill = PoisonPill::default_canary();
        let payload = json!({
            "other_key": "value",
            "payload": "safe content"
        });

        assert!(!scan_for_poison(&payload, &pill));
    }

    #[test]
    fn test_handle_validate_allows_safe_command() {
        // Test that safe commands are allowed by testing the underlying logic directly
        let mut engine = Engine::new();
        engine.policies.insert("test".to_string(), Policy {
            id: "test".to_string(),
            match_type: PolicyType::Simple("DANGEROUS".to_string()),
            action: Action::Block,
            context: PolicyContext::All,
            kill: false,
        });
        engine.roles.insert("default".to_string(), Role {
            name: "default".to_string(),
            policies: vec!["test".to_string()],
            is_dynamic: false,
        });

        let result = scan_content("ECHO HELLO", Some("default"), &engine, PolicyContext::All);
        assert_eq!(result.verdict, "ALLOW");
    }

    #[test]
    fn test_handle_validate_blocks_dangerous_command() {
        let mut engine = Engine::new();
        engine.policies.insert("block_drop".to_string(), Policy {
            id: "block_drop".to_string(),
            match_type: PolicyType::Simple("DROP".to_string()),
            action: Action::Block,
            context: PolicyContext::All,
            kill: false,
        });
        engine.roles.insert("default".to_string(), Role {
            name: "default".to_string(),
            policies: vec!["block_drop".to_string()],
            is_dynamic: false,
        });

        let result = scan_content("DROP TABLE users", Some("default"), &engine, PolicyContext::All);
        assert_eq!(result.verdict, "BLOCK");
    }

    #[test]
    fn test_handle_validate_context_routing() {
        let mut engine = Engine::new();
        engine.policies.insert("shell_only".to_string(), Policy {
            id: "shell_only".to_string(),
            match_type: PolicyType::Simple("RM".to_string()),
            action: Action::Block,
            context: PolicyContext::Shell,
            kill: false,
        });
        engine.roles.insert("default".to_string(), Role {
            name: "default".to_string(),
            policies: vec!["shell_only".to_string()],
            is_dynamic: false,
        });

        // Should block in Shell context
        let result = scan_content("RM -rf /", Some("default"), &engine, PolicyContext::Shell);
        assert_eq!(result.verdict, "BLOCK");

        // Should allow in Network context
        let result = scan_content("RM -rf /", Some("default"), &engine, PolicyContext::Network);
        assert_eq!(result.verdict, "ALLOW");
    }

    #[test]
    fn test_handle_validate_with_role() {
        let mut engine = Engine::new();
        engine.policies.insert("admin_block".to_string(), Policy {
            id: "admin_block".to_string(),
            match_type: PolicyType::Simple("SECRET".to_string()),
            action: Action::Block,
            context: PolicyContext::All,
            kill: false,
        });
        engine.roles.insert("admin".to_string(), Role {
            name: "admin".to_string(),
            policies: vec!["admin_block".to_string()],
            is_dynamic: false,
        });
        engine.roles.insert("user".to_string(), Role {
            name: "user".to_string(),
            policies: vec![],
            is_dynamic: false,
        });

        // Admin role should block
        let result = scan_content("SECRET DATA", Some("admin"), &engine, PolicyContext::All);
        assert_eq!(result.verdict, "BLOCK");

        // User role should allow (no policies)
        let result = scan_content("SECRET DATA", Some("user"), &engine, PolicyContext::All);
        assert_eq!(result.verdict, "ALLOW");
    }

    #[test]
    fn test_app_state_traffic_log_path() {
        let state = create_test_app_state();
        assert_eq!(state.traffic_log_path, std::path::PathBuf::from("/tmp/test_traffic.jsonl"));
    }

    #[test]
    fn test_app_state_broadcast_channel() {
        let (tx, mut rx) = broadcast::channel::<String>(100);
        tx.send("test message".to_string()).unwrap();

        let msg = rx.try_recv().unwrap();
        assert_eq!(msg, "test message");
    }

    #[test]
    fn test_app_state_policy_engine_access() {
        let mut engine = Engine::new();
        engine.policies.insert("test".to_string(), Policy {
            id: "test".to_string(),
            match_type: PolicyType::Simple("pattern".to_string()),
            action: Action::Block,
            context: PolicyContext::All,
            kill: false,
        });

        let state = create_test_app_state_with_engine(engine);
        assert!(state.policy_engine.read().unwrap().policies.contains_key("test"));
    }

    #[tokio::test]
    async fn test_dashboard_redirect() {
        use axum::response::IntoResponse;
        let response = dashboard_redirect().await.into_response();
        // Verify it returns a redirect response
        assert_eq!(response.status(), axum::http::StatusCode::PERMANENT_REDIRECT);
    }

    #[test]
    fn test_static_handler_not_found() {
        use axum::http::Uri;
        use axum::response::IntoResponse;
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let uri: Uri = "/dashboard/nonexistent.html".parse().unwrap();
            let response = static_handler(uri).await.into_response();
            assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
        });
    }

    #[test]
    fn test_static_handler_index() {
        use axum::http::Uri;
        use axum::response::IntoResponse;
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let uri: Uri = "/dashboard/index.html".parse().unwrap();
            let response = static_handler(uri).await.into_response();
            // Should return 200 if index.html exists in assets
            // Note: This depends on the Assets embed
            assert!(response.status() == axum::http::StatusCode::OK ||
                    response.status() == axum::http::StatusCode::NOT_FOUND);
        });
    }

    #[tokio::test]
    async fn test_get_version() {
        use axum::extract::State;
        use axum::response::IntoResponse;
        let state = create_test_app_state();
        let response = get_version(State(state)).await.into_response();
        // Should return JSON with version, edition, and enforcement_tier
        let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("version").is_some());
        assert!(json.get("edition").is_some());
        assert!(json.get("enforcement_tier").is_some());
    }

    #[test]
    fn test_get_recent_events_empty_file() {
        use axum::response::IntoResponse;
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let state = create_test_app_state_with_path(
                std::path::PathBuf::from("/tmp/nonexistent_traffic_test.jsonl")
            );
            let response = get_recent_events(State(state), Query(EventQuery::default())).await.into_response();
            let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
            let json: Value = serde_json::from_slice(&body).unwrap();
            assert!(json.get("events").unwrap().as_array().unwrap().is_empty());
        });
    }

    #[test]
    fn test_get_recent_events_with_data() {
        use axum::response::IntoResponse;
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("traffic.jsonl");

            // Write some test events
            let event1 = r#"{"verdict": "ALLOW", "timestamp": "2026-01-01T00:00:00Z"}"#;
            let event2 = r#"{"verdict": "BLOCK", "timestamp": "2026-01-01T00:01:00Z"}"#;
            std::fs::write(&path, format!("{}\n{}\n", event1, event2)).unwrap();

            let state = create_test_app_state_with_path(path);
            let response = get_recent_events(State(state), Query(EventQuery::default())).await.into_response();
            let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
            let json: Value = serde_json::from_slice(&body).unwrap();

            let events = json.get("events").unwrap().as_array().unwrap();
            assert_eq!(events.len(), 2);
        });
    }

    #[test]
    fn test_handle_integrations_install_nonexistent() {
        // Test that installing a nonexistent integration doesn't panic
        handle_integrations(IntegrationsCommands::Install {
            name: "nonexistent_integration_xyz".to_string(),
        });
    }

    #[test]
    fn test_handle_integrations_uninstall_nonexistent() {
        handle_integrations(IntegrationsCommands::Uninstall {
            name: "nonexistent_integration_xyz".to_string(),
        });
    }

    #[test]
    fn test_handle_integrations_status_specific() {
        handle_integrations(IntegrationsCommands::Status {
            name: Some("nonexistent_integration_xyz".to_string()),
        });
    }

    #[test]
    fn test_log_traffic_event_with_invalid_parent() {
        // Test that logging to an invalid path doesn't panic
        // (it should silently fail)
        let path = std::path::PathBuf::from("/root/nonexistent_dir/traffic.jsonl");
        log_traffic_event(&path, r#"{"test": "event"}"#);
        // Should not panic, just silently fail
    }

    #[test]
    fn test_policy_context_variants() {
        // Test all context variants
        assert_eq!(PolicyContext::Shell, PolicyContext::Shell);
        assert_eq!(PolicyContext::Network, PolicyContext::Network);
        assert_eq!(PolicyContext::Syscall, PolicyContext::Syscall);
        assert_eq!(PolicyContext::All, PolicyContext::All);
        assert_ne!(PolicyContext::Shell, PolicyContext::Network);
    }

    #[test]
    fn test_seccomp_decision_variants() {
        // Test SeccompDecision variants
        let allow = SeccompDecision::Allow;
        let block = SeccompDecision::Block { errno: 1 };
        let kill = SeccompDecision::Kill;

        assert_eq!(allow, SeccompDecision::Allow);
        assert_eq!(block, SeccompDecision::Block { errno: 1 });
        assert_eq!(kill, SeccompDecision::Kill);
    }

    #[test]
    fn test_syscall_event_creation() {
        let event = SyscallEvent {
            syscall_name: "read".to_string(),
            syscall_number: 0,
            args: vec!["3".to_string(), "buf".to_string(), "1024".to_string()],
            pid: 1234,
            ppid: 1,
            timestamp: "2026-03-04T12:00:00Z".to_string(),
        };

        assert_eq!(event.syscall_name, "read");
        assert_eq!(event.syscall_number, 0);
        assert_eq!(event.args.len(), 3);
        assert_eq!(event.pid, 1234);
        assert_eq!(event.ppid, 1);
    }
}
