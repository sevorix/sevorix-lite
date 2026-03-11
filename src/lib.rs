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
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    process::Command,
    sync::Arc,
};
use tokio::sync::broadcast;

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

use assets::Assets;
pub use cli::{Cli, Commands, ConfigCommands, HubCommands, IntegrationsCommands};
pub use daemon::{DaemonManager, EbpfDaemonManager, is_ebpf_daemon_running, is_watchtower_running};
pub use integrations::{IntegrationRegistry, Integration, IntegrationStatus, InstallResult, Manifest, claude_code::ClaudeCodeIntegration, codex::CodexIntegration, openclaw::OpenClawIntegration};
use policy::{Engine, PolicyContext};
use proxy::proxy_handler;
use scanner::{log_threat, log_kill, scan_content, scan_for_poison, scan_syscall_with_engine, PoisonPill};
use sevorix_core::{SyscallEvent, SeccompDecision};

#[derive(Clone)]
pub struct AppState {
    pub tx: broadcast::Sender<String>,
    pub policy_engine: Arc<Engine>,
    pub traffic_log_path: std::path::PathBuf,
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
            match registry.get(&name) {
                Some(integration) => {
                    match integration.install() {
                        Ok(result) => {
                            println!("Successfully installed '{}'", name);
                            if !result.files_modified.is_empty() {
                                println!("Modified files:");
                                for f in &result.files_modified {
                                    println!("  - {}", f);
                                }
                            }
                            if result.restart_required {
                                println!("Note: A restart may be required for changes to take effect.");
                            }
                            println!("{}", result.message);
                        }
                        Err(e) => {
                            eprintln!("Failed to install '{}': {}", name, e);
                        }
                    }
                }
                None => {
                    eprintln!("Integration '{}' not found.", name);
                    println!("Available integrations: (none registered yet)");
                    println!("Use 'sevorix integrations list' to see available integrations.");
                }
            }
        }
        IntegrationsCommands::Uninstall { name } => {
            match registry.get(&name) {
                Some(integration) => {
                    match integration.uninstall() {
                        Ok(()) => {
                            println!("Successfully uninstalled '{}'", name);
                            if let Ok(Some(manifest)) = registry.load_manifest(&name) {
                                if let Some(backup_path) = &manifest.backup_path {
                                    println!("Backup preserved at: {}", backup_path);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to uninstall '{}': {}", name, e);
                        }
                    }
                }
                None => {
                    eprintln!("Integration '{}' not found.", name);
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
                    match registry.get(&n) {
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
    let text = command.to_uppercase();
    let result = scan_content(&text, role.as_deref(), &engine, policy_context);

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

pub async fn run_server(allowed_roles: Option<Vec<String>>) -> anyhow::Result<()> {
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

    let app_state = Arc::new(AppState {
        tx,
        policy_engine: Arc::new(engine),
        traffic_log_path: proj_dirs
            .state_dir()
            .unwrap_or_else(|| proj_dirs.cache_dir())
            .join("traffic_events.jsonl"),
    });

    // Define the Routes
    let app = Router::new()
        .route("/analyze", post(analyze_intent))
        .route("/analyze-syscall", post(analyze_syscall))
        .route("/api/ebpf-event", post(ebpf_event_handler))
        .route("/open-log", post(open_log_file))
        .route("/ws", get(ws_handler))
        .route("/api/events", get(get_recent_events))
        .route("/dashboard/*file", get(static_handler))
        // also redirect /dashboard to /dashboard/index.html
        .route("/dashboard", get(dashboard_redirect));


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
    if let Some(state_dir) = proj_dirs.state_dir() {
        tracing::info!("📝 Logging Threats to: {}/threat_log.txt", state_dir.display());
    }
    tracing::info!("--------------------------------------------------");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
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

async fn analyze_intent(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<Value>,
) -> Response {
    let start_time = std::time::Instant::now();
    let text = payload["payload"].as_str().unwrap_or("").to_uppercase();
    let agent_id = payload["agent"].as_str().unwrap_or("Unknown-Agent");
    let role = payload["role"].as_str();

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
    let mut scan = scan_content(&text, role, &state.policy_engine, context);


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
        "context": context_str
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
    let decision = scan_syscall_with_engine(&event, &state.policy_engine);

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
            SeccompDecision::Block { errno } => format!("Syscall blocked (errno={})", errno),
            SeccompDecision::Kill => "Critical violation - process killed".to_string(),
            SeccompDecision::Allow => "Syscall allowed".to_string(),
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


async fn open_log_file() {
    // Try xdg-open for Linux desktops, fallback to notepad for WSL/Windows users who might run this
    // But since this is a CLI Refactor task, we might want to defer this or log the path
    // For now keep notepad but also try xdg-open
    if Command::new("xdg-open").arg("threat_log.txt").spawn().is_ok() {
        return;
    }
    let _ = Command::new("notepad").arg("threat_log.txt").spawn();
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
}

/// Query the traffic event log with server-side filtering, search, and pagination.
///
/// Reads the JSONL file once, applies all filters, then returns a single page.
/// The abstraction is intentionally thin so the reader can later be swapped
/// for a cloud logging backend (e.g. Datadog, CloudWatch) behind a trait.
async fn get_recent_events(
    State(state): State<Arc<AppState>>,
    Query(q): Query<EventQuery>,
) -> impl IntoResponse {
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

    let mut matched: Vec<Value> = Vec::new();

    if let Ok(file) = std::fs::File::open(&state.traffic_log_path) {
        use std::io::{BufRead, BufReader};
        let reader = BufReader::new(file);

        for line in reader.lines().map_while(Result::ok) {
            let Ok(event) = serde_json::from_str::<Value>(&line) else { continue };

            // Layer filter.
            // "network" in the filter matches both "network" (eBPF) and "http" (proxy).
            if let Some(ref layers) = layer_filter {
                let event_layer = event.get("layer").and_then(|v| v.as_str()).unwrap_or("shell");
                let canonical = if event_layer == "http" { "network" } else { event_layer };
                if !layers.iter().any(|l| l == canonical) {
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
    }))
}

/// Get version and edition info
async fn health_handler() -> impl IntoResponse {
    StatusCode::OK
}

async fn get_version() -> impl IntoResponse {
    #[cfg(not(feature = "pro"))]
    let edition = "lite";

    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "edition": edition
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
            policy_engine: Arc::new(Engine::new()),
            traffic_log_path: PathBuf::from("/tmp/test_traffic.jsonl"),
        })
    }

    #[allow(dead_code)]
    fn create_test_app_state_with_path(path: PathBuf) -> Arc<AppState> {
        let (tx, _) = broadcast::channel(100);
        Arc::new(AppState {
            tx,
            policy_engine: Arc::new(Engine::new()),
            traffic_log_path: path,
        })
    }

    fn create_test_app_state_with_engine(engine: Engine) -> Arc<AppState> {
        let (tx, _) = broadcast::channel(100);
        Arc::new(AppState {
            tx,
            policy_engine: Arc::new(engine),
            traffic_log_path: PathBuf::from("/tmp/test_traffic.jsonl"),
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

        let result = scan_content("BLOCKME", None, &engine, PolicyContext::All);
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
        let engine = Engine::new();
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
        assert!(state.policy_engine.policies.contains_key("test"));
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

        let result = scan_content("SUSPICIOUS content", None, &engine, PolicyContext::All);
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

        let result = scan_content("KILLME now", None, &engine, PolicyContext::All);
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

        let result = scan_content("ECHO HELLO", None, &engine, PolicyContext::All);
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

        let result = scan_content("DROP TABLE users", None, &engine, PolicyContext::All);
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
        let result = scan_content("RM -rf /", None, &engine, PolicyContext::Shell);
        assert_eq!(result.verdict, "BLOCK");

        // Should allow in Network context
        let result = scan_content("RM -rf /", None, &engine, PolicyContext::Network);
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
        assert!(state.policy_engine.policies.contains_key("test"));
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
        use axum::response::IntoResponse;
        let response = get_version().await.into_response();
        // Should return JSON with version and edition
        let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("version").is_some());
        assert!(json.get("edition").is_some());
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
