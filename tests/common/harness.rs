use dashmap::DashMap;
use sevorix_core::EnforcementTier;
use sevorix_watchtower::{
    build_router,
    policy::Engine,
    AppState,
};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, RwLock},
};
use tempfile::TempDir;
use tokio::{net::TcpListener, sync::broadcast};

/// A self-contained test server with isolated config directory.
/// Dropped automatically at end of test (TempDir cleans up).
pub struct TestHarness {
    pub addr: SocketAddr,
    pub client: reqwest::Client,
    _dir: TempDir,
    pub config_dir: PathBuf,
    pub state: Arc<AppState>,
}

impl TestHarness {
    /// Spin up a server with an empty policy engine.
    pub async fn new() -> Self {
        Self::with_role(None).await
    }

    /// Spin up a server with an optional default role.
    pub async fn with_role(default_role: Option<String>) -> Self {
        let dir = TempDir::new().unwrap();
        let config_dir = dir.path().to_path_buf();

        // Create required subdirectories
        std::fs::create_dir_all(config_dir.join("policies")).unwrap();
        std::fs::create_dir_all(config_dir.join("roles")).unwrap();
        std::fs::create_dir_all(config_dir.join("logs")).unwrap();

        let engine = Engine::new();
        let session_id = uuid::Uuid::new_v4().to_string();
        let traffic_log_path = config_dir.join("logs").join(format!("{}-traffic.jsonl", session_id));

        let (tx, _rx) = broadcast::channel(8192);

        let state = Arc::new(AppState {
            tx,
            policy_engine: Arc::new(RwLock::new(engine)),
            traffic_log_path,
            log_dir: config_dir.join("logs"),
            session_id,
            enforcement_tier: EnforcementTier::Standard,
            active_sessions: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
            pending_decisions: Arc::new(DashMap::new()),
            intervention_timeout_secs: 30,
            intervention_timeout_allow: false,
            current_role: Arc::new(RwLock::new(default_role)),
        });

        let app = build_router(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap();

        TestHarness { addr, client, _dir: dir, config_dir, state }
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Write a single policy JSON object into the policies dir.
    pub fn add_policy(&self, id: &str, policy_json: serde_json::Value) {
        let path = self.config_dir.join("policies").join(format!("{}.json", id));
        std::fs::write(path, serde_json::to_string_pretty(&policy_json).unwrap()).unwrap();
    }

    /// Write a role JSON object into the roles dir.
    pub fn add_role(&self, name: &str, role_json: serde_json::Value) {
        let path = self.config_dir.join("roles").join(format!("{}.json", name));
        std::fs::write(path, serde_json::to_string_pretty(&role_json).unwrap()).unwrap();
    }

    /// Reload policies by posting to /api/policies/reload.
    /// Call this after add_policy/add_role to make them take effect.
    pub async fn reload_policies(&self) {
        self.client
            .post(format!("{}/api/policies/reload", self.base_url()))
            .send()
            .await
            .unwrap();
    }

    /// Directly add a policy to the engine (no HTTP needed).
    pub fn add_policy_direct(&self, policy: sevorix_watchtower::policy::Policy) {
        self.state.policy_engine.write().unwrap().add_policy(policy);
    }

    /// Directly add a role to the engine (no HTTP needed).
    pub fn add_role_direct(&self, role: sevorix_watchtower::policy::Role) {
        self.state.policy_engine.write().unwrap().add_role(role);
    }

    /// Create a TestHarness with specific timeout settings.
    pub async fn with_timeout(timeout_secs: u64, timeout_allow: bool) -> Self {
        let dir = TempDir::new().unwrap();
        let config_dir = dir.path().to_path_buf();
        std::fs::create_dir_all(config_dir.join("policies")).unwrap();
        std::fs::create_dir_all(config_dir.join("roles")).unwrap();
        std::fs::create_dir_all(config_dir.join("logs")).unwrap();

        let session_id = uuid::Uuid::new_v4().to_string();
        let traffic_log_path = config_dir.join("logs").join(format!("{}-traffic.jsonl", session_id));
        let (tx, _rx) = broadcast::channel(8192);

        let state = Arc::new(AppState {
            tx,
            policy_engine: Arc::new(RwLock::new(Engine::new())),
            traffic_log_path,
            log_dir: config_dir.join("logs"),
            session_id,
            enforcement_tier: EnforcementTier::Standard,
            active_sessions: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
            pending_decisions: Arc::new(DashMap::new()),
            intervention_timeout_secs: timeout_secs,
            intervention_timeout_allow: timeout_allow,
            current_role: Arc::new(RwLock::new(None)),
        });

        let app = build_router(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });

        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        TestHarness { addr, client, _dir: dir, config_dir, state }
    }
}
