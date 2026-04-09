// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

//! End-to-end tests for HTTPS MITM interception.
//!
//! These tests verify that:
//! 1. HTTPS GET requests through the MITM proxy log the full payload (not just the CONNECT tunnel).
//! 2. HTTPS POST requests with blocked content (e.g. "DROP TABLE") are blocked with 403.

mod common;

use dashmap::DashMap;
use rcgen::{CertificateParams, IsCa, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sevorix_core::EnforcementTier;
use sevorix_watchtower::{
    build_router,
    policy::{Action, Engine, Policy, PolicyContext, PolicyType, Role},
    tls::{CaStore, TlsContext},
    AppState,
};
use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
};
use tempfile::TempDir;
use tokio::{net::TcpListener, sync::broadcast};
use tokio_rustls::TlsAcceptor;

// ---------------------------------------------------------------------------
// Upstream HTTPS server helper
// ---------------------------------------------------------------------------

/// Start a minimal self-signed HTTPS server on a random port.
///
/// Returns `(port, join_handle)`.  The server accepts connections in a loop,
/// performs a TLS handshake with a freshly generated self-signed cert for
/// `127.0.0.1`, reads the request line, and responds with a fixed 200 OK.
async fn start_upstream_https_server() -> (u16, tokio::task::JoinHandle<()>) {
    // Generate a self-signed cert for 127.0.0.1 (separate from Sevorix CA).
    let key_pair = KeyPair::generate().expect("upstream key pair");

    let mut params =
        CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("upstream cert params");
    params.subject_alt_names = vec![SanType::IpAddress("127.0.0.1".parse().expect("valid IP"))];
    params.is_ca = IsCa::NoCa;

    let cert = params
        .self_signed(&key_pair)
        .expect("self-signed upstream cert");

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der =
        PrivateKeyDer::try_from(key_pair.serialize_der()).expect("upstream private key DER");

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("upstream rustls ServerConfig");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream TcpListener bind");
    let port = listener.local_addr().expect("upstream local addr").port();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((tcp, _peer)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                let mut tls = match acceptor.accept(tcp).await {
                    Ok(s) => s,
                    Err(_) => return,
                };

                // Read until we have at least the request line (or EOF).
                let mut buf = vec![0u8; 4096];
                let _ = tls.read(&mut buf).await;

                // Respond with a minimal HTTP/1.1 200 OK.
                let response =
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nContent-Type: text/plain\r\n\r\nok-body";
                let _ = tls.write_all(response).await;
                let _ = tls.shutdown().await;
            });
        }
    });

    (port, handle)
}

// ---------------------------------------------------------------------------
// MitmTestHarness
// ---------------------------------------------------------------------------

/// A self-contained MITM test environment.
///
/// Spins up:
/// * A temp CA dir with `CaStore::load_or_create` + `TlsContext`
/// * The Sevorix proxy server with `tls_context: Some(...)` and the given role
/// * A `reqwest::Client` that trusts the Sevorix CA and routes through the proxy
pub struct MitmTestHarness {
    pub addr: SocketAddr,
    pub state: Arc<AppState>,
    pub client: reqwest::Client,
    /// The upstream HTTPS port (returned by `start_upstream_https_server`).
    pub upstream_port: u16,
    _upstream_handle: tokio::task::JoinHandle<()>,
    _dir: TempDir,
}

impl MitmTestHarness {
    pub async fn new() -> Self {
        Self::with_role("test").await
    }

    pub async fn with_role(role_name: &str) -> Self {
        let dir = TempDir::new().expect("temp dir");
        let config_dir = dir.path().to_path_buf();

        // Create required subdirectories.
        std::fs::create_dir_all(config_dir.join("policies")).unwrap();
        std::fs::create_dir_all(config_dir.join("roles")).unwrap();
        std::fs::create_dir_all(config_dir.join("logs")).unwrap();

        // Build the Sevorix CA and TLS context.
        let ca_dir = config_dir.join("ca");
        std::fs::create_dir_all(&ca_dir).unwrap();
        let ca = CaStore::load_or_create(&ca_dir).expect("CaStore::load_or_create");
        let ca_pem = ca.ca_cert_pem().to_string();
        let tls_ctx = Arc::new(TlsContext::new(ca));

        // Build AppState with an http_client that accepts self-signed upstream certs.
        let session_id = uuid::Uuid::new_v4().to_string();
        let traffic_log_path = config_dir
            .join("logs")
            .join(format!("{}-traffic.jsonl", session_id));

        let (tx, _rx) = broadcast::channel(8192);

        let engine = Engine::new();
        let state = Arc::new(AppState {
            tx,
            policy_engine: Arc::new(std::sync::RwLock::new(engine)),
            traffic_log_path,
            log_dir: config_dir.join("logs"),
            session_id,
            port: 3000,
            enforcement_tier: EnforcementTier::Standard,
            active_sessions: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
            pending_decisions: Arc::new(DashMap::new()),
            intervention_timeout_secs: 30,
            intervention_timeout_allow: false,
            current_role: Arc::new(std::sync::RwLock::new(Some(role_name.to_string()))),
            // Accept self-signed upstream certs so our minimal test HTTPS server works.
            http_client: reqwest::Client::builder()
                .no_proxy()
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            tls_context: Some(tls_ctx),
            hook_registry: std::sync::Arc::new(sevorix_watchtower::hooks::HookRegistry::new()),
        });

        // Register an empty role so traffic is not blocked by "role not found".
        state.policy_engine.write().unwrap().add_role(Role {
            name: role_name.to_string(),
            policies: vec![],
            is_dynamic: false,
        });

        // Start the Sevorix proxy.
        let app = build_router(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("proxy listener");
        let addr = listener.local_addr().expect("proxy local addr");

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Start the upstream HTTPS server.
        let (upstream_port, upstream_handle) = start_upstream_https_server().await;

        // Build a reqwest client that:
        // * uses the Sevorix proxy
        // * accepts the proxy's MITM cert (danger_accept_invalid_certs covers both
        //   OpenSSL and rustls backends; adding the CA PEM alone is unreliable when
        //   reqwest uses native-tls because the CA cert object re-created from PEM
        //   during `load_or_create` may differ from the one used to sign leaf certs)
        let proxy_url = format!("http://{}", addr);
        // Still add the CA cert for documentation/correctness; also set
        // danger_accept_invalid_certs as a belt-and-suspenders for the test env.
        let ca_cert =
            reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("reqwest CA cert from PEM");
        let client = reqwest::Client::builder()
            .add_root_certificate(ca_cert)
            .proxy(reqwest::Proxy::all(&proxy_url).expect("proxy url"))
            .danger_accept_invalid_certs(true)
            .build()
            .expect("reqwest client");

        MitmTestHarness {
            addr,
            state,
            client,
            upstream_port,
            _upstream_handle: upstream_handle,
            _dir: dir,
        }
    }

    /// Read all JSONL log entries from the traffic log file.
    pub fn read_log_entries(&self) -> Vec<serde_json::Value> {
        let path = &self.state.traffic_log_path;
        let Ok(contents) = std::fs::read_to_string(path) else {
            return vec![];
        };
        contents
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// --- Log entry helpers ---
// Non-pro format: { "verdict": "ALLOW", "lane": "GREEN", "payload": "GET ..." }
// Pro signed-receipt format: { "payload": { "decision": "ALLOW", "lane": "GREEN", "action_payload": "GET ..." }, "signature": ... }

fn log_entry_verdict<'a>(entry: &'a serde_json::Value) -> &'a str {
    entry
        .get("verdict")
        .and_then(|v| v.as_str())
        .or_else(|| {
            entry
                .get("payload")
                .and_then(|p| p.get("decision"))
                .and_then(|v| v.as_str())
        })
        .unwrap_or("")
}

fn log_entry_payload<'a>(entry: &'a serde_json::Value) -> &'a str {
    entry
        .get("payload")
        .and_then(|v| v.as_str())
        .or_else(|| {
            entry
                .get("payload")
                .and_then(|p| p.get("action_payload"))
                .and_then(|v| v.as_str())
        })
        .unwrap_or("")
}

fn log_entry_lane<'a>(entry: &'a serde_json::Value) -> &'a str {
    entry
        .get("lane")
        .and_then(|v| v.as_str())
        .or_else(|| {
            entry
                .get("payload")
                .and_then(|p| p.get("lane"))
                .and_then(|v| v.as_str())
        })
        .unwrap_or("")
}

/// Test 1: HTTPS GET through the MITM proxy logs the full request payload.
///
/// When MITM is enabled the proxy decrypts the tunnel and logs
/// `"GET https://127.0.0.1:PORT/test ..."` rather than just
/// `"CONNECT tunnel to 127.0.0.1:PORT"`.
#[tokio::test]
async fn test_mitm_https_get_logs_full_payload() {
    let h = MitmTestHarness::new().await;
    let upstream_url = format!("https://127.0.0.1:{}/test", h.upstream_port);

    // Give the upstream server a moment to be ready.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = h
        .client
        .get(&upstream_url)
        .send()
        .await
        .expect("HTTPS GET through MITM proxy");

    assert_eq!(
        resp.status(),
        200,
        "expected 200 from upstream through MITM proxy"
    );

    // Give the proxy time to flush the log entry.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let entries = h.read_log_entries();
    assert!(
        !entries.is_empty(),
        "traffic log should contain at least one entry"
    );

    // There must be at least one ALLOW entry whose payload contains
    // the full request line (not just the CONNECT tunnel message).
    // Handles both non-pro format (entry["verdict"], entry["payload"] as string)
    // and pro signed-receipt format (entry["payload"]["decision"], entry["payload"]["action_payload"]).
    let has_full_payload = entries.iter().any(|entry| {
        let verdict = log_entry_verdict(entry);
        let payload = log_entry_payload(entry);
        verdict == "ALLOW" && payload.contains("GET https://127.0.0.1")
    });

    assert!(
        has_full_payload,
        "expected a log entry with verdict=ALLOW and payload containing 'GET https://127.0.0.1'; \
         entries were: {:#?}",
        entries
    );
}

/// Test 2: HTTPS POST with "DROP TABLE" in the body is blocked with 403.
///
/// The MITM proxy decrypts the tunnel, scans the body, matches the
/// block policy, and returns 403 — never forwarding to upstream.
/// The log assertion checks only `verdict == "BLOCK"` (not `lane`) because
/// the pro signed-receipt format stores the decision in `payload.decision`
/// and does not include a `lane` field in the receipt payload.
#[tokio::test]
async fn test_mitm_https_post_drop_table_blocked() {
    let h = MitmTestHarness::new().await;

    // Add a block policy for "DROP TABLE" scoped to Network context.
    {
        let mut engine = h.state.policy_engine.write().unwrap();
        engine.add_policy(Policy {
            id: "block-drop".to_string(),
            match_type: PolicyType::Simple("DROP TABLE".to_string()),
            action: Action::Block,
            context: PolicyContext::Network,
            kill: false,
            syscall: vec![],
        });
        // Attach the policy to the role.
        engine.add_role(Role {
            name: "test".to_string(),
            policies: vec!["block-drop".to_string()],
            is_dynamic: false,
        });
    }

    let upstream_url = format!("https://127.0.0.1:{}/query", h.upstream_port);

    // Give the upstream server a moment to be ready.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = h
        .client
        .post(&upstream_url)
        .body(r#"{"query": "DROP TABLE users"}"#)
        .header("content-type", "application/json")
        .send()
        .await
        .expect("HTTPS POST through MITM proxy");

    assert_eq!(
        resp.status(),
        403,
        "expected 403 (blocked) for DROP TABLE payload through MITM"
    );

    // Give the proxy time to flush the log entry.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let entries = h.read_log_entries();
    assert!(
        !entries.is_empty(),
        "traffic log should contain at least one entry after a blocked request"
    );

    // There must be a BLOCK entry in the log.
    // Note: lane is not checked here because the pro signed-receipt format does not
    // include a `lane` field in the receipt payload (non-pro format does have `lane`).
    let has_block_entry = entries.iter().any(|entry| {
        let verdict = log_entry_verdict(entry);
        verdict == "BLOCK"
    });

    assert!(
        has_block_entry,
        "expected a log entry with verdict=BLOCK; entries were: {:#?}",
        entries
    );
}
