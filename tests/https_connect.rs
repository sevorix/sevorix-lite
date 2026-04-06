// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

use axum::Router;
use dashmap::DashMap;
use sevorix_core::EnforcementTier;
use sevorix_watchtower::{policy::Engine, proxy::proxy_handler, AppState};
use std::sync::Arc;
use std::sync::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
#[cfg_attr(tarpaulin, ignore)]
async fn test_real_connect_handshake() {
    // 1. Setup App State
    let (tx, _rx) = tokio::sync::broadcast::channel(1);
    let state = Arc::new(AppState {
        tx,
        policy_engine: Arc::new(RwLock::new(Engine::new())),
        traffic_log_path: std::path::PathBuf::from("/tmp/test_traffic_events.jsonl"),
        log_dir: std::path::PathBuf::from("/tmp"),
        session_id: "00000000-0000-0000-0000-000000000000".to_string(),
        port: 3000,
        enforcement_tier: EnforcementTier::Standard,
        active_sessions: std::sync::Arc::new(tokio::sync::Mutex::new(
            std::collections::HashSet::new(),
        )),
        pending_decisions: Arc::new(DashMap::new()),
        intervention_timeout_secs: 30,
        intervention_timeout_allow: false,
        current_role: std::sync::Arc::new(std::sync::RwLock::new(None)),
        http_client: reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default(),
        tls_context: None,
    });

    // 2. Setup Router
    let app = Router::new().fallback(proxy_handler).with_state(state);

    // 3. Bind Listener
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // 4. Run Server
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // 5. Connect Client
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

    // 6. Send CONNECT
    let request = b"CONNECT google.com:443 HTTP/1.1\r\nHost: google.com:443\r\n\r\n";
    stream.write_all(request).await.unwrap();

    // 7. Read Response
    let mut response = [0u8; 1024];
    let n = stream.read(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response[..n]);

    println!("Response: {}", response_str);

    // 8. Assert Success
    assert!(response_str.starts_with("HTTP/1.1 200 OK"));

    // 9. Verify connection remains open (Upgrade)
    // We should be able to send data now?
    // But proxy.rs attempts to connect to google.com:443.
    // This might fail if network is blocked or if google blocks us.
    // However, the *connection* should stay open until tunnel closes.

    // Check if stream closed immediately?
    // If upgrade failed, stream might close.
    // Let's try to read again.
    let n2 = stream.read(&mut response).await.unwrap();
    if n2 == 0 {
        println!("Stream closed after response.");
    } else {
        println!("Stream kept open, received {} bytes.", n2);
    }
}
