// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

#[allow(deprecated)]
use crate::log_traffic_event;
use crate::policy::PolicyContext;
use crate::scanner::{log_threat, scan_content, scan_for_poison, PoisonPill};
use crate::{await_decision_with_pause, AppState, PendingEntry};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, Method, StatusCode},
    response::{IntoResponse, Response},
};
use http_body::{Body as HttpBody, Frame, SizeHint};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, watch};

struct NoHintBody;

impl HttpBody for NoHintBody {
    type Data = axum::body::Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        true
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

pub async fn proxy_handler(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let start_time = std::time::Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();

    // Features: Logging: Log destination domain and method.
    // Extract host from URI
    tracing::info!("[PROXY] {} {}", method, uri);

    if method == Method::CONNECT {
        // Features: CONNECT (Tunneling)
        if let Some(host) = uri.host() {
            let port = uri.port_u16().unwrap_or(443);
            let addr = format!("{}:{}", host, port);
            let addr_for_tunnel = addr.clone();

            // Extract the upgrade future synchronously to ensure hyper sees the intention to upgrade
            // BEFORE we return the response.
            let on_upgrade = hyper::upgrade::on(req);

            // Spawn a task to handle the upgraded connection
            tokio::task::spawn(async move {
                match on_upgrade.await {
                    Ok(upgraded) => {
                        // tracing::debug!("[PROXY] Upgrade successful for {}", addr);
                        if let Err(e) = tunnel(upgraded, addr_for_tunnel).await {
                            tracing::error!("[PROXY] Tunnel error: {}", e);
                        }
                    }
                    Err(e) => tracing::error!("[PROXY] Upgrade error: {}", e),
                }
            });

            // Broadcast CONNECT event
            let event = json!({
                "verdict": "ALLOW",
                "lane": "GREEN",
                "layer": "network",
                "payload": format!("CONNECT tunnel to {}", addr),
                "timestamp": chrono::Local::now().to_rfc3339(),
                "latency": start_time.elapsed().as_millis() as u64,
                "reason": "HTTPS Tunnel Established",
                "confidence": "N/A"
            });
            let event_str = event.to_string();
            #[allow(deprecated)]
            log_traffic_event(&state.traffic_log_path, &event_str);
            let _ = state.tx.send(event_str);

            // Return 200 OK for CONNECT. Explicitly remove Content-Length header to avoid conflicts.
            // Using a custom body with no size hint ensures hyper doesn't add Content-Length: 0.
            let mut res = Response::new(Body::new(NoHintBody));
            res.headers_mut().remove(header::CONTENT_LENGTH);
            return res;
        } else {
            return (
                StatusCode::BAD_REQUEST,
                "CONNECT must be to a socket address",
            )
                .into_response();
        }
    }

    // Capture the body for scanning
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Failed to read body: {}", e),
            )
                .into_response()
        }
    };

    // Convert to string for analysis (lossy)
    let body_str = String::from_utf8_lossy(&bytes).to_string();
    if !body_str.is_empty() {
        // Truncate payload for display
        let display_payload = if body_str.len() > 100 {
            format!("{}...", &body_str[..100])
        } else {
            body_str.clone()
        };
        tracing::debug!("[PROXY] Payload: {}", display_payload);
    }

    // --- SECURITY SCANNING ---

    // 1. Poison Pill
    let pill = PoisonPill::default_canary();
    // Try to parse as JSON for poison pill, or check raw string if not JSON
    // scan_for_poison expects a Value. Let's create a wrapper if it's not JSON?
    // Actually scan_for_poison is designed for JSON payload.
    // If body is JSON, parse it.
    let json_body: Option<Value> = serde_json::from_str(&body_str).ok();

    if let Some(val) = &json_body {
        if scan_for_poison(val, &pill) {
            return (
                StatusCode::FORBIDDEN,
                "SEVORIX CRITICAL: Honey-Pot Triggered. Agent Compromised.".to_string(),
            )
                .into_response();
        }
    } else {
        // If not JSON, we might want to scan raw text for the value?
        // scan_for_poison implementation:
        // checks keys/values.
        // If raw text contains the secret value, we should probably block too.
        if body_str.contains(pill.value) {
            return (
                StatusCode::FORBIDDEN,
                "SEVORIX CRITICAL: Honey-Pot Triggered. Agent Compromised.".to_string(),
            )
                .into_response();
        }
    }

    // 2. Decision Engine
    let agent_id = "Proxy-Agent";
    let resolved_role: Option<String> = state.current_role.read().unwrap().clone();
    let Some(ref role) = resolved_role else {
        return (
            StatusCode::FORBIDDEN,
            "SEVORIX: No role configured for this session. Use `sevorix session set-role`."
                .to_string(),
        )
            .into_response();
    };

    // Include the request line (method + URL) in the scanned content so URL-based policies match.
    let scan_payload = if body_str.is_empty() {
        format!("{} {}", method, uri)
    } else {
        format!("{} {}\n\n{}", method, uri, body_str)
    };

    let mut scan = scan_content(
        &scan_payload,
        Some(role.as_str()),
        &state.policy_engine.read().unwrap(),
        PolicyContext::Network,
    );

    // 3. Jury Consultation

    // 4. Act on Verdict
    if scan.verdict == "BLOCK" {
        let msg = scan
            .log_msg
            .unwrap_or_else(|| "Blocked by policy".to_string());
        let score = scan.log_score.unwrap_or_else(|| "Unknown".to_string());

        log_threat(agent_id, &body_str, &msg, &score);

        let elapsed = start_time.elapsed().as_millis() as u64;

        // Include URL and body in payload for all requests
        let display_payload = if body_str.is_empty() {
            format!("{} {}", method, uri)
        } else {
            format!(
                "{} {}\n\n{}",
                method,
                uri,
                body_str.chars().take(2000).collect::<String>()
            )
        };

        // Broadcast event
        let event = json!({
            "verdict": scan.verdict,
            "lane": scan.lane,
            "layer": "network",
            "payload": display_payload,
            "timestamp": chrono::Local::now().to_rfc3339(),
            "latency": elapsed,
            "reason": msg,
            "confidence": score,
            "context": "Network"
        });
        let event_str = event.to_string();
        #[allow(deprecated)]
        log_traffic_event(&state.traffic_log_path, &event_str);
        let _ = state.tx.send(event_str);

        return (StatusCode::FORBIDDEN, format!("Request Blocked: {}", msg)).into_response();
    }

    // --- USER INTERVENTION for FLAG (network channel) ---
    if scan.verdict == "FLAG" {
        let display_payload_flag = if body_str.is_empty() {
            format!("{} {}", method, uri)
        } else {
            format!(
                "{} {}\n\n{}",
                method,
                uri,
                body_str.chars().take(2000).collect::<String>()
            )
        };

        let event_id = uuid::Uuid::new_v4().to_string();
        let (decision_tx, decision_rx) = oneshot::channel::<bool>();
        let (pause_tx, pause_rx) = watch::channel(false);
        state.pending_decisions.insert(
            event_id.clone(),
            PendingEntry {
                decision_tx,
                pause_tx,
            },
        );

        let pending_event = json!({
            "type": "PENDING",
            "event_id": event_id,
            "verdict": "FLAG",
            "lane": "YELLOW",
            "layer": "network",
            "payload": display_payload_flag,
            "timestamp": chrono::Local::now().to_rfc3339(),
            "reason": scan.log_msg,
            "context": "Network",
            "timeout_secs": state.intervention_timeout_secs,
            "timeout_action": if state.intervention_timeout_allow { "allow" } else { "block" },
        });
        #[allow(deprecated)]
        log_traffic_event(&state.traffic_log_path, &pending_event.to_string());
        let _ = state.tx.send(pending_event.to_string());

        let allowed = await_decision_with_pause(
            decision_rx,
            pause_rx,
            state.intervention_timeout_secs,
            state.intervention_timeout_allow,
        )
        .await;

        // Still in map → timeout fired (not resolved by decide_handler)
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
                "layer": "network",
                "payload": display_payload_flag,
                "timestamp": chrono::Local::now().to_rfc3339(),
                "latency": elapsed,
                "reason": "Blocked by operator",
                "confidence": "Manual Override",
                "context": "Network",
            });
            let block_str = block_event.to_string();
            #[allow(deprecated)]
            log_traffic_event(&state.traffic_log_path, &block_str);
            let _ = state.tx.send(block_str);
            return (StatusCode::FORBIDDEN, "Request blocked by operator.").into_response();
        }

        // Operator allowed — update verdict for the broadcast below
        scan.verdict = "ALLOW".to_string();
        scan.lane = "GREEN".to_string();
        scan.log_msg = Some("Allowed by operator intervention".to_string());
    }

    // Broadcast allow event if needed (maybe too noisy? Main app does it)
    // Let's broadcast "ALLOW" events too so dashboard sees traffic.
    let elapsed = start_time.elapsed().as_millis() as u64;

    // Include URL and body in payload for all requests
    let display_payload = if body_str.is_empty() {
        format!("{} {}", method, uri)
    } else {
        format!(
            "{} {}\n\n{}",
            method,
            uri,
            body_str.chars().take(2000).collect::<String>()
        )
    };

    let event = json!({
        "verdict": scan.verdict,
        "lane": scan.lane,
        "layer": "network",
        "payload": display_payload,
        "timestamp": chrono::Local::now().to_rfc3339(),
        "latency": elapsed,
        "reason": scan.log_msg,
        "confidence": scan.log_score,
        "context": "Network"
    });
    let event_str = event.to_string();
    #[allow(deprecated)]
    log_traffic_event(&state.traffic_log_path, &event_str);
    let _ = state.tx.send(event_str);

    // Features: Forwarding (HTTP)
    // Create new client request and stream response.

    // Use the shared client (no_proxy prevents re-entering the proxy via env vars).
    let client = state.http_client.clone();

    // Note: Request URI in proxy mode is absolute.
    let url = uri.to_string();

    let mut req_builder = client.request(method, &url);

    // Forward headers
    for (key, value) in parts.headers.iter() {
        // Skip host header as reqwest sets it? Or keep it?
        // Reqwest sets Host based on URL.
        // Copying all headers is generally safe, but some are restricted.
        req_builder = req_builder.header(key, value);
    }

    // Set body
    req_builder = req_builder.body(bytes);

    match req_builder.send().await {
        Ok(res) => {
            let status = res.status();
            let headers = res.headers().clone();
            let body = Body::from_stream(res.bytes_stream());

            let mut response = Response::new(body);
            *response.status_mut() = status;
            for (key, value) in headers.iter() {
                response.headers_mut().insert(key, value.clone());
            }

            response
        }
        Err(e) => {
            tracing::error!("[PROXY] Forwarding error: {}", e);
            (StatusCode::BAD_GATEWAY, format!("Forwarding failed: {}", e)).into_response()
        }
    }
}

async fn tunnel(upgraded: Upgraded, addr: String) -> std::io::Result<()> {
    // Wrap hyper's Upgraded in TokioIo to implement tokio::io traits
    let mut upgraded = TokioIo::new(upgraded);

    // Connect to the target
    let mut server = TcpStream::connect(addr).await?;

    // Bidirectional copy
    let (from_client, from_server) =
        tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;

    tracing::debug!(
        "[PROXY] Tunnel closed. Bytes: {} up, {} down",
        from_client,
        from_server
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Action, Engine, Policy, PolicyContext, PolicyType, Role};
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{Request, StatusCode};
    use dashmap::DashMap;
    use std::sync::RwLock;

    fn create_test_state() -> Arc<AppState> {
        let (tx, _) = tokio::sync::broadcast::channel(1);
        let mut engine = Engine::new();
        engine.roles.insert(
            "default".to_string(),
            Role {
                name: "default".to_string(),
                policies: vec![],
                is_dynamic: false,
            },
        );
        Arc::new(AppState {
            tx,
            policy_engine: Arc::new(RwLock::new(engine)),
            traffic_log_path: std::path::PathBuf::from("/tmp/test_traffic_events.jsonl"),
            log_dir: std::path::PathBuf::from("/tmp"),
            session_id: "00000000-0000-0000-0000-000000000000".to_string(),
            port: 3000,
            enforcement_tier: sevorix_core::EnforcementTier::Standard,
            active_sessions: std::sync::Arc::new(tokio::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
            pending_decisions: Arc::new(DashMap::new()),
            intervention_timeout_secs: 30,
            intervention_timeout_allow: false,
            current_role: std::sync::Arc::new(std::sync::RwLock::new(Some("default".to_string()))),
            http_client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
        })
    }

    fn create_blocking_state() -> Arc<AppState> {
        let (tx, _) = tokio::sync::broadcast::channel(1);
        let mut engine = Engine::new();
        // Add a blocking policy
        engine.policies.insert(
            "block_test".to_string(),
            Policy {
                id: "block_test".to_string(),
                match_type: PolicyType::Simple("BLOCK ME".to_string()),
                action: Action::Block,
                context: PolicyContext::All, // Added context
                kill: false,
            },
        );
        engine.roles.insert(
            "default".to_string(),
            Role {
                name: "default".to_string(),
                policies: vec!["block_test".to_string()],
                is_dynamic: false,
            },
        );

        Arc::new(AppState {
            tx,
            policy_engine: Arc::new(RwLock::new(engine)),
            traffic_log_path: std::path::PathBuf::from("/tmp/test_traffic_events.jsonl"),
            log_dir: std::path::PathBuf::from("/tmp"),
            session_id: "00000000-0000-0000-0000-000000000000".to_string(),
            enforcement_tier: sevorix_core::EnforcementTier::Standard,
            active_sessions: std::sync::Arc::new(tokio::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
            pending_decisions: Arc::new(DashMap::new()),
            intervention_timeout_secs: 30,
            intervention_timeout_allow: false,
            port: 3000,
            current_role: std::sync::Arc::new(std::sync::RwLock::new(Some("default".to_string()))),
            http_client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
        })
    }

    #[tokio::test]
    async fn test_proxy_connect_invalid_host() {
        let state = create_test_state();
        let req = Request::builder()
            .method("CONNECT")
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = proxy_handler(State(state), req).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_proxy_connect_valid_structure() {
        let state = create_test_state();
        let req = Request::builder()
            .method("CONNECT")
            .uri("example.com:443")
            .body(Body::empty())
            .unwrap();

        let response = proxy_handler(State(state), req).await;
        // Should return 200 OK (empty body)
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_proxy_poison_pill_block() {
        let state = create_test_state();
        let pill = PoisonPill::default_canary();
        // JSON Body with poison pill
        let body_content = json!({
            "AWS_SECRET": pill.value,
            "other": "data"
        })
        .to_string();

        let req = Request::builder()
            .method("POST")
            .uri("http://example.com/api")
            .body(Body::from(body_content))
            .unwrap();

        let response = proxy_handler(State(state), req).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_proxy_policy_block() {
        let state = create_blocking_state();
        let body_content = "This request contains BLOCK ME data.";

        let req = Request::builder()
            .method("POST")
            .uri("http://example.com/api")
            .body(Body::from(body_content))
            .unwrap();

        let response = proxy_handler(State(state), req).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_proxy_poison_pill_in_raw_text() {
        let state = create_test_state();
        let pill = PoisonPill::default_canary();
        // Raw text containing the poison pill value
        let body_content = format!("Some text with {} embedded in it", pill.value);

        let req = Request::builder()
            .method("POST")
            .uri("http://example.com/api")
            .body(Body::from(body_content))
            .unwrap();

        let response = proxy_handler(State(state), req).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_proxy_allows_safe_request() {
        let state = create_test_state();
        let body_content = "This is a safe request";

        let req = Request::builder()
            .method("POST")
            .uri("http://example.com/api")
            .body(Body::from(body_content))
            .unwrap();

        let response = proxy_handler(State(state), req).await;
        // Will fail to connect to example.com, but that's OK - we just verify
        // it doesn't get blocked by policy
        assert_ne!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_proxy_empty_body() {
        let state = create_test_state();

        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/api")
            .body(Body::empty())
            .unwrap();

        let response = proxy_handler(State(state), req).await;
        // Should not crash on empty body
        assert_ne!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_no_hint_body_is_end_stream() {
        let body = NoHintBody;
        assert!(body.is_end_stream());
    }

    #[test]
    fn test_no_hint_body_size_hint() {
        let body = NoHintBody;
        let hint = body.size_hint();
        assert_eq!(hint.lower(), 0);
        assert_eq!(hint.upper(), None);
    }
}
