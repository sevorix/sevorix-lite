// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

//! Integration tests for session kill, freeze, unfreeze, register, and unregister.
//!
//! Cgroup helper calls are best-effort in the handlers — they fail silently when
//! the helper isn't available (test environment). State management and WebSocket
//! broadcasts are always exercised.

mod common;
use common::harness::TestHarness;
use common::ws_client::WsClient;
use serde_json::json;
use std::time::Duration;

// A fake cgroup path that passes the session ID regex in the helper
// (agent-<uuid> format) but won't require the cgroup FS to exist.
const FAKE_CGROUP: &str = "/sys/fs/cgroup/sevorix/agent-00000000-0000-0000-0000-000000000001";
const FAKE_CGROUP_2: &str = "/sys/fs/cgroup/sevorix/agent-00000000-0000-0000-0000-000000000002";

// ── Register / Unregister ────────────────────────────────────────────────────

/// Register adds the cgroup path to active_sessions; GET /api/active-sessions reflects it.
#[tokio::test]
async fn test_session_register_adds_to_active_sessions() {
    let h = TestHarness::new().await;

    let res = h
        .client
        .post(format!("{}/api/session/register", h.base_url()))
        .json(&json!({ "cgroup_path": FAKE_CGROUP }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let body: serde_json::Value = h
        .client
        .get(format!("{}/api/active-sessions", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let sessions = body["sessions"].as_array().unwrap();
    assert!(
        sessions.iter().any(|s| s == FAKE_CGROUP),
        "registered cgroup should appear in active-sessions"
    );
}

/// Unregister removes the cgroup path; active-sessions returns empty.
#[tokio::test]
async fn test_session_unregister_removes_from_active_sessions() {
    let h = TestHarness::new().await;

    h.client
        .post(format!("{}/api/session/register", h.base_url()))
        .json(&json!({ "cgroup_path": FAKE_CGROUP }))
        .send()
        .await
        .unwrap();

    let res = h
        .client
        .post(format!("{}/api/session/unregister", h.base_url()))
        .json(&json!({ "cgroup_path": FAKE_CGROUP }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let body: serde_json::Value = h
        .client
        .get(format!("{}/api/active-sessions", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let sessions = body["sessions"].as_array().unwrap();
    assert!(
        sessions.is_empty(),
        "active-sessions should be empty after unregister"
    );
}

/// Register with no cgroup_path field is a no-op (200, sessions unchanged).
#[tokio::test]
async fn test_session_register_missing_field_is_noop() {
    let h = TestHarness::new().await;

    let res = h
        .client
        .post(format!("{}/api/session/register", h.base_url()))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let body: serde_json::Value = h
        .client
        .get(format!("{}/api/active-sessions", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(body["sessions"].as_array().unwrap().is_empty());
}

// ── Kill ─────────────────────────────────────────────────────────────────────

/// Kill clears active_sessions and returns killed count.
#[tokio::test]
async fn test_session_kill_clears_active_sessions() {
    let h = TestHarness::new().await;

    // Register two sessions
    for cgroup in [FAKE_CGROUP, FAKE_CGROUP_2] {
        h.client
            .post(format!("{}/api/session/register", h.base_url()))
            .json(&json!({ "cgroup_path": cgroup }))
            .send()
            .await
            .unwrap();
    }

    let res = h
        .client
        .post(format!("{}/api/session/kill", h.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["status"], "ok");

    let sessions_body: serde_json::Value = h
        .client
        .get(format!("{}/api/active-sessions", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        sessions_body["sessions"].as_array().unwrap().is_empty(),
        "active-sessions should be empty after kill"
    );
}

/// Kill broadcasts a SESSION_KILLED WebSocket event.
#[tokio::test]
async fn test_session_kill_broadcasts_ws_event() {
    let h = TestHarness::new().await;
    let mut ws = WsClient::connect(h.addr).await;

    h.client
        .post(format!("{}/api/session/register", h.base_url()))
        .json(&json!({ "cgroup_path": FAKE_CGROUP }))
        .send()
        .await
        .unwrap();

    h.client
        .post(format!("{}/api/session/kill", h.base_url()))
        .send()
        .await
        .unwrap();

    let event = ws
        .wait_for_event(|e| e["type"] == "SESSION_KILLED", Duration::from_secs(3))
        .await
        .expect("should receive SESSION_KILLED WebSocket event");

    assert_eq!(event["type"], "SESSION_KILLED");
    assert!(event["timestamp"].is_string());
}

/// Kill with no registered sessions returns ok with zero killed and broadcasts.
#[tokio::test]
async fn test_session_kill_empty_sessions_still_broadcasts() {
    let h = TestHarness::new().await;
    let mut ws = WsClient::connect(h.addr).await;

    let res = h
        .client
        .post(format!("{}/api/session/kill", h.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["killed"], 0);

    ws.wait_for_event(|e| e["type"] == "SESSION_KILLED", Duration::from_secs(3))
        .await
        .expect("SESSION_KILLED should broadcast even with no sessions");
}

/// Kill clears any pending intervention decisions.
#[tokio::test]
async fn test_session_kill_clears_pending_decisions() {
    let h = TestHarness::new().await;

    // Inject a fake pending decision directly via state
    let (decision_tx, _decision_rx) = tokio::sync::oneshot::channel::<bool>();
    let (pause_tx, _pause_rx) = tokio::sync::watch::channel(false);
    h.state.pending_decisions.insert(
        "fake-event-id".to_string(),
        sevorix_watchtower::PendingEntry {
            decision_tx,
            pause_tx,
        },
    );
    assert_eq!(h.state.pending_decisions.len(), 1);

    h.client
        .post(format!("{}/api/session/kill", h.base_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(
        h.state.pending_decisions.len(),
        0,
        "kill should clear pending decisions"
    );
}

// ── Freeze ───────────────────────────────────────────────────────────────────

/// Freeze returns ok and broadcasts SESSION_FROZEN.
#[tokio::test]
async fn test_session_freeze_broadcasts_ws_event() {
    let h = TestHarness::new().await;
    let mut ws = WsClient::connect(h.addr).await;

    h.client
        .post(format!("{}/api/session/register", h.base_url()))
        .json(&json!({ "cgroup_path": FAKE_CGROUP }))
        .send()
        .await
        .unwrap();

    let res = h
        .client
        .post(format!("{}/api/session/freeze", h.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["frozen"], 1);

    let event = ws
        .wait_for_event(|e| e["type"] == "SESSION_FROZEN", Duration::from_secs(3))
        .await
        .expect("should receive SESSION_FROZEN WebSocket event");
    assert_eq!(event["type"], "SESSION_FROZEN");
    assert!(event["timestamp"].is_string());
}

/// Freeze does not alter the active_sessions set.
#[tokio::test]
async fn test_session_freeze_does_not_modify_active_sessions() {
    let h = TestHarness::new().await;

    h.client
        .post(format!("{}/api/session/register", h.base_url()))
        .json(&json!({ "cgroup_path": FAKE_CGROUP }))
        .send()
        .await
        .unwrap();

    h.client
        .post(format!("{}/api/session/freeze", h.base_url()))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = h
        .client
        .get(format!("{}/api/active-sessions", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sessions = body["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 1, "freeze must not remove sessions");
    assert_eq!(sessions[0], FAKE_CGROUP);
}

/// Freeze with no sessions still returns ok and broadcasts.
#[tokio::test]
async fn test_session_freeze_empty_sessions_still_broadcasts() {
    let h = TestHarness::new().await;
    let mut ws = WsClient::connect(h.addr).await;

    let res = h
        .client
        .post(format!("{}/api/session/freeze", h.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.json::<serde_json::Value>().await.unwrap()["frozen"], 0);

    ws.wait_for_event(|e| e["type"] == "SESSION_FROZEN", Duration::from_secs(3))
        .await
        .expect("SESSION_FROZEN should broadcast even with no sessions");
}

// ── Unfreeze ─────────────────────────────────────────────────────────────────

/// Unfreeze returns ok and broadcasts SESSION_UNFROZEN.
#[tokio::test]
async fn test_session_unfreeze_broadcasts_ws_event() {
    let h = TestHarness::new().await;
    let mut ws = WsClient::connect(h.addr).await;

    h.client
        .post(format!("{}/api/session/register", h.base_url()))
        .json(&json!({ "cgroup_path": FAKE_CGROUP }))
        .send()
        .await
        .unwrap();

    // Freeze first (best-effort, no real cgroup needed)
    h.client
        .post(format!("{}/api/session/freeze", h.base_url()))
        .send()
        .await
        .unwrap();
    let _ = ws
        .wait_for_event(|e| e["type"] == "SESSION_FROZEN", Duration::from_secs(3))
        .await;

    let res = h
        .client
        .post(format!("{}/api/session/unfreeze", h.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(
        res.json::<serde_json::Value>().await.unwrap()["status"],
        "ok"
    );

    let event = ws
        .wait_for_event(|e| e["type"] == "SESSION_UNFROZEN", Duration::from_secs(3))
        .await
        .expect("should receive SESSION_UNFROZEN WebSocket event");
    assert_eq!(event["type"], "SESSION_UNFROZEN");
    assert!(event["timestamp"].is_string());
}

/// Unfreeze does not alter the active_sessions set.
#[tokio::test]
async fn test_session_unfreeze_does_not_modify_active_sessions() {
    let h = TestHarness::new().await;

    h.client
        .post(format!("{}/api/session/register", h.base_url()))
        .json(&json!({ "cgroup_path": FAKE_CGROUP }))
        .send()
        .await
        .unwrap();

    h.client
        .post(format!("{}/api/session/unfreeze", h.base_url()))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = h
        .client
        .get(format!("{}/api/active-sessions", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sessions = body["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 1, "unfreeze must not remove sessions");
}

// ── Lifecycle sequence ────────────────────────────────────────────────────────

/// Full lifecycle: register → freeze → unfreeze → kill → sessions empty.
#[tokio::test]
async fn test_session_full_lifecycle() {
    let h = TestHarness::new().await;
    let mut ws = WsClient::connect(h.addr).await;
    let base = h.base_url();

    // Register
    h.client
        .post(format!("{}/api/session/register", base))
        .json(&json!({ "cgroup_path": FAKE_CGROUP }))
        .send()
        .await
        .unwrap();

    // Freeze
    h.client
        .post(format!("{}/api/session/freeze", base))
        .send()
        .await
        .unwrap();
    ws.wait_for_event(|e| e["type"] == "SESSION_FROZEN", Duration::from_secs(3))
        .await
        .expect("SESSION_FROZEN after freeze");

    // Unfreeze
    h.client
        .post(format!("{}/api/session/unfreeze", base))
        .send()
        .await
        .unwrap();
    ws.wait_for_event(|e| e["type"] == "SESSION_UNFROZEN", Duration::from_secs(3))
        .await
        .expect("SESSION_UNFROZEN after unfreeze");

    // Kill
    h.client
        .post(format!("{}/api/session/kill", base))
        .send()
        .await
        .unwrap();
    ws.wait_for_event(|e| e["type"] == "SESSION_KILLED", Duration::from_secs(3))
        .await
        .expect("SESSION_KILLED after kill");

    // Verify empty
    let body: serde_json::Value = h
        .client
        .get(format!("{}/api/active-sessions", base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        body["sessions"].as_array().unwrap().is_empty(),
        "sessions should be empty after kill"
    );
}
