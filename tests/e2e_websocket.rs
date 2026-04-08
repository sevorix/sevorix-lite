// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

mod common;
use common::harness::TestHarness;
use common::ws_client::WsClient;
use serde_json::json;
use sevorix_watchtower::policy::{Action, Policy, PolicyContext, PolicyType, Role};
use std::time::Duration;

// ── helpers ───────────────────────────────────────────────────────────────────

async fn harness_with_block_policy() -> TestHarness {
    let h = TestHarness::with_role(Some("test".to_string())).await;
    h.add_policy_direct(Policy {
        id: "block-p".to_string(),
        match_type: PolicyType::Simple("BLOCK_WORD".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
        syscall: vec![],
    });
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: vec!["block-p".to_string()],
        is_dynamic: false,
    });
    h
}

async fn analyze(h: &TestHarness, payload: &str) -> serde_json::Value {
    h.client
        .post(format!("{}/analyze", h.base_url()))
        .json(&json!({"payload": payload, "context": "Shell"}))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap()
}

// ── 6.1 – WebSocket receives ALLOW event after safe analyze ───────────────────

#[tokio::test]
async fn test_6_1_event_received_on_analyze_allow() {
    let h = harness_with_block_policy().await;
    let mut ws = WsClient::connect(h.addr).await;

    let resp = analyze(&h, "safe text").await;
    assert_eq!(resp["status"], "ALLOW", "expected ALLOW but got: {resp}");

    let event = ws
        .wait_for_event(|e| e["verdict"] == "ALLOW", Duration::from_secs(5))
        .await;
    assert!(
        event.is_some(),
        "expected ALLOW event on WebSocket but timed out"
    );
}

// ── 6.2 – WebSocket receives BLOCK event after blocked analyze ────────────────

#[tokio::test]
async fn test_6_2_event_received_on_analyze_block() {
    let h = harness_with_block_policy().await;
    let mut ws = WsClient::connect(h.addr).await;

    let resp = analyze(&h, "BLOCK_WORD").await;
    assert_eq!(resp["status"], "BLOCK", "expected BLOCK but got: {resp}");

    let event = ws
        .wait_for_event(|e| e["verdict"] == "BLOCK", Duration::from_secs(5))
        .await;
    assert!(
        event.is_some(),
        "expected BLOCK event on WebSocket but timed out"
    );
}

// ── 6.3 – PENDING event is broadcast when a FLAG is held ─────────────────────

#[tokio::test]
async fn test_6_3_pending_event_broadcast_on_flag() {
    let h = TestHarness::with_role(Some("test".to_string())).await;
    h.add_policy_direct(Policy {
        id: "flag-p".to_string(),
        match_type: PolicyType::Simple("FLAG_WORD".to_string()),
        action: Action::Flag,
        context: PolicyContext::All,
        kill: false,
        syscall: vec![],
    });
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: vec!["flag-p".to_string()],
        is_dynamic: false,
    });

    let mut ws = WsClient::connect(h.addr).await;

    // Spawn the analyze call in background — it will block waiting for a decision
    let base_url = h.base_url();
    let client = h.client.clone();
    let analyze_handle = tokio::spawn(async move {
        client
            .post(format!("{}/analyze", base_url))
            .json(&json!({"payload": "FLAG_WORD", "context": "Shell"}))
            .send()
            .await
            .ok()
    });

    // Wait for the PENDING event
    let event = ws
        .wait_for_event(|e| e["type"] == "PENDING", Duration::from_secs(5))
        .await;
    assert!(
        event.is_some(),
        "expected PENDING event on WebSocket but timed out"
    );

    let event = event.unwrap();
    assert!(
        event["event_id"].is_string() && !event["event_id"].as_str().unwrap().is_empty(),
        "PENDING event must have a non-empty event_id; got: {event}"
    );
    assert!(
        event["payload"].is_string(),
        "PENDING event must have a payload field; got: {event}"
    );
    assert!(
        event["timeout_secs"].is_number(),
        "PENDING event must have a timeout_secs field; got: {event}"
    );

    // Clean up: send a decision so the analyze task can unblock
    let event_id = event["event_id"].as_str().unwrap().to_string();
    h.client
        .post(format!("{}/api/decide", h.base_url()))
        .json(&json!({"event_id": event_id, "action": "block"}))
        .send()
        .await
        .unwrap();

    let _ = analyze_handle.await;
}

// ── 6.4 – DECIDED event is broadcast after an operator decision ───────────────

#[tokio::test]
async fn test_6_4_decided_event_broadcast_after_decision() {
    let h = TestHarness::with_role(Some("test".to_string())).await;
    h.add_policy_direct(Policy {
        id: "flag-p2".to_string(),
        match_type: PolicyType::Simple("FLAG_WORD".to_string()),
        action: Action::Flag,
        context: PolicyContext::All,
        kill: false,
        syscall: vec![],
    });
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: vec!["flag-p2".to_string()],
        is_dynamic: false,
    });

    let mut ws = WsClient::connect(h.addr).await;

    // Spawn the analyze call in background
    let base_url = h.base_url();
    let client = h.client.clone();
    let analyze_handle = tokio::spawn(async move {
        client
            .post(format!("{}/analyze", base_url))
            .json(&json!({"payload": "FLAG_WORD", "context": "Shell"}))
            .send()
            .await
            .ok()
    });

    // Wait for PENDING to arrive
    let pending = ws
        .wait_for_event(|e| e["type"] == "PENDING", Duration::from_secs(5))
        .await
        .expect("expected PENDING event but timed out");

    let event_id = pending["event_id"].as_str().unwrap().to_string();

    // Send the allow decision
    h.client
        .post(format!("{}/api/decide", h.base_url()))
        .json(&json!({"event_id": event_id, "action": "allow"}))
        .send()
        .await
        .unwrap();

    // Wait for the DECIDED event
    let decided = ws
        .wait_for_event(|e| e["type"] == "DECIDED", Duration::from_secs(5))
        .await;
    assert!(
        decided.is_some(),
        "expected DECIDED event on WebSocket but timed out"
    );

    let decided = decided.unwrap();
    assert_eq!(
        decided["action"], "allow",
        "DECIDED event action should be 'allow'; got: {decided}"
    );

    let _ = analyze_handle.await;
}

// ── 6.6 – Multiple subscribers all receive the same event ─────────────────────

#[tokio::test]
async fn test_6_6_multiple_subscribers_all_receive() {
    let h = harness_with_block_policy().await;

    let mut ws1 = WsClient::connect(h.addr).await;
    let mut ws2 = WsClient::connect(h.addr).await;
    let mut ws3 = WsClient::connect(h.addr).await;

    let resp = analyze(&h, "BLOCK_WORD").await;
    assert_eq!(resp["status"], "BLOCK", "expected BLOCK but got: {resp}");

    let ev1 = ws1
        .wait_for_event(|e| e["verdict"] == "BLOCK", Duration::from_secs(5))
        .await;
    let ev2 = ws2
        .wait_for_event(|e| e["verdict"] == "BLOCK", Duration::from_secs(5))
        .await;
    let ev3 = ws3
        .wait_for_event(|e| e["verdict"] == "BLOCK", Duration::from_secs(5))
        .await;

    assert!(ev1.is_some(), "ws1 did not receive BLOCK event");
    assert!(ev2.is_some(), "ws2 did not receive BLOCK event");
    assert!(ev3.is_some(), "ws3 did not receive BLOCK event");
}

// ── 6.7 – Disconnected subscriber does not crash the server ───────────────────

#[tokio::test]
async fn test_6_7_subscriber_disconnect_no_crash() {
    let h = harness_with_block_policy().await;

    // Connect and immediately drop the client
    {
        let _ws = WsClient::connect(h.addr).await;
        // _ws is dropped here, closing the WebSocket connection
    }

    // Generate several events — the server should not crash
    for _ in 0..5 {
        analyze(&h, "safe text").await;
    }

    // Verify the server is still alive and healthy
    let resp = h
        .client
        .get(format!("{}/health", h.base_url()))
        .send()
        .await
        .expect("health check request failed");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "server should still be healthy after subscriber disconnect"
    );
}

// ── 6.8 – Late subscriber receives no backlog of historical events ─────────────

#[tokio::test]
async fn test_6_8_late_subscriber_no_backlog() {
    let h = harness_with_block_policy().await;

    // Generate 5 events before connecting the WebSocket client
    for i in 0..5 {
        if i % 2 == 0 {
            analyze(&h, "safe text").await;
        } else {
            analyze(&h, "BLOCK_WORD").await;
        }
    }

    // Brief pause to let all events be fully processed and broadcast
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect after all events have already been emitted
    let mut ws = WsClient::connect(h.addr).await;

    // Give any potential backlog a moment to arrive
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Drain — a late subscriber should receive no historical events
    let buffered = ws.drain();
    assert_eq!(
        buffered.len(),
        0,
        "late subscriber should receive no backlog; got {} events: {:?}",
        buffered.len(),
        buffered
    );
}
