mod common;
use common::harness::TestHarness;
use common::ws_client::WsClient;
use serde_json::json;
use sevorix_watchtower::policy::{Action, Policy, PolicyContext, PolicyType, Role};
use std::time::Duration;
use tokio::time::timeout;

async fn harness_with_flag_policy() -> TestHarness {
    let h = TestHarness::with_role(Some("test".to_string())).await;
    h.add_policy_direct(Policy {
        id: "flag-p".to_string(),
        match_type: PolicyType::Simple("FLAGGED_CONTENT".to_string()),
        action: Action::Flag,
        context: PolicyContext::All,
        kill: false,
    });
    h.add_policy_direct(Policy {
        id: "block-p".to_string(),
        match_type: PolicyType::Simple("BLOCK_THIS".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
    });
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: vec!["flag-p".to_string(), "block-p".to_string()],
        is_dynamic: false,
    });
    h
}

/// 3.1 — A flagged request is held; operator allows it; analyze resolves with FLAG status.
#[tokio::test]
async fn test_3_1_flagged_request_held_operator_allows() {
    let h = harness_with_flag_policy().await;
    let mut ws = WsClient::connect(h.addr).await;
    let base = h.base_url();
    let client = h.client.clone();

    // Start analyze in background — it will block waiting for intervention
    let analyze_task = tokio::spawn(async move {
        client
            .post(format!("{}/analyze", base))
            .json(&json!({"payload": "FLAGGED_CONTENT", "context": "Shell"}))
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap()
    });

    // Wait for PENDING event
    let pending = ws
        .wait_for_event(|e| e["type"] == "PENDING", Duration::from_secs(5))
        .await
        .expect("should receive PENDING event");
    let event_id = pending["event_id"].as_str().unwrap().to_string();

    // Operator decides: allow
    h.client
        .post(format!("{}/api/decide", h.base_url()))
        .json(&json!({"event_id": event_id, "action": "allow"}))
        .send()
        .await
        .unwrap();

    // Wait for DECIDED event
    let decided = ws
        .wait_for_event(|e| e["type"] == "DECIDED", Duration::from_secs(5))
        .await
        .expect("should receive DECIDED event");
    assert_eq!(decided["action"], "allow");

    // Analyze call should now resolve with ALLOW (operator allowed it)
    let result = timeout(Duration::from_secs(5), analyze_task)
        .await
        .expect("analyze should complete")
        .unwrap();
    assert_eq!(result["status"], "ALLOW");
}

/// 3.2 — A flagged request is held; operator blocks it; analyze resolves with BLOCK status.
#[tokio::test]
async fn test_3_2_flagged_request_held_operator_blocks() {
    let h = harness_with_flag_policy().await;
    let mut ws = WsClient::connect(h.addr).await;
    let base = h.base_url();
    let client = h.client.clone();

    // Start analyze in background — it will block waiting for intervention
    let analyze_task = tokio::spawn(async move {
        client
            .post(format!("{}/analyze", base))
            .json(&json!({"payload": "FLAGGED_CONTENT", "context": "Shell"}))
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap()
    });

    // Wait for PENDING event
    let pending = ws
        .wait_for_event(|e| e["type"] == "PENDING", Duration::from_secs(5))
        .await
        .expect("should receive PENDING event");
    let event_id = pending["event_id"].as_str().unwrap().to_string();

    // Operator decides: block
    h.client
        .post(format!("{}/api/decide", h.base_url()))
        .json(&json!({"event_id": event_id, "action": "block"}))
        .send()
        .await
        .unwrap();

    // Wait for DECIDED event
    let decided = ws
        .wait_for_event(|e| e["type"] == "DECIDED", Duration::from_secs(5))
        .await
        .expect("should receive DECIDED event");
    assert_eq!(decided["action"], "block");

    // Analyze call should now resolve with BLOCK
    let result = timeout(Duration::from_secs(5), analyze_task)
        .await
        .expect("analyze should complete")
        .unwrap();
    assert_eq!(result["status"], "BLOCK");
}

/// 3.4 — When intervention timeout expires with block-on-timeout configured,
/// the analyze endpoint returns BLOCK.
#[tokio::test]
async fn test_3_4_timeout_expires_with_block_action() {
    let h = TestHarness::with_timeout(2, false).await;
    h.add_policy_direct(Policy {
        id: "flag-p".to_string(),
        match_type: PolicyType::Simple("FLAGGED_CONTENT".to_string()),
        action: Action::Flag,
        context: PolicyContext::All,
        kill: false,
    });
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: vec!["flag-p".to_string()],
        is_dynamic: false,
    });
    // Override current_role to "test"
    {
        let mut role = h.state.current_role.write().unwrap();
        *role = Some("test".to_string());
    }

    let base = h.base_url();
    let client = h.client.clone();

    // Start analyze in background — it will block until timeout
    let analyze_task = tokio::spawn(async move {
        client
            .post(format!("{}/analyze", base))
            .json(&json!({"payload": "FLAGGED_CONTENT", "context": "Shell"}))
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap()
    });

    // Wait for the timeout to fire (2 seconds + buffer)
    tokio::time::sleep(Duration::from_secs(3)).await;

    // The task should have resolved with BLOCK (timed out → blocked)
    let result = timeout(Duration::from_secs(5), analyze_task)
        .await
        .expect("analyze should complete after timeout")
        .unwrap();
    assert_eq!(result["status"], "BLOCK");
}

/// 3.5 — When intervention timeout expires with allow-on-timeout configured,
/// the analyze endpoint returns FLAG.
#[tokio::test]
async fn test_3_5_timeout_expires_with_allow_action() {
    let h = TestHarness::with_timeout(2, true).await;
    h.add_policy_direct(Policy {
        id: "flag-p".to_string(),
        match_type: PolicyType::Simple("FLAGGED_CONTENT".to_string()),
        action: Action::Flag,
        context: PolicyContext::All,
        kill: false,
    });
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: vec!["flag-p".to_string()],
        is_dynamic: false,
    });
    // Override current_role to "test"
    {
        let mut role = h.state.current_role.write().unwrap();
        *role = Some("test".to_string());
    }

    let base = h.base_url();
    let client = h.client.clone();

    // Start analyze in background — it will block until timeout
    let analyze_task = tokio::spawn(async move {
        client
            .post(format!("{}/analyze", base))
            .json(&json!({"payload": "FLAGGED_CONTENT", "context": "Shell"}))
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap()
    });

    // Wait for the timeout to fire (2 seconds + buffer)
    tokio::time::sleep(Duration::from_secs(3)).await;

    // The task should have resolved with ALLOW (timed out → allowed; server sets verdict=ALLOW)
    let result = timeout(Duration::from_secs(5), analyze_task)
        .await
        .expect("analyze should complete after timeout")
        .unwrap();
    assert_eq!(result["status"], "ALLOW");
}

/// 3.8 — Sending a decide request for an unknown event_id returns 404.
#[tokio::test]
async fn test_3_8_invalid_event_id_returns_error() {
    let h = TestHarness::new().await;

    let resp = h
        .client
        .post(format!("{}/api/decide", h.base_url()))
        .json(&json!({"event_id": "nonexistent-uuid", "action": "allow"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

/// 3.9 — A BLOCK policy match is not held for intervention; the response is immediate.
#[tokio::test]
async fn test_3_9_red_lane_not_held() {
    let h = TestHarness::with_role(Some("test".to_string())).await;
    h.add_policy_direct(Policy {
        id: "block-p".to_string(),
        match_type: PolicyType::Simple("BLOCK_THIS".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
    });
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: vec!["block-p".to_string()],
        is_dynamic: false,
    });

    // This should return immediately — no intervention hold for BLOCK
    let result = timeout(
        Duration::from_secs(3),
        h.client
            .post(format!("{}/analyze", h.base_url()))
            .json(&json!({"payload": "BLOCK_THIS", "context": "Shell"}))
            .send(),
    )
    .await
    .expect("request should complete immediately, not hang")
    .unwrap()
    .json::<serde_json::Value>()
    .await
    .unwrap();

    assert_eq!(result["status"], "BLOCK");
}
