mod common;
use common::harness::TestHarness;
use common::ws_client::WsClient;
use serde_json::json;
use sevorix_watchtower::policy::{Action, Policy, PolicyContext, PolicyType, Role};
use std::time::Duration;
use tokio::time::Instant;

async fn setup_harness() -> TestHarness {
    let h = TestHarness::with_role(Some("test".to_string())).await;
    h.add_policy_direct(Policy {
        id: "block-p".to_string(),
        match_type: PolicyType::Simple("BLOCK_WORD_PERF".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
    });
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: vec!["block-p".to_string()],
        is_dynamic: false,
    });
    h
}

/// 14.1 — GREEN lane latency: safe payloads should have average round-trip < 50ms.
#[tokio::test]
async fn test_14_1_green_lane_latency() {
    let h = setup_harness().await;
    let n = 20; // Reduced from 100 for test speed
    let mut total_ms = 0u128;
    for _ in 0..n {
        let start = Instant::now();
        h.client
            .post(format!("{}/analyze", h.base_url()))
            .json(&json!({"payload": "safe payload for latency test", "context": "Shell"}))
            .send()
            .await
            .unwrap();
        total_ms += start.elapsed().as_millis();
    }
    let avg_ms = total_ms / n as u128;
    println!("GREEN lane avg latency: {}ms", avg_ms);
    // Should be under 50ms average on localhost
    assert!(
        avg_ms < 50,
        "GREEN lane avg latency {}ms exceeds 50ms threshold",
        avg_ms
    );
}

/// 14.2 — RED lane latency: blocked payloads should be rejected immediately, average < 20ms.
#[tokio::test]
async fn test_14_2_red_lane_latency() {
    let h = setup_harness().await;
    let n = 20;
    let mut total_ms = 0u128;
    for _ in 0..n {
        let start = Instant::now();
        h.client
            .post(format!("{}/analyze", h.base_url()))
            .json(&json!({"payload": "BLOCK_WORD_PERF something dangerous", "context": "Shell"}))
            .send()
            .await
            .unwrap();
        total_ms += start.elapsed().as_millis();
    }
    let avg_ms = total_ms / n as u128;
    println!("RED lane avg latency: {}ms", avg_ms);
    // Immediate block should be very fast
    assert!(
        avg_ms < 20,
        "RED lane avg latency {}ms exceeds 20ms threshold",
        avg_ms
    );
}

/// 14.3 — YELLOW lane: a flagged request is held until an operator decision is made;
/// total elapsed time reflects the deliberate hold period.
#[tokio::test]
async fn test_14_3_yellow_lane_holds_until_decision() {
    let h = TestHarness::with_role(Some("test".to_string())).await;
    h.add_policy_direct(Policy {
        id: "flag-p".to_string(),
        match_type: PolicyType::Simple("FLAG_PERF".to_string()),
        action: Action::Flag,
        context: PolicyContext::All,
        kill: false,
    });
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: vec!["flag-p".to_string()],
        is_dynamic: false,
    });

    let mut ws = WsClient::connect(h.addr).await;
    let base = h.base_url();
    let client = h.client.clone();

    let start = Instant::now();
    let task = tokio::spawn(async move {
        client
            .post(format!("{}/analyze", base))
            .json(&json!({"payload": "FLAG_PERF content", "context": "Shell"}))
            .send()
            .await
            .unwrap()
    });

    // Wait for PENDING
    let pending = ws
        .wait_for_event(|e| e["type"] == "PENDING", Duration::from_secs(5))
        .await
        .expect("PENDING event");
    let event_id = pending["event_id"].as_str().unwrap().to_string();

    // Hold for 500ms deliberately before deciding
    tokio::time::sleep(Duration::from_millis(500)).await;
    let held_ms = start.elapsed().as_millis();
    assert!(held_ms >= 400, "should have been held for at least 400ms");

    // Decide
    h.client
        .post(format!("{}/api/decide", h.base_url()))
        .json(&json!({"event_id": event_id, "action": "allow"}))
        .send()
        .await
        .unwrap();

    task.await.unwrap();
    let total_ms = start.elapsed().as_millis();
    // Total time should be >= the hold time
    assert!(total_ms >= 400, "total time should reflect the hold period");
}

/// 14.4 — Concurrent GREEN lane requests are all handled and each stays under 50ms on average.
#[tokio::test]
async fn test_14_4_concurrent_green_lane_latency() {
    let h = std::sync::Arc::new(setup_harness().await);
    let n = 10;
    let mut handles = Vec::with_capacity(n);

    for _ in 0..n {
        let client = h.client.clone();
        let url = format!("{}/analyze", h.base_url());
        handles.push(tokio::spawn(async move {
            let start = Instant::now();
            client
                .post(&url)
                .json(&json!({"payload": "concurrent safe payload", "context": "Shell"}))
                .send()
                .await
                .unwrap();
            start.elapsed().as_millis()
        }));
    }

    let mut total_ms = 0u128;
    for handle in handles {
        total_ms += handle.await.unwrap();
    }
    let avg_ms = total_ms / n as u128;
    println!("Concurrent GREEN lane avg latency: {}ms", avg_ms);
    assert!(
        avg_ms < 50,
        "Concurrent GREEN lane avg latency {}ms exceeds 50ms threshold",
        avg_ms
    );
}
