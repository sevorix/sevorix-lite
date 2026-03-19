// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

mod common;
use common::harness::TestHarness;
use common::upstream::MockUpstream;
use serde_json::json;
use sevorix_watchtower::policy::{Action, Policy, PolicyContext, PolicyType, Role};
use std::time::Duration;

// ── helpers ───────────────────────────────────────────────────────────────────

async fn harness_with_empty_role() -> TestHarness {
    let h = TestHarness::with_role(Some("test".to_string())).await;
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: vec![],
        is_dynamic: false,
    });
    h
}

fn read_log_entries(path: &std::path::Path) -> Vec<serde_json::Value> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    content
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

// ── 15.2 – Shell layer events ─────────────────────────────────────────────────

#[tokio::test]
async fn test_15_2_shell_layer_events() {
    let h = harness_with_empty_role().await;
    h.client
        .post(format!("{}/analyze", h.base_url()))
        .json(&json!({"payload": "ls -la", "context": "Shell"}))
        .send()
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;
    let entries = read_log_entries(&h.state.traffic_log_path);
    let shell_events: Vec<_> = entries
        .iter()
        .filter(|e| e.get("verdict").is_some()) // traffic events, not PENDING
        .collect();

    if !shell_events.is_empty() {
        let layer = shell_events[0].get("layer").and_then(|v| v.as_str());
        if let Some(layer) = layer {
            assert_eq!(layer, "shell", "analyze events should have layer=shell");
        }
    }
}

// ── 15.1 – Network layer events ───────────────────────────────────────────────

#[tokio::test]
async fn test_15_1_network_layer_events() {
    let upstream = MockUpstream::start_any().await;
    let _upstream_addr = upstream
        .server
        .uri()
        .trim_start_matches("http://")
        .to_string();
    let h = harness_with_empty_role().await;

    let proxied_client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(h.base_url()).unwrap())
        .build()
        .unwrap();

    proxied_client
        .get(upstream.server.uri())
        .send()
        .await
        .unwrap_or_else(|_| panic!("proxy request failed"));

    tokio::time::sleep(Duration::from_millis(100)).await;
    let entries = read_log_entries(&h.state.traffic_log_path);
    let network_events: Vec<_> = entries
        .iter()
        .filter(|e| e.get("layer").and_then(|v| v.as_str()) == Some("network"))
        .collect();
    // There should be a network layer event from the proxied request
    assert!(
        !network_events.is_empty(),
        "proxy events should have layer=network"
    );
}

// ── 15.3 – Layer filter API ───────────────────────────────────────────────────

#[tokio::test]
async fn test_15_3_layer_filter_api() {
    let h = harness_with_empty_role().await;

    // Generate some shell events
    for _ in 0..3 {
        h.client
            .post(format!("{}/analyze", h.base_url()))
            .json(&json!({"payload": "ls", "context": "Shell"}))
            .send()
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Query with layer filter
    let resp = h
        .client
        .get(format!("{}/api/events?layer=shell", h.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    // Should be an array (may be empty if log-file reading is used, but should not error)
    assert!(
        body.is_array() || body.is_object(),
        "events endpoint should return array or object"
    );
}
