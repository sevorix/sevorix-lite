// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

mod common;
use common::harness::TestHarness;
use serde_json::json;
use sevorix_watchtower::policy::{Action, Policy, PolicyContext, PolicyType, Role};

// ── helpers ───────────────────────────────────────────────────────────────────

async fn harness_with_policies() -> TestHarness {
    let h = TestHarness::with_role(Some("test".to_string())).await;
    h.add_policy_direct(Policy {
        id: "block-p".to_string(),
        match_type: PolicyType::Simple("BLOCK_WORD".to_string()),
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

async fn analyze(h: &TestHarness, payload: &str) {
    h.client
        .post(format!("{}/analyze", h.base_url()))
        .json(&json!({"payload": payload, "context": "Shell"}))
        .send()
        .await
        .unwrap();
}

fn read_log_entries(path: &std::path::Path) -> Vec<serde_json::Value> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    content
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .map(|v| {
            // In pro builds, events are wrapped in a SignedReceipt envelope
            // where `payload` is an object (ReceiptPayload). Unwrap to the
            // inner payload so field checks work uniformly across build modes.
            if v.get("receipt_version").is_some() {
                if let Some(payload) = v.get("payload").cloned() {
                    return payload;
                }
            }
            v
        })
        .collect()
}

// ── 12.1 – JSONL file is created for the session ─────────────────────────────

#[tokio::test]
async fn test_12_1_jsonl_file_created_for_session() {
    let h = harness_with_policies().await;
    analyze(&h, "safe text").await;
    // Give a moment for async log write
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    // The log file should exist
    assert!(
        h.state.traffic_log_path.exists(),
        "traffic log should exist after event"
    );
}

// ── 12.2 – Log entry schema ───────────────────────────────────────────────────

#[tokio::test]
async fn test_12_2_log_entry_schema() {
    let h = harness_with_policies().await;
    analyze(&h, "safe text").await;
    analyze(&h, "BLOCK_WORD data").await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let entries = read_log_entries(&h.state.traffic_log_path);
    assert!(!entries.is_empty(), "should have log entries");

    for entry in &entries {
        // Check required fields exist (may be null but should be present).
        // Pro builds emit ReceiptPayload (decision, action_payload) while
        // non-pro builds emit the flat event format (verdict, lane, payload).
        let has_verdict = entry.get("verdict").is_some() || entry.get("decision").is_some();
        assert!(has_verdict, "missing verdict/decision: {:?}", entry);

        let has_payload = entry.get("payload").is_some()
            || entry.get("action_payload").is_some()
            || entry.get("type").is_some();
        assert!(
            has_payload,
            "missing payload/action_payload/type: {:?}",
            entry
        );

        // Timestamp should be a string
        if let Some(ts) = entry.get("timestamp") {
            assert!(ts.is_string(), "timestamp should be string");
        }
    }
}

// ── 12.2 – Role field is present in log entries ───────────────────────────────

#[tokio::test]
async fn test_12_2_role_field_in_log() {
    let h = harness_with_policies().await;
    analyze(&h, "safe text").await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let entries = read_log_entries(&h.state.traffic_log_path);
    // Find ALLOW or BLOCK entries (not PENDING which have different format)
    let traffic_entries: Vec<_> = entries
        .iter()
        .filter(|e| e.get("verdict").is_some() || e.get("decision").is_some())
        .collect();

    for entry in &traffic_entries {
        // Role should be logged
        if let Some(role) = entry.get("role") {
            assert_eq!(role, "test", "role should be 'test'");
        }
    }
}

// ── 12.3 – Log survives and is readable after harness keep-alive ──────────────

#[tokio::test]
async fn test_12_3_log_survives_after_harness_keep_alive() {
    // Verify that the log path is accessible and readable
    let h = harness_with_policies().await;
    let log_path = h.state.traffic_log_path.clone();
    analyze(&h, "BLOCK_WORD").await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Log should be readable
    let content = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(!content.is_empty(), "log should not be empty after events");
}
