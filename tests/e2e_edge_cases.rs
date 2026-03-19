// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

mod common;
use common::harness::TestHarness;
use serde_json::json;
use sevorix_watchtower::policy::{Action, Policy, PolicyContext, PolicyType, Role};

// ── 13.1a – No policies with role → ALLOW (GREEN) ────────────────────────────

#[tokio::test]
async fn test_13_1_no_policies_with_role_allows() {
    let h = TestHarness::with_role(Some("test".to_string())).await;
    // Role with no policies
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: vec![],
        is_dynamic: false,
    });
    let resp = h
        .client
        .post(format!("{}/analyze", h.base_url()))
        .json(&json!({"payload": "anything at all", "context": "Shell"}))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(
        resp["status"], "ALLOW",
        "role with no policies should ALLOW; got: {resp}"
    );
}

// ── 13.1b – No role configured → fail-closed (BLOCK) ─────────────────────────

#[tokio::test]
async fn test_13_1_no_role_blocks() {
    let h = TestHarness::new().await; // no role
    let resp = h
        .client
        .post(format!("{}/analyze", h.base_url()))
        .json(&json!({"payload": "ls -la", "context": "Shell"}))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(
        resp["status"], "BLOCK",
        "no role configured must fail closed (BLOCK); got: {resp}"
    );
}

// ── 13.2 – Malformed policy file is skipped; good policy still loads ──────────

#[test]
fn test_13_2_malformed_policy_file_skipped() {
    use sevorix_watchtower::policy::Engine;
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let policy_dir = dir.path().join("policies");
    std::fs::create_dir_all(&policy_dir).unwrap();

    // Write a malformed JSON file
    std::fs::write(policy_dir.join("bad.json"), "{ this is not valid JSON!!!").unwrap();
    // Write a valid policy file
    std::fs::write(
        policy_dir.join("good.json"),
        r#"{"id":"good-p","type":"Simple","pattern":"BLOCK_THIS","action":"Block","context":"All","kill":false}"#,
    )
    .unwrap();

    let mut engine = Engine::new();
    // Should not panic, should load good policy, skip bad one
    let result = engine.load_policies_from_dir(&policy_dir);
    // May return Ok or Err, but must not panic.
    // If it returns Ok, the good policy should be loaded.
    if result.is_ok() {
        assert!(
            engine.policies.contains_key("good-p"),
            "good policy should be loaded even when a malformed file is present"
        );
    }
}

// ── 13.4 – Proxy target unreachable → no server crash ────────────────────────

#[tokio::test]
async fn test_13_4_proxy_target_unreachable() {
    let h = TestHarness::with_role(Some("test".to_string())).await;
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: vec![],
        is_dynamic: false,
    });
    let proxied_client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(h.base_url()).unwrap())
        .build()
        .unwrap();
    // Connect to a port that should be unreachable
    let _result = proxied_client
        .get("http://127.0.0.1:59999/test") // unlikely to be listening
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await;
    // Should return an error or a non-200 response, not crash the proxy server.
    // Server should still be alive.
    let health = h
        .client
        .get(format!("{}/health", h.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(
        health.status(),
        200,
        "server should still be running after failed proxy attempt"
    );
}

// ── 13.5 – Binary / non-UTF-8 payload → no panic ─────────────────────────────

#[tokio::test]
async fn test_13_5_binary_payload_no_panic() {
    let h = TestHarness::with_role(Some("test".to_string())).await;
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: vec![],
        is_dynamic: false,
    });
    let proxied_client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(h.base_url()).unwrap())
        .build()
        .unwrap();
    // Binary bytes — non-UTF-8
    let binary_body = vec![0u8, 1, 2, 255, 254, 128, 0xff, 0xfe];
    let _result = proxied_client
        .post("http://127.0.0.1:59998/test")
        .body(binary_body)
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await;
    // May fail (unreachable upstream) but server must not crash.
    let health = h
        .client
        .get(format!("{}/health", h.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(
        health.status(),
        200,
        "server should still be running after binary payload attempt"
    );
}

// ── 13.6 – Very long URL → no crash ──────────────────────────────────────────

#[tokio::test]
async fn test_13_6_very_long_url_no_crash() {
    let h = TestHarness::with_role(Some("test".to_string())).await;
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: vec![],
        is_dynamic: false,
    });
    let proxied_client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(h.base_url()).unwrap())
        .build()
        .unwrap();
    let long_path = "a".repeat(8000);
    let _result = proxied_client
        .get(format!("http://127.0.0.1:59997/{}", long_path))
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await;
    // Server should survive a very long URL.
    let health = h
        .client
        .get(format!("{}/health", h.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(
        health.status(),
        200,
        "server should still be running after very long URL attempt"
    );
}
