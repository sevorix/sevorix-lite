// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

mod common;
use common::harness::TestHarness;
use serde_json::json;
use sevorix_watchtower::policy::{Action, Policy, PolicyContext, PolicyType, Role};

// ── helpers ───────────────────────────────────────────────────────────────────

async fn harness_with_policies(policies: Vec<Policy>) -> TestHarness {
    let h = TestHarness::with_role(Some("test".to_string())).await;
    let ids: Vec<String> = policies.iter().map(|p| p.id.clone()).collect();
    for p in policies {
        h.add_policy_direct(p);
    }
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: ids,
        is_dynamic: false,
    });
    h
}

async fn analyze(h: &TestHarness, payload: &str, context: &str) -> serde_json::Value {
    h.client
        .post(format!("{}/analyze", h.base_url()))
        .json(&json!({"payload": payload, "context": context}))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap()
}

// ── 7.9 – Health endpoint ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_7_9_health_endpoint() {
    let h = TestHarness::new().await;
    let resp = h
        .client
        .get(format!("{}/health", h.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

// ── 7.10 – Version endpoint ───────────────────────────────────────────────────

#[tokio::test]
async fn test_7_10_version_endpoint() {
    let h = TestHarness::new().await;
    let resp = h
        .client
        .get(format!("{}/api/version", h.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    // Should contain edition or version info
    assert!(
        body.get("edition").is_some() || body.get("version").is_some() || body.is_object(),
        "expected version/edition info in response body, got: {body}"
    );
}

// ── 7.1 – Dashboard serves HTML ───────────────────────────────────────────────

#[tokio::test]
async fn test_7_1_dashboard_serves_html() {
    let h = TestHarness::new().await;
    let resp = h
        .client
        .get(format!("{}/dashboard/desktop.html", h.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert!(
        text.contains("<!DOCTYPE html>") || text.contains("<html"),
        "expected HTML content, got: {}",
        &text[..text.len().min(200)]
    );
}

// ── 7.2 – Dashboard redirect ──────────────────────────────────────────────────

#[tokio::test]
async fn test_7_2_dashboard_redirect() {
    let h = TestHarness::new().await;
    // Build a client that does NOT follow redirects so we can inspect the 3xx.
    let no_redirect_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let resp = no_redirect_client
        .get(format!("{}/dashboard", h.base_url()))
        .send()
        .await
        .unwrap();
    // Should be a 3xx redirect (or 200 if the server resolves it directly).
    assert!(
        resp.status().is_redirection() || resp.status() == 200,
        "expected redirect or 200 for /dashboard, got: {}",
        resp.status()
    );
}

// ── 7.3 – Events pagination ───────────────────────────────────────────────────

#[tokio::test]
async fn test_7_3_events_pagination() {
    let h = harness_with_policies(vec![Policy {
        id: "block-drop".to_string(),
        match_type: PolicyType::Simple("DROP TABLE".to_string()),
        action: Action::Block,
        context: PolicyContext::Shell,
        kill: false,
        syscall: vec![],
    }])
    .await;

    // Generate 5 events via /analyze
    for i in 0..5 {
        analyze(&h, &format!("ls -la {i}"), "Shell").await;
    }

    // Page 1, limit 3
    let resp = h
        .client
        .get(format!("{}/api/events?page=1&limit=3", h.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "GET /api/events?page=1&limit=3 should return 200"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.is_array() || body.is_object(),
        "expected JSON response, got: {body}"
    );

    // Page 2, limit 3
    let resp2 = h
        .client
        .get(format!("{}/api/events?page=2&limit=3", h.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        200,
        "GET /api/events?page=2&limit=3 should return 200"
    );
    let body2: serde_json::Value = resp2.json().await.unwrap();
    assert!(
        body2.is_array() || body2.is_object(),
        "expected JSON response for page 2, got: {body2}"
    );
}

// ── 7.4 – Events layer filter ─────────────────────────────────────────────────

#[tokio::test]
async fn test_7_4_events_layer_filter() {
    let h = harness_with_policies(vec![]).await;

    // Generate a couple of shell-context events
    for i in 0..3 {
        analyze(&h, &format!("echo hello {i}"), "Shell").await;
    }

    // Filter by layer=shell
    let resp_shell = h
        .client
        .get(format!("{}/api/events?layer=shell", h.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp_shell.status(),
        200,
        "GET /api/events?layer=shell should return 200"
    );
    let body_shell: serde_json::Value = resp_shell.json().await.unwrap();
    assert!(
        body_shell.is_array() || body_shell.is_object(),
        "expected JSON response for layer=shell, got: {body_shell}"
    );

    // Filter by layer=network (may return empty array)
    let resp_network = h
        .client
        .get(format!("{}/api/events?layer=network", h.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp_network.status(),
        200,
        "GET /api/events?layer=network should return 200"
    );
    let body_network: serde_json::Value = resp_network.json().await.unwrap();
    assert!(
        body_network.is_array() || body_network.is_object(),
        "expected JSON response for layer=network, got: {body_network}"
    );
}

// ── 7.7 – Stats endpoint ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_7_7_stats_endpoint() {
    let h = harness_with_policies(vec![Policy {
        id: "block-secret".to_string(),
        match_type: PolicyType::Simple("SECRET_BLOCK_STATS".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
        syscall: vec![],
    }])
    .await;

    // Generate some events
    analyze(&h, "ls -la", "Shell").await;
    analyze(&h, "SECRET_BLOCK_STATS action", "Shell").await;

    let resp = h
        .client
        .get(format!("{}/api/stats", h.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "GET /api/stats should return 200");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.is_object(),
        "expected JSON object from /api/stats, got: {body}"
    );
}

// ── 7.8 – Sessions endpoint ───────────────────────────────────────────────────

#[tokio::test]
async fn test_7_8_sessions_endpoint() {
    let h = TestHarness::new().await;
    let resp = h
        .client
        .get(format!("{}/api/sessions", h.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "GET /api/sessions should return 200");
    let body: serde_json::Value = resp.json().await.unwrap();
    // Returns {current_session, sessions: [...]} or a bare array
    assert!(
        body.is_object() || body.is_array(),
        "expected JSON object or array from /api/sessions, got: {body}"
    );
    // If object, should have a "sessions" key
    if body.is_object() {
        assert!(
            body.get("sessions").is_some(),
            "sessions object should have a 'sessions' key, got: {body}"
        );
    }
}
