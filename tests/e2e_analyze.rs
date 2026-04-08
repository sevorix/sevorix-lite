// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

mod common;
use common::harness::TestHarness;
use serde_json::json;
use sevorix_watchtower::policy::{Action, Policy, PolicyContext, PolicyType, Role};

// ── helpers ──────────────────────────────────────────────────────────────────

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

// ── 2.1 – BLOCK verdict for a dangerous command ───────────────────────────────

#[tokio::test]
async fn test_2_1_block_verdict_for_dangerous_command() {
    let h = harness_with_policies(vec![Policy {
        id: "block-drop".to_string(),
        match_type: PolicyType::Simple("DROP TABLE".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
        syscall: vec![],
    }])
    .await;

    let resp = analyze(&h, "DROP TABLE users", "Shell").await;
    assert_eq!(resp["status"], "BLOCK", "expected BLOCK but got: {resp}");
    assert_eq!(resp["lane"], "RED", "expected RED but got: {resp}");
}

// ── 2.2 – ALLOW verdict for a safe command ────────────────────────────────────

#[tokio::test]
async fn test_2_2_allow_verdict_for_safe_command() {
    let h = harness_with_policies(vec![Policy {
        id: "block-drop".to_string(),
        match_type: PolicyType::Simple("DROP TABLE".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
        syscall: vec![],
    }])
    .await;

    let resp = analyze(&h, "ls -la", "Shell").await;
    assert_eq!(resp["status"], "ALLOW", "expected ALLOW but got: {resp}");
    assert_eq!(resp["lane"], "GREEN", "expected GREEN but got: {resp}");
}

// ── 2.4 – Shell policy does NOT trigger on Network context ────────────────────

#[tokio::test]
async fn test_2_4_shell_policy_does_not_trigger_on_network_context() {
    let h = harness_with_policies(vec![Policy {
        id: "block-secret-shell".to_string(),
        match_type: PolicyType::Simple("SECRET_KEYWORD".to_string()),
        action: Action::Block,
        context: PolicyContext::Shell,
        kill: false,
        syscall: vec![],
    }])
    .await;

    let resp = analyze(&h, "SECRET_KEYWORD", "Network").await;
    assert_eq!(
        resp["status"], "ALLOW",
        "Shell policy should not apply to Network context; got: {resp}"
    );
}

// ── 2.5 – Network policy triggers on Network context ─────────────────────────

#[tokio::test]
async fn test_2_5_network_policy_triggers_on_network_context() {
    let h = harness_with_policies(vec![Policy {
        id: "block-secret-network".to_string(),
        match_type: PolicyType::Simple("SECRET_KEYWORD".to_string()),
        action: Action::Block,
        context: PolicyContext::Network,
        kill: false,
        syscall: vec![],
    }])
    .await;

    let resp = analyze(&h, "SECRET_KEYWORD", "Network").await;
    assert_eq!(resp["status"], "BLOCK", "expected BLOCK but got: {resp}");
}

// ── 2.6 – All-context policy applies everywhere ───────────────────────────────

#[tokio::test]
async fn test_2_6_all_context_policy_applies_everywhere() {
    let h = harness_with_policies(vec![Policy {
        id: "block-universal".to_string(),
        match_type: PolicyType::Simple("UNIVERSAL_BLOCK".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
        syscall: vec![],
    }])
    .await;

    let resp_shell = analyze(&h, "UNIVERSAL_BLOCK", "Shell").await;
    assert_eq!(
        resp_shell["status"], "BLOCK",
        "expected BLOCK for Shell context; got: {resp_shell}"
    );

    let resp_network = analyze(&h, "UNIVERSAL_BLOCK", "Network").await;
    assert_eq!(
        resp_network["status"], "BLOCK",
        "expected BLOCK for Network context; got: {resp_network}"
    );
}

// ── 2.7 – Role-scoped evaluation ─────────────────────────────────────────────

#[tokio::test]
async fn test_2_7_role_scoped_evaluation() {
    // ── admin harness: has the block policy ──────────────────────────────────
    let h_admin = TestHarness::with_role(Some("admin".to_string())).await;

    let block_policy = Policy {
        id: "block-drop-admin".to_string(),
        match_type: PolicyType::Simple("DROP TABLE".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
        syscall: vec![],
    };
    h_admin.add_policy_direct(block_policy);
    h_admin.add_role_direct(Role {
        name: "admin".to_string(),
        policies: vec!["block-drop-admin".to_string()],
        is_dynamic: false,
    });
    // readonly role exists but has no policies
    h_admin.add_role_direct(Role {
        name: "readonly".to_string(),
        policies: vec![],
        is_dynamic: false,
    });

    let resp_admin = analyze(&h_admin, "DROP TABLE", "Shell").await;
    assert_eq!(
        resp_admin["status"], "BLOCK",
        "admin role should block DROP TABLE; got: {resp_admin}"
    );

    // ── readonly harness: no policies attached ────────────────────────────────
    let h_readonly = TestHarness::with_role(Some("readonly".to_string())).await;

    // Register the same block policy in the engine so the policy *exists*,
    // but the readonly role does not reference it.
    h_readonly.add_policy_direct(Policy {
        id: "block-drop-admin".to_string(),
        match_type: PolicyType::Simple("DROP TABLE".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
        syscall: vec![],
    });
    h_readonly.add_role_direct(Role {
        name: "readonly".to_string(),
        policies: vec![],
        is_dynamic: false,
    });

    let resp_readonly = analyze(&h_readonly, "DROP TABLE", "Shell").await;
    assert_eq!(
        resp_readonly["status"], "ALLOW",
        "readonly role has no policies, should ALLOW; got: {resp_readonly}"
    );
}

// ── 2.8 – Missing payload field ───────────────────────────────────────────────

#[tokio::test]
async fn test_2_8_missing_payload_field() {
    let h = harness_with_policies(vec![]).await;

    let resp = h
        .client
        .post(format!("{}/analyze", h.base_url()))
        .json(&json!({"context": "Shell"}))
        .send()
        .await
        .unwrap();

    let status = resp.status().as_u16();
    assert_ne!(
        status, 500,
        "missing payload should not cause a 500 error; got {status}"
    );
}

// ── 2.9 – agent_id field is accepted ─────────────────────────────────────────

#[tokio::test]
async fn test_2_9_agent_id_tracking() {
    let h = harness_with_policies(vec![]).await;

    let resp = h
        .client
        .post(format!("{}/analyze", h.base_url()))
        .json(&json!({"payload": "ls -la", "context": "Shell", "agent": "test-bot-123"}))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status().as_u16(),
        200,
        "agent field should be accepted without error"
    );
}

// ── 2.no_role – fail-closed when no role is configured ───────────────────────

#[tokio::test]
async fn test_2_no_role_fails_closed() {
    // TestHarness::new() passes None as the default role → fail-closed
    let h = TestHarness::new().await;

    let resp = analyze(&h, "ls -la", "Shell").await;
    assert_eq!(
        resp["status"], "BLOCK",
        "no role configured must fail closed (BLOCK); got: {resp}"
    );
}
