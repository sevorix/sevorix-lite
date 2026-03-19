// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

mod common;
use common::harness::TestHarness;
use serde_json::json;
use sevorix_watchtower::policy::{Action, Policy, PolicyContext, PolicyType, Role};
use std::time::Duration;

// ── helpers ───────────────────────────────────────────────────────────────────

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

async fn harness_with_policy(policy: Policy) -> TestHarness {
    let h = TestHarness::with_role(Some("test".to_string())).await;
    let pid = policy.id.clone();
    h.add_policy_direct(policy);
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: vec![pid],
        is_dynamic: false,
    });
    h
}

// ── 4.1 – Simple match is case-sensitive ─────────────────────────────────────

#[tokio::test]
async fn test_4_1_simple_match_case_sensitive() {
    let h = harness_with_policy(Policy {
        id: "block-drop".to_string(),
        match_type: PolicyType::Simple("DROP TABLE".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
    })
    .await;

    let resp_upper = analyze(&h, "DROP TABLE users", "Shell").await;
    assert_eq!(
        resp_upper["status"], "BLOCK",
        "exact-case match must BLOCK; got: {resp_upper}"
    );

    let resp_lower = analyze(&h, "drop table users", "Shell").await;
    assert_eq!(
        resp_lower["status"], "ALLOW",
        "lowercase must not match (case-sensitive); got: {resp_lower}"
    );
}

// ── 4.2 – Regex match ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_4_2_regex_match() {
    let h = harness_with_policy(Policy {
        id: "block-ssn".to_string(),
        match_type: PolicyType::Regex(r"\b\d{3}-\d{2}-\d{4}\b".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
    })
    .await;

    let resp_match = analyze(&h, "123-45-6789", "Shell").await;
    assert_eq!(
        resp_match["status"], "BLOCK",
        "SSN pattern should match and BLOCK; got: {resp_match}"
    );

    let resp_no_match = analyze(&h, "12345-6789", "Shell").await;
    assert_eq!(
        resp_no_match["status"], "ALLOW",
        "malformed SSN should not match, expected ALLOW; got: {resp_no_match}"
    );
}

// ── 4.3 – Executable match ───────────────────────────────────────────────────

#[tokio::test]
async fn test_4_3_executable_match() {
    // Use `grep -q EXECUTE_BLOCK` as the executable policy command.
    // The Executable policy pipes content to stdin; grep exits 0 if found (→ BLOCK),
    // exits 1 if not found (→ ALLOW). No temp script needed.
    let h = harness_with_policy(Policy {
        id: "exec-p".to_string(),
        match_type: PolicyType::Executable("grep -q EXECUTE_BLOCK".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
    })
    .await;

    let resp_block = analyze(&h, "EXECUTE_BLOCK something", "Shell").await;
    assert_eq!(
        resp_block["status"], "BLOCK",
        "executable exits 0 — should BLOCK; got: {resp_block}"
    );

    let resp_allow = analyze(&h, "safe content", "Shell").await;
    assert_eq!(
        resp_allow["status"], "ALLOW",
        "executable exits 1 — should ALLOW; got: {resp_allow}"
    );
}

// ── 4.4 – Invalid regex is skipped gracefully ────────────────────────────────

#[tokio::test]
async fn test_4_4_invalid_regex_graceful() {
    let h = harness_with_policy(Policy {
        id: "bad-regex".to_string(),
        match_type: PolicyType::Regex("[invalid regex(".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
    })
    .await;

    // An invalid regex policy must be silently skipped — no panic, payload ALLOWed.
    let resp = analyze(&h, "anything here", "Shell").await;
    assert_eq!(
        resp["status"], "ALLOW",
        "invalid regex policy should be skipped; got: {resp}"
    );

    // Confirm server is still alive by sending a normal request.
    let health = h
        .client
        .get(format!("{}/health", h.base_url()))
        .send()
        .await;
    assert!(
        health.is_ok(),
        "server must still respond after invalid-regex policy"
    );
}

// ── 4.5 – BLOCK takes precedence over FLAG ───────────────────────────────────

#[tokio::test]
async fn test_4_5_block_takes_precedence_over_flag() {
    let h = TestHarness::with_role(Some("test".to_string())).await;

    let flag_policy = Policy {
        id: "flag-both".to_string(),
        match_type: PolicyType::Simple("BOTH_MATCH".to_string()),
        action: Action::Flag,
        context: PolicyContext::All,
        kill: false,
    };
    let block_policy = Policy {
        id: "block-both".to_string(),
        match_type: PolicyType::Simple("BOTH_MATCH".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
    };

    h.add_policy_direct(flag_policy);
    h.add_policy_direct(block_policy);
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: vec!["flag-both".to_string(), "block-both".to_string()],
        is_dynamic: false,
    });

    let resp = analyze(&h, "BOTH_MATCH", "Shell").await;
    assert_eq!(
        resp["status"], "BLOCK",
        "BLOCK must take precedence over FLAG when both match; got: {resp}"
    );
    assert_eq!(
        resp["lane"], "RED",
        "lane must be RED when BLOCK wins; got: {resp}"
    );
}

// ── 4.6 – kill flag does not change external verdict ─────────────────────────

#[tokio::test]
async fn test_4_6_kill_flag_in_policy() {
    let h = harness_with_policy(Policy {
        id: "kill-policy".to_string(),
        match_type: PolicyType::Simple("KILL_CMD".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: true,
    })
    .await;

    let resp = analyze(&h, "KILL_CMD something", "Shell").await;
    assert_eq!(
        resp["status"], "BLOCK",
        "kill:true policy must still return BLOCK to caller; got: {resp}"
    );
}
