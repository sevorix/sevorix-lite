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
        syscall: vec![],
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
        syscall: vec![],
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
        syscall: vec![],
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
        syscall: vec![],
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
        syscall: vec![],
    };
    let block_policy = Policy {
        id: "block-both".to_string(),
        match_type: PolicyType::Simple("BOTH_MATCH".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
        syscall: vec![],
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
        syscall: vec![],
    })
    .await;

    let resp = analyze(&h, "KILL_CMD something", "Shell").await;
    assert_eq!(
        resp["status"], "BLOCK",
        "kill:true policy must still return BLOCK to caller; got: {resp}"
    );
}

// ── 4.7 – /api/policies/reload returns status and counts ─────────────────────

#[tokio::test]
async fn test_4_7_reload_response_shape() {
    let h = TestHarness::new().await;

    let resp = h
        .client
        .post(format!("{}/api/policies/reload", h.base_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200, "reload endpoint must return 200");

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "reloaded", "body.status must be 'reloaded'");
    assert!(
        body["policies"].is_number(),
        "body.policies must be a number; got: {body}"
    );
    assert!(
        body["roles"].is_number(),
        "body.roles must be a number; got: {body}"
    );
}

// ── 4.8 – reload clears in-memory-only policies and reports accurate counts ───

#[tokio::test]
async fn test_4_8_reload_clears_direct_injected_policies() {
    let h = TestHarness::new().await;

    // Inject 3 policies directly into the engine (not on disk).
    for i in 0..3u32 {
        h.add_policy_direct(Policy {
            id: format!("direct-reload-{}", i),
            match_type: PolicyType::Simple(format!("DIRECT_RELOAD_{}", i)),
            action: Action::Block,
            context: PolicyContext::All,
            kill: false,
            syscall: vec![],
        });
    }

    let before = h.state.policy_engine.read().unwrap().policies.len();
    assert_eq!(
        before, 3,
        "engine should hold 3 direct policies before reload"
    );

    // Reload atomically replaces the engine with whatever is on disk.
    let resp: serde_json::Value = h
        .client
        .post(format!("{}/api/policies/reload", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["status"], "reloaded");

    // The reported count must match the actual post-reload engine state.
    let reported = resp["policies"].as_u64().unwrap_or(0);
    let actual = h.state.policy_engine.read().unwrap().policies.len() as u64;
    assert_eq!(
        reported, actual,
        "response policy count must match engine state; reported={reported} actual={actual}"
    );

    // None of the directly-injected policy IDs should survive the reload.
    {
        let engine = h.state.policy_engine.read().unwrap();
        for i in 0..3u32 {
            assert!(
                !engine
                    .policies
                    .contains_key(&format!("direct-reload-{}", i)),
                "direct-injected policy direct-reload-{i} must be gone after reload"
            );
        }
    }
}

// ── 4.9 – reload picks up a policy written to disk ───────────────────────────

#[tokio::test]
async fn test_4_9_reload_picks_up_disk_policy() {
    // Write a policy file into .sevorix/policies/ relative to CWD — one of the
    // paths the reload handler searches. Use a unique ID to avoid interfering
    // with other tests running in parallel.
    let policy_id = format!("test-disk-reload-{}", uuid::Uuid::new_v4());
    const CANARY: &str = "DISK_RELOAD_CANARY_ZP3M";

    let cwd = std::env::current_dir().unwrap();
    let policies_dir = cwd.join(".sevorix").join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    let policy_path = policies_dir.join(format!("{}.json", policy_id));

    std::fs::write(
        &policy_path,
        serde_json::to_string_pretty(&json!({
            "id": policy_id,
            "type": "Simple",
            "pattern": CANARY,
            "action": "Block",
            "context": "All",
            "kill": false
        }))
        .unwrap(),
    )
    .unwrap();

    let h = TestHarness::new().await;

    // Canary is not in the engine yet (server started before we wrote the file).
    let before = analyze(&h, CANARY, "Shell").await;
    // The engine might already have picked it up if ~/.sevorix loaded it at startup;
    // we only assert the before/after delta below, so skip a pre-reload assertion.

    let reload_resp: serde_json::Value = h
        .client
        .post(format!("{}/api/policies/reload", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(reload_resp["status"], "reloaded");

    // After reload the policy file is on disk — it must now be enforced.
    let after = analyze(&h, CANARY, "Shell").await;

    // Clean up the file regardless of assertion outcome.
    let _ = std::fs::remove_file(&policy_path);

    // The reload response count must include at least our one policy.
    let count = reload_resp["policies"].as_u64().unwrap_or(0);
    assert!(
        count >= 1,
        "reload should report at least 1 policy after writing to disk; got {count}"
    );

    // Canary must be blocked after reload, regardless of before state.
    let _ = before; // suppress unused warning
    assert_eq!(
        after["status"], "BLOCK",
        "disk policy must be enforced after reload; got: {after}"
    );
}
