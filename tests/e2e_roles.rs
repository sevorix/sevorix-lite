mod common;
use common::harness::TestHarness;
use sevorix_watchtower::policy::{Action, Policy, PolicyContext, PolicyType, Role};
use serde_json::json;

// ── helpers ──────────────────────────────────────────────────────────────────

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

// ── 5.1 – Role with subset of policies ───────────────────────────────────────

#[tokio::test]
async fn test_5_1_role_with_subset_of_policies() {
    let h = TestHarness::with_role(Some("limited".to_string())).await;

    // Three policies, but the role only references two of them.
    h.add_policy_direct(Policy {
        id: "block-a".to_string(),
        match_type: PolicyType::Simple("AAA".to_string()),
        action: Action::Block,
        context: PolicyContext::Shell,
        kill: false,
    });
    h.add_policy_direct(Policy {
        id: "block-b".to_string(),
        match_type: PolicyType::Simple("BBB".to_string()),
        action: Action::Block,
        context: PolicyContext::Shell,
        kill: false,
    });
    h.add_policy_direct(Policy {
        id: "block-c".to_string(),
        match_type: PolicyType::Simple("CCC".to_string()),
        action: Action::Block,
        context: PolicyContext::Shell,
        kill: false,
    });

    // "limited" role only includes block-a and block-b, NOT block-c.
    h.add_role_direct(Role {
        name: "limited".to_string(),
        policies: vec!["block-a".to_string(), "block-b".to_string()],
        is_dynamic: false,
    });

    let resp_a = analyze(&h, "AAA").await;
    assert_eq!(resp_a["status"], "BLOCK", "block-a is in role, expected BLOCK; got: {resp_a}");

    let resp_b = analyze(&h, "BBB").await;
    assert_eq!(resp_b["status"], "BLOCK", "block-b is in role, expected BLOCK; got: {resp_b}");

    let resp_c = analyze(&h, "CCC").await;
    assert_eq!(
        resp_c["status"], "ALLOW",
        "block-c is NOT in role, expected ALLOW; got: {resp_c}"
    );
}

// ── 5.2 – Unknown role → BLOCK (fail-closed) ─────────────────────────────────
//
// When current_role is set to a name that is not in engine.roles,
// scan_content returns BLOCK with "Role not found" reason (fail-closed).
// See scanner.rs: `if !engine.roles.contains_key(role) { return BLOCK; }`

#[tokio::test]
async fn test_5_2_unknown_role_fails_closed() {
    // current_role names a role that we never add to the engine.
    let h = TestHarness::with_role(Some("nonexistent".to_string())).await;

    // Add a policy to the engine, but no role named "nonexistent".
    h.add_policy_direct(Policy {
        id: "block-anything".to_string(),
        match_type: PolicyType::Simple("hello".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
    });

    // scan_content fails closed: role not in engine → BLOCK (not ALLOW).
    let resp = analyze(&h, "hello").await;
    assert_eq!(
        resp["status"], "BLOCK",
        "unknown role must fail-closed (BLOCK); got: {resp}"
    );
}

// ── 5.3 – No role configured → fail-closed (BLOCK) ───────────────────────────

#[tokio::test]
async fn test_5_3_no_role_configured_fails_closed() {
    // TestHarness::new() sets current_role = None → fail-closed path.
    let h = TestHarness::new().await;

    let resp = analyze(&h, "ls -la").await;
    assert_eq!(
        resp["status"], "BLOCK",
        "no role configured must fail closed (BLOCK); got: {resp}"
    );
}

// ── 5.6 – session set-role updates the active role at runtime ─────────────────

#[tokio::test]
async fn test_5_6_session_set_role_updates_role() {
    let h = TestHarness::with_role(Some("admin".to_string())).await;

    // admin role has a block policy for "SECRET".
    h.add_policy_direct(Policy {
        id: "block-secret".to_string(),
        match_type: PolicyType::Simple("SECRET".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
    });
    h.add_role_direct(Role {
        name: "admin".to_string(),
        policies: vec!["block-secret".to_string()],
        is_dynamic: false,
    });

    // readonly role has no policies.
    h.add_role_direct(Role {
        name: "readonly".to_string(),
        policies: vec![],
        is_dynamic: false,
    });

    // Under admin: "SECRET" should be blocked.
    let resp_before = analyze(&h, "SECRET").await;
    assert_eq!(
        resp_before["status"], "BLOCK",
        "admin role should BLOCK 'SECRET'; got: {resp_before}"
    );

    // Switch to readonly role at runtime.
    let set_role_resp = h
        .client
        .post(format!("{}/api/session/set-role", h.base_url()))
        .json(&json!({"role": "readonly"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        set_role_resp.status().as_u16(),
        200,
        "set-role to 'readonly' should succeed"
    );

    // Under readonly: "SECRET" has no matching policy → ALLOW.
    let resp_after = analyze(&h, "SECRET").await;
    assert_eq!(
        resp_after["status"], "ALLOW",
        "readonly role has no policies, expected ALLOW; got: {resp_after}"
    );
}

// ── 5.7 – session set-role rejects unknown role ───────────────────────────────

#[tokio::test]
async fn test_5_7_session_set_role_rejects_unknown() {
    let h = TestHarness::with_role(Some("admin".to_string())).await;

    // admin role blocks "FORBIDDEN".
    h.add_policy_direct(Policy {
        id: "block-forbidden".to_string(),
        match_type: PolicyType::Simple("FORBIDDEN".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
    });
    h.add_role_direct(Role {
        name: "admin".to_string(),
        policies: vec!["block-forbidden".to_string()],
        is_dynamic: false,
    });

    // Attempt to switch to a role that doesn't exist.
    let bad_resp = h
        .client
        .post(format!("{}/api/session/set-role", h.base_url()))
        .json(&json!({"role": "doesnotexist"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        bad_resp.status().as_u16(),
        400,
        "set-role to unknown role should return 400"
    );

    // The active role must still be "admin"; the block policy should still fire.
    let resp = analyze(&h, "FORBIDDEN").await;
    assert_eq!(
        resp["status"], "BLOCK",
        "admin role should still be active after rejected set-role; got: {resp}"
    );
}

// ── 5.8 – Traffic log records the active role ────────────────────────────────

#[tokio::test]
async fn test_5_8_role_in_traffic_log() {
    let h = TestHarness::with_role(Some("test-role".to_string())).await;

    // Add a minimal role so the engine recognises it.
    h.add_role_direct(Role {
        name: "test-role".to_string(),
        policies: vec![],
        is_dynamic: false,
    });

    // Fire a request so an entry is written to the traffic log.
    let _ = analyze(&h, "some payload").await;

    // Read the JSONL log and parse the last (most recent) entry.
    let log_content = std::fs::read_to_string(&h.state.traffic_log_path)
        .expect("traffic log should exist after an analyze call");

    let last_line = log_content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .last()
        .expect("traffic log should have at least one entry");

    let entry: serde_json::Value =
        serde_json::from_str(last_line).expect("traffic log entry should be valid JSON");

    assert_eq!(
        entry["role"], "test-role",
        "traffic log entry should record the active role; got: {entry}"
    );
}
