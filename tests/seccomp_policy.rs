// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

//! End-to-end tests for seccomp syscall policy enforcement.
//!
//! Covers two layers:
//!
//! 1. **HTTP endpoint** (`/syscall-policy`): verifies that Watchtower translates
//!    configured policies into the correct `rules` and `deny_names` wire format.
//!
//! 2. **`CompiledRuleSet` evaluation**: verifies that the client-side rule engine
//!    correctly allows/denies syscalls against compiled rules, including the
//!    first-match-wins ordering guarantee.

mod common;

use sevorix_watchtower::policy::{Action, Engine, Policy, PolicyContext, PolicyType, Role};

// ---------------------------------------------------------------------------
// /syscall-policy endpoint tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_syscall_policy_empty_with_no_policies() {
    let h = common::harness::TestHarness::new().await;

    let resp: serde_json::Value = h
        .client
        .get(format!("{}/syscall-policy", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["deny_names"], serde_json::json!([]));
    assert_eq!(resp["rules"], serde_json::json!([]));
}

#[tokio::test]
async fn test_syscall_policy_simple_block_appears_in_rules() {
    let h = common::harness::TestHarness::new().await;

    h.add_policy_direct(Policy {
        id: "block-unlink".to_string(),
        match_type: PolicyType::Simple("unlink".to_string()),
        action: Action::Block,
        context: PolicyContext::Syscall,
        kill: false,
        syscall: vec![],
    });
    h.add_role_direct(Role {
        name: "default".to_string(),
        policies: vec!["block-unlink".to_string()],
        is_dynamic: false,
    });

    let resp: serde_json::Value = h
        .client
        .get(format!("{}/syscall-policy", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let rules = resp["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["syscall"], "unlink");
    assert_eq!(rules[0]["action"], "Deny");
    assert!(rules[0]["path_pattern"].is_null());

    let deny_names = resp["deny_names"].as_array().unwrap();
    assert!(deny_names.iter().any(|n| n == "unlink"));
}

#[tokio::test]
async fn test_syscall_policy_all_context_included() {
    let h = common::harness::TestHarness::new().await;

    h.add_policy_direct(Policy {
        id: "block-ptrace".to_string(),
        match_type: PolicyType::Simple("ptrace".to_string()),
        action: Action::Block,
        context: PolicyContext::All, // All context should be included
        kill: false,
        syscall: vec![],
    });
    h.add_role_direct(Role {
        name: "default".to_string(),
        policies: vec!["block-ptrace".to_string()],
        is_dynamic: false,
    });

    let resp: serde_json::Value = h
        .client
        .get(format!("{}/syscall-policy", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let rules = resp["rules"].as_array().unwrap();
    assert!(rules.iter().any(|r| r["syscall"] == "ptrace"));
}

#[tokio::test]
async fn test_syscall_policy_shell_context_excluded() {
    let h = common::harness::TestHarness::new().await;

    h.add_policy_direct(Policy {
        id: "block-drop".to_string(),
        match_type: PolicyType::Simple("DROP TABLE".to_string()),
        action: Action::Block,
        context: PolicyContext::Shell, // Shell context must NOT appear in syscall-policy
        kill: false,
        syscall: vec![],
    });
    h.add_role_direct(Role {
        name: "default".to_string(),
        policies: vec!["block-drop".to_string()],
        is_dynamic: false,
    });

    let resp: serde_json::Value = h
        .client
        .get(format!("{}/syscall-policy", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["rules"], serde_json::json!([]));
    assert_eq!(resp["deny_names"], serde_json::json!([]));
}

#[tokio::test]
async fn test_syscall_policy_network_context_excluded() {
    let h = common::harness::TestHarness::new().await;

    h.add_policy_direct(Policy {
        id: "block-connect".to_string(),
        match_type: PolicyType::Simple("connect".to_string()),
        action: Action::Block,
        context: PolicyContext::Network,
        kill: false,
        syscall: vec![],
    });
    h.add_role_direct(Role {
        name: "default".to_string(),
        policies: vec!["block-connect".to_string()],
        is_dynamic: false,
    });

    let resp: serde_json::Value = h
        .client
        .get(format!("{}/syscall-policy", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["rules"], serde_json::json!([]));
}

#[tokio::test]
async fn test_syscall_policy_allow_action_excluded() {
    let h = common::harness::TestHarness::new().await;

    h.add_policy_direct(Policy {
        id: "allow-open".to_string(),
        match_type: PolicyType::Simple("open".to_string()),
        action: Action::Allow, // Allow policies must NOT appear in deny rules
        context: PolicyContext::Syscall,
        kill: false,
        syscall: vec![],
    });
    h.add_role_direct(Role {
        name: "default".to_string(),
        policies: vec!["allow-open".to_string()],
        is_dynamic: false,
    });

    let resp: serde_json::Value = h
        .client
        .get(format!("{}/syscall-policy", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["rules"], serde_json::json!([]));
    assert_eq!(resp["deny_names"], serde_json::json!([]));
}

#[tokio::test]
async fn test_syscall_policy_regex_block_has_path_pattern() {
    let h = common::harness::TestHarness::new().await;

    h.add_policy_direct(Policy {
        id: "block-etc-writes".to_string(),
        match_type: PolicyType::Regex("^/etc/.*".to_string()),
        action: Action::Block,
        context: PolicyContext::Syscall,
        kill: false,
        syscall: vec!["unlinkat".to_string()],
    });
    h.add_role_direct(Role {
        name: "default".to_string(),
        policies: vec!["block-etc-writes".to_string()],
        is_dynamic: false,
    });

    let resp: serde_json::Value = h
        .client
        .get(format!("{}/syscall-policy", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let rules = resp["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["action"], "Deny");
    assert_eq!(rules[0]["syscall"], "unlinkat");
    assert_eq!(rules[0]["path_pattern"], "^/etc/.*");

    // Regex policies don't appear in legacy deny_names
    assert_eq!(resp["deny_names"], serde_json::json!([]));
}

#[tokio::test]
async fn test_syscall_policy_regex_without_syscall_excluded() {
    let h = common::harness::TestHarness::new().await;

    // Regex policy missing the `syscall` field — must be silently excluded from rules
    // (misconfiguration; we can't know which syscall to intercept).
    h.add_policy_direct(Policy {
        id: "bad-regex".to_string(),
        match_type: PolicyType::Regex("^/etc/.*".to_string()),
        action: Action::Block,
        context: PolicyContext::Syscall,
        kill: false,
        syscall: vec![],
    });
    h.add_role_direct(Role {
        name: "default".to_string(),
        policies: vec!["bad-regex".to_string()],
        is_dynamic: false,
    });

    let resp: serde_json::Value = h
        .client
        .get(format!("{}/syscall-policy", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["rules"], serde_json::json!([]));
}

#[tokio::test]
async fn test_syscall_policy_executable_block_appears_in_rules() {
    let h = common::harness::TestHarness::new().await;

    h.add_policy_direct(Policy {
        id: "exec-unlink-check".to_string(),
        match_type: PolicyType::Executable("/usr/local/bin/check-unlink".to_string()),
        action: Action::Block,
        context: PolicyContext::Syscall,
        kill: false,
        syscall: vec!["unlink".to_string()],
    });
    h.add_role_direct(Role {
        name: "default".to_string(),
        policies: vec!["exec-unlink-check".to_string()],
        is_dynamic: false,
    });

    let resp: serde_json::Value = h
        .client
        .get(format!("{}/syscall-policy", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let rules = resp["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["action"], "Deny");
    assert_eq!(rules[0]["syscall"], "unlink");
    assert_eq!(rules[0]["executable"], "/usr/local/bin/check-unlink");

    // Executable policies don't appear in legacy deny_names
    assert_eq!(resp["deny_names"], serde_json::json!([]));
}

#[tokio::test]
async fn test_syscall_policy_executable_without_syscall_excluded() {
    let h = common::harness::TestHarness::new().await;

    h.add_policy_direct(Policy {
        id: "exec-no-syscall".to_string(),
        match_type: PolicyType::Executable("/usr/local/bin/check".to_string()),
        action: Action::Block,
        context: PolicyContext::Syscall,
        kill: false,
        syscall: vec![],
    });
    h.add_role_direct(Role {
        name: "default".to_string(),
        policies: vec!["exec-no-syscall".to_string()],
        is_dynamic: false,
    });

    let resp: serde_json::Value = h
        .client
        .get(format!("{}/syscall-policy", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["rules"], serde_json::json!([]));
}

#[tokio::test]
async fn test_syscall_policy_multiple_policies() {
    let h = common::harness::TestHarness::new().await;

    for (id, name) in [("p1", "unlink"), ("p2", "rename"), ("p3", "ptrace")] {
        h.add_policy_direct(Policy {
            id: id.to_string(),
            match_type: PolicyType::Simple(name.to_string()),
            action: Action::Block,
            context: PolicyContext::Syscall,
            kill: false,
            syscall: vec![],
        });
    }
    h.add_role_direct(Role {
        name: "default".to_string(),
        policies: vec!["p1".to_string(), "p2".to_string(), "p3".to_string()],
        is_dynamic: false,
    });

    let resp: serde_json::Value = h
        .client
        .get(format!("{}/syscall-policy", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let rules = resp["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 3);
    let deny_names = resp["deny_names"].as_array().unwrap();
    assert_eq!(deny_names.len(), 3);
}

#[tokio::test]
async fn test_syscall_policy_role_query_param() {
    let h = common::harness::TestHarness::new().await;

    h.add_policy_direct(Policy {
        id: "block-unlink".to_string(),
        match_type: PolicyType::Simple("unlink".to_string()),
        action: Action::Block,
        context: PolicyContext::Syscall,
        kill: false,
        syscall: vec![],
    });
    // Only the "restricted" role has this policy
    h.add_role_direct(Role {
        name: "restricted".to_string(),
        policies: vec!["block-unlink".to_string()],
        is_dynamic: false,
    });

    // Default role has no policies
    let default_resp: serde_json::Value = h
        .client
        .get(format!("{}/syscall-policy", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(default_resp["rules"], serde_json::json!([]));

    // Restricted role returns the rule
    let restricted_resp: serde_json::Value = h
        .client
        .get(format!("{}/syscall-policy?role=restricted", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rules = restricted_resp["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["syscall"], "unlink");
}

// ---------------------------------------------------------------------------
// Array syscall field and Simple-with-syscall-override tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_syscall_policy_array_generates_one_rule_per_syscall() {
    let h = common::harness::TestHarness::new().await;

    // A single Regex policy covering three syscall variants via the array form.
    h.add_policy_direct(Policy {
        id: "protect-etc".to_string(),
        match_type: PolicyType::Regex("^/etc/".to_string()),
        action: Action::Block,
        context: PolicyContext::Syscall,
        kill: false,
        syscall: vec![
            "unlink".to_string(),
            "unlinkat".to_string(),
            "rmdir".to_string(),
        ],
    });
    h.add_role_direct(Role {
        name: "default".to_string(),
        policies: vec!["protect-etc".to_string()],
        is_dynamic: false,
    });

    let resp: serde_json::Value = h
        .client
        .get(format!("{}/syscall-policy", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let rules = resp["rules"].as_array().unwrap();
    // One rule per syscall name
    assert_eq!(rules.len(), 3);
    let syscalls: Vec<&str> = rules
        .iter()
        .map(|r| r["syscall"].as_str().unwrap())
        .collect();
    assert!(syscalls.contains(&"unlink"));
    assert!(syscalls.contains(&"unlinkat"));
    assert!(syscalls.contains(&"rmdir"));
    for rule in rules {
        assert_eq!(rule["action"], "Deny");
        assert_eq!(rule["path_pattern"], "^/etc/");
    }
    // Regex policies don't appear in legacy deny_names
    assert_eq!(resp["deny_names"], serde_json::json!([]));
}

#[tokio::test]
async fn test_syscall_policy_simple_with_explicit_syscall_field() {
    let h = common::harness::TestHarness::new().await;

    // Simple policy with explicit `syscall` field — syscall field takes precedence
    // over pattern as the intercepted syscall name.
    h.add_policy_direct(Policy {
        id: "block-file-ops".to_string(),
        match_type: PolicyType::Simple("ignored-pattern".to_string()),
        action: Action::Block,
        context: PolicyContext::Syscall,
        kill: false,
        syscall: vec!["unlink".to_string(), "rename".to_string()],
    });
    h.add_role_direct(Role {
        name: "default".to_string(),
        policies: vec!["block-file-ops".to_string()],
        is_dynamic: false,
    });

    let resp: serde_json::Value = h
        .client
        .get(format!("{}/syscall-policy", h.base_url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let rules = resp["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2);
    let syscalls: Vec<&str> = rules
        .iter()
        .map(|r| r["syscall"].as_str().unwrap())
        .collect();
    assert!(syscalls.contains(&"unlink"));
    assert!(syscalls.contains(&"rename"));
    // Pattern ("ignored-pattern") must NOT appear as a syscall name
    assert!(!syscalls.contains(&"ignored-pattern"));

    let deny_names = resp["deny_names"].as_array().unwrap();
    assert!(deny_names.contains(&serde_json::json!("unlink")));
    assert!(deny_names.contains(&serde_json::json!("rename")));
}

// ---------------------------------------------------------------------------
// Policy::validate() fail-fast tests (unit level)
// ---------------------------------------------------------------------------

#[test]
fn test_validate_regex_syscall_policy_without_syscall_field_fails() {
    use sevorix_watchtower::policy::{Action, Policy, PolicyContext, PolicyType};
    let p = Policy {
        id: "bad".to_string(),
        match_type: PolicyType::Regex("^/etc/".to_string()),
        action: Action::Block,
        context: PolicyContext::Syscall,
        kill: false,
        syscall: vec![],
    };
    let err = p.validate().unwrap_err();
    assert!(err.contains("bad"), "error should name the policy ID");
    assert!(
        err.contains("syscall"),
        "error should mention the missing field"
    );
}

#[test]
fn test_validate_executable_syscall_policy_without_syscall_field_fails() {
    use sevorix_watchtower::policy::{Action, Policy, PolicyContext, PolicyType};
    let p = Policy {
        id: "exec-bad".to_string(),
        match_type: PolicyType::Executable("/usr/bin/check".to_string()),
        action: Action::Block,
        context: PolicyContext::Syscall,
        kill: false,
        syscall: vec![],
    };
    assert!(p.validate().is_err());
}

#[test]
fn test_validate_regex_syscall_policy_with_syscall_field_passes() {
    use sevorix_watchtower::policy::{Action, Policy, PolicyContext, PolicyType};
    let p = Policy {
        id: "good".to_string(),
        match_type: PolicyType::Regex("^/etc/".to_string()),
        action: Action::Block,
        context: PolicyContext::Syscall,
        kill: false,
        syscall: vec!["unlinkat".to_string()],
    };
    assert!(p.validate().is_ok());
}

#[test]
fn test_validate_regex_non_syscall_context_without_syscall_field_passes() {
    use sevorix_watchtower::policy::{Action, Policy, PolicyContext, PolicyType};
    // Regex + Shell context without syscall field is fine — syscall field only
    // matters for Syscall context.
    let p = Policy {
        id: "shell-regex".to_string(),
        match_type: PolicyType::Regex("DROP.*TABLE".to_string()),
        action: Action::Block,
        context: PolicyContext::Shell,
        kill: false,
        syscall: vec![],
    };
    assert!(p.validate().is_ok());
}

// CompiledRuleSet evaluation is tested as unit tests inside sevorix-core/src/seccomp.rs
// where SyscallInfo can be constructed without exposing libseccomp types to the
// integration test boundary.
