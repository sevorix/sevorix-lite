// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

use sevorix_watchtower::policy::{Action, Engine, Policy, PolicyContext, PolicyType, Role};
use sevorix_watchtower::scanner::scan_content;

#[test]
fn test_integration_policy_workflow() {
    // 1. Setup Engine
    let mut engine = Engine::new();

    // 2. Add Policies
    let block_sql = Policy {
        id: "block_sql".to_string(),
        match_type: PolicyType::Simple("DROP TABLE".to_string()),
        action: Action::Block,
        context: PolicyContext::Shell, // Only for Shell? or All? Let's say Shell
        kill: false,
        syscall: vec![],
    };
    engine.add_policy(block_sql);

    let flag_sensitive = Policy {
        id: "flag_sensitive".to_string(),
        match_type: PolicyType::Simple("secret".to_string()),
        action: Action::Flag,
        context: PolicyContext::All,
        kill: false,
        syscall: vec![],
    };
    engine.add_policy(flag_sensitive);

    // 3. Add Role
    let role = Role {
        name: "developer".to_string(),
        policies: vec!["block_sql".to_string(), "flag_sensitive".to_string()],
        is_dynamic: false,
    };
    engine.add_role(role);

    // 4. Test Scan (Green Lane)
    // "SELECT * FROM users" does not match "DROP TABLE" (simple) or "secret"
    let safe_payload = "SELECT * FROM users";
    let scan = scan_content(
        safe_payload,
        Some("developer"),
        &engine,
        PolicyContext::Network,
    );
    assert_eq!(scan.verdict, "ALLOW");
    assert_eq!(scan.lane, "GREEN");

    // 5. Test Block (Red Lane) via Shell context
    // Note: our policy "block_sql" is context=Shell.
    // If we scan with context=Shell, it should block.
    let malicious_payload = "DROP TABLE users";
    let scan_block = scan_content(
        malicious_payload,
        Some("developer"),
        &engine,
        PolicyContext::Shell,
    );

    // scan_content returns valid SecurityScanResult from scanner logic
    // check scanner.rs rules:
    // If Action::Block -> Verdict: "BLOCK", Lane: "RED"

    assert_eq!(scan_block.verdict, "BLOCK");
    assert_eq!(scan_block.lane, "RED");
    assert!(scan_block.log_msg.is_some());

    // 6. Test Flag (Yellow Lane)
    let risky_payload = "show me the secret";
    let scan_flag = scan_content(
        risky_payload,
        Some("developer"),
        &engine,
        PolicyContext::All,
    );

    assert_eq!(scan_flag.verdict, "FLAG");
    assert_eq!(scan_flag.lane, "YELLOW");
}
