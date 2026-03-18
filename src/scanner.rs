use crate::policy::{Action, Engine, PolicyContext};
use directories::ProjectDirs;
use sevorix_core::{SyscallEvent, SeccompDecision};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::Write;

// -------- Poison Pill Security --------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoisonPill {
    pub id: &'static str,
    pub key: &'static str,
    pub value: &'static str,
    pub trigger_weight: u8,
}

impl PoisonPill {
    pub fn default_canary() -> Self {
        PoisonPill {
            id: "internal-canary-1",
            key: "AWS_SECRET",
            value: "sev-canary-999",
            trigger_weight: 100,
        }
    }
}

/// Scans the JSON payload for the poison pill.
/// Returns true (triggered) if the key and value are both matched.
pub fn scan_for_poison(payload: &Value, pill: &PoisonPill) -> bool {
    // Search at the top level for key matching
    if let Some(found_value) = payload.get(pill.key) {
        if found_value == pill.value {
            return true;
        }
        // Flexible: if value is a JSON string matching, allow also
        if let Some(s) = found_value.as_str() {
            if s == pill.value {
                return true;
            }
        }
    }
    // Additionally, search in the "payload" field, if it's string
    if let Some(inner) = payload.get("payload") {
        if let Some(s) = inner.as_str() {
            if s.contains(pill.value) {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------
// 1. THE BRAIN: DECISION LOGIC
// ---------------------------------------------------------

#[derive(Debug, PartialEq)]
pub struct SecurityScanResult {
    pub verdict: String, // Keeping existing struct
    pub lane: String,
    pub delay: u64,
    pub log_msg: Option<String>,
    pub log_score: Option<String>,
    /// If true, kill the traced process instead of returning EPERM.
    /// Used for critical violations where EPERM return isn't sufficient.
    pub kill: bool,
}

pub fn scan_content(
    text: &str,
    role_name: Option<&str>,
    engine: &Engine,
    context: PolicyContext,
) -> SecurityScanResult {
    // Check against policies for the specified role. If no role is provided, block.
    let Some(role) = role_name else {
        return SecurityScanResult {
            verdict: "BLOCK".to_string(),
            lane: "RED".to_string(),
            delay: 0,
            log_msg: Some("No role configured".to_string()),
            log_score: Some("100%".to_string()),
            kill: false,
        };
    };
    if !engine.roles.contains_key(role) {
        return SecurityScanResult {
            verdict: "BLOCK".to_string(),
            lane: "RED".to_string(),
            delay: 0,
            log_msg: Some(format!("Role '{}' not found in policy engine", role)),
            log_score: Some("100%".to_string()),
            kill: false,
        };
    }
    if let Some(decision) = engine.check_role(role, text, context) {
        match decision.action {
            Action::Block => {
                let (msg, score) = match decision.policy_id.as_str() {
                    "block_drop" | "block_delete" => (
                        Some(
                            "CRITICAL: SQL Injection Heuristic (Data Destruction Attempt)"
                                .to_string(),
                        ),
                        Some("99.8%".to_string()),
                    ),
                    "block_wire" | "block_funds" => (
                        Some("CRITICAL: Unauthorized Financial Transaction Detected".to_string()),
                        Some("98.5%".to_string()),
                    ),
                    _ => (
                        Some("CRITICAL: Policy Violation - Blocked".to_string()),
                        Some("99.0%".to_string()),
                    ),
                };

                return SecurityScanResult {
                    verdict: "BLOCK".to_string(),
                    lane: "RED".to_string(),
                    delay: 0,
                    log_msg: msg,
                    log_score: score,
                    kill: decision.kill,
                };
            }
            Action::Flag => {
                return SecurityScanResult {
                    verdict: "FLAG".to_string(),
                    lane: "YELLOW".to_string(),
                    delay: 500,
                    log_msg: None,
                    log_score: None,
                    kill: false,
                };
            }
            Action::Allow => {
                // Treated as safe, fall through
            }
        }
    }

    SecurityScanResult {
        verdict: "ALLOW".to_string(),
        lane: "GREEN".to_string(),
        delay: 5,
        log_msg: None,
        log_score: None,
        kill: false,
    }
}

/// Scans a syscall event against the provided policies.
/// Formats the syscall event as a string and checks against policies with Syscall context.
pub fn scan_syscall(event: &SyscallEvent, policies: &[crate::policy::Policy]) -> SecurityScanResult {
    // Format syscall event as a string for pattern matching
    let args_str = event.args.join(", ");
    let content = format!(
        "{}({}) [pid={}, ppid={}]",
        event.syscall_name, args_str, event.pid, event.ppid
    );

    // Create engine from policies
    let mut engine = Engine::new();
    for policy in policies {
        engine.add_policy(policy.clone());
    }

    // Set up default role with all policies
    let policy_ids: Vec<String> = policies.iter().map(|p| p.id.clone()).collect();
    engine.roles.insert(
        "default".to_string(),
        crate::policy::Role {
            name: "default".to_string(),
            policies: policy_ids,
            is_dynamic: false,
        },
    );

    scan_content(&content, Some("default"), &engine, PolicyContext::Syscall)
}

/// Scans a syscall event against a policy engine.
///
/// This is a more efficient version of `scan_syscall` that takes an
/// existing engine reference instead of creating a new one each time.
///
/// # Arguments
///
/// * `event` - The syscall event to analyze
/// * `engine` - The policy engine to check against
///
/// # Returns
///
/// A `SeccompDecision` indicating what action to take.
pub fn scan_syscall_with_engine(event: &SyscallEvent, engine: &Engine) -> SeccompDecision {
    // Format syscall event as a string for pattern matching
    let args_str = event.args.join(", ");
    let content = format!(
        "{}({}) [pid={}, ppid={}]",
        event.syscall_name, args_str, event.pid, event.ppid
    );

    // Check against the engine with Syscall context
    let result = scan_content(&content, Some("default"), engine, PolicyContext::Syscall);

    // Convert SecurityScanResult to SeccompDecision
    if result.verdict == "BLOCK" {
        if result.kill {
            SeccompDecision::Kill
        } else {
            SeccompDecision::Block { errno: libc::EPERM }
        }
    } else {
        // ALLOW or FLAG both mean allow
        SeccompDecision::Allow
    }
}

pub fn log_threat(agent: &str, payload: &str, reason: &str, score: &str) {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let log_entry = format!(
        "[{}] BLOCKED | Agent: {} | Score: {}\n   REASON: {}\n   PAYLOAD: {}\n--------------------------------------------------\n",
        timestamp, agent, score, reason, payload
    );

    // Determine path
    let path = if let Some(proj_dirs) = ProjectDirs::from("com", "sevorix", "sevorix") {
        let state_dir = proj_dirs.state_dir().unwrap_or(proj_dirs.cache_dir());
        // Start/Daemon usually ensures this exists, but let's be safe
        let _ = std::fs::create_dir_all(state_dir);
        state_dir.join("threat_log.txt")
    } else {
        std::path::PathBuf::from("threat_log.txt")
    };

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = file.write_all(log_entry.as_bytes());
    }
}

/// Log a PTRACE_KILL event for critical violations.
///
/// This logs when a traced process is killed due to a policy with kill=true.
pub fn log_kill(syscall_name: &str, pid: u32, ppid: u32, args: &[String], policy_id: &str) {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let args_str = args.join(", ");
    let log_entry = format!(
        "[{}] KILLED | Policy: {} | Syscall: {}({}) | PID: {} | PPID: {}\n--------------------------------------------------\n",
        timestamp, policy_id, syscall_name, args_str, pid, ppid
    );

    // Determine path
    let path = if let Some(proj_dirs) = ProjectDirs::from("com", "sevorix", "sevorix") {
        let state_dir = proj_dirs.state_dir().unwrap_or(proj_dirs.cache_dir());
        let _ = std::fs::create_dir_all(state_dir);
        state_dir.join("kill_log.txt")
    } else {
        std::path::PathBuf::from("kill_log.txt")
    };

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = file.write_all(log_entry.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Action, Engine, Policy, PolicyType, Role};
    use serde_json::json;

    fn create_test_engine() -> Engine {
        let mut engine = Engine::new();

        // Define policies matching old logic
        let policies = vec![
            ("block_drop", "DROP", Action::Block),
            ("block_delete", "DELETE", Action::Block),
            ("block_wire", "WIRE", Action::Block),
            ("block_funds", "FUNDS", Action::Block),
            ("flag_select", "SELECT", Action::Flag),
            ("flag_admin", "ADMIN", Action::Flag),
        ];

        let mut policy_ids = Vec::new();

        for (id, pattern, action) in policies {
            engine.policies.insert(
                id.to_string(),
                Policy {
                    id: id.to_string(),
                    match_type: PolicyType::Simple(pattern.to_string()),
                    action,
                    context: PolicyContext::All,
                    kill: false,
                },
            );
            policy_ids.push(id.to_string());
        }

        engine.roles.insert(
            "default".to_string(),
            Role {
                name: "default".to_string(),
                policies: policy_ids,
                is_dynamic: false,
            },
        );

        engine
    }

    #[test]
    fn test_scan_for_poison_direct_match() {
        let pill = PoisonPill {
            id: "test-pill",
            key: "SECRET_KEY",
            value: "super-secret",
            trigger_weight: 100,
        };

        let payload = json!({
            "SECRET_KEY": "super-secret",
            "payload": "innocent content"
        });

        assert!(
            scan_for_poison(&payload, &pill),
            "Should detect poison pill in direct key match"
        );
    }

    #[test]
    fn test_scan_for_poison_embedded_match() {
        let pill = PoisonPill {
            id: "test-pill",
            key: "SECRET_KEY",
            value: "super-secret",
            trigger_weight: 100,
        };

        let payload = json!({
            "payload": "Here is the super-secret embedded"
        });

        assert!(
            scan_for_poison(&payload, &pill),
            "Should detect poison pill embedded in payload string"
        );
    }

    #[test]
    fn test_scan_for_poison_negative() {
        let pill = PoisonPill {
            id: "test-pill",
            key: "SECRET_KEY",
            value: "super-secret",
            trigger_weight: 100,
        };

        let payload = json!({
            "SECRET_KEY": "wrong-secret",
            "payload": "totally safe"
        });

        assert!(
            !scan_for_poison(&payload, &pill),
            "Should NOT detect poison pill"
        );
    }

    #[test]
    fn test_red_lane_drop() {
        let engine = create_test_engine();
        let result = scan_content("DROP TABLE users", Some("default"), &engine, PolicyContext::All);
        assert_eq!(result.verdict, "BLOCK");
        assert_eq!(result.lane, "RED");
        assert!(result.log_msg.unwrap().contains("Data Destruction"));
    }

    #[test]
    fn test_red_lane_wire() {
        let engine = create_test_engine();
        let result = scan_content("WIRE FUNDS TO ABROAD", Some("default"), &engine, PolicyContext::All);
        assert_eq!(result.verdict, "BLOCK");
        assert_eq!(result.lane, "RED");
        assert!(result.log_msg.unwrap().contains("Financial Transaction"));
    }

    #[test]
    fn test_yellow_lane_select() {
        let engine = create_test_engine();
        let result = scan_content("SELECT * FROM users", Some("default"), &engine, PolicyContext::All);
        assert_eq!(result.verdict, "FLAG");
        assert_eq!(result.lane, "YELLOW");
        assert_eq!(result.delay, 500);
    }

    #[test]
    fn test_green_lane_safe() {
        let engine = create_test_engine();
        let result = scan_content("Hello World", Some("default"), &engine, PolicyContext::All);
        assert_eq!(result.verdict, "ALLOW");
        assert_eq!(result.lane, "GREEN");
        assert_eq!(result.delay, 5);
    }

    #[test]
    fn test_scan_syscall_blocks_dangerous() {
        let policies = vec![
            Policy {
                id: "block_execve".to_string(),
                match_type: PolicyType::Simple("execve".to_string()),
                action: Action::Block,
                context: PolicyContext::Syscall,
                kill: false,
            },
        ];

        let event = SyscallEvent {
            syscall_name: "execve".to_string(),
            syscall_number: 59,
            args: vec!["/bin/sh".to_string(), "-c".to_string(), "ls".to_string()],
            pid: 1234,
            ppid: 1,
            timestamp: "2026-02-25T12:00:00Z".to_string(),
        };

        let result = scan_syscall(&event, &policies);
        assert_eq!(result.verdict, "BLOCK");
        assert_eq!(result.lane, "RED");
    }

    #[test]
    fn test_scan_syscall_allows_safe() {
        let policies = vec![
            Policy {
                id: "block_execve".to_string(),
                match_type: PolicyType::Simple("execve".to_string()),
                action: Action::Block,
                context: PolicyContext::Syscall,
                kill: false,
            },
        ];

        let event = SyscallEvent {
            syscall_name: "read".to_string(),
            syscall_number: 0,
            args: vec!["3".to_string(), "buffer".to_string(), "1024".to_string()],
            pid: 1234,
            ppid: 1,
            timestamp: "2026-02-25T12:00:00Z".to_string(),
        };

        let result = scan_syscall(&event, &policies);
        assert_eq!(result.verdict, "ALLOW");
        assert_eq!(result.lane, "GREEN");
    }

    #[test]
    fn test_scan_syscall_flags_suspicious() {
        let policies = vec![
            Policy {
                id: "flag_connect".to_string(),
                match_type: PolicyType::Simple("connect".to_string()),
                action: Action::Flag,
                context: PolicyContext::Syscall,
                kill: false,
            },
        ];

        let event = SyscallEvent {
            syscall_name: "connect".to_string(),
            syscall_number: 42,
            args: vec!["sockfd".to_string(), "addr".to_string()],
            pid: 1234,
            ppid: 1,
            timestamp: "2026-02-25T12:00:00Z".to_string(),
        };

        let result = scan_syscall(&event, &policies);
        assert_eq!(result.verdict, "FLAG");
        assert_eq!(result.lane, "YELLOW");
    }

    #[test]
    fn test_scan_syscall_with_engine_blocks() {
        let mut engine = Engine::new();
        engine.policies.insert("block_execve".to_string(), Policy {
            id: "block_execve".to_string(),
            match_type: PolicyType::Simple("execve".to_string()),
            action: Action::Block,
            context: PolicyContext::Syscall,
            kill: false,
        });
        engine.roles.insert("default".to_string(), Role {
            name: "default".to_string(),
            policies: vec!["block_execve".to_string()],
            is_dynamic: false,
        });

        let event = SyscallEvent {
            syscall_name: "execve".to_string(),
            syscall_number: 59,
            args: vec!["/bin/sh".to_string()],
            pid: 1234,
            ppid: 1,
            timestamp: "2026-02-25T12:00:00Z".to_string(),
        };

        let decision = scan_syscall_with_engine(&event, &engine);
        assert_eq!(decision, SeccompDecision::Block { errno: libc::EPERM });
    }

    #[test]
    fn test_scan_syscall_with_engine_kills() {
        let mut engine = Engine::new();
        engine.policies.insert("kill_execve".to_string(), Policy {
            id: "kill_execve".to_string(),
            match_type: PolicyType::Simple("execve".to_string()),
            action: Action::Block,
            context: PolicyContext::Syscall,
            kill: true,
        });
        engine.roles.insert("default".to_string(), Role {
            name: "default".to_string(),
            policies: vec!["kill_execve".to_string()],
            is_dynamic: false,
        });

        let event = SyscallEvent {
            syscall_name: "execve".to_string(),
            syscall_number: 59,
            args: vec!["/bin/sh".to_string()],
            pid: 1234,
            ppid: 1,
            timestamp: "2026-02-25T12:00:00Z".to_string(),
        };

        let decision = scan_syscall_with_engine(&event, &engine);
        assert_eq!(decision, SeccompDecision::Kill);
    }

    #[test]
    fn test_scan_syscall_with_engine_allows() {
        let mut engine = Engine::new();
        engine.policies.insert("block_execve".to_string(), Policy {
            id: "block_execve".to_string(),
            match_type: PolicyType::Simple("execve".to_string()),
            action: Action::Block,
            context: PolicyContext::Syscall,
            kill: false,
        });
        engine.roles.insert("default".to_string(), Role {
            name: "default".to_string(),
            policies: vec!["block_execve".to_string()],
            is_dynamic: false,
        });

        let event = SyscallEvent {
            syscall_name: "read".to_string(),
            syscall_number: 0,
            args: vec!["3".to_string(), "buf".to_string(), "1024".to_string()],
            pid: 1234,
            ppid: 1,
            timestamp: "2026-02-25T12:00:00Z".to_string(),
        };

        let decision = scan_syscall_with_engine(&event, &engine);
        assert_eq!(decision, SeccompDecision::Allow);
    }

    #[test]
    fn test_scan_syscall_with_engine_flags_as_allow() {
        let mut engine = Engine::new();
        engine.policies.insert("flag_connect".to_string(), Policy {
            id: "flag_connect".to_string(),
            match_type: PolicyType::Simple("connect".to_string()),
            action: Action::Flag,
            context: PolicyContext::Syscall,
            kill: false,
        });
        engine.roles.insert("default".to_string(), Role {
            name: "default".to_string(),
            policies: vec!["flag_connect".to_string()],
            is_dynamic: false,
        });

        let event = SyscallEvent {
            syscall_name: "connect".to_string(),
            syscall_number: 42,
            args: vec!["sockfd".to_string()],
            pid: 1234,
            ppid: 1,
            timestamp: "2026-02-25T12:00:00Z".to_string(),
        };

        // FLAG verdict should be treated as Allow in seccomp context
        let decision = scan_syscall_with_engine(&event, &engine);
        assert_eq!(decision, SeccompDecision::Allow);
    }

    #[test]
    fn test_scan_content_with_kill_flag() {
        let mut engine = Engine::new();
        engine.policies.insert("kill_policy".to_string(), Policy {
            id: "kill_policy".to_string(),
            match_type: PolicyType::Simple("dangerous".to_string()),
            action: Action::Block,
            context: PolicyContext::All,
            kill: true,
        });
        engine.roles.insert("default".to_string(), Role {
            name: "default".to_string(),
            policies: vec!["kill_policy".to_string()],
            is_dynamic: false,
        });

        let result = scan_content("dangerous operation", Some("default"), &engine, PolicyContext::All);
        assert_eq!(result.verdict, "BLOCK");
        assert!(result.kill);
    }

    #[test]
    fn test_poison_pill_default_canary() {
        let pill = PoisonPill::default_canary();
        assert_eq!(pill.id, "internal-canary-1");
        assert_eq!(pill.key, "AWS_SECRET");
        assert_eq!(pill.value, "sev-canary-999");
        assert_eq!(pill.trigger_weight, 100);
    }

    #[test]
    fn test_security_scan_result_fields() {
        let result = SecurityScanResult {
            verdict: "BLOCK".to_string(),
            lane: "RED".to_string(),
            delay: 0,
            log_msg: Some("Test message".to_string()),
            log_score: Some("99%".to_string()),
            kill: true,
        };

        assert_eq!(result.verdict, "BLOCK");
        assert_eq!(result.lane, "RED");
        assert_eq!(result.delay, 0);
        assert!(result.kill);
    }

    #[test]
    fn test_scan_content_unknown_policy_id() {
        let mut engine = Engine::new();
        engine.policies.insert("unknown_id".to_string(), Policy {
            id: "unknown_id".to_string(),
            match_type: PolicyType::Simple("blockme".to_string()),
            action: Action::Block,
            context: PolicyContext::All,
            kill: false,
        });
        engine.roles.insert("default".to_string(), Role {
            name: "default".to_string(),
            policies: vec!["unknown_id".to_string()],
            is_dynamic: false,
        });

        let result = scan_content("blockme please", Some("default"), &engine, PolicyContext::All);
        assert_eq!(result.verdict, "BLOCK");
        assert!(result.log_msg.unwrap().contains("Policy Violation"));
    }

    #[test]
    fn test_log_threat_writes_to_file() {
        // The log function writes to ProjectDirs, so we can't easily verify
        // the file contents. But we can verify it doesn't panic.
        log_threat("test-agent", "DROP TABLE users", "SQL Injection detected", "99.5%");
    }

    #[test]
    fn test_log_kill_writes_to_file() {
        // Similar to test_log_threat_writes_to_file, this verifies no panic
        log_kill("execve", 1234, 1, &["/bin/sh".to_string(), "-c".to_string()], "kill_policy");
    }

    #[test]
    fn test_scan_content_with_shell_context() {
        let mut engine = create_test_engine();
        engine.policies.insert("shell_only".to_string(), Policy {
            id: "shell_only".to_string(),
            match_type: PolicyType::Simple("RMMOD".to_string()),
            action: Action::Block,
            context: PolicyContext::Shell,
            kill: false,
        });
        engine.roles.get_mut("default").unwrap().policies.push("shell_only".to_string());

        // Should block in Shell context
        let result = scan_content("RMMOD some_module", Some("default"), &engine, PolicyContext::Shell);
        assert_eq!(result.verdict, "BLOCK");

        // Should NOT block in Network context
        let result = scan_content("RMMOD some_module", Some("default"), &engine, PolicyContext::Network);
        assert_eq!(result.verdict, "ALLOW");
    }

    #[test]
    fn test_scan_content_with_network_context() {
        let mut engine = create_test_engine();
        engine.policies.insert("net_only".to_string(), Policy {
            id: "net_only".to_string(),
            match_type: PolicyType::Simple("CURL".to_string()),
            action: Action::Flag,
            context: PolicyContext::Network,
            kill: false,
        });
        engine.roles.get_mut("default").unwrap().policies.push("net_only".to_string());

        // Should flag in Network context
        let result = scan_content("CURL http://example.com", Some("default"), &engine, PolicyContext::Network);
        assert_eq!(result.verdict, "FLAG");

        // Should NOT flag in Shell context
        let result = scan_content("CURL http://example.com", Some("default"), &engine, PolicyContext::Shell);
        assert_eq!(result.verdict, "ALLOW");
    }

    #[test]
    fn test_scan_content_multiple_matching_policies() {
        let mut engine = Engine::new();
        engine.policies.insert("block1".to_string(), Policy {
            id: "block1".to_string(),
            match_type: PolicyType::Simple("MATCH".to_string()),
            action: Action::Block,
            context: PolicyContext::All,
            kill: false,
        });
        engine.policies.insert("block2".to_string(), Policy {
            id: "block2".to_string(),
            match_type: PolicyType::Simple("MATCH".to_string()),
            action: Action::Block,
            context: PolicyContext::All,
            kill: false,
        });
        engine.roles.insert("default".to_string(), Role {
            name: "default".to_string(),
            policies: vec!["block1".to_string(), "block2".to_string()],
            is_dynamic: false,
        });

        // Should return first block decision
        let result = scan_content("MATCH", Some("default"), &engine, PolicyContext::All);
        assert_eq!(result.verdict, "BLOCK");
    }

    #[test]
    fn test_scan_content_block_takes_precedence_over_flag() {
        let mut engine = Engine::new();
        engine.policies.insert("flag1".to_string(), Policy {
            id: "flag1".to_string(),
            match_type: PolicyType::Simple("TEST".to_string()),
            action: Action::Flag,
            context: PolicyContext::All,
            kill: false,
        });
        engine.policies.insert("block1".to_string(), Policy {
            id: "block1".to_string(),
            match_type: PolicyType::Simple("TEST".to_string()),
            action: Action::Block,
            context: PolicyContext::All,
            kill: false,
        });
        engine.roles.insert("default".to_string(), Role {
            name: "default".to_string(),
            policies: vec!["flag1".to_string(), "block1".to_string()],
            is_dynamic: false,
        });

        let result = scan_content("TEST", Some("default"), &engine, PolicyContext::All);
        assert_eq!(result.verdict, "BLOCK");
    }

    #[test]
    fn test_scan_for_poison_json_string_value() {
        let pill = PoisonPill::default_canary();
        let payload = json!({
            "AWS_SECRET": pill.value
        });

        assert!(scan_for_poison(&payload, &pill));
    }

    #[test]
    fn test_scan_for_poison_as_string_in_payload() {
        let pill = PoisonPill::default_canary();
        let payload = json!({
            "data": "something",
            "payload": format!("prefix {} suffix", pill.value)
        });

        assert!(scan_for_poison(&payload, &pill));
    }

    #[test]
    fn test_security_scan_result_equality() {
        let result1 = SecurityScanResult {
            verdict: "BLOCK".to_string(),
            lane: "RED".to_string(),
            delay: 0,
            log_msg: Some("test".to_string()),
            log_score: Some("99%".to_string()),
            kill: false,
        };

        let result2 = SecurityScanResult {
            verdict: "BLOCK".to_string(),
            lane: "RED".to_string(),
            delay: 0,
            log_msg: Some("test".to_string()),
            log_score: Some("99%".to_string()),
            kill: false,
        };

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_scan_syscall_format() {
        let policies = vec![];
        let event = SyscallEvent {
            syscall_name: "open".to_string(),
            syscall_number: 2,
            args: vec!["path/to/file".to_string(), "O_RDONLY".to_string()],
            pid: 42,
            ppid: 1,
            timestamp: "2026-03-04T12:00:00Z".to_string(),
        };

        let result = scan_syscall(&event, &policies);
        assert_eq!(result.verdict, "ALLOW");
        assert_eq!(result.lane, "GREEN");
    }

    #[test]
    fn test_scan_syscall_with_args() {
        let policies = vec![Policy {
            id: "block_open".to_string(),
            match_type: PolicyType::Simple("secret".to_string()),
            action: Action::Block,
            context: PolicyContext::Syscall,
            kill: false,
        }];

        let event = SyscallEvent {
            syscall_name: "open".to_string(),
            syscall_number: 2,
            args: vec!["/etc/secret/file".to_string()],
            pid: 42,
            ppid: 1,
            timestamp: "2026-03-04T12:00:00Z".to_string(),
        };

        let result = scan_syscall(&event, &policies);
        assert_eq!(result.verdict, "BLOCK");
    }
}
