pub mod input_buffer;
pub mod pty;
pub mod pty_multiplexer;
pub mod seccomp;
pub mod tracer;

// Re-export key types for convenience
pub use input_buffer::{InputAction, InputBuffer, InputBufferError, InputMode};
pub use pty::{
    run_pty_shell_with_callback, spawn_pty_shell_with_seccomp, PtyError, PtyShellHandle,
    PtySyscallEvent,
};
pub use pty_multiplexer::{
    MultiplexerMode, PassthroughDetector, PtyMultiplexer, PtyMultiplexerConfig,
    PtyMultiplexerError, Verdict,
};
pub use seccomp::{
    extract_args_from_seccomp, kernel_supports_seccomp_notify, spawn_seccomp_shell,
    spawn_seccomp_shell_with_handler, syscall_event_from_request, syscall_name, AllowAllHandler,
    CallbackPolicyHandler, SeccompDecision, SeccompNotifier, SeccompNotifierError,
    SeccompPolicyHandler, SyscallCategory, SyscallInfo,
};

/// **DEPRECATED**: The `tracer` module is deprecated in favor of `seccomp-unotify`.
/// Do not use these exports. They will be removed in a future release.
///
/// See the `seccomp` module for the recommended approach to syscall interception.
#[deprecated(
    since = "0.7.0",
    note = "Use seccomp module instead. The tracer module is deprecated."
)]
#[doc(hidden)]
#[allow(deprecated)]
pub use tracer::{block_syscall, extract_args, kill_syscall, spawn_traced_shell, TracedProcess};

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "pattern")]
pub enum PolicyType {
    Simple(String),
    Regex(String),
    Executable(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Action {
    Allow,
    Block,
    Flag,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub enum PolicyContext {
    Shell,
    Network,
    Syscall,
    #[default]
    All,
}

/// Represents a syscall event captured by the tracer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    /// Name of the syscall (e.g., "open", "read", "write")
    pub syscall_name: String,
    /// System call number (architecture-specific)
    pub syscall_number: i64,
    /// String representation of syscall arguments
    pub args: Vec<String>,
    /// Process ID that made the syscall
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Timestamp of the event (ISO 8601 format)
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    #[serde(flatten)]
    pub match_type: PolicyType,
    pub action: Action,
    #[serde(default)]
    pub context: PolicyContext,
    /// If true, kill the traced process instead of returning EPERM.
    /// Use for critical violations where EPERM return isn't sufficient.
    #[serde(default)]
    pub kill: bool,
}

impl Policy {
    pub fn matches(&self, content: &str, regex_cache: &HashMap<String, Regex>) -> bool {
        match &self.match_type {
            PolicyType::Simple(pattern) => content.contains(pattern),
            PolicyType::Regex(_) => {
                if let Some(re) = regex_cache.get(&self.id) {
                    re.is_match(content)
                } else {
                    false
                }
            }
            PolicyType::Executable(command) => {
                let parts: Vec<&str> = command.split_whitespace().collect();
                if parts.is_empty() {
                    return false;
                }

                let program = parts[0];
                let args = &parts[1..];

                match Command::new(program)
                    .args(args)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                {
                    Ok(mut child) => {
                        if let Some(mut stdin) = child.stdin.take() {
                            if stdin.write_all(content.as_bytes()).is_err() {
                                return false;
                            }
                        }
                        match child.wait() {
                            Ok(status) => status.success(),
                            Err(_) => false,
                        }
                    }
                    Err(_) => false,
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub policies: Vec<String>,
    pub is_dynamic: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    // ========================================
    // PolicyType Tests
    // ========================================

    #[test]
    fn test_policy_type_simple_serialization() {
        let simple = PolicyType::Simple("DROP TABLE".to_string());
        let json = serde_json::to_string(&simple).unwrap();
        assert!(json.contains("Simple"));
        assert!(json.contains("DROP TABLE"));
    }

    #[test]
    fn test_policy_type_regex_serialization() {
        let regex = PolicyType::Regex("SELECT.*FROM".to_string());
        let json = serde_json::to_string(&regex).unwrap();
        assert!(json.contains("Regex"));
        assert!(json.contains("SELECT.*FROM"));
    }

    #[test]
    fn test_policy_type_executable_serialization() {
        let exec = PolicyType::Executable("/usr/bin/grep".to_string());
        let json = serde_json::to_string(&exec).unwrap();
        assert!(json.contains("Executable"));
        assert!(json.contains("/usr/bin/grep"));
    }

    #[test]
    fn test_policy_type_deserialization() {
        let json = r#"{"type":"Simple","pattern":"DROP TABLE"}"#;
        let policy_type: PolicyType = serde_json::from_str(json).unwrap();
        match policy_type {
            PolicyType::Simple(s) => assert_eq!(s, "DROP TABLE"),
            _ => panic!("Expected Simple variant"),
        }
    }

    // ========================================
    // Action Tests
    // ========================================

    #[test]
    fn test_action_equality() {
        assert_eq!(Action::Allow, Action::Allow);
        assert_eq!(Action::Block, Action::Block);
        assert_eq!(Action::Flag, Action::Flag);
        assert_ne!(Action::Allow, Action::Block);
    }

    #[test]
    fn test_action_serialization() {
        let allow = Action::Allow;
        let json = serde_json::to_string(&allow).unwrap();
        assert_eq!(json, r#""Allow""#);

        let block = Action::Block;
        let json = serde_json::to_string(&block).unwrap();
        assert_eq!(json, r#""Block""#);

        let flag = Action::Flag;
        let json = serde_json::to_string(&flag).unwrap();
        assert_eq!(json, r#""Flag""#);
    }

    #[test]
    fn test_action_deserialization() {
        let action: Action = serde_json::from_str(r#""Allow""#).unwrap();
        assert_eq!(action, Action::Allow);

        let action: Action = serde_json::from_str(r#""Block""#).unwrap();
        assert_eq!(action, Action::Block);

        let action: Action = serde_json::from_str(r#""Flag""#).unwrap();
        assert_eq!(action, Action::Flag);
    }

    // ========================================
    // PolicyContext Tests
    // ========================================

    #[test]
    fn test_policy_context_default() {
        let ctx = PolicyContext::default();
        assert_eq!(ctx, PolicyContext::All);
    }

    #[test]
    fn test_policy_context_serialization() {
        let ctx = PolicyContext::Shell;
        let json = serde_json::to_string(&ctx).unwrap();
        assert_eq!(json, r#""Shell""#);

        let ctx = PolicyContext::Network;
        let json = serde_json::to_string(&ctx).unwrap();
        assert_eq!(json, r#""Network""#);

        let ctx = PolicyContext::Syscall;
        let json = serde_json::to_string(&ctx).unwrap();
        assert_eq!(json, r#""Syscall""#);

        let ctx = PolicyContext::All;
        let json = serde_json::to_string(&ctx).unwrap();
        assert_eq!(json, r#""All""#);
    }

    #[test]
    fn test_policy_context_deserialization() {
        let ctx: PolicyContext = serde_json::from_str(r#""Shell""#).unwrap();
        assert_eq!(ctx, PolicyContext::Shell);

        let ctx: PolicyContext = serde_json::from_str(r#""Network""#).unwrap();
        assert_eq!(ctx, PolicyContext::Network);

        let ctx: PolicyContext = serde_json::from_str(r#""Syscall""#).unwrap();
        assert_eq!(ctx, PolicyContext::Syscall);

        let ctx: PolicyContext = serde_json::from_str(r#""All""#).unwrap();
        assert_eq!(ctx, PolicyContext::All);
    }

    // ========================================
    // SyscallEvent Tests
    // ========================================

    #[test]
    fn test_syscall_event_creation() {
        let event = SyscallEvent {
            syscall_name: "open".to_string(),
            syscall_number: 2,
            args: vec!["/etc/passwd".to_string(), "r".to_string()],
            pid: 1234,
            ppid: 1,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        assert_eq!(event.syscall_name, "open");
        assert_eq!(event.syscall_number, 2);
        assert_eq!(event.args.len(), 2);
        assert_eq!(event.pid, 1234);
        assert_eq!(event.ppid, 1);
    }

    #[test]
    fn test_syscall_event_serialization() {
        let event = SyscallEvent {
            syscall_name: "read".to_string(),
            syscall_number: 0,
            args: vec![],
            pid: 100,
            ppid: 99,
            timestamp: "2024-01-01T12:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("read"));
        assert!(json.contains("\"syscall_name\""));
        assert!(json.contains("\"syscall_number\":0"));
    }

    #[test]
    fn test_syscall_event_deserialization() {
        let json = r#"{
            "syscall_name": "write",
            "syscall_number": 1,
            "args": ["fd:3", "buf:0x7fff", "count:1024"],
            "pid": 42,
            "ppid": 1,
            "timestamp": "2024-06-15T10:30:00Z"
        }"#;

        let event: SyscallEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.syscall_name, "write");
        assert_eq!(event.syscall_number, 1);
        assert_eq!(event.args.len(), 3);
        assert_eq!(event.pid, 42);
    }

    // ========================================
    // Policy::matches() Tests
    // ========================================

    #[test]
    fn test_policy_matches_simple_found() {
        let policy = Policy {
            id: "test-1".to_string(),
            match_type: PolicyType::Simple("DROP".to_string()),
            action: Action::Block,
            context: PolicyContext::default(),
            kill: false,
        };

        let cache = HashMap::new();
        assert!(policy.matches("DROP TABLE users", &cache));
        assert!(policy.matches("Please DROP this file", &cache));
    }

    #[test]
    fn test_policy_matches_simple_not_found() {
        let policy = Policy {
            id: "test-2".to_string(),
            match_type: PolicyType::Simple("DELETE".to_string()),
            action: Action::Block,
            context: PolicyContext::default(),
            kill: false,
        };

        let cache = HashMap::new();
        assert!(!policy.matches("SELECT * FROM users", &cache));
        assert!(!policy.matches("INSERT INTO users", &cache));
    }

    #[test]
    fn test_policy_matches_simple_case_sensitive() {
        let policy = Policy {
            id: "test-3".to_string(),
            match_type: PolicyType::Simple("drop".to_string()),
            action: Action::Block,
            context: PolicyContext::default(),
            kill: false,
        };

        let cache = HashMap::new();
        assert!(policy.matches("drop table", &cache));
        assert!(!policy.matches("DROP TABLE", &cache)); // Case sensitive
    }

    #[test]
    fn test_policy_matches_simple_empty_pattern() {
        let policy = Policy {
            id: "test-4".to_string(),
            match_type: PolicyType::Simple("".to_string()),
            action: Action::Flag,
            context: PolicyContext::default(),
            kill: false,
        };

        let cache = HashMap::new();
        // Empty pattern matches everything (contains always returns true for empty)
        assert!(policy.matches("anything", &cache));
        assert!(policy.matches("", &cache));
    }

    #[test]
    fn test_policy_matches_simple_in_content() {
        let policy = Policy {
            id: "test-5".to_string(),
            match_type: PolicyType::Simple("secret".to_string()),
            action: Action::Flag,
            context: PolicyContext::default(),
            kill: false,
        };

        let cache = HashMap::new();
        assert!(policy.matches("show me the secret key", &cache));
        assert!(policy.matches("secret_password", &cache));
        assert!(!policy.matches("SECRET", &cache)); // Case sensitive
    }

    #[test]
    fn test_policy_matches_regex_basic() {
        let policy = Policy {
            id: "regex-1".to_string(),
            match_type: PolicyType::Regex("SELECT.*FROM".to_string()),
            action: Action::Block,
            context: PolicyContext::default(),
            kill: false,
        };

        let mut cache = HashMap::new();
        let re = Regex::new("SELECT.*FROM").unwrap();
        cache.insert("regex-1".to_string(), re);

        assert!(policy.matches("SELECT * FROM users", &cache));
        assert!(policy.matches("SELECT name FROM table", &cache));
        assert!(!policy.matches("INSERT INTO users", &cache));
    }

    #[test]
    fn test_policy_matches_regex_not_in_cache() {
        let policy = Policy {
            id: "regex-2".to_string(),
            match_type: PolicyType::Regex("pattern".to_string()),
            action: Action::Block,
            context: PolicyContext::default(),
            kill: false,
        };

        let cache = HashMap::new(); // Empty cache
                                    // When regex is not in cache, matches returns false
        assert!(!policy.matches("pattern matches", &cache));
    }

    #[test]
    fn test_policy_matches_regex_case_insensitive() {
        let policy = Policy {
            id: "regex-3".to_string(),
            match_type: PolicyType::Regex("(?i)password".to_string()),
            action: Action::Flag,
            context: PolicyContext::default(),
            kill: false,
        };

        let mut cache = HashMap::new();
        let re = Regex::new("(?i)password").unwrap();
        cache.insert("regex-3".to_string(), re);

        assert!(policy.matches("PASSWORD", &cache));
        assert!(policy.matches("Password", &cache));
        assert!(policy.matches("password123", &cache));
        assert!(!policy.matches("pass", &cache));
    }

    #[test]
    fn test_policy_matches_regex_special_chars() {
        let policy = Policy {
            id: "regex-4".to_string(),
            match_type: PolicyType::Regex(r"\d{3}-\d{4}".to_string()),
            action: Action::Flag,
            context: PolicyContext::default(),
            kill: false,
        };

        let mut cache = HashMap::new();
        let re = Regex::new(r"\d{3}-\d{4}").unwrap();
        cache.insert("regex-4".to_string(), re);

        assert!(policy.matches("Phone: 123-4567", &cache));
        assert!(policy.matches("SSN: 555-1234 end", &cache));
        assert!(!policy.matches("No match here", &cache));
    }

    #[test]
    fn test_policy_matches_executable_empty_command() {
        let policy = Policy {
            id: "exec-1".to_string(),
            match_type: PolicyType::Executable("".to_string()),
            action: Action::Block,
            context: PolicyContext::default(),
            kill: false,
        };

        let cache = HashMap::new();
        // Empty command should return false
        assert!(!policy.matches("test content", &cache));
    }

    #[test]
    fn test_policy_matches_executable_whitespace_only() {
        let policy = Policy {
            id: "exec-2".to_string(),
            match_type: PolicyType::Executable("   ".to_string()),
            action: Action::Block,
            context: PolicyContext::default(),
            kill: false,
        };

        let cache = HashMap::new();
        // Whitespace-only command should return false
        assert!(!policy.matches("test content", &cache));
    }

    #[test]
    fn test_policy_matches_executable_nonexistent_command() {
        let policy = Policy {
            id: "exec-3".to_string(),
            match_type: PolicyType::Executable("/nonexistent/command".to_string()),
            action: Action::Block,
            context: PolicyContext::default(),
            kill: false,
        };

        let cache = HashMap::new();
        // Non-existent command should return false
        assert!(!policy.matches("test content", &cache));
    }

    #[test]
    fn test_policy_matches_executable_success() {
        // Use /bin/true which should exist on all Unix systems
        let policy = Policy {
            id: "exec-4".to_string(),
            match_type: PolicyType::Executable("/bin/true".to_string()),
            action: Action::Allow,
            context: PolicyContext::default(),
            kill: false,
        };

        let cache = HashMap::new();
        // /bin/true always succeeds (exit code 0)
        // But it won't receive input since we pipe stdin
        // The matches() function returns true if exit code is 0
        assert!(policy.matches("", &cache));
    }

    #[test]
    fn test_policy_matches_executable_with_args() {
        // Use /bin/cat which echoes input back
        let policy = Policy {
            id: "exec-5".to_string(),
            match_type: PolicyType::Executable("/bin/cat".to_string()),
            action: Action::Allow,
            context: PolicyContext::default(),
            kill: false,
        };

        let cache = HashMap::new();
        // /bin/cat will succeed if it receives valid input
        assert!(policy.matches("test", &cache));
    }

    // ========================================
    // Policy Serialization Tests
    // ========================================

    #[test]
    fn test_policy_serialization() {
        let policy = Policy {
            id: "policy-1".to_string(),
            match_type: PolicyType::Simple("DROP".to_string()),
            action: Action::Block,
            context: PolicyContext::Shell,
            kill: false,
        };

        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("policy-1"));
        assert!(json.contains("DROP"));
        assert!(json.contains("Block"));
        assert!(json.contains("Shell"));
    }

    #[test]
    fn test_policy_deserialization() {
        let json = r#"{
            "id": "test-policy",
            "type": "Simple",
            "pattern": "secret",
            "action": "Flag",
            "context": "All",
            "kill": false
        }"#;

        let policy: Policy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.id, "test-policy");
        assert_eq!(policy.action, Action::Flag);
        assert_eq!(policy.context, PolicyContext::All);
        assert!(!policy.kill);
    }

    #[test]
    fn test_policy_default_context() {
        let json = r#"{
            "id": "no-context-policy",
            "type": "Simple",
            "pattern": "test",
            "action": "Allow",
            "kill": false
        }"#;

        let policy: Policy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.context, PolicyContext::All); // Default
    }

    #[test]
    fn test_policy_kill_field() {
        let json = r#"{
            "id": "kill-policy",
            "type": "Simple",
            "pattern": "danger",
            "action": "Block",
            "context": "Shell",
            "kill": true
        }"#;

        let policy: Policy = serde_json::from_str(json).unwrap();
        assert!(policy.kill);
    }

    // ========================================
    // Role Tests
    // ========================================

    #[test]
    fn test_role_creation() {
        let role = Role {
            name: "admin".to_string(),
            policies: vec!["policy-1".to_string(), "policy-2".to_string()],
            is_dynamic: false,
        };

        assert_eq!(role.name, "admin");
        assert_eq!(role.policies.len(), 2);
        assert!(!role.is_dynamic);
    }

    #[test]
    fn test_role_serialization() {
        let role = Role {
            name: "developer".to_string(),
            policies: vec!["read".to_string(), "write".to_string()],
            is_dynamic: true,
        };

        let json = serde_json::to_string(&role).unwrap();
        assert!(json.contains("developer"));
        assert!(json.contains("read"));
        assert!(json.contains("write"));
        assert!(json.contains("is_dynamic\":true"));
    }

    #[test]
    fn test_role_deserialization() {
        let json = r#"{
            "name": "guest",
            "policies": ["readonly"],
            "is_dynamic": false
        }"#;

        let role: Role = serde_json::from_str(json).unwrap();
        assert_eq!(role.name, "guest");
        assert_eq!(role.policies, vec!["readonly"]);
        assert!(!role.is_dynamic);
    }

    #[test]
    fn test_role_empty_policies() {
        let role = Role {
            name: "empty".to_string(),
            policies: vec![],
            is_dynamic: false,
        };

        assert!(role.policies.is_empty());
    }

    // ========================================
    // Edge Cases and Error Handling
    // ========================================

    #[test]
    fn test_syscall_event_empty_args() {
        let event = SyscallEvent {
            syscall_name: "getpid".to_string(),
            syscall_number: 39,
            args: vec![],
            pid: 1,
            ppid: 0,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        assert!(event.args.is_empty());
    }

    #[test]
    fn test_policy_action_clone() {
        let action = Action::Block;
        let cloned = action.clone();
        assert_eq!(action, cloned);
    }

    #[test]
    fn test_policy_type_clone() {
        let policy_type = PolicyType::Simple("test".to_string());
        let cloned = policy_type.clone();
        match cloned {
            PolicyType::Simple(s) => assert_eq!(s, "test"),
            _ => panic!("Expected Simple variant"),
        }
    }

    #[test]
    fn test_policy_clone() {
        let policy = Policy {
            id: "clone-test".to_string(),
            match_type: PolicyType::Regex(".*".to_string()),
            action: Action::Flag,
            context: PolicyContext::Network,
            kill: true,
        };

        let cloned = policy.clone();
        assert_eq!(policy.id, cloned.id);
        assert_eq!(policy.action, cloned.action);
        assert_eq!(policy.context, cloned.context);
        assert_eq!(policy.kill, cloned.kill);
    }
}
