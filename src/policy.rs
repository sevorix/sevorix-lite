// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

#![allow(dead_code)]

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs;

pub use sevorix_core::{Action, Policy, PolicyContext, PolicyType, Role};

#[derive(Debug, Clone, PartialEq)]
pub enum PolicySource {
    BuiltIn,
    User,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub policy_id: String,
    pub action: Action,
    /// If true, kill the traced process instead of returning EPERM.
    pub kill: bool,
    pub source: PolicySource,
}

#[derive(Debug, Serialize, Deserialize)]
struct PolicyConfig {
    policies: Vec<Policy>,
    roles: Vec<Role>,
}

pub struct Engine {
    pub policies: HashMap<String, Policy>,
    pub roles: HashMap<String, Role>,
    regex_cache: HashMap<String, Regex>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    #[allow(clippy::let_and_return)] // `let engine` is needed in pro to shadow as mut
    pub fn new() -> Self {
        let engine = Self {
            policies: HashMap::new(),
            roles: HashMap::new(),
            regex_cache: HashMap::new(),
        };
        engine
    }

    pub fn add_policy(&mut self, policy: Policy) {
        if let PolicyType::Regex(ref pattern) = policy.match_type {
            if let Ok(re) = Regex::new(pattern) {
                self.regex_cache.insert(policy.id.clone(), re);
            } else {
                tracing::error!("Failed to compile regex for policy: {}", policy.id);
            }
        }
        self.policies.insert(policy.id.clone(), policy);
    }

    fn check_policy_set<'a>(
        policies: impl Iterator<Item = &'a Policy>,
        regex_cache: &HashMap<String, Regex>,
        content: &str,
        context: PolicyContext,
        source: PolicySource,
    ) -> Option<Decision> {
        let mut flagged: Option<Decision> = None;
        for policy in policies {
            let should_check = match context {
                PolicyContext::All => true,
                _ => policy.context == PolicyContext::All || policy.context == context,
            };
            if !should_check {
                continue;
            }
            if policy.matches(content, regex_cache) {
                match policy.action {
                    Action::Block => {
                        return Some(Decision {
                            policy_id: policy.id.clone(),
                            action: Action::Block,
                            kill: policy.kill,
                            source,
                        });
                    }
                    Action::Flag => {
                        if flagged.is_none() {
                            flagged = Some(Decision {
                                policy_id: policy.id.clone(),
                                action: Action::Flag,
                                kill: policy.kill,
                                source: source.clone(),
                            });
                        }
                    }
                    Action::Allow => {}
                }
            }
        }
        flagged
    }

    pub fn add_role(&mut self, role: Role) {
        self.roles.insert(role.name.clone(), role);
    }

    /// Look up a compiled regex for a policy by ID.
    pub fn get_regex(&self, policy_id: &str) -> Option<&Regex> {
        self.regex_cache.get(policy_id)
    }

    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn Error>> {
        let content = fs::read_to_string(path)?;
        let config: PolicyConfig = serde_json::from_str(&content)?;

        let mut engine = Self::new();

        for policy in config.policies {
            engine.add_policy(policy);
        }

        for role in config.roles {
            engine.add_role(role);
        }

        Ok(engine)
    }

    pub fn load_policies_from_dir(&mut self, path: &std::path::Path) -> Result<(), Box<dyn Error>> {
        if !path.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let content = fs::read_to_string(&path)?;
                // Try Vec<Policy>
                if let Ok(policies) = serde_json::from_str::<Vec<Policy>>(&content) {
                    for policy in policies {
                        policy
                            .validate()
                            .map_err(|e| format!("{} (in {})", e, path.display()))?;
                        policy.warn_if_suspicious();
                        self.add_policy(policy);
                    }
                } else if let Ok(policy) = serde_json::from_str::<Policy>(&content) {
                    policy
                        .validate()
                        .map_err(|e| format!("{} (in {})", e, path.display()))?;
                    policy.warn_if_suspicious();
                    self.add_policy(policy);
                } else {
                    tracing::warn!("Warning: Failed to parse policy file: {}", path.display());
                }
            }
        }
        Ok(())
    }

    pub fn load_roles_from_dir(&mut self, path: &std::path::Path) -> Result<(), Box<dyn Error>> {
        if !path.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let content = fs::read_to_string(&path)?;
                // Try Vec<Role>
                if let Ok(roles) = serde_json::from_str::<Vec<Role>>(&content) {
                    for role in roles {
                        self.add_role(role);
                    }
                } else if let Ok(role) = serde_json::from_str::<Role>(&content) {
                    self.add_role(role);
                } else {
                    tracing::warn!("Warning: Failed to parse role file: {}", path.display());
                }
            }
        }
        Ok(())
    }

    pub fn retain_roles(&mut self, allowed_roles: &[String]) {
        self.roles.retain(|name, _| allowed_roles.contains(name));
    }

    pub fn merge(&mut self, other: Engine) {
        for (_, policy) in other.policies {
            self.add_policy(policy);
        }
        for (_, role) in other.roles {
            self.add_role(role);
        }
    }

    pub fn check(&self, content: &str, context: PolicyContext) -> Option<Decision> {
        // Built-in policies always run first and cannot be overridden (pro only).

        Self::check_policy_set(
            self.policies.values(),
            &self.regex_cache,
            content,
            context,
            PolicySource::User,
        )
    }

    pub fn check_role(
        &self,
        role_name: &str,
        content: &str,
        context: PolicyContext,
    ) -> Option<Decision> {
        // Built-in policies always apply regardless of role (pro only).

        let role = self.roles.get(role_name)?;

        let mut flagged: Option<Decision> = None;

        for policy_id in &role.policies {
            if let Some(policy) = self.policies.get(policy_id) {
                let should_check = match context {
                    PolicyContext::All => true,
                    _ => policy.context == PolicyContext::All || policy.context == context,
                };

                if !should_check {
                    continue;
                }

                let matched = policy.matches(content, &self.regex_cache);

                if matched {
                    match policy.action {
                        Action::Block => {
                            return Some(Decision {
                                policy_id: policy.id.clone(),
                                action: Action::Block,
                                kill: policy.kill,
                                source: PolicySource::User,
                            });
                        }
                        Action::Flag => {
                            if flagged.is_none() {
                                flagged = Some(Decision {
                                    policy_id: policy.id.clone(),
                                    action: Action::Flag,
                                    kill: policy.kill,
                                    source: PolicySource::User,
                                });
                            }
                        }
                        Action::Allow => {}
                    }
                }
            }
        }

        flagged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_context() {
        let mut engine = Engine::new();
        engine.policies.insert(
            "p_shell".to_string(),
            Policy {
                id: "p_shell".to_string(),
                match_type: PolicyType::Simple("rm".to_string()),
                action: Action::Block,
                context: PolicyContext::Shell,
                kill: false,
                syscall: vec![],
            },
        );
        engine.policies.insert(
            "p_net".to_string(),
            Policy {
                id: "p_net".to_string(),
                match_type: PolicyType::Simple("curl".to_string()),
                action: Action::Block,
                context: PolicyContext::Network,
                kill: false,
                syscall: vec![],
            },
        );
        engine.policies.insert(
            "p_all".to_string(),
            Policy {
                id: "p_all".to_string(),
                match_type: PolicyType::Simple("bad".to_string()),
                action: Action::Block,
                context: PolicyContext::All,
                kill: false,
                syscall: vec![],
            },
        );

        let d = engine.check("rm -rf", PolicyContext::Shell);
        assert!(d.is_some(), "Shell policy should trigger in Shell check");

        let d = engine.check("curl google.com", PolicyContext::Shell);
        assert!(
            d.is_none(),
            "Network policy should NOT trigger in Shell check"
        );

        let d = engine.check("bad", PolicyContext::Shell);
        assert!(d.is_some(), "All policy should trigger in Shell check");

        let d = engine.check("rm -rf", PolicyContext::Network);
        assert!(
            d.is_none(),
            "Shell policy should NOT trigger in Network check"
        );

        let d = engine.check("curl google.com", PolicyContext::Network);
        assert!(
            d.is_some(),
            "Network policy should trigger in Network check"
        );

        let d = engine.check("rm -rf", PolicyContext::All);
        assert!(d.is_some(), "Shell policy should trigger in All check");

        let d = engine.check("curl google.com", PolicyContext::All);
        assert!(d.is_some(), "Network policy should trigger in All check");
    }

    #[test]
    fn test_load_config() {
        let config_json = r#"{
            "policies": [
                {
                    "id": "p1",
                    "type": "Simple",
                    "pattern": "bad_word",
                    "action": "Block"
                },
                {
                    "id": "p2",
                    "type": "Regex",
                    "pattern": "secret\\d+",
                    "action": "Flag"
                }
            ],
            "roles": [
                {
                    "name": "admin",
                    "policies": ["p1", "p2"],
                    "is_dynamic": false
                }
            ]
        }"#;

        let config: PolicyConfig =
            serde_json::from_str(config_json).expect("Failed to deserialize");
        assert_eq!(config.policies.len(), 2);
        assert_eq!(config.roles.len(), 1);
    }

    #[test]
    fn test_engine_check() {
        let mut engine = Engine::new();
        engine.policies.insert(
            "p1".to_string(),
            Policy {
                id: "p1".to_string(),
                match_type: PolicyType::Simple("bad".to_string()),
                action: Action::Block,
                context: PolicyContext::All,
                kill: false,
                syscall: vec![],
            },
        );

        let decision = engine.check("this contains bad word", PolicyContext::All);
        assert!(decision.is_some());
        assert_eq!(decision.unwrap().action, Action::Block);

        let decision_safe = engine.check("this is safe", PolicyContext::All);
        assert!(decision_safe.is_none());
    }

    #[test]
    fn test_check_role_isolation() {
        let mut engine = Engine::new();
        engine.policies.insert(
            "p1".to_string(),
            Policy {
                id: "p1".to_string(),
                match_type: PolicyType::Simple("bad".to_string()),
                action: Action::Block,
                context: PolicyContext::All,
                kill: false,
                syscall: vec![],
            },
        );
        engine.policies.insert(
            "p2".to_string(),
            Policy {
                id: "p2".to_string(),
                match_type: PolicyType::Simple("worse".to_string()),
                action: Action::Block,
                context: PolicyContext::All,
                kill: false,
                syscall: vec![],
            },
        );

        engine.roles.insert(
            "r1".to_string(),
            Role {
                name: "r1".to_string(),
                policies: vec!["p1".to_string()],
                is_dynamic: false,
            },
        );

        let d1 = engine.check_role("r1", "this is bad", PolicyContext::All);
        assert!(d1.is_some());
        assert_eq!(d1.unwrap().policy_id, "p1");

        let d2 = engine.check_role("r1", "this is worse", PolicyContext::All);
        assert!(d2.is_none());

        let d3 = engine.check("this is worse", PolicyContext::All);
        assert!(d3.is_some());
    }

    #[test]
    fn test_regex_policy() {
        let mut engine = Engine::new();
        let pid = "p_regex".to_string();
        engine.policies.insert(
            pid.clone(),
            Policy {
                id: pid.clone(),
                match_type: PolicyType::Regex("\\d{3}".to_string()),
                action: Action::Flag,
                context: PolicyContext::All,
                kill: false,
                syscall: vec![],
            },
        );
        engine
            .regex_cache
            .insert(pid.clone(), Regex::new("\\d{3}").unwrap());

        let decision = engine.check("contains 123 number", PolicyContext::All);
        assert!(decision.is_some());
        assert_eq!(decision.unwrap().action, Action::Flag);
    }

    #[test]
    fn test_executable_policy() {
        let mut engine = Engine::new();
        let pid = "p_exec".to_string();

        engine.policies.insert(
            pid.clone(),
            Policy {
                id: pid.clone(),
                match_type: PolicyType::Executable("grep -q forbidden".to_string()),
                action: Action::Block,
                context: PolicyContext::All,
                kill: false,
                syscall: vec![],
            },
        );

        let decision = engine.check("this is forbidden content", PolicyContext::All);
        assert!(decision.is_some());
        assert_eq!(decision.unwrap().action, Action::Block);

        let decision_safe = engine.check("this is allowed content", PolicyContext::All);
        assert!(decision_safe.is_none());
    }

    #[test]
    fn test_add_policy_with_invalid_regex() {
        let mut engine = Engine::new();
        let policy = Policy {
            id: "bad_regex".to_string(),
            match_type: PolicyType::Regex("[invalid(".to_string()),
            action: Action::Block,
            context: PolicyContext::All,
            kill: false,
            syscall: vec![],
        };

        // Should not panic, just log error and not cache regex
        engine.add_policy(policy);
        assert!(engine.policies.contains_key("bad_regex"));
        assert!(!engine.regex_cache.contains_key("bad_regex"));
    }

    #[test]
    fn test_add_policy_with_valid_regex() {
        let mut engine = Engine::new();
        let policy = Policy {
            id: "good_regex".to_string(),
            match_type: PolicyType::Regex("\\d+".to_string()),
            action: Action::Block,
            context: PolicyContext::All,
            kill: false,
            syscall: vec![],
        };

        engine.add_policy(policy);
        assert!(engine.policies.contains_key("good_regex"));
        assert!(engine.regex_cache.contains_key("good_regex"));
    }

    #[test]
    fn test_add_role() {
        let mut engine = Engine::new();
        let role = Role {
            name: "admin".to_string(),
            policies: vec!["p1".to_string()],
            is_dynamic: false,
        };

        engine.add_role(role);
        assert!(engine.roles.contains_key("admin"));
    }

    #[test]
    fn test_retain_roles() {
        let mut engine = Engine::new();
        engine.roles.insert(
            "admin".to_string(),
            Role {
                name: "admin".to_string(),
                policies: vec![],
                is_dynamic: false,
            },
        );
        engine.roles.insert(
            "user".to_string(),
            Role {
                name: "user".to_string(),
                policies: vec![],
                is_dynamic: false,
            },
        );
        engine.roles.insert(
            "guest".to_string(),
            Role {
                name: "guest".to_string(),
                policies: vec![],
                is_dynamic: false,
            },
        );

        engine.retain_roles(&["admin".to_string(), "user".to_string()]);

        assert!(engine.roles.contains_key("admin"));
        assert!(engine.roles.contains_key("user"));
        assert!(!engine.roles.contains_key("guest"));
    }

    #[test]
    fn test_merge_engines() {
        let mut engine1 = Engine::new();
        engine1.policies.insert(
            "p1".to_string(),
            Policy {
                id: "p1".to_string(),
                match_type: PolicyType::Simple("bad".to_string()),
                action: Action::Block,
                context: PolicyContext::All,
                kill: false,
                syscall: vec![],
            },
        );
        engine1.roles.insert(
            "r1".to_string(),
            Role {
                name: "r1".to_string(),
                policies: vec!["p1".to_string()],
                is_dynamic: false,
            },
        );

        let mut engine2 = Engine::new();
        engine2.policies.insert(
            "p2".to_string(),
            Policy {
                id: "p2".to_string(),
                match_type: PolicyType::Simple("worse".to_string()),
                action: Action::Flag,
                context: PolicyContext::All,
                kill: false,
                syscall: vec![],
            },
        );
        engine2.roles.insert(
            "r2".to_string(),
            Role {
                name: "r2".to_string(),
                policies: vec!["p2".to_string()],
                is_dynamic: false,
            },
        );

        engine1.merge(engine2);

        assert!(engine1.policies.contains_key("p1"));
        assert!(engine1.policies.contains_key("p2"));
        assert!(engine1.roles.contains_key("r1"));
        assert!(engine1.roles.contains_key("r2"));
    }

    #[test]
    fn test_check_returns_first_block() {
        let mut engine = Engine::new();
        engine.policies.insert(
            "flag1".to_string(),
            Policy {
                id: "flag1".to_string(),
                match_type: PolicyType::Simple("test".to_string()),
                action: Action::Flag,
                context: PolicyContext::All,
                kill: false,
                syscall: vec![],
            },
        );
        engine.policies.insert(
            "block1".to_string(),
            Policy {
                id: "block1".to_string(),
                match_type: PolicyType::Simple("test".to_string()),
                action: Action::Block,
                context: PolicyContext::All,
                kill: false,
                syscall: vec![],
            },
        );

        // Block should take precedence
        let decision = engine.check("test content", PolicyContext::All);
        assert!(decision.is_some());
        assert_eq!(decision.unwrap().action, Action::Block);
    }

    #[test]
    fn test_check_returns_flag_if_no_block() {
        let mut engine = Engine::new();
        engine.policies.insert(
            "flag1".to_string(),
            Policy {
                id: "flag1".to_string(),
                match_type: PolicyType::Simple("test".to_string()),
                action: Action::Flag,
                context: PolicyContext::All,
                kill: false,
                syscall: vec![],
            },
        );

        let decision = engine.check("test content", PolicyContext::All);
        assert!(decision.is_some());
        assert_eq!(decision.unwrap().action, Action::Flag);
    }

    #[test]
    fn test_check_returns_none_for_allow() {
        let mut engine = Engine::new();
        engine.policies.insert(
            "allow1".to_string(),
            Policy {
                id: "allow1".to_string(),
                match_type: PolicyType::Simple("test".to_string()),
                action: Action::Allow,
                context: PolicyContext::All,
                kill: false,
                syscall: vec![],
            },
        );

        let decision = engine.check("test content", PolicyContext::All);
        assert!(decision.is_none());
    }

    #[test]
    fn test_check_role_returns_none_for_unknown_role() {
        let engine = Engine::new();

        let decision = engine.check_role("nonexistent", "test", PolicyContext::All);
        assert!(decision.is_none());
    }

    #[test]
    fn test_check_kill_flag_propagates() {
        let mut engine = Engine::new();
        engine.policies.insert(
            "kill_policy".to_string(),
            Policy {
                id: "kill_policy".to_string(),
                match_type: PolicyType::Simple("killme".to_string()),
                action: Action::Block,
                context: PolicyContext::All,
                kill: true,
                syscall: vec![],
            },
        );
        engine.roles.insert(
            "default".to_string(),
            Role {
                name: "default".to_string(),
                policies: vec!["kill_policy".to_string()],
                is_dynamic: false,
            },
        );

        let decision = engine.check("killme", PolicyContext::All);
        assert!(decision.is_some());
        assert!(decision.as_ref().unwrap().kill);
    }

    #[test]
    fn test_check_role_context_filtering() {
        let mut engine = Engine::new();
        engine.policies.insert(
            "shell_only".to_string(),
            Policy {
                id: "shell_only".to_string(),
                match_type: PolicyType::Simple("rm".to_string()),
                action: Action::Block,
                context: PolicyContext::Shell,
                kill: false,
                syscall: vec![],
            },
        );
        engine.roles.insert(
            "default".to_string(),
            Role {
                name: "default".to_string(),
                policies: vec!["shell_only".to_string()],
                is_dynamic: false,
            },
        );

        // Should match in Shell context
        let decision = engine.check_role("default", "rm -rf", PolicyContext::Shell);
        assert!(decision.is_some());

        // Should NOT match in Network context
        let decision = engine.check_role("default", "rm -rf", PolicyContext::Network);
        assert!(decision.is_none());
    }

    #[test]
    fn test_default_engine() {
        let engine = Engine::default();
        assert!(engine.policies.is_empty());
        assert!(engine.roles.is_empty());
        assert!(engine.regex_cache.is_empty());
    }
}

#[test]
fn test_load_from_file() {
    use std::io::Write;
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let path = dir.path().join("policies.json");

    let content = r#"{
            "policies": [
                {
                    "id": "file_policy",
                    "type": "Simple",
                    "pattern": "dangerous",
                    "action": "Block"
                }
            ],
            "roles": [
                {
                    "name": "test_role",
                    "policies": ["file_policy"],
                    "is_dynamic": false
                }
            ]
        }"#;

    let mut file = std::fs::File::create(&path).expect("Failed to create file");
    file.write_all(content.as_bytes()).expect("Failed to write");

    let engine = Engine::load_from_file(path.to_str().unwrap()).expect("Failed to load");

    assert!(engine.policies.contains_key("file_policy"));
    assert!(engine.roles.contains_key("test_role"));
}

#[test]
fn test_load_from_file_missing() {
    let result = Engine::load_from_file("/nonexistent/path/policies.json");
    assert!(result.is_err());
}

#[test]
fn test_load_policies_from_dir() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let policy_path = dir.path().join("policy1.json");

    let content = r#"{
            "id": "dir_policy",
            "type": "Simple",
            "pattern": "test",
            "action": "Flag"
        }"#;

    std::fs::write(&policy_path, content).expect("Failed to write");

    let mut engine = Engine::new();
    engine
        .load_policies_from_dir(dir.path())
        .expect("Failed to load");

    assert!(engine.policies.contains_key("dir_policy"));
}

#[test]
fn test_load_policies_from_dir_multiple() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");

    // Write array of policies
    let policy_path = dir.path().join("policies.json");
    let content = r#"[
            {"id": "p1", "type": "Simple", "pattern": "a", "action": "Block"},
            {"id": "p2", "type": "Simple", "pattern": "b", "action": "Flag"}
        ]"#;
    std::fs::write(&policy_path, content).expect("Failed to write");

    let mut engine = Engine::new();
    engine
        .load_policies_from_dir(dir.path())
        .expect("Failed to load");

    assert!(engine.policies.contains_key("p1"));
    assert!(engine.policies.contains_key("p2"));
}

#[test]
fn test_load_policies_from_nonexistent_dir() {
    let mut engine = Engine::new();
    let result = engine.load_policies_from_dir(std::path::Path::new("/nonexistent/dir"));
    assert!(result.is_ok()); // Should not error on nonexistent dir
}

#[test]
fn test_load_roles_from_dir() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let role_path = dir.path().join("role.json");

    let content = r#"{
            "name": "dir_role",
            "policies": ["p1"],
            "is_dynamic": false
        }"#;

    std::fs::write(&role_path, content).expect("Failed to write");

    let mut engine = Engine::new();
    engine
        .load_roles_from_dir(dir.path())
        .expect("Failed to load");

    assert!(engine.roles.contains_key("dir_role"));
}

#[test]
fn test_load_roles_from_dir_multiple() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");

    let role_path = dir.path().join("roles.json");
    let content = r#"[
            {"name": "r1", "policies": [], "is_dynamic": false},
            {"name": "r2", "policies": [], "is_dynamic": true}
        ]"#;
    std::fs::write(&role_path, content).expect("Failed to write");

    let mut engine = Engine::new();
    engine
        .load_roles_from_dir(dir.path())
        .expect("Failed to load");

    assert!(engine.roles.contains_key("r1"));
    assert!(engine.roles.contains_key("r2"));
}

#[test]
fn test_load_roles_from_nonexistent_dir() {
    let mut engine = Engine::new();
    let result = engine.load_roles_from_dir(std::path::Path::new("/nonexistent/dir"));
    assert!(result.is_ok());
}

#[test]
fn test_load_policies_ignores_non_json() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");

    // Create non-JSON file
    let txt_path = dir.path().join("policy.txt");
    std::fs::write(&txt_path, "not json").expect("Failed to write");

    let mut engine = Engine::new();
    let result = engine.load_policies_from_dir(dir.path());
    assert!(result.is_ok());
    assert!(engine.policies.is_empty()); // No policies loaded
}

#[test]
fn test_load_roles_ignores_invalid_json() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");

    let role_path = dir.path().join("invalid.json");
    std::fs::write(&role_path, "not valid json").expect("Failed to write");

    let mut engine = Engine::new();
    let result = engine.load_roles_from_dir(dir.path());
    assert!(result.is_ok()); // Should not error, just warn
}
