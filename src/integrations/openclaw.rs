//! OpenClaw integration for Sevorix.
//!
//! This integration configures OpenClaw to use sevsh as its shell,
//! ensuring all Bash commands are validated through Sevorix.

use super::{InstallResult, Integration, IntegrationStatus};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::PathBuf;

/// OpenClaw integration.
///
/// Modifies `~/.openclaw/openclaw.json` to set the SHELL environment variable
/// to sevsh, ensuring all shell commands from OpenClaw are validated
/// through Sevorix.
pub struct OpenClawIntegration {
    /// Path to the sevsh binary.
    sevsh_path: PathBuf,
    /// Path to OpenClaw config.
    config_path: PathBuf,
    /// Path to Sevorix state directory for daemon check.
    state_dir: PathBuf,
}

impl OpenClawIntegration {
    /// Create a new OpenClaw integration instance.
    pub fn new() -> Result<Self> {
        let user_dirs = directories::UserDirs::new()
            .context("Could not determine user directories")?;

        let home = user_dirs.home_dir();
        let sevsh_path = home.join(".local/bin/sevsh");
        let config_path = home.join(".openclaw/openclaw.json");

        // Get Sevorix state directory for daemon check
        let proj_dirs = directories::ProjectDirs::from("com", "sevorix", "sevorix")
            .context("Could not determine project directories")?;
        let state_dir = proj_dirs
            .state_dir()
            .unwrap_or_else(|| proj_dirs.cache_dir())
            .to_path_buf();

        Ok(Self {
            sevsh_path,
            config_path,
            state_dir,
        })
    }

    /// Create a new instance with custom paths (for testing).
    #[cfg(test)]
    pub fn new_for_test(sevsh_path: PathBuf, config_path: PathBuf, state_dir: PathBuf) -> Self {
        Self {
            sevsh_path,
            config_path,
            state_dir,
        }
    }

    /// Check if the Sevorix daemon is running.
    fn is_daemon_running(&self) -> bool {
        let pid_path = self.state_dir.join("sevorix.pid");
        if let Ok(content) = std::fs::read_to_string(&pid_path) {
            if let Ok(pid) = content.trim().parse::<i32>() {
                // Check if process exists
                unsafe { libc::kill(pid, 0) == 0 }
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Check if sevsh is installed.
    fn is_sevsh_installed(&self) -> bool {
        self.sevsh_path.exists() && self.sevsh_path.is_file()
    }

    /// Create a backup of the config file if it exists.
    fn backup_config(&self) -> Result<Option<PathBuf>> {
        if !self.config_path.exists() {
            return Ok(None);
        }

        let backup_path = self.config_path.with_extension("json.backup");
        std::fs::copy(&self.config_path, &backup_path)
            .context("Failed to create config backup")?;

        Ok(Some(backup_path))
    }

    /// Read existing config or create new empty config.
    fn read_config(&self) -> Result<Value> {
        if self.config_path.exists() {
            let content = std::fs::read_to_string(&self.config_path)
                .context("Failed to read config file")?;
            // OpenClaw uses JSON5, but we parse as JSON (basic support)
            // JSON5 features like comments will be stripped
            let content = Self::strip_json5_extras(&content);
            serde_json::from_str(&content)
                .context("Failed to parse config JSON")
        } else {
            Ok(json!({}))
        }
    }

    /// Strip JSON5-specific syntax to make it parseable as JSON.
    fn strip_json5_extras(content: &str) -> String {
        content
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                // Remove single-line comments
                !trimmed.starts_with("//")
            })
            .map(|line| {
                // Remove trailing comments
                if let Some(pos) = line.find("//") {
                    &line[..pos]
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Write config to file.
    fn write_config(&self, config: &Value) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = self.config_path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create .openclaw directory")?;
        }

        let content = serde_json::to_string_pretty(config)
            .context("Failed to serialize config")?;
        std::fs::write(&self.config_path, content)
            .context("Failed to write config file")?;

        Ok(())
    }

    /// Get the sevsh path as a tilde-expanded string.
    fn sevsh_path_string(&self) -> String {
        // Use tilde notation for portability
        "~/.local/bin/sevsh".to_string()
    }
}

impl Integration for OpenClawIntegration {
    fn name(&self) -> &str {
        "OpenClaw"
    }

    fn description(&self) -> &str {
        "Configures OpenClaw to use sevsh as its shell for command validation"
    }

    fn is_installed(&self) -> bool {
        if !self.config_path.exists() {
            return false;
        }

        // Check if config contains our SHELL configuration in env
        if let Ok(config) = self.read_config() {
            // Check env.SHELL
            if let Some(env) = config.get("env") {
                if let Some(shell) = env.get("SHELL") {
                    if let Some(shell_str) = shell.as_str() {
                        return shell_str.contains("sevsh");
                    }
                }
            }
            // Also check models.providers.*.shell configuration
            // OpenClaw can have shell set at provider level
            if let Some(models) = config.get("models") {
                if let Some(models_obj) = models.as_object() {
                    for (_provider, config) in models_obj {
                        if let Some(config_obj) = config.as_object() {
                            if let Some(shell) = config_obj.get("shell") {
                                if let Some(shell_str) = shell.as_str() {
                                    if shell_str.contains("sevsh") {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        false
    }

    fn install(&self) -> Result<InstallResult> {
        let mut files_modified = Vec::new();
        let mut config_changes = Vec::new();

        // Pre-check: Verify daemon is running
        if !self.is_daemon_running() {
            anyhow::bail!(
                "Sevorix daemon is not running. Start it with 'sevorix start' first."
            );
        }

        // Pre-check: Verify sevsh is installed
        if !self.is_sevsh_installed() {
            anyhow::bail!(
                "sevsh is not installed at {}. Install it first.",
                self.sevsh_path.display()
            );
        }

        // Backup existing config if present
        let backup_path = self.backup_config()?;
        if backup_path.is_some() {
            config_changes.push(format!(
                "Backed up existing config to {:?}",
                backup_path.unwrap()
            ));
        }

        // Read existing config
        let mut config = self.read_config()?;

        // Get or create env object
        let env = config
            .get("env")
            .cloned()
            .unwrap_or_else(|| json!({}));

        let mut env_obj = env.as_object()
            .cloned()
            .unwrap_or_default();

        // Check if SHELL is already set
        let had_existing_shell = env_obj.contains_key("SHELL");
        if had_existing_shell {
            let old_shell = env_obj.get("SHELL")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            config_changes.push(format!("Replacing existing SHELL: {}", old_shell));
        }

        // Set SHELL to sevsh
        env_obj.insert("SHELL".to_string(), json!(self.sevsh_path_string()));

        // Update config
        if let Value::Object(ref mut map) = config {
            map.insert("env".to_string(), Value::Object(env_obj));
        }

        // Write updated config
        self.write_config(&config)?;
        files_modified.push(self.config_path.display().to_string());
        config_changes.push(format!(
            "Set SHELL to {} in ~/.openclaw/openclaw.json",
            self.sevsh_path_string()
        ));

        let message = if had_existing_shell {
            "OpenClaw integration installed (replaced existing SHELL setting)."
        } else {
            "OpenClaw integration installed. All shell commands from OpenClaw agents will now be validated through Sevorix."
        };

        Ok(InstallResult {
            files_modified,
            config_changes,
            restart_required: false,
            message: message.to_string(),
        })
    }

    fn uninstall(&self) -> Result<()> {
        if !self.config_path.exists() {
            return Ok(());
        }

        // Read current config
        let mut config = self.read_config()?;

        // Remove our SHELL setting from env
        if let Some(env) = config.get_mut("env") {
            if let Value::Object(ref mut env_map) = env {
                env_map.remove("SHELL");

                // If env is now empty, remove it entirely
                if env_map.is_empty() {
                    if let Value::Object(ref mut config_map) = config {
                        config_map.remove("env");
                    }
                }
            }
        }

        // Write updated config
        self.write_config(&config)?;

        println!("OpenClaw integration uninstalled.");
        println!("The SHELL setting has been removed from ~/.openclaw/openclaw.json");

        // Check for backup and offer to restore
        let backup_path = self.config_path.with_extension("json.backup");
        if backup_path.exists() {
            println!("Backup exists at: {}", backup_path.display());
            println!("To restore original config: mv {} {}",
                backup_path.display(),
                self.config_path.display()
            );
        }

        Ok(())
    }

    fn status(&self) -> IntegrationStatus {
        // Check pre-requisites
        if !self.is_daemon_running() {
            return IntegrationStatus::Corrupted {
                reason: "Sevorix daemon is not running".to_string(),
            };
        }

        if !self.is_sevsh_installed() {
            return IntegrationStatus::Corrupted {
                reason: format!("sevsh not found at {}", self.sevsh_path.display()),
            };
        }

        // Check installation status
        if self.is_installed() {
            IntegrationStatus::Installed
        } else {
            IntegrationStatus::NotInstalled
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_integration(temp_dir: &TempDir) -> OpenClawIntegration {
        let sevsh_path = temp_dir.path().join(".local/bin/sevsh");
        let config_path = temp_dir.path().join(".openclaw/openclaw.json");
        let state_dir = temp_dir.path().join(".local/state/sevorix");

        // Create sevsh binary mock
        if let Some(parent) = sevsh_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&sevsh_path, "#!/bin/bash\necho sevsh").unwrap();

        // Create state dir
        std::fs::create_dir_all(&state_dir).unwrap();

        OpenClawIntegration::new_for_test(sevsh_path, config_path, state_dir)
    }

    fn create_running_daemon(state_dir: &PathBuf) {
        let pid_path = state_dir.join("sevorix.pid");
        std::fs::write(&pid_path, std::process::id().to_string()).unwrap();
    }

    #[test]
    fn test_integration_name() {
        let integration = OpenClawIntegration::new().unwrap();
        assert_eq!(integration.name(), "OpenClaw");
    }

    #[test]
    fn test_sevsh_path() {
        let integration = OpenClawIntegration::new().unwrap();
        assert!(integration.sevsh_path_string().contains("sevsh"));
    }

    #[test]
    fn test_description() {
        let integration = OpenClawIntegration::new().unwrap();
        assert!(integration.description().contains("OpenClaw"));
        assert!(integration.description().contains("sevsh"));
    }

    #[test]
    fn test_is_installed_no_config_file() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        assert!(!integration.is_installed());
    }

    #[test]
    fn test_is_installed_empty_config() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        if let Some(parent) = integration.config_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.config_path, "{}").unwrap();

        assert!(!integration.is_installed());
    }

    #[test]
    fn test_is_installed_with_shell_in_env() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        if let Some(parent) = integration.config_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let config = r#"{"env": {"SHELL": "~/.local/bin/sevsh"}}"#;
        std::fs::write(&integration.config_path, config).unwrap();

        assert!(integration.is_installed());
    }

    #[test]
    fn test_is_installed_with_shell_in_provider() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        if let Some(parent) = integration.config_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let config = r#"{"models": {"claude": {"shell": "~/.local/bin/sevsh"}}}"#;
        std::fs::write(&integration.config_path, config).unwrap();

        assert!(integration.is_installed());
    }

    #[test]
    fn test_is_installed_with_different_shell() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        if let Some(parent) = integration.config_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let config = r#"{"env": {"SHELL": "/bin/sh"}}"#;
        std::fs::write(&integration.config_path, config).unwrap();

        assert!(!integration.is_installed());
    }

    #[test]
    fn test_is_installed_malformed_json() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        if let Some(parent) = integration.config_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.config_path, "not valid json").unwrap();

        assert!(!integration.is_installed());
    }

    #[test]
    fn test_strip_json5_extras_removes_comments() {
        let input = r#"{
  // This is a comment
  "key": "value",
  "nested": {
    // Another comment
    "inner": true
  }
}"#;

        let stripped = OpenClawIntegration::strip_json5_extras(input);
        assert!(!stripped.contains("// This is a comment"));
        assert!(!stripped.contains("// Another comment"));
        assert!(stripped.contains("\"key\": \"value\""));
    }

    #[test]
    fn test_strip_json5_extras_removes_trailing_comments() {
        let input = r#"{"key": "value" // trailing comment}"#;
        let stripped = OpenClawIntegration::strip_json5_extras(input);

        assert!(!stripped.contains("trailing comment"));
        assert!(stripped.contains("\"key\": \"value\""));
    }

    #[test]
    fn test_backup_config_creates_backup() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        if let Some(parent) = integration.config_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.config_path, r#"{"test": true}"#).unwrap();

        let backup_path = integration.backup_config().unwrap();
        assert!(backup_path.is_some());

        let backup = backup_path.unwrap();
        assert!(backup.exists());
        assert!(backup.to_str().unwrap().ends_with(".backup"));

        let content = std::fs::read_to_string(&backup).unwrap();
        assert_eq!(content, r#"{"test": true}"#);
    }

    #[test]
    fn test_backup_config_no_file() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        let backup_path = integration.backup_config().unwrap();
        assert!(backup_path.is_none());
    }

    #[test]
    fn test_read_config_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        if let Some(parent) = integration.config_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.config_path, r#"{"key": "value"}"#).unwrap();

        let config = integration.read_config().unwrap();
        assert_eq!(config["key"], "value");
    }

    #[test]
    fn test_read_config_with_json5_comments() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        if let Some(parent) = integration.config_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let config_with_comments = r#"{
  // Configuration
  "key": "value"
}"#;
        std::fs::write(&integration.config_path, config_with_comments).unwrap();

        let config = integration.read_config().unwrap();
        assert_eq!(config["key"], "value");
    }

    #[test]
    fn test_read_config_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        let config = integration.read_config().unwrap();
        assert!(config.is_object());
        assert!(config.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_write_config_creates_file() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        let config = json!({"env": {"SHELL": "test"}});
        integration.write_config(&config).unwrap();

        assert!(integration.config_path.exists());

        let content = std::fs::read_to_string(&integration.config_path).unwrap();
        assert!(content.contains("SHELL"));
    }

    #[test]
    fn test_is_daemon_running_no_pid_file() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        assert!(!integration.is_daemon_running());
    }

    #[test]
    fn test_is_daemon_running_with_valid_pid() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);

        assert!(integration.is_daemon_running());
    }

    #[test]
    fn test_is_daemon_running_with_invalid_pid() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        let pid_path = integration.state_dir.join("sevorix.pid");
        std::fs::write(&pid_path, "999999999").unwrap();

        assert!(!integration.is_daemon_running());
    }

    #[test]
    fn test_is_sevsh_installed_true() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        assert!(integration.is_sevsh_installed());
    }

    #[test]
    fn test_is_sevsh_installed_false() {
        let temp_dir = TempDir::new().unwrap();
        let sevsh_path = temp_dir.path().join(".local/bin/sevsh");
        let config_path = temp_dir.path().join(".openclaw/openclaw.json");
        let state_dir = temp_dir.path().join(".local/state/sevorix");

        std::fs::create_dir_all(&state_dir).unwrap();

        let integration = OpenClawIntegration::new_for_test(sevsh_path, config_path, state_dir);
        assert!(!integration.is_sevsh_installed());
    }

    #[test]
    fn test_status_corrupted_daemon_not_running() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        let status = integration.status();
        assert!(matches!(status, IntegrationStatus::Corrupted { .. }));

        if let IntegrationStatus::Corrupted { reason } = status {
            assert!(reason.contains("daemon"));
        }
    }

    #[test]
    fn test_status_corrupted_sevsh_not_installed() {
        let temp_dir = TempDir::new().unwrap();
        let sevsh_path = temp_dir.path().join(".local/bin/sevsh");
        let config_path = temp_dir.path().join(".openclaw/openclaw.json");
        let state_dir = temp_dir.path().join(".local/state/sevorix");

        std::fs::create_dir_all(&state_dir).unwrap();
        create_running_daemon(&state_dir);

        let integration = OpenClawIntegration::new_for_test(sevsh_path, config_path, state_dir);
        let status = integration.status();

        assert!(matches!(status, IntegrationStatus::Corrupted { .. }));
        if let IntegrationStatus::Corrupted { reason } = status {
            assert!(reason.contains("sevsh"));
        }
    }

    #[test]
    fn test_status_not_installed() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);

        let status = integration.status();
        assert_eq!(status, IntegrationStatus::NotInstalled);
    }

    #[test]
    fn test_status_installed() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);

        if let Some(parent) = integration.config_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let config = r#"{"env": {"SHELL": "~/.local/bin/sevsh"}}"#;
        std::fs::write(&integration.config_path, config).unwrap();

        let status = integration.status();
        assert_eq!(status, IntegrationStatus::Installed);
    }

    #[test]
    fn test_install_fails_no_daemon() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        let result = integration.install();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("daemon"));
    }

    #[test]
    fn test_install_success() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);

        let result = integration.install().unwrap();
        assert!(result.files_modified.len() > 0);
        assert!(result.message.contains("OpenClaw"));

        // Verify config was written
        assert!(integration.config_path.exists());
        let config = std::fs::read_to_string(&integration.config_path).unwrap();
        assert!(config.contains("sevsh"));
    }

    #[test]
    fn test_install_replaces_existing_shell() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);

        if let Some(parent) = integration.config_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.config_path, r#"{"env": {"SHELL": "/bin/csh"}}"#).unwrap();

        let result = integration.install().unwrap();
        assert!(result.config_changes.iter().any(|c| c.contains("Replacing")));

        let config = integration.read_config().unwrap();
        assert_eq!(config["env"]["SHELL"], "~/.local/bin/sevsh");
    }

    #[test]
    fn test_install_creates_backup() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);

        if let Some(parent) = integration.config_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.config_path, r#"{"existing": true}"#).unwrap();

        let result = integration.install().unwrap();
        assert!(result.config_changes.iter().any(|c| c.contains("Backed up")));

        let backup_path = integration.config_path.with_extension("json.backup");
        assert!(backup_path.exists());
    }

    #[test]
    fn test_uninstall_removes_shell_setting() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        if let Some(parent) = integration.config_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.config_path, r#"{"env": {"SHELL": "~/.local/bin/sevsh", "DEBUG": "1"}}"#).unwrap();

        integration.uninstall().unwrap();

        let config = integration.read_config().unwrap();
        assert!(!config["env"].get("SHELL").is_some());
        assert_eq!(config["env"]["DEBUG"], "1");
    }

    #[test]
    fn test_uninstall_removes_empty_env() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        if let Some(parent) = integration.config_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.config_path, r#"{"env": {"SHELL": "~/.local/bin/sevsh"}}"#).unwrap();

        integration.uninstall().unwrap();

        let config = integration.read_config().unwrap();
        assert!(!config.get("env").is_some());
    }

    #[test]
    fn test_uninstall_no_config_file() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        integration.uninstall().unwrap();
    }

    #[test]
    fn test_install_preserves_other_config() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);

        if let Some(parent) = integration.config_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.config_path, r#"{"providers": ["openai", "anthropic"], "default": "claude"}"#).unwrap();

        integration.install().unwrap();

        let config = integration.read_config().unwrap();
        assert_eq!(config["default"], "claude");
        assert_eq!(config["env"]["SHELL"], "~/.local/bin/sevsh");
    }

    #[test]
    fn test_is_installed_checks_multiple_providers() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        if let Some(parent) = integration.config_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let config = r#"{
  "models": {
    "provider1": {"model": "gpt-4"},
    "provider2": {"shell": "~/.local/bin/sevsh"}
  }
}"#;
        std::fs::write(&integration.config_path, config).unwrap();

        assert!(integration.is_installed());
    }
}