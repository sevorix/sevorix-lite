//! Claude Code integration for Sevorix.
//!
//! This integration configures Claude Code to use sevsh as its shell,
//! ensuring all Bash commands are validated through Sevorix.

use super::{InstallResult, Integration, IntegrationStatus};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::PathBuf;

/// Claude Code integration.
///
/// Modifies `~/.claude/settings.json` to set the SHELL environment variable
/// to sevsh, ensuring all Bash commands from Claude Code are validated
/// through Sevorix.
pub struct ClaudeCodeIntegration {
    /// Path to the sevsh binary.
    sevsh_path: PathBuf,
    /// Path to Claude Code settings.
    settings_path: PathBuf,
    /// Path to Sevorix state directory for PID check.
    state_dir: PathBuf,
}

impl ClaudeCodeIntegration {
    /// Create a new Claude Code integration instance.
    pub fn new() -> Result<Self> {
        let user_dirs = directories::UserDirs::new()
            .context("Could not determine user directories")?;

        let home = user_dirs.home_dir();
        let sevsh_path = home.join(".local/bin/sevsh");
        let settings_path = home.join(".claude/settings.json");

        // Get Sevorix state directory for daemon check
        let proj_dirs = directories::ProjectDirs::from("com", "sevorix", "sevorix")
            .context("Could not determine project directories")?;
        let state_dir = proj_dirs
            .state_dir()
            .unwrap_or_else(|| proj_dirs.cache_dir())
            .to_path_buf();

        Ok(Self {
            sevsh_path,
            settings_path,
            state_dir,
        })
    }

    /// Create a new instance with custom paths (for testing).
    #[cfg(test)]
    pub fn new_for_test(sevsh_path: PathBuf, settings_path: PathBuf, state_dir: PathBuf) -> Self {
        Self {
            sevsh_path,
            settings_path,
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

    /// Create a backup of the settings file if it exists.
    fn backup_settings(&self) -> Result<Option<PathBuf>> {
        if !self.settings_path.exists() {
            return Ok(None);
        }

        let backup_path = self.settings_path.with_extension("json.backup");
        std::fs::copy(&self.settings_path, &backup_path)
            .context("Failed to create settings backup")?;

        Ok(Some(backup_path))
    }

    /// Read existing settings or create new empty settings.
    fn read_settings(&self) -> Result<Value> {
        if self.settings_path.exists() {
            let content = std::fs::read_to_string(&self.settings_path)
                .context("Failed to read settings file")?;
            serde_json::from_str(&content)
                .context("Failed to parse settings JSON")
        } else {
            Ok(json!({}))
        }
    }

    /// Write settings to file.
    fn write_settings(&self, settings: &Value) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = self.settings_path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create .claude directory")?;
        }

        let content = serde_json::to_string_pretty(settings)
            .context("Failed to serialize settings")?;
        std::fs::write(&self.settings_path, content)
            .context("Failed to write settings file")?;

        Ok(())
    }

    /// Get the sevsh path as a tilde-expanded string.
    fn sevsh_path_string(&self) -> String {
        // Use tilde notation for portability
        "~/.local/bin/sevsh".to_string()
    }
}

impl Integration for ClaudeCodeIntegration {
    fn name(&self) -> &str {
        "Claude Code"
    }

    fn description(&self) -> &str {
        "Configures Claude Code to use sevsh as its shell for command validation"
    }

    fn is_installed(&self) -> bool {
        if !self.settings_path.exists() {
            return false;
        }

        // Check if settings contain our SHELL configuration
        if let Ok(settings) = self.read_settings() {
            if let Some(env) = settings.get("env") {
                if let Some(shell) = env.get("SHELL") {
                    if let Some(shell_str) = shell.as_str() {
                        return shell_str.contains("sevsh");
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

        // Backup existing settings if present
        let backup_path = self.backup_settings()?;
        if backup_path.is_some() {
            config_changes.push(format!(
                "Backed up existing settings to {:?}",
                backup_path.unwrap()
            ));
        }

        // Read existing settings
        let mut settings = self.read_settings()?;

        // Ensure env object exists and add SHELL
        let env = settings
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

        env_obj.insert("SHELL".to_string(), json!(self.sevsh_path_string()));

        // Update settings
        if let Value::Object(ref mut map) = settings {
            map.insert("env".to_string(), Value::Object(env_obj));
        }

        // Write updated settings
        self.write_settings(&settings)?;
        files_modified.push(self.settings_path.display().to_string());
        config_changes.push(format!(
            "Set SHELL to {} in ~/.claude/settings.json",
            self.sevsh_path_string()
        ));

        let message = if had_existing_shell {
            "Claude Code integration installed (replaced existing SHELL setting)."
        } else {
            "Claude Code integration installed. All Bash commands will now be validated through Sevorix."
        };

        Ok(InstallResult {
            files_modified,
            config_changes,
            restart_required: false,
            message: message.to_string(),
        })
    }

    fn uninstall(&self) -> Result<()> {
        if !self.settings_path.exists() {
            return Ok(());
        }

        // Read current settings
        let mut settings = self.read_settings()?;

        // Remove our SHELL setting from env
        if let Some(env) = settings.get_mut("env") {
            if let Value::Object(ref mut env_map) = env {
                env_map.remove("SHELL");

                // If env is now empty, remove it entirely
                if env_map.is_empty() {
                    if let Value::Object(ref mut settings_map) = settings {
                        settings_map.remove("env");
                    }
                }
            }
        }

        // Write updated settings
        self.write_settings(&settings)?;

        println!("Claude Code integration uninstalled.");
        println!("The SHELL setting has been removed from ~/.claude/settings.json");

        // Check for backup and offer to restore
        let backup_path = self.settings_path.with_extension("json.backup");
        if backup_path.exists() {
            println!("Backup exists at: {}", backup_path.display());
            println!("To restore original settings: mv {} {}",
                backup_path.display(),
                self.settings_path.display()
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

    fn create_test_integration(temp_dir: &TempDir) -> ClaudeCodeIntegration {
        let sevsh_path = temp_dir.path().join(".local/bin/sevsh");
        let settings_path = temp_dir.path().join(".claude/settings.json");
        let state_dir = temp_dir.path().join(".local/state/sevorix");

        // Create sevsh binary mock
        if let Some(parent) = sevsh_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&sevsh_path, "#!/bin/bash\necho sevsh").unwrap();

        // Create state dir
        std::fs::create_dir_all(&state_dir).unwrap();

        ClaudeCodeIntegration::new_for_test(sevsh_path, settings_path, state_dir)
    }

    fn create_running_daemon(state_dir: &PathBuf) {
        let pid_path = state_dir.join("sevorix.pid");
        // Use current process PID for testing (it exists)
        std::fs::write(&pid_path, std::process::id().to_string()).unwrap();
    }

    #[test]
    fn test_integration_name() {
        let integration = ClaudeCodeIntegration::new().unwrap();
        assert_eq!(integration.name(), "Claude Code");
    }

    #[test]
    fn test_sevsh_path() {
        let integration = ClaudeCodeIntegration::new().unwrap();
        assert!(integration.sevsh_path_string().contains("sevsh"));
    }

    #[test]
    fn test_description() {
        let integration = ClaudeCodeIntegration::new().unwrap();
        assert!(integration.description().contains("Claude Code"));
        assert!(integration.description().contains("sevsh"));
    }

    #[test]
    fn test_is_installed_no_settings_file() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        assert!(!integration.is_installed());
    }

    #[test]
    fn test_is_installed_empty_settings() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        // Create empty settings file
        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.settings_path, "{}").unwrap();

        assert!(!integration.is_installed());
    }

    #[test]
    fn test_is_installed_with_shell_setting() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        // Create settings with SHELL set to sevsh
        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let settings = r#"{"env": {"SHELL": "~/.local/bin/sevsh"}}"#;
        std::fs::write(&integration.settings_path, settings).unwrap();

        assert!(integration.is_installed());
    }

    #[test]
    fn test_is_installed_with_different_shell() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        // Create settings with different SHELL
        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let settings = r#"{"env": {"SHELL": "/bin/bash"}}"#;
        std::fs::write(&integration.settings_path, settings).unwrap();

        assert!(!integration.is_installed());
    }

    #[test]
    fn test_is_installed_malformed_json() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.settings_path, "not valid json").unwrap();

        assert!(!integration.is_installed());
    }

    #[test]
    fn test_backup_settings_creates_backup() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        // Create settings file
        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.settings_path, r#"{"test": true}"#).unwrap();

        let backup_path = integration.backup_settings().unwrap();
        assert!(backup_path.is_some());

        let backup = backup_path.unwrap();
        assert!(backup.exists());
        assert!(backup.to_str().unwrap().ends_with(".backup"));

        let content = std::fs::read_to_string(&backup).unwrap();
        assert_eq!(content, r#"{"test": true}"#);
    }

    #[test]
    fn test_backup_settings_no_file() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        let backup_path = integration.backup_settings().unwrap();
        assert!(backup_path.is_none());
    }

    #[test]
    fn test_read_settings_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.settings_path, r#"{"key": "value"}"#).unwrap();

        let settings = integration.read_settings().unwrap();
        assert_eq!(settings["key"], "value");
    }

    #[test]
    fn test_read_settings_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        let settings = integration.read_settings().unwrap();
        assert!(settings.is_object());
        assert!(settings.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_write_settings_creates_file() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        let settings = json!({"env": {"SHELL": "test"}});
        integration.write_settings(&settings).unwrap();

        assert!(integration.settings_path.exists());

        let content = std::fs::read_to_string(&integration.settings_path).unwrap();
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
        let settings_path = temp_dir.path().join(".claude/settings.json");
        let state_dir = temp_dir.path().join(".local/state/sevorix");

        std::fs::create_dir_all(&state_dir).unwrap();

        let integration = ClaudeCodeIntegration::new_for_test(sevsh_path, settings_path, state_dir);
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
        let settings_path = temp_dir.path().join(".claude/settings.json");
        let state_dir = temp_dir.path().join(".local/state/sevorix");

        std::fs::create_dir_all(&state_dir).unwrap();
        create_running_daemon(&state_dir);

        let integration = ClaudeCodeIntegration::new_for_test(sevsh_path, settings_path, state_dir);
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

        // Create settings with SHELL set to sevsh
        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let settings = r#"{"env": {"SHELL": "~/.local/bin/sevsh"}}"#;
        std::fs::write(&integration.settings_path, settings).unwrap();

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
        assert!(result.message.contains("Claude Code"));

        // Verify settings were written
        assert!(integration.settings_path.exists());
        let settings = std::fs::read_to_string(&integration.settings_path).unwrap();
        assert!(settings.contains("sevsh"));
    }

    #[test]
    fn test_install_replaces_existing_shell() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);

        // Create settings with existing SHELL
        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.settings_path, r#"{"env": {"SHELL": "/bin/bash"}}"#).unwrap();

        let result = integration.install().unwrap();
        assert!(result.config_changes.iter().any(|c| c.contains("Replacing")));

        // Verify SHELL was changed
        let settings = integration.read_settings().unwrap();
        assert_eq!(settings["env"]["SHELL"], "~/.local/bin/sevsh");
    }

    #[test]
    fn test_install_creates_backup() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);

        // Create existing settings
        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.settings_path, r#"{"existing": true}"#).unwrap();

        let result = integration.install().unwrap();
        assert!(result.config_changes.iter().any(|c| c.contains("Backed up")));

        // Verify backup exists
        let backup_path = integration.settings_path.with_extension("json.backup");
        assert!(backup_path.exists());
    }

    #[test]
    fn test_uninstall_removes_shell_setting() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        // Create settings with SHELL
        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.settings_path, r#"{"env": {"SHELL": "~/.local/bin/sevsh", "OTHER": "value"}}"#).unwrap();

        integration.uninstall().unwrap();

        let settings = integration.read_settings().unwrap();
        assert!(!settings["env"].get("SHELL").is_some());
        assert_eq!(settings["env"]["OTHER"], "value");
    }

    #[test]
    fn test_uninstall_removes_empty_env() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        // Create settings with only SHELL in env
        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.settings_path, r#"{"env": {"SHELL": "~/.local/bin/sevsh"}}"#).unwrap();

        integration.uninstall().unwrap();

        let settings = integration.read_settings().unwrap();
        assert!(!settings.get("env").is_some());
    }

    #[test]
    fn test_uninstall_no_settings_file() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        // Should not fail when no settings file exists
        integration.uninstall().unwrap();
    }

    #[test]
    fn test_install_preserves_other_settings() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);

        // Create settings with other configuration
        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.settings_path, r#"{"api_key": "secret", "theme": "dark"}"#).unwrap();

        integration.install().unwrap();

        let settings = integration.read_settings().unwrap();
        assert_eq!(settings["api_key"], "secret");
        assert_eq!(settings["theme"], "dark");
        assert_eq!(settings["env"]["SHELL"], "~/.local/bin/sevsh");
    }
}
