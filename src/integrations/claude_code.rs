//! Claude Code integration for Sevorix.
//!
//! This integration configures Claude Code to route all Bash commands through
//! sevsh by prepending `~/.sevorix/bin` to PATH in `~/.claude/settings.json`.
//! That directory contains a `bash` wrapper that invokes sevsh, so Claude
//! Code's shell resolution picks it up before the system bash.

use super::{InstallResult, Integration, IntegrationStatus};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::PathBuf;

/// Claude Code integration.
///
/// Modifies `~/.claude/settings.json` to prepend `~/.sevorix/bin` to PATH,
/// ensuring all Bash commands from Claude Code are validated through Sevorix.
pub struct ClaudeCodeIntegration {
    /// Path to the sevsh binary.
    sevsh_path: PathBuf,
    /// Path to `~/.sevorix/bin` (contains the bash wrapper).
    sevorix_bin_path: PathBuf,
    /// Path to Claude Code settings.
    settings_path: PathBuf,
    /// Path to Sevorix state directory for PID check.
    state_dir: PathBuf,
    /// User home directory (for locating shell rc files).
    home_dir: PathBuf,
    /// Shell alias name to create for `sudo sevorix-claude-launcher` (default: "claude").
    alias: String,
}

impl ClaudeCodeIntegration {
    /// Create a new Claude Code integration instance.
    pub fn new() -> Result<Self> {
        let user_dirs = directories::UserDirs::new()
            .context("Could not determine user directories")?;

        let home = user_dirs.home_dir();
        let sevsh_path = home.join(".local/bin/sevsh");
        let sevorix_bin_path = home.join(".sevorix/bin");
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
            sevorix_bin_path,
            settings_path,
            state_dir,
            home_dir: home.to_path_buf(),
            alias: "claude".to_string(),
        })
    }

    /// Create a new instance with custom paths (for testing).
    #[cfg(test)]
    pub fn new_for_test(
        sevsh_path: PathBuf,
        sevorix_bin_path: PathBuf,
        settings_path: PathBuf,
        state_dir: PathBuf,
        home_dir: PathBuf,
    ) -> Self {
        Self {
            sevsh_path,
            sevorix_bin_path,
            settings_path,
            state_dir,
            home_dir,
            alias: "claude".to_string(),
        }
    }

    /// Set the shell alias name to create during install (builder method).
    pub fn with_alias(mut self, alias: String) -> Self {
        self.alias = alias;
        self
    }

    /// Write `alias <name>='sudo sevorix-claude-launcher'` to the user's shell rc files.
    /// Writes to ~/.bashrc and ~/.zshrc if they exist. Non-fatal if neither is present.
    fn write_shell_alias(&self) -> Result<Vec<String>> {
        let marker = "# Added by sevorix integrate claude-code";
        let alias_line = format!("alias {}='sudo sevorix-claude-launcher'", self.alias);
        let block = format!("\n{}\n{}\n", marker, alias_line);

        let rc_files = [".bashrc", ".zshrc"];
        let mut modified = Vec::new();

        for rc_name in &rc_files {
            let rc_path = self.home_dir.join(rc_name);
            if !rc_path.exists() {
                continue;
            }
            let content = std::fs::read_to_string(&rc_path)
                .context(format!("Failed to read {}", rc_path.display()))?;
            // Skip if already present (idempotent)
            if content.contains("sevorix-claude-launcher") {
                continue;
            }
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&rc_path)
                .context(format!("Failed to open {} for writing", rc_path.display()))?;
            use std::io::Write;
            file.write_all(block.as_bytes())
                .context(format!("Failed to write alias to {}", rc_path.display()))?;
            modified.push(rc_path.display().to_string());
        }

        Ok(modified)
    }

    /// Remove any sevorix-claude-launcher alias lines from shell rc files.
    fn remove_shell_alias(&self) -> Result<()> {
        let rc_files = [".bashrc", ".zshrc"];

        for rc_name in &rc_files {
            let rc_path = self.home_dir.join(rc_name);
            if !rc_path.exists() {
                continue;
            }
            let content = std::fs::read_to_string(&rc_path)
                .context(format!("Failed to read {}", rc_path.display()))?;
            if !content.contains("sevorix-claude-launcher") {
                continue;
            }
            // Remove the marker line, the alias line, and the blank line before the block
            let new_content: String = content
                .lines()
                .filter(|line| {
                    !line.contains("sevorix-claude-launcher")
                        && !line.contains("# Added by sevorix integrate claude-code")
                })
                .collect::<Vec<_>>()
                .join("\n");
            // Preserve trailing newline if original had one
            let new_content = if content.ends_with('\n') {
                format!("{}\n", new_content.trim_end_matches('\n'))
            } else {
                new_content
            };
            std::fs::write(&rc_path, new_content)
                .context(format!("Failed to write {}", rc_path.display()))?;
        }

        Ok(())
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

    /// Check if the bash wrapper exists in the sevorix bin directory.
    fn is_bash_wrapper_installed(&self) -> bool {
        let wrapper = self.sevorix_bin_path.join("bash");
        wrapper.exists() && wrapper.is_file()
    }

    /// Absolute path string for the sevorix bin directory.
    fn sevorix_bin_path_string(&self) -> String {
        self.sevorix_bin_path.to_string_lossy().into_owned()
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

        // Check if settings contain our PATH configuration
        if let Ok(settings) = self.read_settings() {
            if let Some(env) = settings.get("env") {
                if let Some(path_val) = env.get("PATH") {
                    if let Some(path_str) = path_val.as_str() {
                        return path_str.contains(&self.sevorix_bin_path_string());
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

        // Pre-check: Verify bash wrapper exists
        if !self.is_bash_wrapper_installed() {
            anyhow::bail!(
                "bash wrapper not found at {}/bash. Re-run the Sevorix installer.",
                self.sevorix_bin_path.display()
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

        // Ensure env object exists and update PATH
        let env = settings
            .get("env")
            .cloned()
            .unwrap_or_else(|| json!({}));

        let mut env_obj = env.as_object()
            .cloned()
            .unwrap_or_default();

        let sevorix_bin = self.sevorix_bin_path_string();

        // Prepend sevorix bin to PATH (or build a sensible default PATH)
        let new_path = if let Some(existing_path) = env_obj.get("PATH").and_then(|v| v.as_str()) {
            if existing_path.contains(&sevorix_bin) {
                // Already present, no change needed
                existing_path.to_string()
            } else {
                config_changes.push(format!("Prepending {} to existing PATH", sevorix_bin));
                format!("{}:{}", sevorix_bin, existing_path)
            }
        } else {
            config_changes.push(format!("Setting PATH with {} prepended", sevorix_bin));
            format!("{}:/usr/local/bin:/usr/bin:/bin", sevorix_bin)
        };

        env_obj.insert("PATH".to_string(), json!(new_path));

        // Update settings
        if let Value::Object(ref mut map) = settings {
            map.insert("env".to_string(), Value::Object(env_obj));
        }

        // Write updated settings
        self.write_settings(&settings)?;
        files_modified.push(self.settings_path.display().to_string());

        // Write shell alias for the launcher
        match self.write_shell_alias() {
            Ok(alias_files) if !alias_files.is_empty() => {
                config_changes.push(format!(
                    "Added alias {}='sudo sevorix-claude-launcher' to: {}",
                    self.alias,
                    alias_files.join(", ")
                ));
                files_modified.extend(alias_files);
            }
            Ok(_) => {
                config_changes.push(format!(
                    "No ~/.bashrc or ~/.zshrc found — add manually: alias {}='sudo sevorix-claude-launcher'",
                    self.alias
                ));
            }
            Err(e) => {
                // Non-fatal: alias is a convenience, not required
                config_changes.push(format!(
                    "Warning: could not write shell alias ({}). Add manually: alias {}='sudo sevorix-claude-launcher'",
                    e, self.alias
                ));
            }
        }

        Ok(InstallResult {
            files_modified,
            config_changes,
            restart_required: true,
            message: format!(
                "Claude Code integration installed. Run '{}' (or open a new shell) to start a monitored session.",
                self.alias
            ),
        })
    }

    fn uninstall(&self) -> Result<()> {
        if !self.settings_path.exists() {
            return Ok(());
        }

        // Read current settings
        let mut settings = self.read_settings()?;

        let sevorix_bin = self.sevorix_bin_path_string();

        // Remove our PATH prefix from env
        if let Some(env) = settings.get_mut("env") {
            if let Value::Object(ref mut env_map) = env {
                if let Some(path_val) = env_map.get("PATH").and_then(|v| v.as_str()) {
                    // Strip our prefix (handles "sevorix_bin:" or "sevorix_bin" alone)
                    let new_path = path_val
                        .strip_prefix(&format!("{}:", sevorix_bin))
                        .or_else(|| path_val.strip_prefix(&sevorix_bin))
                        .unwrap_or(path_val)
                        .to_string();

                    if new_path.is_empty() {
                        env_map.remove("PATH");
                    } else {
                        env_map.insert("PATH".to_string(), json!(new_path));
                    }
                }

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

        // Remove shell alias
        self.remove_shell_alias()?;

        println!("Claude Code integration uninstalled.");
        println!("The PATH override has been removed from ~/.claude/settings.json");

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

        if !self.is_bash_wrapper_installed() {
            return IntegrationStatus::Corrupted {
                reason: format!(
                    "bash wrapper not found at {}/bash — re-run the installer",
                    self.sevorix_bin_path.display()
                ),
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
        let sevorix_bin_path = temp_dir.path().join(".sevorix/bin");
        let settings_path = temp_dir.path().join(".claude/settings.json");
        let state_dir = temp_dir.path().join(".local/state/sevorix");

        // Create sevsh binary mock
        if let Some(parent) = sevsh_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&sevsh_path, "#!/bin/bash\necho sevsh").unwrap();

        // Create bash wrapper mock
        std::fs::create_dir_all(&sevorix_bin_path).unwrap();
        std::fs::write(sevorix_bin_path.join("bash"), "#!/bin/sh\nexec sevsh \"$@\"").unwrap();

        // Create state dir
        std::fs::create_dir_all(&state_dir).unwrap();

        ClaudeCodeIntegration::new_for_test(sevsh_path, sevorix_bin_path, settings_path, state_dir, temp_dir.path().to_path_buf())
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

        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.settings_path, "{}").unwrap();

        assert!(!integration.is_installed());
    }

    #[test]
    fn test_is_installed_with_path_containing_sevorix_bin() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let sevorix_bin = integration.sevorix_bin_path_string();
        let settings = format!(r#"{{"env": {{"PATH": "{}:/usr/bin:/bin"}}}}"#, sevorix_bin);
        std::fs::write(&integration.settings_path, settings).unwrap();

        assert!(integration.is_installed());
    }

    #[test]
    fn test_is_installed_without_sevorix_bin_in_path() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let settings = r#"{"env": {"PATH": "/usr/local/bin:/usr/bin:/bin"}}"#;
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

        let settings = json!({"env": {"PATH": "/test/bin:/usr/bin"}});
        integration.write_settings(&settings).unwrap();

        assert!(integration.settings_path.exists());

        let content = std::fs::read_to_string(&integration.settings_path).unwrap();
        assert!(content.contains("PATH"));
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
        let sevorix_bin_path = temp_dir.path().join(".sevorix/bin");
        let settings_path = temp_dir.path().join(".claude/settings.json");
        let state_dir = temp_dir.path().join(".local/state/sevorix");

        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::create_dir_all(&sevorix_bin_path).unwrap();
        std::fs::write(sevorix_bin_path.join("bash"), "#!/bin/sh\nexec sevsh \"$@\"").unwrap();

        let integration = ClaudeCodeIntegration::new_for_test(
            sevsh_path,
            sevorix_bin_path,
            settings_path,
            state_dir,
            temp_dir.path().to_path_buf(),
        );
        assert!(!integration.is_sevsh_installed());
    }

    #[test]
    fn test_is_bash_wrapper_installed_true() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        assert!(integration.is_bash_wrapper_installed());
    }

    #[test]
    fn test_is_bash_wrapper_installed_false() {
        let temp_dir = TempDir::new().unwrap();
        let sevsh_path = temp_dir.path().join(".local/bin/sevsh");
        let sevorix_bin_path = temp_dir.path().join(".sevorix/bin");
        let settings_path = temp_dir.path().join(".claude/settings.json");
        let state_dir = temp_dir.path().join(".local/state/sevorix");

        std::fs::create_dir_all(sevsh_path.parent().unwrap()).unwrap();
        std::fs::write(&sevsh_path, "#!/bin/bash\necho sevsh").unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();
        // sevorix_bin_path exists but bash wrapper does not
        std::fs::create_dir_all(&sevorix_bin_path).unwrap();

        let integration = ClaudeCodeIntegration::new_for_test(
            sevsh_path,
            sevorix_bin_path,
            settings_path,
            state_dir,
            temp_dir.path().to_path_buf(),
        );
        assert!(!integration.is_bash_wrapper_installed());
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
        let sevorix_bin_path = temp_dir.path().join(".sevorix/bin");
        let settings_path = temp_dir.path().join(".claude/settings.json");
        let state_dir = temp_dir.path().join(".local/state/sevorix");

        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::create_dir_all(&sevorix_bin_path).unwrap();
        std::fs::write(sevorix_bin_path.join("bash"), "#!/bin/sh\nexec sevsh \"$@\"").unwrap();
        create_running_daemon(&state_dir);

        let integration = ClaudeCodeIntegration::new_for_test(
            sevsh_path,
            sevorix_bin_path,
            settings_path,
            state_dir,
            temp_dir.path().to_path_buf(),
        );
        let status = integration.status();

        assert!(matches!(status, IntegrationStatus::Corrupted { .. }));
        if let IntegrationStatus::Corrupted { reason } = status {
            assert!(reason.contains("sevsh"));
        }
    }

    #[test]
    fn test_status_corrupted_bash_wrapper_missing() {
        let temp_dir = TempDir::new().unwrap();
        let sevsh_path = temp_dir.path().join(".local/bin/sevsh");
        let sevorix_bin_path = temp_dir.path().join(".sevorix/bin");
        let settings_path = temp_dir.path().join(".claude/settings.json");
        let state_dir = temp_dir.path().join(".local/state/sevorix");

        std::fs::create_dir_all(sevsh_path.parent().unwrap()).unwrap();
        std::fs::write(&sevsh_path, "#!/bin/bash\necho sevsh").unwrap();
        std::fs::create_dir_all(&sevorix_bin_path).unwrap();
        // no bash wrapper
        std::fs::create_dir_all(&state_dir).unwrap();
        create_running_daemon(&state_dir);

        let integration = ClaudeCodeIntegration::new_for_test(
            sevsh_path,
            sevorix_bin_path,
            settings_path,
            state_dir,
            temp_dir.path().to_path_buf(),
        );
        let status = integration.status();

        assert!(matches!(status, IntegrationStatus::Corrupted { .. }));
        if let IntegrationStatus::Corrupted { reason } = status {
            assert!(reason.contains("bash wrapper") || reason.contains("installer"));
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

        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let sevorix_bin = integration.sevorix_bin_path_string();
        let settings = format!(r#"{{"env": {{"PATH": "{}:/usr/bin:/bin"}}}}"#, sevorix_bin);
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
        assert!(!result.files_modified.is_empty());
        assert!(result.message.contains("Claude Code"));

        // Verify PATH was written with sevorix bin prepended
        assert!(integration.settings_path.exists());
        let settings = integration.read_settings().unwrap();
        let path_val = settings["env"]["PATH"].as_str().unwrap();
        assert!(path_val.starts_with(&integration.sevorix_bin_path_string()));
    }

    #[test]
    fn test_install_prepends_to_existing_path() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);

        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(
            &integration.settings_path,
            r#"{"env": {"PATH": "/usr/local/bin:/usr/bin:/bin"}}"#,
        )
        .unwrap();

        let result = integration.install().unwrap();
        assert!(result.config_changes.iter().any(|c| c.contains("Prepending")));

        let settings = integration.read_settings().unwrap();
        let path_val = settings["env"]["PATH"].as_str().unwrap();
        assert!(path_val.starts_with(&integration.sevorix_bin_path_string()));
        assert!(path_val.contains("/usr/local/bin"));
    }

    #[test]
    fn test_install_idempotent_when_path_already_set() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);

        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let sevorix_bin = integration.sevorix_bin_path_string();
        let path = format!("{}:/usr/bin:/bin", sevorix_bin);
        let settings = format!(r#"{{"env": {{"PATH": "{}"}}}}"#, path);
        std::fs::write(&integration.settings_path, settings).unwrap();

        integration.install().unwrap();

        // PATH should not be doubled
        let settings = integration.read_settings().unwrap();
        let path_val = settings["env"]["PATH"].as_str().unwrap();
        assert_eq!(path_val.matches(&sevorix_bin).count(), 1);
    }

    #[test]
    fn test_install_creates_backup() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);

        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.settings_path, r#"{"existing": true}"#).unwrap();

        let result = integration.install().unwrap();
        assert!(result.config_changes.iter().any(|c| c.contains("Backed up")));

        let backup_path = integration.settings_path.with_extension("json.backup");
        assert!(backup_path.exists());
    }

    #[test]
    fn test_uninstall_removes_path_prefix() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let sevorix_bin = integration.sevorix_bin_path_string();
        let settings = format!(
            r#"{{"env": {{"PATH": "{}:/usr/bin:/bin", "OTHER": "value"}}}}"#,
            sevorix_bin
        );
        std::fs::write(&integration.settings_path, settings).unwrap();

        integration.uninstall().unwrap();

        let settings = integration.read_settings().unwrap();
        let path_val = settings["env"]["PATH"].as_str().unwrap();
        assert!(!path_val.contains(&sevorix_bin));
        assert_eq!(settings["env"]["OTHER"], "value");
    }

    #[test]
    fn test_uninstall_removes_empty_env() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let sevorix_bin = integration.sevorix_bin_path_string();
        let settings = format!(r#"{{"env": {{"PATH": "{}"}}}}"#, sevorix_bin);
        std::fs::write(&integration.settings_path, settings).unwrap();

        integration.uninstall().unwrap();

        let settings = integration.read_settings().unwrap();
        assert!(settings.get("env").is_none());
    }

    #[test]
    fn test_uninstall_no_settings_file() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);

        integration.uninstall().unwrap();
    }

    #[test]
    fn test_install_preserves_other_settings() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);

        if let Some(parent) = integration.settings_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&integration.settings_path, r#"{"api_key": "secret", "theme": "dark"}"#).unwrap();

        integration.install().unwrap();

        let settings = integration.read_settings().unwrap();
        assert_eq!(settings["api_key"], "secret");
        assert_eq!(settings["theme"], "dark");
        assert!(settings["env"]["PATH"]
            .as_str()
            .unwrap()
            .contains(&integration.sevorix_bin_path_string()));
    }
}
