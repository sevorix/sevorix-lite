//! Claude Code integration for Sevorix.
//!
//! The integration surfaces as `sevorix integrations start claude`, which
//! execs `sudo sevorix-claude-launcher`. The launcher creates a mount
//! namespace and bind-mounts sevsh over `/bin/bash` inside it, intercepting
//! all of Claude Code's Bash tool calls at the kernel level.
//!
//! `install` / `uninstall` are no-ops beyond verifying prerequisites, since
//! nothing needs to be written to disk.

use super::{InstallResult, Integration, IntegrationStatus};
use anyhow::{Context, Result};
use std::path::PathBuf;

const LAUNCHER_BIN: &str = "/usr/local/bin/sevorix-claude-launcher";

/// Claude Code integration.
pub struct ClaudeCodeIntegration {
    /// Path to the sevsh binary.
    sevsh_path: PathBuf,
    /// Path to the system-wide launcher binary.
    launcher_path: PathBuf,
    /// Path to Sevorix state directory for PID check.
    state_dir: PathBuf,
}

impl ClaudeCodeIntegration {
    pub fn new() -> Result<Self> {
        let user_dirs =
            directories::UserDirs::new().context("Could not determine user directories")?;
        let home = user_dirs.home_dir();

        let proj_dirs = directories::ProjectDirs::from("com", "sevorix", "sevorix")
            .context("Could not determine project directories")?;
        let state_dir = proj_dirs
            .state_dir()
            .unwrap_or_else(|| proj_dirs.cache_dir())
            .to_path_buf();

        Ok(Self {
            sevsh_path: home.join(".local/bin/sevsh"),
            launcher_path: PathBuf::from(LAUNCHER_BIN),
            state_dir,
        })
    }

    #[cfg(test)]
    pub fn new_for_test(sevsh_path: PathBuf, launcher_path: PathBuf, state_dir: PathBuf) -> Self {
        Self {
            sevsh_path,
            launcher_path,
            state_dir,
        }
    }

    fn is_daemon_running(&self) -> bool {
        let pid_path = self.state_dir.join("sevorix.pid");
        if let Ok(content) = std::fs::read_to_string(&pid_path) {
            if let Ok(pid) = content.trim().parse::<i32>() {
                unsafe { libc::kill(pid, 0) == 0 }
            } else {
                false
            }
        } else {
            false
        }
    }

    fn is_sevsh_installed(&self) -> bool {
        self.sevsh_path.exists() && self.sevsh_path.is_file()
    }

    fn is_launcher_installed(&self) -> bool {
        self.launcher_path.exists() && self.launcher_path.is_file()
    }
}

impl Integration for ClaudeCodeIntegration {
    fn name(&self) -> &str {
        "Claude Code"
    }

    fn description(&self) -> &str {
        "Routes Claude Code Bash commands through sevsh via a mount-namespace launcher. \
         Use 'sevorix integrations start claude' to launch a monitored session."
    }

    /// Returns true when all prerequisites are present (sevsh + launcher installed).
    /// There is nothing to configure on disk, so this reflects readiness to start.
    fn is_installed(&self) -> bool {
        self.is_sevsh_installed() && self.is_launcher_installed()
    }

    /// Verifies that prerequisites are in place. Nothing is written to disk.
    fn install(&self) -> Result<InstallResult> {
        if !self.is_daemon_running() {
            anyhow::bail!("Sevorix daemon is not running. Start it with 'sevorix start' first.");
        }
        if !self.is_sevsh_installed() {
            anyhow::bail!(
                "sevsh is not installed at {}. Re-run the Sevorix installer.",
                self.sevsh_path.display()
            );
        }
        if !self.is_launcher_installed() {
            anyhow::bail!(
                "sevorix-claude-launcher not found at {}. Re-run the Sevorix installer.",
                self.launcher_path.display()
            );
        }

        Ok(InstallResult {
            files_modified: vec![],
            config_changes: vec![],
            restart_required: false,
            message: "Claude Code integration is ready. \
                      Run 'sevorix integrations start claude' to launch a monitored session."
                .to_string(),
        })
    }

    /// No-op: nothing was written during install.
    fn uninstall(&self) -> Result<()> {
        println!("Claude Code integration uninstalled.");
        println!("Run 'claude' directly to use Claude Code without Sevorix monitoring.");
        Ok(())
    }

    fn status(&self) -> IntegrationStatus {
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
        if !self.is_launcher_installed() {
            return IntegrationStatus::Corrupted {
                reason: format!(
                    "sevorix-claude-launcher not found at {} — re-run the installer",
                    self.launcher_path.display()
                ),
            };
        }
        IntegrationStatus::Installed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_integration(temp_dir: &TempDir) -> ClaudeCodeIntegration {
        let sevsh_path = temp_dir.path().join(".local/bin/sevsh");
        let launcher_path = temp_dir
            .path()
            .join("usr/local/bin/sevorix-claude-launcher");
        let state_dir = temp_dir.path().join(".local/state/sevorix");

        std::fs::create_dir_all(sevsh_path.parent().unwrap()).unwrap();
        std::fs::write(&sevsh_path, "#!/bin/bash\necho sevsh").unwrap();
        std::fs::create_dir_all(launcher_path.parent().unwrap()).unwrap();
        std::fs::write(&launcher_path, "#!/bin/bash\necho launcher").unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();

        ClaudeCodeIntegration::new_for_test(sevsh_path, launcher_path, state_dir)
    }

    fn create_running_daemon(state_dir: &PathBuf) {
        let pid_path = state_dir.join("sevorix.pid");
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
    fn test_is_installed_when_prerequisites_present() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        assert!(integration.is_installed());
    }

    #[test]
    fn test_is_installed_false_when_sevsh_missing() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        std::fs::remove_file(&integration.sevsh_path).unwrap();
        assert!(!integration.is_installed());
    }

    #[test]
    fn test_is_installed_false_when_launcher_missing() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        std::fs::remove_file(&integration.launcher_path).unwrap();
        assert!(!integration.is_installed());
    }

    #[test]
    fn test_is_daemon_running_no_pid_file() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        assert!(!integration.is_daemon_running());
    }

    #[test]
    fn test_is_daemon_running_valid_pid() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);
        assert!(integration.is_daemon_running());
    }

    #[test]
    fn test_is_daemon_running_invalid_pid() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        std::fs::write(integration.state_dir.join("sevorix.pid"), "999999999").unwrap();
        assert!(!integration.is_daemon_running());
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
    fn test_status_corrupted_sevsh_missing() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);
        std::fs::remove_file(&integration.sevsh_path).unwrap();
        let status = integration.status();
        assert!(matches!(status, IntegrationStatus::Corrupted { .. }));
        if let IntegrationStatus::Corrupted { reason } = status {
            assert!(reason.contains("sevsh"));
        }
    }

    #[test]
    fn test_status_corrupted_launcher_missing() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);
        std::fs::remove_file(&integration.launcher_path).unwrap();
        let status = integration.status();
        assert!(matches!(status, IntegrationStatus::Corrupted { .. }));
        if let IntegrationStatus::Corrupted { reason } = status {
            assert!(reason.contains("launcher"));
        }
    }

    #[test]
    fn test_status_installed_when_prerequisites_met() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);
        assert_eq!(integration.status(), IntegrationStatus::Installed);
    }

    #[test]
    fn test_install_fails_no_daemon() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        let err = integration.install().unwrap_err().to_string();
        assert!(err.contains("daemon"));
    }

    #[test]
    fn test_install_fails_no_sevsh() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);
        std::fs::remove_file(&integration.sevsh_path).unwrap();
        let err = integration.install().unwrap_err().to_string();
        assert!(err.contains("sevsh"));
    }

    #[test]
    fn test_install_fails_no_launcher() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);
        std::fs::remove_file(&integration.launcher_path).unwrap();
        let err = integration.install().unwrap_err().to_string();
        assert!(err.contains("launcher"));
    }

    #[test]
    fn test_install_succeeds_when_prerequisites_met() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        create_running_daemon(&integration.state_dir);
        let result = integration.install().unwrap();
        assert!(result.files_modified.is_empty());
        assert!(result.message.contains("sevorix integrations start"));
    }

    #[test]
    fn test_uninstall_is_noop() {
        let temp_dir = TempDir::new().unwrap();
        let integration = create_test_integration(&temp_dir);
        // Should not fail and should not touch any files
        integration.uninstall().unwrap();
    }
}
