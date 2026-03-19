//! Integration infrastructure for external tool support.
//!
//! This module provides the core Integration trait and registry for managing
//! integrations with external AI tools like Claude Code, OpenClaw, and Codex.

pub mod claude_code;
pub mod codex;
pub mod openclaw;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Result of an installation operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallResult {
    /// Files that were modified or created.
    pub files_modified: Vec<String>,
    /// Configuration changes made.
    pub config_changes: Vec<String>,
    /// Whether a restart is required.
    pub restart_required: bool,
    /// Installation message.
    pub message: String,
}

/// Status of an integration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntegrationStatus {
    /// Integration is installed and active.
    Installed,
    /// Integration is installed but inactive.
    Inactive,
    /// Integration is not installed.
    NotInstalled,
    /// Installation is corrupted or partial.
    Corrupted { reason: String },
}

/// Core trait for integrations.
///
/// Implementations provide support for external AI tools, allowing
/// Sevorix to integrate with various development environments.
pub trait Integration: Send + Sync {
    /// Unique identifier for this integration.
    fn name(&self) -> &str;

    /// Human-readable description.
    fn description(&self) -> &str;

    /// Check if the integration is currently installed.
    fn is_installed(&self) -> bool;

    /// Install the integration.
    ///
    /// This may modify configuration files, create backups, and
    /// set up necessary infrastructure.
    fn install(&self) -> Result<InstallResult>;

    /// Uninstall the integration.
    ///
    /// Restores any modified files from backup and removes
    /// integration-specific configuration.
    fn uninstall(&self) -> Result<()>;

    /// Get the current status of the integration.
    fn status(&self) -> IntegrationStatus;
}

/// Registry for managing integrations.
pub struct IntegrationRegistry {
    integrations: HashMap<String, Arc<dyn Integration>>,
    pub(crate) base_path: PathBuf,
}

impl IntegrationRegistry {
    /// Create a new integration registry.
    ///
    /// The base path is used for storing backups and manifests.
    pub fn new() -> Result<Self> {
        let base_path = Self::get_base_path()?;
        Ok(Self {
            integrations: HashMap::new(),
            base_path,
        })
    }

    /// Get the base path for integration data.
    fn get_base_path() -> Result<PathBuf> {
        if let Some(user_dirs) = directories::UserDirs::new() {
            let home = user_dirs.home_dir();
            let sevorix_dir = home.join(".sevorix");
            std::fs::create_dir_all(&sevorix_dir)?;
            Ok(sevorix_dir)
        } else {
            anyhow::bail!("Could not determine home directory")
        }
    }

    /// Register a new integration.
    pub fn register(&mut self, integration: Arc<dyn Integration>) {
        self.integrations.insert(integration.name().to_string(), integration);
    }

    /// Get an integration by name.
    pub fn get(&self, name: &str) -> Option<Arc<dyn Integration>> {
        self.integrations.get(name).cloned()
    }

    /// List all registered integrations.
    pub fn list(&self) -> Vec<Arc<dyn Integration>> {
        self.integrations.values().cloned().collect()
    }

    /// Get the backup directory for an integration.
    pub fn backup_dir(&self, integration_name: &str) -> PathBuf {
        self.base_path
            .join("backups")
            .join(integration_name)
    }

    /// Get the manifest path for an integration.
    pub fn manifest_path(&self, integration_name: &str) -> PathBuf {
        self.base_path
            .join("integrations")
            .join(integration_name)
            .join("manifest.json")
    }

    /// Create a backup of files before modification.
    pub fn create_backup(&self, integration_name: &str, files: &[PathBuf]) -> Result<PathBuf> {
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let backup_dir = self.backup_dir(integration_name).join(timestamp.to_string());
        std::fs::create_dir_all(&backup_dir)?;

        for file in files {
            if file.exists() {
                let file_name = file.file_name()
                    .ok_or_else(|| anyhow::anyhow!("Invalid file path"))?;
                let dest = backup_dir.join(file_name);
                std::fs::copy(file, dest)?;
            }
        }

        Ok(backup_dir)
    }

    /// Restore files from a backup.
    pub fn restore_backup(&self, integration_name: &str, backup_path: &Path) -> Result<()> {
        let manifest_path = self.manifest_path(integration_name);
        if !manifest_path.exists() {
            return Ok(());
        }

        let manifest: Manifest = serde_json::from_str(&std::fs::read_to_string(&manifest_path)?)?;

        for original_path in &manifest.files_modified {
            let file_name = std::path::Path::new(original_path)
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Invalid file path"))?;
            let backup_file = backup_path.join(file_name);

            if backup_file.exists() {
                std::fs::copy(&backup_file, original_path)?;
            }
        }

        Ok(())
    }

    /// Save a manifest for an integration.
    pub fn save_manifest(&self, integration_name: &str, manifest: &Manifest) -> Result<()> {
        let manifest_path = self.manifest_path(integration_name);
        if let Some(parent) = manifest_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&manifest_path, serde_json::to_string_pretty(manifest)?)?;
        Ok(())
    }

    /// Load a manifest for an integration.
    pub fn load_manifest(&self, integration_name: &str) -> Result<Option<Manifest>> {
        let manifest_path = self.manifest_path(integration_name);
        if !manifest_path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&manifest_path)?;
        Ok(Some(serde_json::from_str(&content)?))
    }

    /// Delete a manifest for an integration.
    pub fn delete_manifest(&self, integration_name: &str) -> Result<()> {
        let manifest_path = self.manifest_path(integration_name);
        if manifest_path.exists() {
            std::fs::remove_file(&manifest_path)?;
        }
        Ok(())
    }
}

impl Default for IntegrationRegistry {
    fn default() -> Self {
        Self::new().expect("Failed to create integration registry")
    }
}

/// Manifest tracking integration installation details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Name of the integration.
    pub name: String,
    /// Version of the integration.
    pub version: String,
    /// Files that were modified during installation.
    pub files_modified: Vec<String>,
    /// Timestamp of installation.
    pub installed_at: String,
    /// Path to the backup created during installation.
    pub backup_path: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    struct MockIntegration {
        name: String,
        installed: bool,
    }

    impl Integration for MockIntegration {
        fn name(&self) -> &str {
            &self.name
        }

        fn description(&self) -> &str {
            "Mock integration for testing"
        }

        fn is_installed(&self) -> bool {
            self.installed
        }

        fn install(&self) -> Result<InstallResult> {
            Ok(InstallResult {
                files_modified: vec![],
                config_changes: vec![],
                restart_required: false,
                message: "Installed".to_string(),
            })
        }

        fn uninstall(&self) -> Result<()> {
            Ok(())
        }

        fn status(&self) -> IntegrationStatus {
            if self.installed {
                IntegrationStatus::Installed
            } else {
                IntegrationStatus::NotInstalled
            }
        }
    }

    #[test]
    fn test_registry_register_and_get() {
        let mut registry = IntegrationRegistry::new().unwrap();
        let integration = Arc::new(MockIntegration {
            name: "test".to_string(),
            installed: false,
        });
        registry.register(integration);

        assert!(registry.get("test").is_some());
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_registry_list() {
        let mut registry = IntegrationRegistry::new().unwrap();
        registry.register(Arc::new(MockIntegration {
            name: "test1".to_string(),
            installed: false,
        }));
        registry.register(Arc::new(MockIntegration {
            name: "test2".to_string(),
            installed: true,
        }));

        let list = registry.list();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_registry_backup_dir() {
        let registry = IntegrationRegistry::new().unwrap();
        let backup_dir = registry.backup_dir("test_integration");
        assert!(backup_dir.to_str().unwrap().contains("test_integration"));
        assert!(backup_dir.to_str().unwrap().contains("backups"));
    }

    #[test]
    fn test_registry_manifest_path() {
        let registry = IntegrationRegistry::new().unwrap();
        let manifest_path = registry.manifest_path("test_integration");
        assert!(manifest_path.to_str().unwrap().contains("test_integration"));
        assert!(manifest_path.to_str().unwrap().contains("manifest.json"));
    }

    #[test]
    fn test_registry_create_backup() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.json");
        std::fs::write(&test_file, r#"{"test": "data"}"#).unwrap();

        let mut registry = IntegrationRegistry::new().unwrap();
        registry.base_path = temp_dir.path().to_path_buf();

        let backup_path = registry.create_backup("test", &[test_file.clone()]).unwrap();
        assert!(backup_path.exists());

        // Verify backup contains the file
        let backup_file = backup_path.join("test.json");
        assert!(backup_file.exists());
        let content = std::fs::read_to_string(&backup_file).unwrap();
        assert_eq!(content, r#"{"test": "data"}"#);
    }

    #[test]
    fn test_registry_create_backup_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let nonexistent = temp_dir.path().join("nonexistent.json");

        let mut registry = IntegrationRegistry::new().unwrap();
        registry.base_path = temp_dir.path().to_path_buf();

        // Should not fail when file doesn't exist
        let backup_path = registry.create_backup("test", &[nonexistent]).unwrap();
        assert!(backup_path.exists());
    }

    #[test]
    fn test_registry_save_and_load_manifest() {
        let temp_dir = TempDir::new().unwrap();

        let mut registry = IntegrationRegistry::new().unwrap();
        registry.base_path = temp_dir.path().to_path_buf();

        let manifest = Manifest {
            name: "test_integration".to_string(),
            version: "1.0.0".to_string(),
            files_modified: vec!["/path/to/file.json".to_string()],
            installed_at: "2024-01-01T00:00:00Z".to_string(),
            backup_path: Some("/path/to/backup".to_string()),
        };

        registry.save_manifest("test", &manifest).unwrap();

        let loaded = registry.load_manifest("test").unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.name, "test_integration");
        assert_eq!(loaded.version, "1.0.0");
        assert_eq!(loaded.files_modified.len(), 1);
    }

    #[test]
    fn test_registry_load_nonexistent_manifest() {
        let temp_dir = TempDir::new().unwrap();

        let mut registry = IntegrationRegistry::new().unwrap();
        registry.base_path = temp_dir.path().to_path_buf();

        let loaded = registry.load_manifest("nonexistent").unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_registry_delete_manifest() {
        let temp_dir = TempDir::new().unwrap();

        let mut registry = IntegrationRegistry::new().unwrap();
        registry.base_path = temp_dir.path().to_path_buf();

        let manifest = Manifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            files_modified: vec![],
            installed_at: "2024-01-01T00:00:00Z".to_string(),
            backup_path: None,
        };

        registry.save_manifest("test", &manifest).unwrap();
        assert!(registry.manifest_path("test").exists());

        registry.delete_manifest("test").unwrap();
        assert!(!registry.manifest_path("test").exists());
    }

    #[test]
    fn test_registry_restore_backup() {
        let temp_dir = TempDir::new().unwrap();

        // Create original file that will be "modified"
        let original_path = temp_dir.path().join("original.json");
        std::fs::write(&original_path, r#"{"original": true}"#).unwrap();

        // Create backup directory with backup file
        let backup_dir = temp_dir.path().join("backups").join("test").join("20240101_000000");
        std::fs::create_dir_all(&backup_dir).unwrap();
        let backup_file = backup_dir.join("original.json");
        std::fs::write(&backup_file, r#"{"original": true}"#).unwrap();

        // Create manifest
        let manifest = Manifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            files_modified: vec![original_path.to_str().unwrap().to_string()],
            installed_at: "2024-01-01T00:00:00Z".to_string(),
            backup_path: Some(backup_dir.to_str().unwrap().to_string()),
        };

        let mut registry = IntegrationRegistry::new().unwrap();
        registry.base_path = temp_dir.path().to_path_buf();
        registry.save_manifest("test", &manifest).unwrap();

        // "Modify" the original file
        std::fs::write(&original_path, r#"{"modified": true}"#).unwrap();

        // Restore from backup
        registry.restore_backup("test", &backup_dir).unwrap();

        // Verify restoration
        let content = std::fs::read_to_string(&original_path).unwrap();
        assert_eq!(content, r#"{"original": true}"#);
    }

    #[test]
    fn test_install_result_serialization() {
        let result = InstallResult {
            files_modified: vec!["/path/to/file".to_string()],
            config_changes: vec!["Changed SHELL".to_string()],
            restart_required: true,
            message: "Installation complete".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: InstallResult = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.files_modified, result.files_modified);
        assert_eq!(parsed.config_changes, result.config_changes);
        assert_eq!(parsed.restart_required, result.restart_required);
        assert_eq!(parsed.message, result.message);
    }

    #[test]
    fn test_integration_status_equality() {
        assert_eq!(IntegrationStatus::Installed, IntegrationStatus::Installed);
        assert_eq!(IntegrationStatus::NotInstalled, IntegrationStatus::NotInstalled);
        assert_ne!(IntegrationStatus::Installed, IntegrationStatus::NotInstalled);

        let corrupted1 = IntegrationStatus::Corrupted { reason: "test".to_string() };
        let corrupted2 = IntegrationStatus::Corrupted { reason: "test".to_string() };
        assert_eq!(corrupted1, corrupted2);
    }

    #[test]
    fn test_manifest_serialization() {
        let manifest = Manifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            files_modified: vec!["/a/b/c".to_string()],
            installed_at: "2024-01-01T00:00:00Z".to_string(),
            backup_path: Some("/backup/path".to_string()),
        };

        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: Manifest = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.name, manifest.name);
        assert_eq!(parsed.version, manifest.version);
        assert_eq!(parsed.files_modified, manifest.files_modified);
    }
}
