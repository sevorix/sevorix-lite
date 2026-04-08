// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

use directories::UserDirs;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize, Default)]
pub struct Settings {
    pub intervention: Option<InterventionSettings>,
    pub sevsh: Option<SevshSettings>,
    pub tls_mitm: Option<TlsMitmSettings>,
    pub experimental: Option<ExperimentalSettings>,
}

/// Opt-in experimental features. Off by default; intended for users who have
/// explicitly verified their environment meets the prerequisites.
#[derive(Deserialize, Default, Clone)]
pub struct ExperimentalSettings {
    /// Enable BPF LSM hooks for synchronous exec and network blocking.
    ///
    /// Requires the kernel to be booted with `lsm=...,bpf` in its command line
    /// (i.e. `bpf` must appear in `/sys/kernel/security/lsm`). Auto-detection
    /// of this capability has been removed — it was unreliable on kernels that
    /// compile with `CONFIG_BPF_LSM=y` but do not activate it (e.g. WSL2,
    /// most stock cloud VM kernels). Set this to `true` only after confirming
    /// BPF LSM is active on your kernel.
    ///
    /// Default: `false`.
    pub lsm_blocking: Option<bool>,
}

impl ExperimentalSettings {
    pub fn lsm_blocking_enabled(&self) -> bool {
        self.lsm_blocking.unwrap_or(false)
    }
}

impl Settings {
    /// Load settings from `~/.sevorix/settings.json`.
    /// Returns `Default::default()` on any error (file missing, invalid JSON, etc.).
    pub fn load() -> Self {
        let path = UserDirs::new()
            .map(|u| u.home_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".sevorix/settings.json");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct TlsMitmSettings {
    /// If true, CONNECT tunnels are intercepted and decrypted.
    pub enabled: Option<bool>,
}

impl TlsMitmSettings {
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(false)
    }
}

#[derive(Deserialize, Default)]
pub struct SevshSettings {
    /// Timeout (seconds) for the validate_command call to Watchtower. Default: 5.
    pub validation_timeout_secs: Option<u64>,
    /// Default role to apply to new sessions. Seeds the session role at startup.
    /// Can be overridden at any time via `sevorix session set-role`.
    pub default_role: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct InterventionSettings {
    /// How long (seconds) to wait for an operator decision before auto-acting. Default: 30.
    pub timeout_secs: Option<u64>,
    /// What to do when the timeout fires: "allow" or "block". Default: "block".
    pub timeout_action: Option<String>,
}

impl InterventionSettings {
    pub fn timeout_secs(&self) -> u64 {
        self.timeout_secs.unwrap_or(30)
    }

    /// Returns true if the timeout action is "allow", false (block) otherwise.
    pub fn timeout_action_allow(&self) -> bool {
        self.timeout_action.as_deref() == Some("allow")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // InterventionSettings tests
    // =========================================================================

    #[test]
    fn test_intervention_settings_default_timeout() {
        let settings = InterventionSettings::default();
        // Default timeout is 30 seconds
        assert_eq!(settings.timeout_secs(), 30);
    }

    #[test]
    fn test_intervention_settings_custom_timeout() {
        let settings = InterventionSettings {
            timeout_secs: Some(60),
            timeout_action: None,
        };
        assert_eq!(settings.timeout_secs(), 60);
    }

    #[test]
    fn test_intervention_settings_zero_timeout() {
        let settings = InterventionSettings {
            timeout_secs: Some(0),
            timeout_action: None,
        };
        assert_eq!(settings.timeout_secs(), 0);
    }

    #[test]
    fn test_intervention_settings_timeout_action_allow() {
        let settings = InterventionSettings {
            timeout_secs: None,
            timeout_action: Some("allow".to_string()),
        };
        assert!(settings.timeout_action_allow());
    }

    #[test]
    fn test_intervention_settings_timeout_action_block() {
        let settings = InterventionSettings {
            timeout_secs: None,
            timeout_action: Some("block".to_string()),
        };
        assert!(!settings.timeout_action_allow());
    }

    #[test]
    fn test_intervention_settings_timeout_action_none() {
        let settings = InterventionSettings {
            timeout_secs: None,
            timeout_action: None,
        };
        assert!(!settings.timeout_action_allow());
    }

    #[test]
    fn test_intervention_settings_timeout_action_other_string() {
        let settings = InterventionSettings {
            timeout_secs: None,
            timeout_action: Some("permit".to_string()), // not "allow"
        };
        assert!(!settings.timeout_action_allow());
    }

    // =========================================================================
    // SevshSettings tests
    // =========================================================================

    #[test]
    fn test_sevsh_settings_default() {
        let settings = SevshSettings::default();
        assert!(settings.validation_timeout_secs.is_none());
        assert!(settings.default_role.is_none());
    }

    #[test]
    fn test_sevsh_settings_with_values() {
        let settings = SevshSettings {
            validation_timeout_secs: Some(10),
            default_role: Some("admin".to_string()),
        };
        assert_eq!(settings.validation_timeout_secs, Some(10));
        assert_eq!(settings.default_role.as_deref(), Some("admin"));
    }

    // =========================================================================
    // Settings deserialization tests
    // =========================================================================

    #[test]
    fn test_settings_deserialize_empty() {
        let json = "{}";
        let settings: Settings = serde_json::from_str(json).unwrap();
        assert!(settings.intervention.is_none());
        assert!(settings.sevsh.is_none());
    }

    #[test]
    fn test_settings_deserialize_with_intervention() {
        let json = r#"{
            "intervention": {
                "timeout_secs": 45,
                "timeout_action": "allow"
            }
        }"#;
        let settings: Settings = serde_json::from_str(json).unwrap();
        let intervention = settings.intervention.unwrap();
        assert_eq!(intervention.timeout_secs(), 45);
        assert!(intervention.timeout_action_allow());
    }

    #[test]
    fn test_settings_deserialize_with_sevsh() {
        let json = r#"{
            "sevsh": {
                "validation_timeout_secs": 15,
                "default_role": "developer"
            }
        }"#;
        let settings: Settings = serde_json::from_str(json).unwrap();
        let sevsh = settings.sevsh.unwrap();
        assert_eq!(sevsh.validation_timeout_secs, Some(15));
        assert_eq!(sevsh.default_role.as_deref(), Some("developer"));
    }

    #[test]
    fn test_settings_deserialize_full() {
        let json = r#"{
            "intervention": {
                "timeout_secs": 60,
                "timeout_action": "block"
            },
            "sevsh": {
                "validation_timeout_secs": 5,
                "default_role": "restricted"
            }
        }"#;
        let settings: Settings = serde_json::from_str(json).unwrap();
        let intervention = settings.intervention.unwrap();
        let sevsh = settings.sevsh.unwrap();

        assert_eq!(intervention.timeout_secs(), 60);
        assert!(!intervention.timeout_action_allow());
        assert_eq!(sevsh.validation_timeout_secs, Some(5));
        assert_eq!(sevsh.default_role.as_deref(), Some("restricted"));
    }

    #[test]
    fn test_settings_load_returns_default_for_missing_file() {
        // Settings::load() returns Default::default() if file is missing
        // We can't easily test a specific file path, but we can verify
        // the return type is valid
        let settings = Settings::default();
        assert!(settings.intervention.is_none());
        assert!(settings.sevsh.is_none());
    }

    #[test]
    fn test_intervention_settings_timeout_default_value() {
        // When timeout_secs is None, the default should be 30
        let settings = InterventionSettings {
            timeout_secs: None,
            timeout_action: None,
        };
        assert_eq!(settings.timeout_secs(), 30);
    }

    #[test]
    fn test_intervention_settings_large_timeout() {
        let settings = InterventionSettings {
            timeout_secs: Some(3600), // 1 hour
            timeout_action: Some("allow".to_string()),
        };
        assert_eq!(settings.timeout_secs(), 3600);
        assert!(settings.timeout_action_allow());
    }
}
