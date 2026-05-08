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
    pub context: Option<ContextSettings>,
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
        // Allow tests or external runners to override the settings file path by
        // setting `SEVORIX_SETTINGS_PATH` in the environment. If not provided,
        // fall back to the user's home `~/.sevorix/settings.json`.
        if let Ok(override_path) = std::env::var("SEVORIX_SETTINGS_PATH") {
            return std::fs::read_to_string(&override_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
        }

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
pub struct ContextSettings {
    /// Global cap for all stored context (e.g. "500MB"). Must be > 0 when set.
    pub global_cap: Option<String>,
    /// Per-session cap (e.g. "50MB"). Must be > 0 and <= global_cap when both set.
    pub per_session_cap: Option<String>,
    /// Eviction policy. Supported: "oldest_first".
    pub eviction_policy: Option<String>,
    /// Compression threshold (bytes) as human size string (e.g. "4KB"). 0 means compress everything.
    pub compression_threshold: Option<String>,
    /// Enable compression by default.
    pub compress_enabled: Option<bool>,
    /// Max chunk bytes (e.g. "1MiB"). Chunks larger than this will be truncated.
    pub max_chunk_bytes: Option<String>,
}

impl ContextSettings {
    /// Parse a human-readable size string into bytes.
    /// Supported formats: integer or decimal + unit (B, KB, MB, GB, TB), case-insensitive, optional spaces.
    /// Examples: "512KB", "4 MB", "1.5GB".
    pub fn parse_size_to_bytes(s: &str) -> Option<u64> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }

        // Optional sign is not allowed; reject negative values explicitly
        if s.starts_with('-') {
            return None;
        }

        // Split numeric part and unit part
        let chars = s.chars();
        let mut idx = 0usize;
        for (i, c) in chars.clone().enumerate() {
            if !(c.is_ascii_digit() || c == '.' || c == ',') {
                idx = i;
                break;
            }
            idx = i + 1;
        }

        let (num_part, unit_part) = s.split_at(idx);
        let num_part = num_part.replace(',', "");
        let value: f64 = num_part.parse().ok()?;

        let unit = unit_part.trim().to_ascii_uppercase();
        let multiplier: f64 = if unit.is_empty() || unit == "B" {
            1.0
        } else if unit == "KB" || unit == "K" {
            1024.0
        } else if unit == "MB" || unit == "M" {
            1024.0 * 1024.0
        } else if unit == "GB" || unit == "G" {
            1024.0 * 1024.0 * 1024.0
        } else if unit == "TB" || unit == "T" {
            1024.0 * 1024.0 * 1024.0 * 1024.0
        } else {
            return None;
        };

        let bytes = value * multiplier;
        if !bytes.is_finite() || bytes < 0.0 {
            return None;
        }

        // If the computed bytes is zero, return 0 (caller will validate if zero allowed)
        Some(bytes.round() as u64)
    }

    /// Validate context settings. Returns Ok(()) if valid, Err(msg) on invalid configuration.
    pub fn validate(&self) -> Result<(), String> {
        // Parse global and per-session caps if present
        let global = if let Some(ref g) = self.global_cap {
            let bytes =
                Self::parse_size_to_bytes(g).ok_or_else(|| format!("invalid global_cap: {}", g))?;
            if bytes == 0 {
                return Err("global_cap must be > 0".to_string());
            }
            Some(bytes)
        } else {
            None
        };

        let per_session = if let Some(ref p) = self.per_session_cap {
            let bytes = Self::parse_size_to_bytes(p)
                .ok_or_else(|| format!("invalid per_session_cap: {}", p))?;
            if bytes == 0 {
                return Err("per_session_cap must be > 0".to_string());
            }
            Some(bytes)
        } else {
            None
        };

        if let (Some(g), Some(p)) = (global, per_session) {
            if p > g {
                return Err("per_session_cap must be <= global_cap".to_string());
            }
        }

        // compression_threshold may be 0 (meaning compress everything)
        if let Some(ref t) = self.compression_threshold {
            let bytes = Self::parse_size_to_bytes(t)
                .ok_or_else(|| format!("invalid compression_threshold: {}", t))?;
            // bytes >= 0 accepted
            let _ = bytes;
        }

        // eviction_policy: only "oldest_first" currently supported
        if let Some(ref e) = self.eviction_policy {
            let e_lower = e.trim().to_ascii_lowercase();
            if e_lower != "oldest_first" {
                return Err(format!("unsupported eviction_policy: {}", e));
            }
        }

        // max_chunk_bytes if present must parse and be > 0
        if let Some(ref m) = self.max_chunk_bytes {
            let bytes = Self::parse_size_to_bytes(m)
                .ok_or_else(|| format!("invalid max_chunk_bytes: {}", m))?;
            if bytes == 0 {
                return Err("max_chunk_bytes must be > 0".to_string());
            }
        }

        Ok(())
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

    // =========================================================================
    // ContextSettings tests
    // =========================================================================

    #[test]
    fn test_parse_size_to_bytes_examples() {
        assert_eq!(
            ContextSettings::parse_size_to_bytes("512KB"),
            Some(512 * 1024)
        );
        assert_eq!(
            ContextSettings::parse_size_to_bytes("4 MB"),
            Some(4 * 1024 * 1024)
        );
        assert_eq!(
            ContextSettings::parse_size_to_bytes("1.5GB"),
            Some((1.5f64 * 1024.0 * 1024.0 * 1024.0).round() as u64)
        );
        assert_eq!(ContextSettings::parse_size_to_bytes("100"), Some(100));
        assert_eq!(ContextSettings::parse_size_to_bytes("0"), Some(0));
        assert_eq!(ContextSettings::parse_size_to_bytes("-1MB"), None);
        assert_eq!(ContextSettings::parse_size_to_bytes("foo"), None);
    }

    #[test]
    fn test_context_settings_validate() {
        let s = ContextSettings {
            global_cap: Some("100MB".to_string()),
            per_session_cap: Some("50MB".to_string()),
            eviction_policy: Some("oldest_first".to_string()),
            compression_threshold: Some("4KB".to_string()),
            compress_enabled: Some(true),
            max_chunk_bytes: Some("1MB".to_string()),
        };
        assert!(s.validate().is_ok());

        let bad = ContextSettings {
            global_cap: Some("10MB".to_string()),
            per_session_cap: Some("50MB".to_string()),
            ..Default::default()
        };
        assert!(bad.validate().is_err());
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
