use directories::UserDirs;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize, Default)]
pub struct Settings {
    pub intervention: Option<InterventionSettings>,
    pub sevsh: Option<SevshSettings>,
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
