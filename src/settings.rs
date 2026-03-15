use serde::Deserialize;

#[derive(Deserialize, Default)]
pub struct Settings {
    pub intervention: Option<InterventionSettings>,
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
