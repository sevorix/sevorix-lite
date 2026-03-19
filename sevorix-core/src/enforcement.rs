// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

//! Enforcement tier detection.
//!
//! Detects whether the kernel supports BPF LSM hooks at runtime, selecting
//! between two enforcement tiers:
//!
//! - **Standard**: seccomp filter applied per-session at startup via
//!   `apply_syscall_deny_filter()`. Works on any Linux kernel.
//! - **Advanced**: BPF LSM hooks + seccomp as base layer. Requires `bpf`
//!   in the kernel's active LSM list (`/sys/kernel/security/lsm`).
//!
//! # WSL2 note
//!
//! WSL2 kernels may compile with `CONFIG_BPF_LSM=y` but omit `bpf` from the
//! active LSM list (`CONFIG_LSM`). Since WSL2 doesn't support custom boot
//! parameters, these kernels will always report `Standard` tier.

use std::fmt;

/// The enforcement tier selected at runtime based on kernel capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementTier {
    /// seccomp-based per-session filter. Works on any Linux kernel.
    Standard,
    /// BPF LSM hooks + seccomp as base layer. Requires kernel BPF LSM support.
    Advanced,
}

impl fmt::Display for EnforcementTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnforcementTier::Standard => write!(f, "Standard (seccomp)"),
            EnforcementTier::Advanced => write!(f, "Advanced (BPF LSM + seccomp)"),
        }
    }
}

/// Detect the best enforcement tier supported by the current kernel.
///
/// Reads `/sys/kernel/security/lsm` and checks whether `bpf` appears in
/// the comma-separated list of active LSMs. Falls back to `Standard` if
/// the file is unreadable (e.g. securityfs not mounted).
pub fn detect_enforcement_tier() -> EnforcementTier {
    match std::fs::read_to_string("/sys/kernel/security/lsm") {
        Ok(content) => {
            if content.trim().split(',').any(|s| s.trim() == "bpf") {
                EnforcementTier::Advanced
            } else {
                EnforcementTier::Standard
            }
        }
        Err(_) => EnforcementTier::Standard,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enforcement_tier_display() {
        assert_eq!(EnforcementTier::Standard.to_string(), "Standard (seccomp)");
        assert_eq!(
            EnforcementTier::Advanced.to_string(),
            "Advanced (BPF LSM + seccomp)"
        );
    }

    #[test]
    fn test_enforcement_tier_equality() {
        assert_eq!(EnforcementTier::Standard, EnforcementTier::Standard);
        assert_eq!(EnforcementTier::Advanced, EnforcementTier::Advanced);
        assert_ne!(EnforcementTier::Standard, EnforcementTier::Advanced);
    }

    #[test]
    fn test_detect_enforcement_tier_returns_valid_tier() {
        // Whatever the kernel reports, it should return one of the two tiers.
        let tier = detect_enforcement_tier();
        assert!(
            tier == EnforcementTier::Standard || tier == EnforcementTier::Advanced,
            "unexpected tier: {:?}",
            tier
        );
    }
}
