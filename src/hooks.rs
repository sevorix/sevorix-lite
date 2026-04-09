// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Lifecycle events at which hooks can fire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookEvent {
    PreAnalyze,
    PostAnalyze,
    PreProxy,
    PostProxy,
    PreLog,
}

/// Outcome returned by a hook execution.
#[derive(Debug, Clone)]
pub enum HookOutcome {
    /// Hook ran without modifying the decision flow.
    Continue,
    /// Hook overrides the verdict. Valid for Post* events.
    OverrideVerdict(String),
    /// Hook modified the payload. Valid for Pre* events.
    ModifyPayload(String),
}

/// Context passed to hooks — both Rust hooks (by reference) and JSON hooks (as stdin JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookContext {
    pub event: HookEvent,
    pub payload: String,
    pub verdict: Option<String>, // "ALLOW", "BLOCK", "FLAG"
    pub role: Option<String>,
    pub context_type: String, // "Shell", "Network", "Syscall"
    pub session_id: String,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Trait for compile-time Rust hooks.
#[async_trait]
pub trait Hook: Send + Sync {
    fn id(&self) -> &str;
    fn description(&self) -> &str;
    fn event(&self) -> HookEvent;
    async fn execute(&self, ctx: &mut HookContext) -> Result<HookOutcome, anyhow::Error>;
}

/// Registry holding both Rust hooks and JSON hooks.
pub struct HookRegistry {
    hooks: Vec<Box<dyn Hook>>,
}

impl HookRegistry {
    pub fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    /// Register a compile-time Rust hook.
    pub fn register(&mut self, hook: Box<dyn Hook>) {
        self.hooks.push(hook);
    }

    /// Run all hooks matching `event` in order (Rust hooks first, then JSON hooks).
    /// Mutates `ctx` in-place. Returns Err only if an on_error:block hook fails.
    pub async fn run_hooks(&self, event: HookEvent, ctx: &mut HookContext) -> anyhow::Result<()> {
        // Run Rust hooks first
        for hook in &self.hooks {
            if hook.event() != event {
                continue;
            }
            match hook.execute(ctx).await {
                Ok(HookOutcome::Continue) => {}
                Ok(HookOutcome::OverrideVerdict(v)) => {
                    ctx.verdict = Some(v);
                }
                Ok(HookOutcome::ModifyPayload(p)) => {
                    ctx.payload = p;
                }
                Err(e) => {
                    tracing::warn!("hooks: rust hook '{}' error: {}", hook.id(), e);
                    // Rust hooks always continue on error (they are internal)
                }
            }
        }

        // Run JSON hooks second

        Ok(())
    }

    /// Returns the number of registered Rust hooks.
    pub fn rust_hook_count(&self) -> usize {
        self.hooks.len()
    }
}

impl Default for HookRegistry {
    fn default() -> Self {
        Self::new()
    }
}
