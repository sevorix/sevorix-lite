// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

//! Sevorix Hub - Policy artifact registry service.
//!
//! This crate provides the core functionality for the Sevorix Hub service,
//! including authentication, artifact management, and audit logging.

pub mod audit;
pub mod auth;
pub mod db;
pub mod error;
pub mod models;
pub mod routes;
pub mod signing;
pub mod store;
pub mod validation;

use db::DbPool;
use store::Store;

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub store: Store,
    pub jwt_secret: String,
    /// Maximum artifact content size in bytes (default: 262144 = 256 KB).
    pub max_artifact_bytes: usize,
    pub require_signed_artifacts: bool,
}
