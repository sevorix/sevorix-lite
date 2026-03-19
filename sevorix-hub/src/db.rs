// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

use anyhow::Result;
use sqlx::{postgres::PgPoolOptions, PgPool};

pub type DbPool = PgPool;

pub async fn create_pool(database_url: &str) -> Result<DbPool> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_pool_invalid_url() {
        // Invalid URL should return an error
        let result = create_pool("not-a-valid-url").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_pool_empty_url() {
        // Empty URL should return an error
        let result = create_pool("").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_pool_malformed_url() {
        // Malformed URL should return an error
        let result = create_pool("postgres:///invalid:port:syntax").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_pool_wrong_scheme() {
        // Wrong scheme should return an error
        let result = create_pool("http://localhost:5432/test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_pool_nonexistent_host() {
        // Non-existent host should return an error (timeout or connection refused)
        let result = create_pool("postgres://nonexistent.host.12345:5432/test").await;
        assert!(result.is_err());
    }

    // Note: Testing successful connection requires a real database,
    // which is done via integration tests.
}
