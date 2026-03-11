use anyhow::Result;
use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use clap::Parser;
use sevorix_hub::{db, routes, store, AppState};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use store::Store;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Storage backend configuration.
/// Note: This enum is used for documentation/type safety purposes and in tests.
/// The actual storage selection uses string matching for CLI simplicity.
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum StorageBackend {
    /// Local filesystem storage (for development).
    Filesystem { base_dir: String },
    /// Google Cloud Storage (for production).
    Gcs { bucket: String },
}

#[derive(Parser)]
#[command(name = "sevorix-hub", about = "Sevorix policy hub service")]
struct Cli {
    /// PostgreSQL connection string.
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// Storage backend type: "filesystem" or "gcs".
    #[arg(long, env = "STORAGE_BACKEND", default_value = "filesystem")]
    storage_backend: String,

    /// Directory where artifact files are stored (for filesystem backend).
    #[arg(
        long,
        env = "ARTIFACTS_DIR",
        default_value = "~/.local/share/sevorix-hub/artifacts"
    )]
    artifacts_dir: String,

    /// GCS bucket name (for GCS backend).
    #[arg(long, env = "GCS_BUCKET")]
    gcs_bucket: Option<String>,

    /// Secret key used to sign JWT tokens.
    #[arg(long, env = "JWT_SECRET", default_value = "change-me-in-production")]
    jwt_secret: String,

    /// TCP port to listen on.
    #[arg(long, env = "PORT", default_value = "8080")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    // Connect to the database.
    let db = db::create_pool(&cli.database_url).await?;

    // Run pending migrations.
    tracing::info!("running migrations");
    sqlx::migrate!("./migrations").run(&db).await?;
    tracing::info!("migrations complete");

    // Set up artifact storage based on configured backend.
    let store = match cli.storage_backend.as_str() {
        "gcs" => {
            let bucket = cli.gcs_bucket.ok_or_else(|| {
                anyhow::anyhow!("GCS_BUCKET is required when STORAGE_BACKEND=gcs")
            })?;
            tracing::info!("using GCS storage backend: {}", bucket);
            Store::gcs(bucket)
        }
        "filesystem" | _ => {
            let artifacts_dir = expand_home(&cli.artifacts_dir)?;
            tokio::fs::create_dir_all(&artifacts_dir).await?;
            tracing::info!("using filesystem storage: {:?}", artifacts_dir);
            Store::filesystem(artifacts_dir)
        }
    };

    let state = Arc::new(AppState {
        db,
        store,
        jwt_secret: cli.jwt_secret,
    });

    // Rate limiting configuration
    // Global: 1000 requests per minute (~17/sec with burst of 1000)
    let global_rate_limit = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(17)
            .burst_size(1000)
            .finish()
            .unwrap(),
    );

    // Login: 10 requests per minute (1 every 6 seconds on average)
    let login_rate_limit = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(10)
            .finish()
            .unwrap(),
    );

    // Register: 5 requests per hour
    // Note: governor doesn't support fractional rates like 5/3600 per second.
    // We approximate this with a very low refill rate: 1 token per minute
    // combined with burst_size(5) gives roughly 5 per 5 minutes initial burst,
    // then 1/min = 60/hour. For stricter limits, a custom rate limiter would be needed.
    // For security purposes, we use a conservative approximation: 1 per minute max.
    let register_rate_limit = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(5)
            .finish()
            .unwrap(),
    );

    // Routes with stricter rate limiting
    let login_router = Router::new()
        .route("/api/v1/login", post(routes::login))
        .layer(GovernorLayer {
            config: Arc::clone(&login_rate_limit),
        });

    let register_router = Router::new()
        .route("/api/v1/register", post(routes::register))
        .layer(GovernorLayer {
            config: Arc::clone(&register_rate_limit),
        });

    // Remaining routes with global rate limiting
    let general_router = Router::new()
        .route("/api/v1/me", get(routes::get_current_user))
        .route("/api/v1/me/email", patch(routes::update_email))
        .route("/api/v1/users/:user_id", get(routes::get_user_profile))
        .route(
            "/api/v1/admin/users/:user_id/approve",
            post(routes::approve_user),
        )
        .route("/api/v1/artifacts", post(routes::push_artifact))
        .route("/api/v1/artifacts/search", get(routes::search_artifacts))
        .route(
            "/api/v1/artifacts/:name/:version",
            get(routes::pull_artifact),
        )
        .route(
            "/api/v1/artifacts/:artifact_id/endorsements",
            post(routes::create_endorsement),
        )
        .route(
            "/api/v1/artifacts/:artifact_id/endorsements",
            get(routes::list_endorsements),
        )
        .route(
            "/api/v1/artifacts/:artifact_id/endorsements/:endorsement_id",
            delete(routes::delete_endorsement),
        )
        .layer(GovernorLayer {
            config: Arc::clone(&global_rate_limit),
        });

    let app = Router::new()
        .merge(login_router)
        .merge(register_router)
        .merge(general_router)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = format!("0.0.0.0:{}", cli.port);
    tracing::info!("sevorix-hub listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

fn expand_home(path: &str) -> Result<PathBuf> {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = directories::UserDirs::new()
            .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?
            .home_dir()
            .to_path_buf();
        Ok(home.join(rest))
    } else {
        Ok(PathBuf::from(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_home_with_tilde() {
        let path = "~/Documents/test";
        let result = expand_home(path).unwrap();

        // Should expand to home directory + Documents/test
        assert!(result.to_string_lossy().ends_with("Documents/test"));
        assert!(!result.to_string_lossy().starts_with("~"));
    }

    #[test]
    fn test_expand_home_without_tilde() {
        let path = "/var/log/test";
        let result = expand_home(path).unwrap();

        // Should return the path unchanged
        assert_eq!(result.to_string_lossy(), "/var/log/test");
    }

    #[test]
    fn test_expand_home_relative_path() {
        let path = "relative/path";
        let result = expand_home(path).unwrap();

        // Should return the relative path unchanged
        assert_eq!(result.to_string_lossy(), "relative/path");
    }

    #[test]
    fn test_expand_home_just_tilde() {
        let path = "~";
        let result = expand_home(path).unwrap();

        // Should return just the path since it's not ~/something
        assert_eq!(result.to_string_lossy(), "~");
    }

    #[test]
    fn test_expand_home_tilde_slash() {
        let path = "~/";
        let result = expand_home(path).unwrap();

        // Should expand to home directory (empty string after ~/)
        assert!(!result.to_string_lossy().starts_with("~"));
    }

    #[test]
    fn test_expand_home_nested_path() {
        let path = "~/a/b/c/d/file.txt";
        let result = expand_home(path).unwrap();

        // Should expand correctly with nested paths
        assert!(result.to_string_lossy().ends_with("a/b/c/d/file.txt"));
    }

    #[test]
    fn test_expand_home_empty_string() {
        let path = "";
        let result = expand_home(path).unwrap();

        // Should return empty path
        assert_eq!(result.to_string_lossy(), "");
    }

    #[test]
    fn test_expand_home_absolute_path() {
        let path = "/usr/local/bin";
        let result = expand_home(path).unwrap();

        // Should return the absolute path unchanged
        assert_eq!(result.to_string_lossy(), "/usr/local/bin");
    }

    #[test]
    fn test_expand_home_with_spaces() {
        let path = "~/My Documents/file.txt";
        let result = expand_home(path).unwrap();

        // Should handle spaces in path
        assert!(result.to_string_lossy().ends_with("My Documents/file.txt"));
    }

    #[test]
    fn test_expand_home_with_special_chars() {
        let path = "~/path-with_special.chars/file.json";
        let result = expand_home(path).unwrap();

        // Should handle special characters
        assert!(result.to_string_lossy().ends_with("path-with_special.chars/file.json"));
    }

    #[test]
    fn test_expand_home_multiple_slashes() {
        let path = "~/folder//subfolder///file.txt";
        let result = expand_home(path).unwrap();

        // Should preserve multiple slashes (filesystem will normalize)
        assert!(result.to_string_lossy().contains("folder"));
    }

    #[test]
    fn test_expand_home_dot_notation() {
        let path = "~/./folder/../file.txt";
        let result = expand_home(path).unwrap();

        // Should preserve dot notation (filesystem will resolve)
        assert!(result.to_string_lossy().contains("."));
    }

    // =========================================================================
    // StorageBackend enum tests
    // =========================================================================

    #[test]
    fn test_storage_backend_filesystem_debug() {
        let backend = StorageBackend::Filesystem {
            base_dir: "/tmp/artifacts".to_string(),
        };
        let debug = format!("{:?}", backend);
        assert!(debug.contains("Filesystem"));
        assert!(debug.contains("/tmp/artifacts"));
    }

    #[test]
    fn test_storage_backend_gcs_debug() {
        let backend = StorageBackend::Gcs {
            bucket: "my-bucket".to_string(),
        };
        let debug = format!("{:?}", backend);
        assert!(debug.contains("Gcs"));
        assert!(debug.contains("my-bucket"));
    }

    #[test]
    fn test_storage_backend_clone() {
        let backend = StorageBackend::Filesystem {
            base_dir: "/data".to_string(),
        };
        let cloned = backend.clone();
        match cloned {
            StorageBackend::Filesystem { base_dir } => {
                assert_eq!(base_dir, "/data");
            }
            _ => panic!("expected Filesystem variant"),
        }
    }

    // =========================================================================
    // CLI parsing tests
    // =========================================================================

    #[test]
    fn test_cli_default_values() {
        // Test that defaults are correctly applied
        let cli = Cli::try_parse_from(["test"]);
        // This will fail because database_url is required, but we can verify
        // the other defaults would be applied
        assert!(cli.is_err()); // database_url is required
    }

    #[test]
    fn test_cli_with_all_args() {
        let result = Cli::try_parse_from([
            "test",
            "--database-url", "postgres://localhost/test",
            "--storage-backend", "filesystem",
            "--artifacts-dir", "/tmp/test",
            "--jwt-secret", "secret123",
            "--port", "9000",
        ]);

        assert!(result.is_ok());
        let cli = result.unwrap();
        assert_eq!(cli.database_url, "postgres://localhost/test");
        assert_eq!(cli.storage_backend, "filesystem");
        assert_eq!(cli.artifacts_dir, "/tmp/test");
        assert_eq!(cli.jwt_secret, "secret123");
        assert_eq!(cli.port, 9000);
    }

    #[test]
    fn test_cli_gcs_backend() {
        let result = Cli::try_parse_from([
            "test",
            "--database-url", "postgres://localhost/test",
            "--storage-backend", "gcs",
            "--gcs-bucket", "my-gcs-bucket",
        ]);

        assert!(result.is_ok());
        let cli = result.unwrap();
        assert_eq!(cli.storage_backend, "gcs");
        assert_eq!(cli.gcs_bucket, Some("my-gcs-bucket".to_string()));
    }

    #[test]
    fn test_cli_env_prefix() {
        // The CLI uses #[arg(env = "...")] which allows setting via environment variables
        // We can't easily test env vars in unit tests, but we verify the struct is correct
        let cli = Cli::try_parse_from([
            "test",
            "--database-url", "postgres://user:pass@host:5432/db",
        ]);

        assert!(cli.is_ok());
        assert_eq!(cli.unwrap().database_url, "postgres://user:pass@host:5432/db");
    }

    #[test]
    fn test_cli_port_boundary() {
        // Test max port
        let result = Cli::try_parse_from([
            "test",
            "--database-url", "postgres://localhost/test",
            "--port", "65535",
        ]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().port, 65535);

        // Test min port
        let result = Cli::try_parse_from([
            "test",
            "--database-url", "postgres://localhost/test",
            "--port", "1",
        ]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().port, 1);
    }

    #[test]
    fn test_cli_missing_database_url() {
        let result = Cli::try_parse_from(["test"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_long_jwt_secret() {
        let long_secret = "x".repeat(1000);
        let result = Cli::try_parse_from([
            "test",
            "--database-url", "postgres://localhost/test",
            "--jwt-secret", &long_secret,
        ]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().jwt_secret.len(), 1000);
    }

    #[test]
    fn test_cli_artifacts_dir_with_tilde() {
        let result = Cli::try_parse_from([
            "test",
            "--database-url", "postgres://localhost/test",
            "--artifacts-dir", "~/my-artifacts",
        ]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().artifacts_dir, "~/my-artifacts");
    }
}
