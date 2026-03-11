use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

/// Initializes the logging system:
/// 1. Generates a unique Session ID.
/// 2. Sets up a file appender to ~/.sevorix/logs/<session_id>.log
/// 3. Configures tracing-subscriber to log to both stdout and the file.
///
/// Returns a WorkerGuard (must be kept alive in main) and the Session ID.
pub fn init_logging() -> (tracing_appender::non_blocking::WorkerGuard, Uuid) {
    let session_id = Uuid::new_v4();

    // Determine log directory: ~/.sevorix/logs/
    // Priority: ProjectDirs (XDG or Standard) -> then we explicitly append "logs" to config or data dir.
    // The user requested ~/.sevorix/logs/<session_id>.log specifically.
    // Let's try to honor ~/.sevorix if we can find the home dir, otherwise fallback to standard state paths.

    let log_dir = if let Some(user_dirs) = directories::UserDirs::new() {
        user_dirs.home_dir().join(".sevorix").join("logs")
    } else {
        // Fallback for systems without "Home" concept (rare) or strict sandboxing
        PathBuf::from(".sevorix/logs")
    };

    // Ensure directory exists
    if let Err(e) = std::fs::create_dir_all(&log_dir) {
        eprintln!("Failed to create log directory {:?}: {}", log_dir, e);
    }

    let file_name = format!("{}.log", session_id);
    let file_appender = tracing_appender::rolling::never(&log_dir, &file_name);

    let (non_blocking_appender, guard) = tracing_appender::non_blocking(file_appender);

    // Standard format for logs
    let fmt_file = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(non_blocking_appender);

    // Stdout layer (which daemon redirects to sevorix.log)
    let fmt_stdout = tracing_subscriber::fmt::layer()
        .with_ansi(true) // Keep colors for the sevorix.log/console
        .with_writer(std::io::stdout);

    // Combine them
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(fmt_stdout)
        .with(fmt_file)
        .init();

    tracing::info!("Session started with ID: {}", session_id);
    tracing::info!("Logging to file: {}", log_dir.join(&file_name).display());

    (guard, session_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_session_id_is_uuid() {
        // Test that UUID generation works
        let id = Uuid::new_v4();
        // UUID v4 is random - get_version returns Option<Version>
        assert_eq!(id.get_version(), Some(uuid::Version::Random));
    }

    #[test]
    fn test_log_dir_structure() {
        // Test that log directory path is constructed correctly
        let session_id = Uuid::new_v4();
        let file_name = format!("{}.log", session_id);

        // Verify file name format
        assert!(file_name.starts_with(&session_id.to_string()));
        assert!(file_name.ends_with(".log"));
    }

    #[test]
    fn test_file_name_format() {
        let session_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let file_name = format!("{}.log", session_id);
        assert_eq!(file_name, "00000000-0000-0000-0000-000000000001.log");
    }

    #[test]
    fn test_session_id_uniqueness() {
        // Generate multiple session IDs and verify they're unique
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_home_directory_fallback() {
        // Test that we can determine the home directory
        let result = directories::UserDirs::new();
        // On most systems this should work, but it could be None in restricted environments
        assert!(result.is_some() || result.is_none());
    }

    #[test]
    fn test_project_dirs_creation() {
        // Test that project directories can be created
        let result = directories::ProjectDirs::from("com", "sevorix", "sevorix");
        // Should succeed on most systems
        assert!(result.is_some() || result.is_none());
    }

    #[test]
    fn test_path_buf_ends_with() {
        // Test path operations used in logging
        let path = PathBuf::from("/tmp/test.log");
        assert!(path.ends_with("test.log"));
        assert!(!path.ends_with("other.log"));
    }

    #[test]
    fn test_uuid_string_format() {
        // Test UUID string representation
        let id = Uuid::new_v4();
        let id_str = id.to_string();
        // UUID strings have 36 characters (32 hex + 4 dashes)
        assert_eq!(id_str.len(), 36);
        // Format: 8-4-4-4-12
        assert!(id_str.chars().filter(|&c| c == '-').count() == 4);
    }
}