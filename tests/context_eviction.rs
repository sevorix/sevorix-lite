// Tests for per-session and global eviction behavior
use std::io::Read;

use sevorix_watchtower::context::{ContextChunkInput, ContextStore, ContextStream};
use tempfile::tempdir;

fn run_child_for(test_name: &str, settings_json: &str) {
    if std::env::var("SEVORIX_TEST_CHILD").is_ok() {
        return;
    }

    let exe = std::env::current_exe().expect("current exe");
    let mut cmd = std::process::Command::new(exe);
    cmd.env("RUST_TEST_THREADS", "1");
    cmd.env("SEVORIX_TEST_CHILD", "1");

    let dir = tempfile::tempdir().expect("tempdir");
    let settings_dir = dir.path().join(".sevorix");
    std::fs::create_dir_all(&settings_dir).unwrap();
    let path = settings_dir.join("settings.json");
    std::fs::write(&path, settings_json).expect("write settings");
    cmd.env("SEVORIX_SETTINGS_PATH", path);

    cmd.arg("--exact");
    cmd.arg(test_name);
    let status = cmd.status().expect("failed to spawn child test");
    assert!(status.success(), "child test failed");
}

#[test]
fn test_per_session_eviction_rewrites_file_under_cap() {
    let settings = r#"{ "context": { "per_session_cap": "300B", "compress_enabled": false } }"#;
    run_child_for(
        "context_eviction::test_per_session_eviction_rewrites_file_under_cap",
        settings,
    );

    if std::env::var("SEVORIX_TEST_CHILD").is_ok() {
        let dir = tempdir().unwrap();
        let store = ContextStore::new(
            dir.path(),
            100,
            std::sync::Arc::new(sevorix_watchtower::settings::ContextSettings::default()),
        )
        .unwrap();

        // Each chunk ~120 bytes; append enough to exceed 300B
        let big = "x".repeat(120);
        store
            .append_chunks(
                "s_ev",
                vec![
                    ContextChunkInput {
                        source: "a".into(),
                        stream: ContextStream::Stdout,
                        raw: big.clone(),
                        text: None,
                        timestamp: None,
                    },
                    ContextChunkInput {
                        source: "a".into(),
                        stream: ContextStream::Stdout,
                        raw: big.clone(),
                        text: None,
                        timestamp: None,
                    },
                    ContextChunkInput {
                        source: "a".into(),
                        stream: ContextStream::Stdout,
                        raw: big.clone(),
                        text: None,
                        timestamp: None,
                    },
                ],
            )
            .unwrap();

        // After eviction per-session file should be rewritten and size <= cap
        let path = dir.path().join("s_ev.jsonl");
        let meta = std::fs::metadata(&path).unwrap();
        assert!(
            meta.len() <= 300,
            "file should be truncated to per_session_cap"
        );

        // Contents should be valid JSONL and contain at least one line
        let mut s = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert!(
            s.lines().count() >= 1,
            "session file should still contain chunks"
        );
    }
}

#[test]
fn test_global_eviction_removes_oldest_sessions() {
    let settings = r#"{ "context": { "global_cap": "250B", "compress_enabled": false } }"#;
    run_child_for(
        "context_eviction::test_global_eviction_removes_oldest_sessions",
        settings,
    );

    if std::env::var("SEVORIX_TEST_CHILD").is_ok() {
        let dir = tempdir().unwrap();
        let store = ContextStore::new(
            dir.path(),
            100,
            std::sync::Arc::new(sevorix_watchtower::settings::ContextSettings::default()),
        )
        .unwrap();

        let small = "y".repeat(200);
        store
            .append_chunks(
                "A",
                vec![ContextChunkInput {
                    source: "x".into(),
                    stream: ContextStream::Stdout,
                    raw: small.clone(),
                    text: None,
                    timestamp: None,
                }],
            )
            .unwrap();
        store
            .append_chunks(
                "B",
                vec![ContextChunkInput {
                    source: "x".into(),
                    stream: ContextStream::Stdout,
                    raw: small.clone(),
                    text: None,
                    timestamp: None,
                }],
            )
            .unwrap();

        // Recreate to force load/eviction
        let _ = ContextStore::new(
            dir.path(),
            100,
            std::sync::Arc::new(sevorix_watchtower::settings::ContextSettings::default()),
        )
        .unwrap();

        let a_exists = dir.path().join("A.jsonl").exists();
        let b_exists = dir.path().join("B.jsonl").exists();

        // With global cap 250B and two ~200B sessions, at least one must be removed
        assert!(
            !(a_exists && b_exists),
            "At least one session should have been evicted"
        );
    }
}
