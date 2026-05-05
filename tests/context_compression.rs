// Tests for ContextStore compression behavior and related metadata
use std::io::Read;

use serde_json::from_str;
use sevorix_watchtower::context::{ContextChunk, ContextChunkInput, ContextStore, ContextStream};
use tempfile::tempdir;

fn run_child_for(test_name: &str, settings_json: Option<&str>) {
    if std::env::var("SEVORIX_TEST_CHILD").is_ok() {
        return;
    }

    let exe = std::env::current_exe().expect("current exe");
    let mut cmd = std::process::Command::new(exe);
    cmd.env("RUST_TEST_THREADS", "1");
    cmd.env("SEVORIX_TEST_CHILD", "1");

    if let Some(s) = settings_json {
        let dir = tempdir().expect("tempdir");
        let settings_dir = dir.path().join(".sevorix");
        std::fs::create_dir_all(&settings_dir).unwrap();
        let path = settings_dir.join("settings.json");
        std::fs::write(&path, s).expect("write settings");
        cmd.env("SEVORIX_SETTINGS_PATH", path);
    }

    cmd.arg("--exact");
    cmd.arg(test_name);
    let status = cmd.status().expect("failed to spawn child test");
    assert!(status.success(), "child test failed");
}

#[test]
fn test_compression_fields_present() {
    // Enable compression and set threshold very low so compression triggers.
    let settings = r#"{ "context": { "compress_enabled": true, "compression_threshold": "1B" } }"#;
    run_child_for(
        "context_compression::test_compression_fields_present",
        Some(settings),
    );

    if std::env::var("SEVORIX_TEST_CHILD").is_ok() {
        let dir = tempdir().unwrap();
        let store = ContextStore::new(
            dir.path(),
            10,
            std::sync::Arc::new(sevorix_watchtower::settings::ContextSettings::default()),
        )
        .unwrap();

        let raw = "a".repeat(1024);
        store
            .append_chunks(
                "s1",
                vec![ContextChunkInput {
                    source: "t".into(),
                    stream: ContextStream::Stdout,
                    raw: raw.clone(),
                    text: None,
                    timestamp: None,
                }],
            )
            .unwrap();

        let path = dir.path().join("s1.jsonl");
        let mut f = std::fs::File::open(&path).unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        let first = s.lines().next().unwrap();
        let chunk: ContextChunk = from_str(first).unwrap();

        assert!(
            chunk.raw_b64.is_some(),
            "raw_b64 should be present when compressed"
        );
        assert_eq!(chunk.compressed.unwrap(), "zstd");
        assert_eq!(chunk.raw_len.unwrap(), 1024);
    }
}

#[test]
fn test_no_compression_when_disabled() {
    let settings = r#"{ "context": { "compress_enabled": false, "compression_threshold": "1B" } }"#;
    run_child_for(
        "context_compression::test_no_compression_when_disabled",
        Some(settings),
    );

    if std::env::var("SEVORIX_TEST_CHILD").is_ok() {
        let dir = tempdir().unwrap();
        let store = ContextStore::new(
            dir.path(),
            10,
            std::sync::Arc::new(sevorix_watchtower::settings::ContextSettings::default()),
        )
        .unwrap();

        let raw = "b".repeat(512);
        store
            .append_chunks(
                "s2",
                vec![ContextChunkInput {
                    source: "t".into(),
                    stream: ContextStream::Stdout,
                    raw: raw.clone(),
                    text: None,
                    timestamp: None,
                }],
            )
            .unwrap();

        let path = dir.path().join("s2.jsonl");
        let mut f = std::fs::File::open(&path).unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        let first = s.lines().next().unwrap();
        let chunk: ContextChunk = from_str(first).unwrap();

        assert!(
            chunk.raw_b64.is_none(),
            "raw_b64 must be None when compression disabled"
        );
        assert!(chunk.compressed.is_none());
        assert_eq!(chunk.raw_len.unwrap(), 512);
    }
}
