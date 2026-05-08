// Tests for truncation and raw length metadata introduced in ContextStore PR
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
fn test_truncation_preserves_utf8() {
    // Set very small max_chunk_bytes so truncation will occur.
    let settings = r#"{ "context": { "max_chunk_bytes": "10B", "compress_enabled": false } }"#;
    run_child_for(
        "context_truncation::test_truncation_preserves_utf8",
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

        // 'é' is 2 bytes in UTF-8; repeat to exceed 10 bytes
        let raw = "é".repeat(10);
        store
            .append_chunks(
                "s3",
                vec![ContextChunkInput {
                    source: "t".into(),
                    stream: ContextStream::Stdout,
                    raw: raw.clone(),
                    text: None,
                    timestamp: None,
                }],
            )
            .unwrap();

        let path = dir.path().join("s3.jsonl");
        let mut f = std::fs::File::open(&path).unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        let first = s.lines().next().unwrap();
        let chunk: ContextChunk = from_str(first).unwrap();

        // Ensure stored.raw is valid UTF-8 and its byte length <= 10
        assert!(
            chunk.raw.is_char_boundary(chunk.raw.len()),
            "stored.raw must be valid UTF-8"
        );
        assert!(chunk.raw.as_bytes().len() <= 10);
    }
}

#[test]
fn test_raw_len_records_original_length() {
    let settings = r#"{ "context": { "max_chunk_bytes": "5B", "compress_enabled": false } }"#;
    run_child_for(
        "context_truncation::test_raw_len_records_original_length",
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

        let raw = "abcdef".to_string(); // 6 bytes
        store
            .append_chunks(
                "s4",
                vec![ContextChunkInput {
                    source: "t".into(),
                    stream: ContextStream::Stdout,
                    raw: raw.clone(),
                    text: None,
                    timestamp: None,
                }],
            )
            .unwrap();

        let path = dir.path().join("s4.jsonl");
        let mut f = std::fs::File::open(&path).unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        let first = s.lines().next().unwrap();
        let chunk: ContextChunk = from_str(first).unwrap();

        assert_eq!(
            chunk.raw_len.unwrap(),
            6,
            "raw_len should record original length before truncation"
        );
        assert!(
            chunk.raw.as_bytes().len() <= 5,
            "stored.raw should be truncated to max_chunk_bytes"
        );
    }
}
