// Tests to verify atomic rewrite behavior for per-session eviction
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
fn test_atomic_rewrite_leaves_no_tmp_files_and_valid_jsonl() {
    let settings = r#"{ "context": { "per_session_cap": "300B", "compress_enabled": false } }"#;
    run_child_for(
        "context_atomic_rewrite::test_atomic_rewrite_leaves_no_tmp_files_and_valid_jsonl",
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

        let big = "z".repeat(120);
        store
            .append_chunks(
                "atomic",
                vec![
                    ContextChunkInput {
                        source: "x".into(),
                        stream: ContextStream::Stdout,
                        raw: big.clone(),
                        text: None,
                        timestamp: None,
                    },
                    ContextChunkInput {
                        source: "x".into(),
                        stream: ContextStream::Stdout,
                        raw: big.clone(),
                        text: None,
                        timestamp: None,
                    },
                    ContextChunkInput {
                        source: "x".into(),
                        stream: ContextStream::Stdout,
                        raw: big.clone(),
                        text: None,
                        timestamp: None,
                    },
                ],
            )
            .unwrap();

        // Check no .jsonl.tmp remains
        let tmp_path = dir.path().join("atomic.jsonl.tmp");
        assert!(
            !tmp_path.exists(),
            "tmp file should not remain after atomic rename"
        );

        // Check the main file exists and is valid JSONL
        let path = dir.path().join("atomic.jsonl");
        let mut s = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        for line in s.lines() {
            let _: serde_json::Value =
                serde_json::from_str(line).expect("line should be valid json");
        }
    }
}
