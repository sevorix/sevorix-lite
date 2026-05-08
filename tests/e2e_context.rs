// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

mod common;

use common::harness::TestHarness;
use serde_json::{json, Value};
use sevorix_watchtower::policy::Role;
use std::{
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

fn sevsh_bin() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    for profile in &["debug", "release"] {
        let p = Path::new(manifest_dir)
            .join("target")
            .join(profile)
            .join("sevsh");
        if p.exists() {
            return p;
        }
    }
    PathBuf::from("sevsh")
}

async fn append_context(h: &TestHarness, session_id: &str, chunks: Vec<Value>) -> Value {
    h.client
        .post(format!("{}/api/context", h.base_url()))
        .json(&json!({
            "session_id": session_id,
            "chunks": chunks,
        }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()
}

async fn get_context(h: &TestHarness, query: &str) -> reqwest::Response {
    h.client
        .get(format!("{}/api/context?{}", h.base_url(), query))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn test_context_roundtrip_persists_and_canonicalizes_text() {
    let h = TestHarness::new().await;
    let session_id = "sevsh-context-roundtrip";

    let appended = append_context(
        &h,
        session_id,
        vec![
            json!({
                "source": "codex",
                "stream": "stdout",
                "raw": "\u{1b}[32mhello\u{1b}[0m",
                "text": "client supplied text should be ignored"
            }),
            json!({
                "source": "codex",
                "stream": "stderr",
                "raw": "plain error"
            }),
        ],
    )
    .await;

    assert_eq!(appended["appended"], 2);

    let persisted_path = h
        .config_dir
        .join("context")
        .join(format!("{session_id}.jsonl"));
    assert!(
        persisted_path.exists(),
        "expected {}",
        persisted_path.display()
    );

    let response = get_context(&h, &format!("session={session_id}")).await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();

    assert_eq!(body["total"], 2);
    let chunks = body["chunks"].as_array().unwrap();
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0]["seq"], 0);
    assert_eq!(chunks[1]["seq"], 1);
    assert_eq!(chunks[0]["text"], "hello");
    assert_eq!(chunks[0]["raw"], "\u{1b}[32mhello\u{1b}[0m");
    assert_eq!(chunks[1]["stream"], "stderr");
}

#[tokio::test]
async fn test_context_query_respects_stream_limit_and_offset() {
    let h = TestHarness::new().await;
    let session_id = "sevsh-context-pagination";

    append_context(
        &h,
        session_id,
        vec![
            json!({
                "source": "sevsh",
                "stream": "stdin",
                "raw": "prompt"
            }),
            json!({
                "source": "sevsh",
                "stream": "stdout",
                "raw": "out-1"
            }),
            json!({
                "source": "sevsh",
                "stream": "stdout",
                "raw": "out-2"
            }),
        ],
    )
    .await;

    let response = get_context(
        &h,
        &format!("session={session_id}&stream=stdout&limit=1&offset=1"),
    )
    .await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();

    assert_eq!(body["total"], 2);
    assert_eq!(body["limit"], 1);
    assert_eq!(body["offset"], 1);

    let chunks = body["chunks"].as_array().unwrap();
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0]["raw"], "out-2");
    assert_eq!(chunks[0]["stream"], "stdout");
}

#[tokio::test]
async fn test_context_isolated_per_session() {
    let h = TestHarness::new().await;

    append_context(
        &h,
        "session-a",
        vec![json!({
            "source": "codex",
            "stream": "stdout",
            "raw": "alpha"
        })],
    )
    .await;
    append_context(
        &h,
        "session-b",
        vec![json!({
            "source": "codex",
            "stream": "stdout",
            "raw": "beta"
        })],
    )
    .await;

    let a_body: Value = get_context(&h, "session=session-a")
        .await
        .json()
        .await
        .unwrap();
    let b_body: Value = get_context(&h, "session=session-b")
        .await
        .json()
        .await
        .unwrap();

    assert_eq!(a_body["total"], 1);
    assert_eq!(b_body["total"], 1);
    assert_eq!(a_body["chunks"][0]["raw"], "alpha");
    assert_eq!(b_body["chunks"][0]["raw"], "beta");
}

#[tokio::test]
async fn test_context_validation_errors_return_400() {
    let h = TestHarness::new().await;

    let missing_session = h
        .client
        .get(format!("{}/api/context", h.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(missing_session.status(), 400);

    let empty_chunks = h
        .client
        .post(format!("{}/api/context", h.base_url()))
        .json(&json!({
            "session_id": "session-a",
            "chunks": []
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(empty_chunks.status(), 400);
}

#[tokio::test]
async fn test_context_defaults_to_current_session_when_session_id_missing() {
    let h = TestHarness::new().await;

    let appended = h
        .client
        .post(format!("{}/api/context", h.base_url()))
        .json(&json!({
            "chunks": [{
                "source": "codex",
                "stream": "stdout",
                "raw": "hello"
            }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(appended.status(), 200);

    let body: Value = appended.json().await.unwrap();
    let current_session = h.state.session_id.clone();
    assert_eq!(body["session_id"], current_session);

    let response = get_context(&h, &format!("session={}", current_session)).await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["total"], 1);
    assert_eq!(body["chunks"][0]["raw"], "hello");
}

#[tokio::test]
async fn test_context_defaults_to_current_session_when_session_id_blank() {
    let h = TestHarness::new().await;

    let appended = h
        .client
        .post(format!("{}/api/context", h.base_url()))
        .json(&json!({
            "session_id": "   ",
            "chunks": [{
                "source": "codex",
                "stream": "stdout",
                "raw": "hello"
            }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(appended.status(), 200);

    let body: Value = appended.json().await.unwrap();
    assert_eq!(body["session_id"], h.state.session_id);
}

#[tokio::test]
async fn test_sevsh_command_accumulates_context_for_active_daemon_session() {
    let h = TestHarness::with_role(Some("default".to_string())).await;
    h.add_role_direct(Role {
        name: "default".to_string(),
        policies: vec![],
        is_dynamic: false,
    });
    let tmp = TempDir::new().unwrap();

    let sevsh_path = sevsh_bin();
    let home_dir = tmp.path().to_path_buf();
    let port = h.addr.port().to_string();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(sevsh_path)
            .args(["--no-sandbox", "-c", "echo hello"])
            .env("HOME", home_dir)
            .env("SEVORIX_PORT", port)
            .output()
            .expect("failed to run sevsh")
    })
    .await
    .expect("sevsh task should join cleanly");

    assert_eq!(
        output.status.code(),
        Some(0),
        "expected sevsh to succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "hello\n");

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .get(format!(
            "{}/api/context?session={}",
            h.base_url(),
            h.state.session_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await.unwrap();
    let chunks = body["chunks"].as_array().unwrap();

    assert!(
        chunks.iter().any(|chunk| {
            chunk["source"] == "sevsh" && chunk["stream"] == "stdin" && chunk["raw"] == "echo hello"
        }),
        "expected stdin chunk for command, got: {body}"
    );
    assert!(
        chunks.iter().any(|chunk| {
            chunk["source"] == "sevsh" && chunk["stream"] == "stdout" && chunk["raw"] == "hello\n"
        }),
        "expected stdout chunk for command output, got: {body}"
    );
}
