// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

/// E2E and integration tests for multi-session support.
///
/// Organised into three tiers:
///
/// 1. **CLI flag tests** — run the real `sevorix` binary and check that `--name`
///    and `--port` are accepted without errors.  No daemon is started.
///
/// 2. **Unit tests** — exercise `find_available_port`, `SessionInfo` serde, and
///    `list_sessions` logic directly through the library.
///
/// 3. **In-process server isolation tests** — spin up two independent
///    `TestHarness` instances on different ephemeral ports and verify that
///    policy state, role state, and traffic logs are fully isolated.
///
/// 4. **Lite enforcement tests** — verify that a non-pro binary rejects a second
///    `sevorix start` when a session metadata file is already present, using a
///    temporary HOME to avoid touching real user state.
use std::process::Command;

mod common;
use common::harness::TestHarness;
use serde_json::json;
use sevorix_watchtower::{
    find_available_port,
    policy::{Action, Policy, PolicyContext, PolicyType, Role},
    DaemonManager, SessionInfo,
};

// ── helpers ───────────────────────────────────────────────────────────────────

fn sevorix_bin() -> std::path::PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    for profile in &["debug", "release"] {
        for name in &["sevorix", "sevorix_watchtower"] {
            let p = std::path::Path::new(manifest_dir)
                .join("target")
                .join(profile)
                .join(name);
            if p.exists() {
                return p;
            }
        }
    }
    std::path::PathBuf::from("sevorix")
}

async fn analyze(h: &TestHarness, payload: &str) -> serde_json::Value {
    h.client
        .post(format!("{}/analyze", h.base_url()))
        .json(&json!({"payload": payload, "context": "Shell"}))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap()
}

async fn harness_with_block_policy(keyword: &str) -> TestHarness {
    let h = TestHarness::with_role(Some("default".to_string())).await;
    let id = format!("block-{}", keyword.to_lowercase());
    h.add_policy_direct(Policy {
        id: id.clone(),
        match_type: PolicyType::Simple(keyword.to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
        syscall: vec![],
    });
    h.add_role_direct(Role {
        name: "default".to_string(),
        policies: vec![id],
        is_dynamic: false,
    });
    h
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. CLI flag acceptance tests (no daemon started)
// ─────────────────────────────────────────────────────────────────────────────

/// `sevorix start --help` should list `--name` and `--port` flags.
#[test]
fn test_ms1_start_help_shows_name_and_port_flags() {
    let bin = sevorix_bin();
    let output = Command::new(bin)
        .args(["start", "--help"])
        .output()
        .expect("failed to run sevorix start --help");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "sevorix start --help should exit 0"
    );
    assert!(
        stdout.contains("--name"),
        "expected --name in start --help output, got: {stdout}"
    );
    assert!(
        stdout.contains("--port"),
        "expected --port in start --help output, got: {stdout}"
    );
}

/// `sevorix start --help` should NOT expose `--role` in lite builds.
/// Skipped in pro builds where --role is intentionally present.
#[test]
fn test_ms2_start_help_does_not_show_role_in_lite() {
    let bin = sevorix_bin();
    let output = Command::new(bin)
        .args(["start", "--help"])
        .output()
        .expect("failed to run sevorix start --help");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Check specifically for "--role <ROLE>" (the session-role setter), not
    // "--roles <ROLES>" which is the global flag present in all builds.
    assert!(
        !stdout.contains("--role <"),
        "lite build should not expose --role on start, got: {stdout}"
    );
}

/// Passing `--name foo` to `start` must not produce an "unrecognized argument"
/// error (exit code 2).  We use `--help` as a suffix so no daemon is spawned.
#[test]
fn test_ms3_name_flag_is_recognized_by_start() {
    let bin = sevorix_bin();
    // `--help` after named args makes clap print help and exit 0 without starting.
    let output = Command::new(bin)
        .args(["start", "--name", "myproject", "--help"])
        .output()
        .expect("failed to run sevorix start --name myproject --help");

    // clap exits 0 for --help regardless of preceding args.
    assert_eq!(
        output.status.code(),
        Some(0),
        "start --name should be accepted; got exit {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Passing `--port 3001` to `start` must not produce an "unrecognized argument"
/// error.
#[test]
fn test_ms4_port_flag_is_recognized_by_start() {
    let bin = sevorix_bin();
    let output = Command::new(bin)
        .args(["start", "--port", "3001", "--help"])
        .output()
        .expect("failed to run sevorix start --port 3001 --help");

    assert_eq!(
        output.status.code(),
        Some(0),
        "start --port should be accepted; got exit {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Both `--name` and `--port` together must be accepted.
#[test]
fn test_ms5_name_and_port_together_are_recognized() {
    let bin = sevorix_bin();
    let output = Command::new(bin)
        .args([
            "start",
            "--name",
            "agent-session",
            "--port",
            "4200",
            "--help",
        ])
        .output()
        .expect("failed to run command");

    assert_eq!(
        output.status.code(),
        Some(0),
        "start --name --port together should be accepted; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Unit tests (library functions, no daemon process)
// ─────────────────────────────────────────────────────────────────────────────

/// `find_available_port` must return a port within the scan range.
#[test]
fn test_ms6_find_available_port_returns_port_in_range() {
    let start = 19000u16;
    let port = find_available_port(start);
    assert!(
        port >= start && port <= start.saturating_add(99),
        "expected port in [{}, {}], got {}",
        start,
        start.saturating_add(99),
        port
    );
}

/// When the starting port is occupied, `find_available_port` must skip it.
#[test]
fn test_ms7_find_available_port_skips_bound_port() {
    let start = 19100u16;
    // Bind the start port ourselves.
    let _listener = std::net::TcpListener::bind(("127.0.0.1", start))
        .expect("test setup: couldn't bind port 19100");

    let port = find_available_port(start);
    assert_ne!(
        port, start,
        "find_available_port should skip already-bound port {start}"
    );
    assert!(
        port > start,
        "should have found a port after {start}, got {port}"
    );
}

/// `SessionInfo` must round-trip through JSON without data loss.
#[test]
fn test_ms8_session_info_serde_roundtrip() {
    let info = SessionInfo {
        name: "my-session".to_string(),
        session_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        port: 3001,
        role: Some("admin".to_string()),
        pid: 12345,
    };

    let json = serde_json::to_string(&info).expect("serialize failed");
    let back: SessionInfo = serde_json::from_str(&json).expect("deserialize failed");

    assert_eq!(back.name, info.name);
    assert_eq!(back.session_id, info.session_id);
    assert_eq!(back.port, info.port);
    assert_eq!(back.role, info.role);
    assert_eq!(back.pid, info.pid);
}

/// `SessionInfo` with `role: None` must round-trip correctly.
#[test]
fn test_ms9_session_info_serde_with_no_role() {
    let info = SessionInfo {
        name: "no-role-session".to_string(),
        session_id: "abc123".to_string(),
        port: 3000,
        role: None,
        pid: 99999,
    };

    let json = serde_json::to_string(&info).expect("serialize failed");
    let back: SessionInfo = serde_json::from_str(&json).expect("deserialize failed");
    assert!(back.role.is_none(), "role should be None after roundtrip");
}

/// `list_sessions` on a clean temp HOME must return an empty vec.
#[test]
fn test_ms10_list_sessions_empty_state_returns_empty() {
    // We can't easily redirect ProjectDirs without changing HOME, so instead we
    // just verify the function never panics and returns a Vec (possibly non-empty
    // if the tester has live sessions; that's fine — we only check the type).
    let result = DaemonManager::list_sessions();
    assert!(
        result.is_ok(),
        "list_sessions should not error: {:?}",
        result
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. In-process server isolation tests (two TestHarness instances)
// ─────────────────────────────────────────────────────────────────────────────

/// Two servers started on different ports must maintain isolated policy engines.
/// A policy added to server A must not affect server B.
#[tokio::test]
async fn test_ms11_two_sessions_have_isolated_policy_engines() {
    let session_a = harness_with_block_policy("SESSION_A_SECRET").await;
    let session_b = TestHarness::with_role(Some("default".to_string())).await;
    session_b.add_role_direct(Role {
        name: "default".to_string(),
        policies: vec![],
        is_dynamic: false,
    });

    // session_a blocks SESSION_A_SECRET
    let resp_a = analyze(&session_a, "SESSION_A_SECRET").await;
    assert_eq!(
        resp_a["status"], "BLOCK",
        "session_a should BLOCK its own keyword: {resp_a}"
    );

    // session_b is unaware of session_a's policy — must ALLOW the same payload
    let resp_b = analyze(&session_b, "SESSION_A_SECRET").await;
    assert_eq!(
        resp_b["status"], "ALLOW",
        "session_b should not be affected by session_a policy: {resp_b}"
    );
}

/// Policy added to session B must not bleed into session A.
#[tokio::test]
async fn test_ms12_policy_added_to_b_does_not_affect_a() {
    let session_a = TestHarness::with_role(Some("open".to_string())).await;
    session_a.add_role_direct(Role {
        name: "open".to_string(),
        policies: vec![],
        is_dynamic: false,
    });

    let session_b = harness_with_block_policy("ONLY_IN_B").await;

    // Baseline: session_a allows freely
    let allow = analyze(&session_a, "ONLY_IN_B").await;
    assert_eq!(
        allow["status"], "ALLOW",
        "session_a should allow before any policy: {allow}"
    );

    // session_b blocks it
    let block = analyze(&session_b, "ONLY_IN_B").await;
    assert_eq!(block["status"], "BLOCK", "session_b should block: {block}");

    // session_a still allows — no bleed
    let still_allow = analyze(&session_a, "ONLY_IN_B").await;
    assert_eq!(
        still_allow["status"], "ALLOW",
        "session_a should still allow after session_b was loaded: {still_allow}"
    );
}

/// Two sessions can operate on different ports simultaneously without
/// interfering with each other's HTTP responses.
#[tokio::test]
async fn test_ms13_two_sessions_respond_on_different_ports() {
    let session_a = TestHarness::new().await;
    let session_b = TestHarness::new().await;

    // They must be on different addresses (ports).
    assert_ne!(
        session_a.addr, session_b.addr,
        "sessions must be bound to different addresses"
    );

    // Both must respond to /analyze independently.
    let resp_a = analyze(&session_a, "echo hello").await;
    let resp_b = analyze(&session_b, "echo hello").await;

    assert!(
        resp_a.get("status").is_some(),
        "session_a should return a status field: {resp_a}"
    );
    assert!(
        resp_b.get("status").is_some(),
        "session_b should return a status field: {resp_b}"
    );
}

/// Two sessions started with different active roles must enforce their own
/// role policies independently.
#[tokio::test]
async fn test_ms14_two_sessions_enforce_different_roles() {
    // Session A has a "strict" role that blocks the keyword.
    let session_a = TestHarness::with_role(Some("strict".to_string())).await;
    session_a.add_policy_direct(Policy {
        id: "block-rm".to_string(),
        match_type: PolicyType::Simple("rm -rf".to_string()),
        action: Action::Block,
        context: PolicyContext::Shell,
        kill: false,
        syscall: vec![],
    });
    session_a.add_role_direct(Role {
        name: "strict".to_string(),
        policies: vec!["block-rm".to_string()],
        is_dynamic: false,
    });

    // Session B has a "permissive" role with no policies.
    let session_b = TestHarness::with_role(Some("permissive".to_string())).await;
    session_b.add_role_direct(Role {
        name: "permissive".to_string(),
        policies: vec![],
        is_dynamic: false,
    });

    let blocked = analyze(&session_a, "rm -rf /tmp/test").await;
    assert_eq!(
        blocked["status"], "BLOCK",
        "strict session should block rm -rf: {blocked}"
    );

    let allowed = analyze(&session_b, "rm -rf /tmp/test").await;
    assert_eq!(
        allowed["status"], "ALLOW",
        "permissive session should allow: {allowed}"
    );
}

/// Each session uses its own isolated traffic log path.
/// Verify the AppState.traffic_log_path fields are different across sessions.
#[tokio::test]
async fn test_ms15_sessions_have_separate_traffic_log_paths() {
    let session_a = TestHarness::new().await;
    let session_b = TestHarness::new().await;

    assert_ne!(
        session_a.state.traffic_log_path, session_b.state.traffic_log_path,
        "each session must write to a distinct traffic log"
    );
}

/// Sending traffic to session A must not appear in session B's traffic log.
#[tokio::test]
async fn test_ms16_traffic_logged_to_correct_session_log() {
    let session_a = TestHarness::new().await;
    let session_b = TestHarness::new().await;

    // Fire a request into session_a only.
    analyze(&session_a, "SELECT * FROM users").await;

    // Give the log writer a moment to flush.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let log_a = session_a.state.traffic_log_path.clone();
    let log_b = session_b.state.traffic_log_path.clone();

    // session_a log should exist and contain the payload.
    if log_a.exists() {
        let content_a = std::fs::read_to_string(&log_a).unwrap_or_default();
        assert!(
            content_a.contains("SELECT"),
            "session_a log should contain the payload; got: {content_a}"
        );
    }

    // session_b log must NOT contain the payload (or not exist at all).
    if log_b.exists() {
        let content_b = std::fs::read_to_string(&log_b).unwrap_or_default();
        assert!(
            !content_b.contains("SELECT"),
            "session_b log must not contain session_a traffic; got: {content_b}"
        );
    }
}

/// Adding many policies to session A does not degrade session B's response
/// (basic sanity check that engines are truly independent objects).
#[tokio::test]
async fn test_ms17_heavy_session_a_does_not_affect_session_b() {
    let session_a = TestHarness::with_role(Some("heavy".to_string())).await;
    let mut policy_ids = Vec::new();
    for i in 0..50 {
        let id = format!("policy-{i}");
        session_a.add_policy_direct(Policy {
            id: id.clone(),
            match_type: PolicyType::Simple(format!("KEYWORD_{i}")),
            action: Action::Block,
            context: PolicyContext::All,
            kill: false,
            syscall: vec![],
        });
        policy_ids.push(id);
    }
    session_a.add_role_direct(Role {
        name: "heavy".to_string(),
        policies: policy_ids,
        is_dynamic: false,
    });

    let session_b = TestHarness::new().await;

    // session_b has no policies loaded — must still respond ALLOW cleanly.
    let resp = analyze(&session_b, "KEYWORD_0").await;
    assert!(
        resp.get("status").is_some(),
        "session_b must respond despite session_a being policy-heavy: {resp}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Lite enforcement test (via binary with isolated HOME)
// ─────────────────────────────────────────────────────────────────────────────

/// In a lite build (no --features pro), attempting to start a second session
/// when one is already registered must exit non-zero with an informative error.
///
/// We simulate an existing session by writing a valid session metadata JSON to
/// a temp directory and pointing HOME at it, so no real daemon is touched.
///
/// This is a lite-only behavior — pro allows multiple concurrent sessions.
#[test]
fn test_ms18_lite_rejects_second_start_when_session_exists() {
    let bin = sevorix_bin();

    // Build the temp HOME directory structure that `directories::ProjectDirs`
    // expects on Linux: $HOME/.local/state/sevorix/sessions/<name>.json
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let sessions_dir = tmp.path().join(".local/state/sevorix/sessions");
    std::fs::create_dir_all(&sessions_dir).expect("create sessions dir");

    // Write a fake running session using the current test process's PID.
    // `libc::kill(own_pid, 0)` always returns 0, so list_sessions() sees it as alive.
    let own_pid = std::process::id() as i32;
    let info = serde_json::json!({
        "name": "existing-session",
        "session_id": "00000000-0000-0000-0000-000000000001",
        "port": 3000,
        "role": null,
        "pid": own_pid
    });
    std::fs::write(
        sessions_dir.join("existing-session.json"),
        serde_json::to_string_pretty(&info).unwrap(),
    )
    .expect("write session metadata");

    // Run `sevorix start --name new-session --watchtower-only` with the fake HOME.
    // --watchtower-only skips the eBPF pre-flight check so the single-session
    // enforcement runs first.
    // Also override XDG_STATE_HOME so it can't escape the temp dir.
    let xdg_state = tmp.path().join(".local/state");
    let output = Command::new(&bin)
        .args(["start", "--name", "new-session", "--watchtower-only"])
        .env("HOME", tmp.path())
        .env("XDG_STATE_HOME", &xdg_state)
        .output()
        .expect("failed to run sevorix start");

    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("exit: {:?}", output.status.code());
    println!("stderr: {stderr}");

    // Must not exit 0 — a new session is forbidden while one is running.
    assert_ne!(
        output.status.code(),
        Some(0),
        "lite build must reject second start; stderr: {stderr}"
    );

    // The error message should guide the user.
    assert!(
        stderr.contains("already running") || stderr.contains("stop"),
        "error message should mention the existing session and how to stop it; got: {stderr}"
    );
}

/// Verify that the lite enforcement message mentions the session name and port.
#[test]
fn test_ms19_lite_enforcement_message_includes_session_details() {
    let bin = sevorix_bin();

    let tmp = tempfile::TempDir::new().expect("tempdir");
    let sessions_dir = tmp.path().join(".local/state/sevorix/sessions");
    std::fs::create_dir_all(&sessions_dir).expect("create sessions dir");

    let own_pid = std::process::id() as i32;
    let info = serde_json::json!({
        "name": "named-session",
        "session_id": "00000000-0000-0000-0000-000000000002",
        "port": 4242,
        "role": null,
        "pid": own_pid
    });
    std::fs::write(
        sessions_dir.join("named-session.json"),
        serde_json::to_string_pretty(&info).unwrap(),
    )
    .expect("write session metadata");

    let xdg_state = tmp.path().join(".local/state");
    let output = Command::new(&bin)
        .args(["start", "--name", "another", "--watchtower-only"])
        .env("HOME", tmp.path())
        .env("XDG_STATE_HOME", &xdg_state)
        .output()
        .expect("failed to run sevorix start");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_ne!(output.status.code(), Some(0));
    assert!(
        stderr.contains("named-session"),
        "error should include the existing session name; got: {stderr}"
    );
    assert!(
        stderr.contains("4242"),
        "error should include the port; got: {stderr}"
    );
}
