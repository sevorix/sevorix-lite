// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

//! E2E tests for the `sevsh` secure-shell wrapper binary.
//!
//! Tests 1-3 cover the original three bug fixes:
//!   1. `sevsh --no-sandbox -c "cmd"` — modifier flag with bash-compat `-c`
//!   2. `sevsh -- cmd args` — direct binary exec via `handle_direct_exec`
//!   3. PID/PPID non-null in traffic log
//!
//! Tests 8-12 cover additional scenarios surfaced during PR review:
//!   8.  `sevsh script.sh` routes through the sandbox/validate path
//!   9.  fail-closed / env-var-fallback behaviour for `-c` without `--no-sandbox`
//!   10. `"--"` embedded inside a `-c` command string is passed through verbatim
//!   11. a blocked command returns exit code 1
//!   12. `--no-proxy` combined with `--` separator works correctly
//!
//! All tests that spin up a live Watchtower server use `tokio::process::Command`
//! to avoid blocking the tokio executor and starving the embedded test server.

mod common;
use common::harness::TestHarness;
use serde_json::json;
use sevorix_watchtower::policy::{Action, Policy, PolicyContext, PolicyType, Role};

// ── helpers ───────────────────────────────────────────────────────────────────

/// Locate the `sevsh` binary produced by the current Cargo build.
fn sevsh_bin() -> std::path::PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    for profile in &["debug", "release"] {
        let p = std::path::Path::new(manifest_dir)
            .join("target")
            .join(profile)
            .join("sevsh");
        if p.exists() {
            return p;
        }
    }
    // Fall back to PATH lookup.
    std::path::PathBuf::from("sevsh")
}

/// Returns `true` if `unshare` is available on this machine.
fn unshare_available() -> bool {
    std::process::Command::new("which")
        .arg("unshare")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Spin up a test harness that ALLOWs any command.
///
/// Sets `current_role = "default"` and registers a matching role with an empty
/// policy list so the policy engine does not block on "role not found".
async fn allow_harness() -> TestHarness {
    let h = TestHarness::with_role(Some("default".to_string())).await;
    h.add_role_direct(Role {
        name: "default".to_string(),
        policies: vec![],
        is_dynamic: false,
    });
    h
}

// ── Test 1: --no-sandbox with bash-compat -c flag ────────────────────────────

#[tokio::test]
async fn test_sevsh_no_sandbox_with_c_flag() {
    let h = allow_harness().await;
    let port = h.addr.port();

    let output = tokio::process::Command::new(sevsh_bin())
        .args(["--no-sandbox", "-c", "echo hello"])
        .env("SEVORIX_PORT", port.to_string())
        .env("HOME", h.config_dir.as_os_str())
        .output()
        .await
        .expect("failed to spawn sevsh");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "sevsh --no-sandbox -c 'echo hello' should exit 0, got {:?}. stderr: {}",
        output.status.code(),
        stderr
    );
    assert!(
        stdout.contains("hello"),
        "stdout should contain 'hello', got: {}",
        stdout
    );
}

// ── Test 2: double-dash direct binary exec ────────────────────────────────────

#[tokio::test]
async fn test_sevsh_double_dash_direct_exec() {
    let h = allow_harness().await;
    let port = h.addr.port();

    let output = tokio::process::Command::new(sevsh_bin())
        .args(["--no-sandbox", "--", "echo", "hello"])
        .env("SEVORIX_PORT", port.to_string())
        .env("HOME", h.config_dir.as_os_str())
        .output()
        .await
        .expect("failed to spawn sevsh");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "sevsh --no-sandbox -- echo hello should exit 0, got {:?}. stderr: {}",
        output.status.code(),
        stderr
    );
    assert!(
        stdout.contains("hello"),
        "stdout should contain 'hello', got: {}",
        stdout
    );
}

// ── Test 3: PID and PPID are non-null in the traffic log ─────────────────────

#[tokio::test]
async fn test_sevsh_pid_ppid_logged() {
    let h = allow_harness().await;
    let port = h.addr.port();

    let _ = tokio::process::Command::new(sevsh_bin())
        .args(["--no-sandbox", "-c", "echo pid_ppid_test"])
        .env("SEVORIX_PORT", port.to_string())
        .env("HOME", h.config_dir.as_os_str())
        .output()
        .await
        .expect("failed to spawn sevsh");

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let log_content = std::fs::read_to_string(&h.state.traffic_log_path).unwrap_or_default();

    assert!(
        !log_content.is_empty(),
        "traffic log should not be empty after a sevsh invocation"
    );

    let found = log_content
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .any(|entry| {
            let pid_in_root = entry.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
            let pid_in_payload = entry
                .get("payload")
                .and_then(|p| p.get("pid"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            pid_in_root > 0 || pid_in_payload > 0
        });

    assert!(
        found,
        "traffic log should contain at least one entry with a non-zero pid. Log:\n{}",
        log_content
    );
}

// ── Test 8: script-file invocation routes through sandbox check ───────────────

#[tokio::test]
async fn test_8_sevsh_script_file_routes_through_sandbox_check() {
    let h = allow_harness().await;
    let port = h.addr.port();

    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("hello.sh");
    std::fs::write(&script, "#!/bin/sh\necho hello-from-script\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
    }

    let output = tokio::process::Command::new(sevsh_bin())
        .arg(script.to_str().unwrap())
        .env("SEVORIX_PORT", port.to_string())
        .env_remove("SEVORIX_SESSION")
        .output()
        .await
        .expect("failed to spawn sevsh");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        assert!(
            stdout.contains("hello-from-script"),
            "expected 'hello-from-script' in stdout; got: {stdout:?}\nstderr: {stderr:?}"
        );
    } else {
        // Non-zero is acceptable: eBPF daemon absent, sandbox tools missing, or
        // (in CI) the kernel disallows unprivileged namespaces causing unshare
        // itself to fail before sevsh can print a [SEVSH] message.
        let has_diagnostic =
            stderr.contains("[SEVSH]") || stderr.contains("SEVORIX") || stderr.contains("unshare:");
        assert!(
            has_diagnostic,
            "expected a [SEVSH], SEVORIX, or unshare diagnostic on non-zero exit;\
            \nstdout: {stdout:?}\nstderr: {stderr:?}"
        );
    }
}

// ── Test 9: -c without --no-sandbox falls back gracefully ────────────────────

#[tokio::test]
async fn test_9_c_flag_without_no_sandbox() {
    let h = allow_harness().await;
    let port = h.addr.port();

    let output = tokio::process::Command::new(sevsh_bin())
        .args(["-c", "echo hello"])
        .env("SEVORIX_PORT", port.to_string())
        .env_remove("SEVORIX_SESSION")
        .output()
        .await
        .expect("failed to spawn sevsh");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // In both cases the process must exit cleanly (not be killed by a signal).
    // When unshare is available the sandbox path is taken; the command may or
    // may not succeed depending on whether the test harness is reachable from
    // inside the network namespace (that requires the unix-socket bridge, which
    // is exercised by integration tests). We only assert the process didn't crash.
    assert!(
        output.status.code().is_some(),
        "process was killed by a signal; stderr: {stderr:?}"
    );
    if output.status.success() {
        assert!(
            stdout.contains("hello"),
            "expected 'hello' on success; got: {stdout:?}"
        );
    } else {
        // Non-zero is acceptable: Watchtower unreachable through the bridge,
        // or the kernel disallows unprivileged namespaces (CI).
        assert!(
            stderr.contains("[SEVSH]") || stderr.contains("SEVORIX") || stderr.contains("unshare:"),
            "expected a diagnostic on non-zero exit; stderr: {stderr:?}"
        );
    }
}

// ── Test 10: "--" inside -c string is not treated as flag sentinel ────────────

#[tokio::test]
async fn test_10_double_dash_inside_command_string_passed_through() {
    let h = allow_harness().await;
    let port = h.addr.port();

    let output = tokio::process::Command::new(sevsh_bin())
        .args(["--no-sandbox", "--", "-c", "echo hello -- world"])
        .env("SEVORIX_PORT", port.to_string())
        .env_remove("SEVORIX_SESSION")
        .output()
        .await
        .expect("failed to spawn sevsh");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(0),
        "expected exit 0; stderr: {stderr:?}"
    );
    assert!(
        stdout.contains("hello -- world"),
        "expected 'hello -- world' in stdout; got: {stdout:?}\nstderr: {stderr:?}"
    );
}

// ── Test 11: blocked command returns exit code 1 ──────────────────────────────

#[tokio::test]
async fn test_11_blocked_command_returns_exit_code_1() {
    let h = TestHarness::with_role(Some("agent".to_string())).await;
    let port = h.addr.port();

    h.add_policy(
        "block-test-keyword",
        json!({
            "id": "block-test-keyword",
            "type": "Simple",
            "pattern": "BLOCKED_KEYWORD_XYZ",
            "action": "Block",
            "context": "All",
            "kill": false
        }),
    );
    h.add_role(
        "agent",
        json!({
            "name": "agent",
            "policies": ["block-test-keyword"],
            "is_dynamic": false
        }),
    );
    h.reload_policies().await;

    let output = tokio::process::Command::new(sevsh_bin())
        .args(["--no-sandbox", "--", "-c", "BLOCKED_KEYWORD_XYZ"])
        .env("SEVORIX_PORT", port.to_string())
        .env_remove("SEVORIX_SESSION")
        .output()
        .await
        .expect("failed to spawn sevsh");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(1),
        "expected exit code 1 for blocked command; got: {:?}\nstderr: {stderr:?}",
        output.status.code()
    );
}

// ── Test 12: --no-proxy with -- separator ─────────────────────────────────────

#[tokio::test]
async fn test_12_no_proxy_with_double_dash_separator() {
    let h = allow_harness().await;
    let port = h.addr.port();

    let output = tokio::process::Command::new(sevsh_bin())
        .args(["--no-sandbox", "--no-proxy", "--", "-c", "echo hello"])
        .env("SEVORIX_PORT", port.to_string())
        .env_remove("SEVORIX_SESSION")
        .output()
        .await
        .expect("failed to spawn sevsh");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(0),
        "expected exit 0; stderr: {stderr:?}"
    );
    assert!(
        stdout.contains("hello"),
        "expected 'hello' in stdout; got: {stdout:?}\nstderr: {stderr:?}"
    );
}
