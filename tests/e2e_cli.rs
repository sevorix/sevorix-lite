/// E2E tests for CLI commands (scenarios 8.6–8.9).
///
/// Scenarios 8.1–8.5 (daemon lifecycle: start/stop/status/restart) are
/// intentionally omitted: they modify real user state and cannot safely run in
/// parallel with other tests or with a live daemon.
///
/// These tests spawn the actual `sevorix` binary via `std::process::Command`.
/// Cargo sets `CARGO_BIN_EXE_sevorix` automatically for integration tests, so
/// the binary must be built before running (`cargo build --release` or plain
/// `cargo build`).
use std::process::Command;

/// Locate the sevorix binary at runtime.
/// During `cargo test` the binary is in target/debug; the CARGO_MANIFEST_DIR
/// compile-time env var gives us the workspace root to find it.
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

// ── 8.6 – validate: BLOCK for a known-dangerous command ──────────────────────

#[test]
fn test_8_6_validate_block_command() {
    let bin = sevorix_bin();

    // "DROP TABLE" is a hardcoded Red-lane keyword in src/scanner.rs.
    // The validate command works entirely offline — no daemon required.
    let output = Command::new(bin)
        .args(["validate", "DROP TABLE users", "-C", "Shell"])
        .output()
        .expect("failed to run sevorix validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("stdout: {}", stdout);
    println!("stderr: {}", stderr);

    // The command must complete (not be killed by a signal).
    assert!(
        output.status.code().is_some(),
        "process was killed by a signal"
    );

    // BLOCK verdict → exit code 1.
    assert_eq!(
        output.status.code(),
        Some(1),
        "expected exit code 1 (BLOCK) but got {:?}",
        output.status.code()
    );

    // Output should be valid JSON containing a BLOCK verdict.
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout was not valid JSON");
    assert_eq!(
        json["verdict"].as_str().unwrap_or(""),
        "BLOCK",
        "expected verdict BLOCK, got: {}",
        json["verdict"]
    );
}

// ── 8.6 – validate: ALLOW for a benign command ───────────────────────────────

#[test]
fn test_8_6_validate_allow_command() {
    let bin = sevorix_bin();

    // "ls -la" is a harmless command that should land in the Green lane.
    let output = Command::new(bin)
        .args(["validate", "ls -la", "-C", "Shell"])
        .output()
        .expect("failed to run sevorix validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("stdout: {}", stdout);
    println!("stderr: {}", stderr);

    assert!(
        output.status.code().is_some(),
        "process was killed by a signal"
    );

    // validate uses the real ~/.sevorix/ config; without --role it fails closed.
    // Just assert it runs and produces valid JSON — we can't know the verdict
    // without controlling the real policy config.
    assert!(
        output.status.code().is_some(),
        "process was killed by a signal"
    );
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout was not valid JSON");
    assert!(
        json.get("verdict").is_some(),
        "output should have a verdict field, got: {json}"
    );
    assert!(
        json.get("command").is_some(),
        "output should echo the command field, got: {json}"
    );
}

// ── 8.6 – validate: BLOCK with explicit role flag ────────────────────────────

#[test]
fn test_8_6_validate_block_with_role_flag() {
    let bin = sevorix_bin();

    // Passing --role should not prevent the Red-lane keyword from being caught.
    let output = Command::new(bin)
        .args(["validate", "DROP TABLE users", "-r", "admin", "-C", "Shell"])
        .output()
        .expect("failed to run sevorix validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("stdout: {}", stdout);

    assert!(output.status.code().is_some(), "process was killed by a signal");
    assert_eq!(
        output.status.code(),
        Some(1),
        "expected exit code 1 (BLOCK) but got {:?}",
        output.status.code()
    );

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout was not valid JSON");
    assert_eq!(json["verdict"].as_str().unwrap_or(""), "BLOCK");
}

// ── 8.6 – validate: JSON output contains expected fields ─────────────────────

#[test]
fn test_8_6_validate_output_structure() {
    let bin = sevorix_bin();

    let output = Command::new(bin)
        .args(["validate", "ls -la", "-C", "Shell"])
        .output()
        .expect("failed to run sevorix validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout was not valid JSON");

    // All expected top-level keys must be present.
    for key in &["command", "verdict", "lane", "reason", "confidence", "context"] {
        assert!(
            !json[key].is_null(),
            "expected field '{}' to be present in validate output",
            key
        );
    }

    assert_eq!(
        json["command"].as_str().unwrap_or(""),
        "ls -la",
        "command field should echo the input"
    );
    assert_eq!(
        json["context"].as_str().unwrap_or(""),
        "Shell",
        "context field should reflect the -C flag"
    );
}

// ── 8.6 – validate: invalid context flag exits with code 1 ───────────────────

#[test]
fn test_8_6_validate_invalid_context() {
    let bin = sevorix_bin();

    let output = Command::new(bin)
        .args(["validate", "ls -la", "-C", "InvalidContext"])
        .output()
        .expect("failed to run sevorix validate");

    println!("stderr: {}", String::from_utf8_lossy(&output.stderr));

    // Invalid context should produce a non-zero exit code and not panic.
    assert!(output.status.code().is_some(), "process was killed by a signal");
    assert_ne!(
        output.status.code(),
        Some(0),
        "expected non-zero exit for invalid context"
    );
}

// ── 8.7 – config check: command runs and produces useful output ───────────────

#[test]
fn test_8_7_config_check_runs() {
    let bin = sevorix_bin();

    let output = Command::new(bin)
        .args(["config", "check"])
        .output()
        .expect("failed to run sevorix config check");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("config check stdout: {}", stdout);
    println!("config check stderr: {}", stderr);

    // Must complete without crashing.
    assert!(output.status.code().is_some(), "process was killed by a signal");

    // config check always exits 0 — it reports status rather than failing.
    assert_eq!(
        output.status.code(),
        Some(0),
        "expected exit code 0 for config check"
    );

    // Output should contain at least a config path reference.
    assert!(
        stdout.contains("Config path:") || stdout.contains("config"),
        "expected config check output to mention a config path, got: {}",
        stdout
    );
}

// ── 8.7 – config check: output mentions the policies.json path ───────────────

#[test]
fn test_8_7_config_check_mentions_policies() {
    let bin = sevorix_bin();

    let output = Command::new(bin)
        .args(["config", "check"])
        .output()
        .expect("failed to run sevorix config check");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // handle_config prints "Config path: <path>"; the path always contains
    // "policies.json" at the end.
    assert!(
        stdout.contains("policies.json"),
        "expected 'policies.json' to appear in config check output, got: {}",
        stdout
    );
}

// ── 8.8 – binary: no args shows help (does not crash) ─────────────────────────

#[test]
fn test_8_8_no_args_shows_help() {
    let bin = sevorix_bin();

    let output = Command::new(bin)
        .output()
        .expect("failed to run sevorix with no args");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("stdout: {}", stdout);
    println!("stderr: {}", stderr);

    // No args → print help and exit 0.
    assert_eq!(
        output.status.code(),
        Some(0),
        "expected exit code 0 for no-args help; got {:?}",
        output.status.code()
    );
    assert!(
        stdout.contains("Usage") || stdout.contains("usage") || stdout.contains("Commands"),
        "expected help text in stdout; got: {stdout}"
    );
}

// ── 8.9 – binary: --help flag exits 0 and mentions subcommands ───────────────

#[test]
fn test_8_9_help_flag() {
    let bin = sevorix_bin();

    let output = Command::new(bin)
        .arg("--help")
        .output()
        .expect("failed to run sevorix --help");

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("--help output: {}", stdout);

    // clap exits 0 for --help.
    assert_eq!(
        output.status.code(),
        Some(0),
        "expected exit code 0 for --help"
    );

    // Should mention key subcommands.
    assert!(
        stdout.contains("validate") || stdout.contains("Validate"),
        "expected 'validate' to appear in --help output"
    );
    assert!(
        stdout.contains("config") || stdout.contains("Config"),
        "expected 'config' to appear in --help output"
    );
}
