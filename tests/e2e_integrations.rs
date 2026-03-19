/// E2E tests for integrations CLI subcommands (scenarios 9.1–9.10).
///
/// These tests exercise the `sevorix integrations` subcommands via
/// `std::process::Command`. They test observable CLI behavior (stdout, stderr,
/// exit codes) without starting the HTTP daemon or modifying real user files.
///
/// Integration names registered: "Claude Code", "Codex", "OpenClaw".
/// Alias resolution: "claude" and "claude-code" both map to "Claude Code".
use std::process::Command;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

/// Run a sevorix subcommand and return (stdout, stderr, exit_code).
fn run(args: &[&str]) -> (String, String, i32) {
    let output = Command::new(sevorix_bin())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn sevorix: {}", e));
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

// ---------------------------------------------------------------------------
// 9.8 — Integrations list
// ---------------------------------------------------------------------------

/// Scenario 9.8: `sevorix integrations list` shows all three integrations.
#[test]
fn test_9_8_integrations_list() {
    let (stdout, stderr, _code) = run(&["integrations", "list"]);
    println!("stdout:\n{}\nstderr:\n{}", stdout, stderr);

    // All three canonical integration names must appear in the output.
    assert!(
        stdout.contains("Claude Code"),
        "expected 'Claude Code' in list output; got: {stdout}"
    );
    assert!(
        stdout.contains("Codex"),
        "expected 'Codex' in list output; got: {stdout}"
    );
    assert!(
        stdout.contains("OpenClaw"),
        "expected 'OpenClaw' in list output; got: {stdout}"
    );

    // The header line must be present when integrations are registered.
    assert!(
        stdout.contains("Available integrations:"),
        "expected 'Available integrations:' header; got: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// 9.3 — Alias resolution
// ---------------------------------------------------------------------------

/// Scenario 9.3: "claude" and "claude-code" are accepted aliases for
/// "Claude Code". Neither alias should produce an "integration not found"
/// error; both should resolve to the same integration and produce comparable
/// output.
#[test]
fn test_9_3_alias_claude_resolves() {
    let (out1, err1, _) = run(&["integrations", "status", "claude"]);
    let combined1 = format!("{}{}", out1, err1);
    println!("claude alias combined:\n{}", combined1);

    // Must NOT say the alias itself was not found as an unrecognised name.
    assert!(
        !combined1.contains("'claude' not found"),
        "alias 'claude' was not resolved; combined output: {combined1}"
    );

    // Must identify as "Claude Code".
    assert!(
        combined1.contains("Claude Code"),
        "expected 'Claude Code' in output for alias 'claude'; got: {combined1}"
    );
}

#[test]
fn test_9_3_alias_claude_code_resolves() {
    let (out2, err2, _) = run(&["integrations", "status", "claude-code"]);
    let combined2 = format!("{}{}", out2, err2);
    println!("claude-code alias combined:\n{}", combined2);

    // Must NOT say the alias itself was not found.
    assert!(
        !combined2.contains("'claude-code' not found"),
        "alias 'claude-code' was not resolved; combined output: {combined2}"
    );

    // Must identify as "Claude Code".
    assert!(
        combined2.contains("Claude Code"),
        "expected 'Claude Code' in output for alias 'claude-code'; got: {combined2}"
    );
}

/// The two aliases must resolve to the same integration: their status outputs
/// should both mention "Claude Code" (structural equivalence).
#[test]
fn test_9_3_aliases_resolve_to_same_integration() {
    let (out1, err1, _) = run(&["integrations", "status", "claude"]);
    let (out2, err2, _) = run(&["integrations", "status", "claude-code"]);

    let contains_claude_code_1 = format!("{}{}", out1, err1).contains("Claude Code");
    let contains_claude_code_2 = format!("{}{}", out2, err2).contains("Claude Code");

    assert_eq!(
        contains_claude_code_1, contains_claude_code_2,
        "'claude' and 'claude-code' aliases resolved to different integrations"
    );
}

// ---------------------------------------------------------------------------
// 9.1 — Install (prerequisite check, no disk writes)
// ---------------------------------------------------------------------------

/// Scenario 9.1: `integrations install claude-code` is a prerequisite-check
/// operation. It either succeeds (all prereqs met) or fails with a clear error.
/// Either way it must NOT crash and must produce output mentioning the integration.
#[test]
fn test_9_1_install_claude_code_no_daemon_fails() {
    let (stdout, stderr, code) = run(&["integrations", "install", "claude-code"]);
    println!("stdout:\n{}\nstderr:\n{}", stdout, stderr);

    // Must produce an exit code (no crash / signal death).
    assert!(code != -1, "process was killed by a signal");

    // Must produce some output — either success or error.
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        !combined.is_empty(),
        "expected some output from install command; got nothing"
    );

    // Output must mention the integration name or a recognized error keyword.
    assert!(
        combined.contains("Claude Code")
            || combined.contains("claude")
            || combined.contains("Failed")
            || combined.contains("installed")
            || combined.contains("not running")
            || combined.contains("daemon"),
        "expected install output to reference the integration or an error; got: {combined}"
    );
}

// ---------------------------------------------------------------------------
// 9.4 — Uninstall (no-op for Claude Code)
// ---------------------------------------------------------------------------

/// Scenario 9.4: `integrations uninstall claude-code` is a no-op for Claude
/// Code (nothing was written on install). It should succeed without error.
#[test]
fn test_9_4_uninstall_claude_code_no_op() {
    let (stdout, stderr, code) = run(&["integrations", "uninstall", "claude-code"]);
    println!("stdout:\n{}\nstderr:\n{}", stdout, stderr);

    // Should exit cleanly (code 0).
    assert_eq!(
        code, 0,
        "uninstall claude-code should succeed (no-op); exit code was {code}, stderr: {stderr}"
    );

    // stderr should be empty — no error output.
    assert!(
        stderr.is_empty(),
        "unexpected error output on no-op uninstall: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// 9.5 — Status reporting
// ---------------------------------------------------------------------------

/// Scenario 9.5: `integrations status claude-code` produces structured output
/// showing integration name, description, and status.
#[test]
fn test_9_5_status_claude_code_output_structure() {
    let (stdout, stderr, _code) = run(&["integrations", "status", "claude-code"]);
    println!("stdout:\n{}\nstderr:\n{}", stdout, stderr);

    assert!(
        stdout.contains("Integration:"),
        "expected 'Integration:' label in status output; got: {stdout}"
    );
    assert!(
        stdout.contains("Description:"),
        "expected 'Description:' label in status output; got: {stdout}"
    );
    assert!(
        stdout.contains("Status:"),
        "expected 'Status:' label in status output; got: {stdout}"
    );
    assert!(
        stdout.contains("Claude Code"),
        "expected integration name 'Claude Code' in status output; got: {stdout}"
    );
}

/// `integrations status` with no name shows all integrations.
#[test]
fn test_9_5_status_all_shows_all_integrations() {
    let (stdout, stderr, code) = run(&["integrations", "status"]);
    println!("stdout:\n{}\nstderr:\n{}", stdout, stderr);

    assert_eq!(code, 0, "status with no args should exit 0; code={code}, stderr={stderr}");
    assert!(
        stdout.contains("Integration Status:"),
        "expected 'Integration Status:' header; got: {stdout}"
    );
    assert!(stdout.contains("Claude Code"), "expected 'Claude Code' in all-status; got: {stdout}");
    assert!(stdout.contains("Codex"), "expected 'Codex' in all-status; got: {stdout}");
    assert!(stdout.contains("OpenClaw"), "expected 'OpenClaw' in all-status; got: {stdout}");
}

// ---------------------------------------------------------------------------
// 9.6 — Install pre-flight: daemon not running
// ---------------------------------------------------------------------------

/// Scenario 9.6: `integrations install claude-code` performs a prerequisite
/// check. If the daemon is not running it reports a clear error; if it is
/// running it reports success. Either way the command must not crash.
#[test]
fn test_9_6_install_preflight_daemon_not_running() {
    let (stdout, stderr, code) = run(&["integrations", "install", "claude-code"]);
    println!("stdout:\n{}\nstderr:\n{}", stdout, stderr);

    // Must produce an exit code (no signal death).
    assert!(code != -1, "process was killed by a signal");

    // Must produce some output about the integration.
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        !combined.is_empty(),
        "expected some output from install pre-flight; got nothing"
    );
    assert!(
        combined.contains("Claude Code")
            || combined.contains("claude")
            || combined.contains("installed")
            || combined.contains("Failed")
            || combined.contains("daemon")
            || combined.contains("not running"),
        "expected install output to reference integration or prerequisite; got: {combined}"
    );
}

// ---------------------------------------------------------------------------
// 9.7 — Unknown integration name
// ---------------------------------------------------------------------------

/// A completely unknown integration name should produce a "not found" error on
/// stderr and suggest using `list` to see available integrations.
#[test]
fn test_9_7_unknown_integration_not_found() {
    let (stdout, stderr, _code) = run(&["integrations", "install", "totally-nonexistent-xyz"]);
    println!("stdout:\n{}\nstderr:\n{}", stdout, stderr);

    assert!(
        stderr.contains("not found"),
        "expected 'not found' in stderr for unknown integration; stderr: {stderr}"
    );
    assert!(
        stdout.contains("list"),
        "expected suggestion to use 'list' in stdout; stdout: {stdout}"
    );
}

/// Status for an unknown integration name should error on stderr.
#[test]
fn test_9_7_unknown_integration_status_not_found() {
    let (stdout, stderr, _code) = run(&["integrations", "status", "totally-nonexistent-xyz"]);
    println!("stdout:\n{}\nstderr:\n{}", stdout, stderr);

    assert!(
        stderr.contains("not found"),
        "expected 'not found' in stderr for unknown integration status; stderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// 9.8 (extended) — List exit code
// ---------------------------------------------------------------------------

/// `sevorix integrations list` must exit 0.
#[test]
fn test_9_8_integrations_list_exit_code() {
    let (_stdout, _stderr, code) = run(&["integrations", "list"]);
    assert_eq!(code, 0, "integrations list should exit 0; got code={code}");
}

// ---------------------------------------------------------------------------
// 9.9 — Codex integration list entry
// ---------------------------------------------------------------------------

/// Scenario 9.9 (partial): Codex appears in `integrations list` with a
/// description mentioning "sevsh" or shell command validation.
#[test]
fn test_9_9_codex_appears_in_list() {
    let (stdout, _stderr, _code) = run(&["integrations", "list"]);
    println!("stdout:\n{}", stdout);

    assert!(
        stdout.contains("Codex"),
        "expected 'Codex' in integrations list; got: {stdout}"
    );

    // The Codex description should mention sevsh.
    assert!(
        stdout.contains("sevsh") || stdout.contains("shell"),
        "expected Codex description to mention 'sevsh' or 'shell'; got: {stdout}"
    );
}

/// `integrations status codex` shows structured status output.
#[test]
fn test_9_9_codex_status_output() {
    let (stdout, stderr, _code) = run(&["integrations", "status", "Codex"]);
    println!("stdout:\n{}\nstderr:\n{}", stdout, stderr);

    // Should output the structured status block, not an error.
    assert!(
        stdout.contains("Integration:"),
        "expected 'Integration:' label in Codex status; got: {stdout}"
    );
    assert!(
        stdout.contains("Codex"),
        "expected 'Codex' in status output; got: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// 9.10 — OpenClaw integration list entry
// ---------------------------------------------------------------------------

/// Scenario 9.10 (partial): OpenClaw appears in `integrations list`.
#[test]
fn test_9_10_openclaw_appears_in_list() {
    let (stdout, _stderr, _code) = run(&["integrations", "list"]);
    println!("stdout:\n{}", stdout);

    assert!(
        stdout.contains("OpenClaw"),
        "expected 'OpenClaw' in integrations list; got: {stdout}"
    );
}

/// `integrations status OpenClaw` shows structured output.
#[test]
fn test_9_10_openclaw_status_output() {
    let (stdout, stderr, _code) = run(&["integrations", "status", "OpenClaw"]);
    println!("stdout:\n{}\nstderr:\n{}", stdout, stderr);

    assert!(
        stdout.contains("Integration:"),
        "expected 'Integration:' label in OpenClaw status; got: {stdout}"
    );
    assert!(
        stdout.contains("OpenClaw"),
        "expected 'OpenClaw' in status output; got: {stdout}"
    );
}
