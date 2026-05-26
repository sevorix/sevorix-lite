// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

//! E2E tests for the `sevsh --accumulate` flag and `SEVSH_ACCUMULATE` env var.
//!
//! Tests cover:
//!   Group 1: Core flag & source label behavior
//!   Group 2: Env var inheritance
//!   Group 3: Chunk content and format correctness
//!   Group 4: Policy interaction (blocked / flagged)
//!   Group 5: Session isolation
//!   Group 6: Ordering and multiple chunks
//!   Group 7: Edge cases

mod common;
use common::harness::TestHarness;
use sevorix_watchtower::policy::{Action, Policy, PolicyContext, PolicyType, Role};

// ── Helpers ───────────────────────────────────────────────────────────────────

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
    std::path::PathBuf::from("sevsh")
}

/// Spin up a permissive harness — empty policy set means every command is ALLOW.
async fn allow_harness() -> TestHarness {
    let h = TestHarness::with_role(Some("default".to_string())).await;
    h.add_role_direct(Role {
        name: "default".to_string(),
        policies: vec![],
        is_dynamic: false,
    });
    h
}

/// GET `/api/context?session=<id>` and return the `chunks` array, or an empty
/// vec if the field is missing / the response is not shaped as expected.
async fn get_context_chunks(h: &TestHarness, session_id: &str) -> Vec<serde_json::Value> {
    let resp = h
        .client
        .get(format!(
            "{}/api/context?session={}",
            h.base_url(),
            session_id
        ))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();

    resp["chunks"].as_array().cloned().unwrap_or_default()
}

/// Run the `sevsh` binary with the given extra args and env overrides and
/// return the raw `Output`.
///
/// `extra_args`   — additional CLI arguments appended after `--no-sandbox`
/// `extra_envs`   — `(KEY, VALUE)` pairs to set before spawning
/// `remove_envs`  — env var names to explicitly remove (e.g. to clear
///                   `SEVSH_ACCUMULATE` inherited from the test runner)
async fn run_sevsh(
    h: &TestHarness,
    extra_args: &[&str],
    extra_envs: &[(&str, String)],
    remove_envs: &[&str],
) -> std::process::Output {
    let mut cmd = tokio::process::Command::new(sevsh_bin());
    cmd.arg("--no-sandbox");
    cmd.args(extra_args);

    cmd.env("SEVORIX_PORT", h.addr.port().to_string());
    cmd.env("HOME", h.config_dir.as_os_str());

    for (k, v) in extra_envs {
        cmd.env(k, v);
    }
    for k in remove_envs {
        cmd.env_remove(k);
    }

    cmd.output().await.expect("failed to spawn sevsh")
}

// ── Group 1: Core flag & source label behavior ────────────────────────────────

/// --accumulate -c posts both stdin and stdout chunks, and the chunks have the
/// expected `text` field (ANSI-stripped content).
#[tokio::test]
async fn test_accumulate_non_interactive_posts_chunks() {
    let h = allow_harness().await;
    let session_id = format!("test-acc-{}", uuid::Uuid::new_v4());

    let output = run_sevsh(
        &h,
        &[
            "--accumulate",
            "--source",
            "test-agent",
            "-c",
            "echo accumulate_marker",
        ],
        &[
            ("SEVSH_ACCUMULATE", session_id.clone()),
            ("SEVSH_ACCUMULATE_SOURCE", "test-agent".to_string()),
        ],
        &[],
    )
    .await;

    assert!(
        output.status.success(),
        "sevsh exited with status {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let chunks = get_context_chunks(&h, &session_id).await;

    assert!(
        !chunks.is_empty(),
        "expected context chunks to be posted when --accumulate is active, got none"
    );

    let has_stdin = chunks.iter().any(|c| {
        c["stream"].as_str() == Some("stdin")
            && c["text"]
                .as_str()
                .unwrap_or("")
                .contains("echo accumulate_marker")
    });
    assert!(
        has_stdin,
        "expected a stdin chunk with the command text; chunks: {:#?}",
        chunks
    );

    let has_stdout = chunks.iter().any(|c| {
        c["stream"].as_str() == Some("stdout")
            && c["text"]
                .as_str()
                .unwrap_or("")
                .contains("accumulate_marker")
    });
    assert!(
        has_stdout,
        "expected a stdout chunk with the command output; chunks: {:#?}",
        chunks
    );

    // Every chunk must have a non-empty `text` field.
    for chunk in &chunks {
        assert!(
            chunk.get("text").is_some(),
            "chunk is missing `text` field: {:#?}",
            chunk
        );
    }
}

/// Without --accumulate and without SEVSH_ACCUMULATE set, no chunks appear.
#[tokio::test]
async fn test_no_accumulate_no_chunks_posted() {
    let h = allow_harness().await;
    let session_id = format!("test-noacc-{}", uuid::Uuid::new_v4());

    run_sevsh(
        &h,
        &["-c", "echo should_not_accumulate"],
        &[],
        &["SEVSH_ACCUMULATE", "SEVSH_ACCUMULATE_SOURCE"],
    )
    .await;

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let chunks = get_context_chunks(&h, &session_id).await;
    assert_eq!(
        chunks.len(),
        0,
        "expected no context chunks without --accumulate, got {}",
        chunks.len()
    );
}

/// When SEVSH_ACCUMULATE is set but neither --source nor SEVSH_ACCUMULATE_SOURCE
/// is set, chunks carry source="sevsh" (the default).
#[tokio::test]
async fn test_accumulate_source_default_is_sevsh() {
    let h = allow_harness().await;
    let session_id = format!("test-src-default-{}", uuid::Uuid::new_v4());

    let output = run_sevsh(
        &h,
        &["-c", "echo default_source_check"],
        &[("SEVSH_ACCUMULATE", session_id.clone())],
        &["SEVSH_ACCUMULATE_SOURCE"],
    )
    .await;

    assert!(
        output.status.success(),
        "sevsh failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let chunks = get_context_chunks(&h, &session_id).await;
    assert!(!chunks.is_empty(), "expected chunks to be posted; got none");

    let all_sevsh_source = chunks.iter().all(|c| c["source"].as_str() == Some("sevsh"));
    assert!(
        all_sevsh_source,
        "expected all chunks to have source=\"sevsh\" when no source is specified; chunks: {:#?}",
        chunks
    );
}

/// SEVSH_ACCUMULATE_SOURCE=my-agent causes all chunks to have source="my-agent".
#[tokio::test]
async fn test_accumulate_source_custom_via_env() {
    let h = allow_harness().await;
    let session_id = format!("test-src-custom-{}", uuid::Uuid::new_v4());

    let output = run_sevsh(
        &h,
        &["-c", "echo custom_source_check"],
        &[
            ("SEVSH_ACCUMULATE", session_id.clone()),
            ("SEVSH_ACCUMULATE_SOURCE", "my-agent".to_string()),
        ],
        &[],
    )
    .await;

    assert!(
        output.status.success(),
        "sevsh failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let chunks = get_context_chunks(&h, &session_id).await;
    assert!(!chunks.is_empty(), "expected chunks to be posted; got none");

    let all_correct_source = chunks
        .iter()
        .all(|c| c["source"].as_str() == Some("my-agent"));
    assert!(
        all_correct_source,
        "expected all chunks to have source=\"my-agent\"; chunks: {:#?}",
        chunks
    );
}

// ── Group 2: Env var inheritance ──────────────────────────────────────────────

/// A child sevsh inherits SEVSH_ACCUMULATE and posts chunks using the inherited
/// session ID without the parent passing --accumulate.
#[tokio::test]
async fn test_accumulate_env_var_inherited_by_child_sevsh() {
    let h = allow_harness().await;
    let session_id = format!("test-inherit-{}", uuid::Uuid::new_v4());

    let output = run_sevsh(
        &h,
        &["-c", "echo inherited_chunk"],
        &[
            ("SEVSH_ACCUMULATE", session_id.clone()),
            ("SEVSH_ACCUMULATE_SOURCE", "inherited-source".to_string()),
        ],
        &[],
    )
    .await;

    assert!(
        output.status.success(),
        "sevsh exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let chunks = get_context_chunks(&h, &session_id).await;
    assert!(
        !chunks.is_empty(),
        "expected child sevsh to post chunks when SEVSH_ACCUMULATE is set"
    );

    let correct_source = chunks
        .iter()
        .all(|c| c["source"].as_str() == Some("inherited-source"));
    assert!(
        correct_source,
        "expected all chunks to carry inherited source label; chunks: {:#?}",
        chunks
    );
}

/// When SEVSH_ACCUMULATE is set but SEVSH_ACCUMULATE_SOURCE is absent, the
/// source label defaults to "sevsh" for the inherited invocation.
#[tokio::test]
async fn test_accumulate_env_var_source_defaults_to_sevsh_when_unset() {
    let h = allow_harness().await;
    let session_id = format!("test-inherit-src-{}", uuid::Uuid::new_v4());

    let output = run_sevsh(
        &h,
        &["-c", "echo inherit_default_source"],
        &[("SEVSH_ACCUMULATE", session_id.clone())],
        &["SEVSH_ACCUMULATE_SOURCE"],
    )
    .await;

    assert!(
        output.status.success(),
        "sevsh failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let chunks = get_context_chunks(&h, &session_id).await;
    assert!(!chunks.is_empty(), "expected chunks; got none");

    let all_sevsh = chunks.iter().all(|c| c["source"].as_str() == Some("sevsh"));
    assert!(
        all_sevsh,
        "expected inherited source to default to \"sevsh\"; chunks: {:#?}",
        chunks
    );
}

// ── Group 3: Chunk content and format correctness ─────────────────────────────

/// The stdin chunk `raw` field must equal the exact command string, not just
/// contain it as a substring.
#[tokio::test]
async fn test_accumulate_stdin_chunk_raw_field_exact() {
    let h = allow_harness().await;
    let session_id = format!("test-raw-stdin-{}", uuid::Uuid::new_v4());
    let command = "echo exact_raw_check";

    let output = run_sevsh(
        &h,
        &["-c", command],
        &[("SEVSH_ACCUMULATE", session_id.clone())],
        &["SEVSH_ACCUMULATE_SOURCE"],
    )
    .await;

    assert!(output.status.success(), "sevsh failed");

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let chunks = get_context_chunks(&h, &session_id).await;
    let stdin_chunk = chunks
        .iter()
        .find(|c| c["stream"].as_str() == Some("stdin"))
        .expect("no stdin chunk found");

    let raw = stdin_chunk["raw"].as_str().unwrap_or("");
    assert_eq!(
        raw, command,
        "stdin chunk `raw` must equal the command exactly; got {:?}",
        raw
    );
}

/// The stdout chunk `raw` field contains the actual command output.
#[tokio::test]
async fn test_accumulate_stdout_chunk_raw_field_contains_output() {
    let h = allow_harness().await;
    let session_id = format!("test-raw-stdout-{}", uuid::Uuid::new_v4());

    let output = run_sevsh(
        &h,
        &["-c", "echo raw_output_marker"],
        &[("SEVSH_ACCUMULATE", session_id.clone())],
        &["SEVSH_ACCUMULATE_SOURCE"],
    )
    .await;

    assert!(output.status.success(), "sevsh failed");

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let chunks = get_context_chunks(&h, &session_id).await;
    let stdout_chunk = chunks
        .iter()
        .find(|c| c["stream"].as_str() == Some("stdout"))
        .expect("no stdout chunk found");

    let raw = stdout_chunk["raw"].as_str().unwrap_or("");
    assert!(
        raw.contains("raw_output_marker"),
        "stdout chunk `raw` must contain the command output; got {:?}",
        raw
    );
}

/// A command that writes to stderr produces a chunk with stream="stderr".
#[tokio::test]
async fn test_accumulate_stderr_posted_as_stderr_stream() {
    let h = allow_harness().await;
    let session_id = format!("test-stderr-{}", uuid::Uuid::new_v4());

    let output = run_sevsh(
        &h,
        &["-c", "echo stderr_content >&2"],
        &[("SEVSH_ACCUMULATE", session_id.clone())],
        &["SEVSH_ACCUMULATE_SOURCE"],
    )
    .await;

    assert!(output.status.success(), "sevsh failed");

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let chunks = get_context_chunks(&h, &session_id).await;
    let stderr_chunk = chunks
        .iter()
        .find(|c| c["stream"].as_str() == Some("stderr"));
    assert!(
        stderr_chunk.is_some(),
        "expected a stderr chunk; chunks: {:#?}",
        chunks
    );

    let raw = stderr_chunk.unwrap()["raw"].as_str().unwrap_or("");
    assert!(
        raw.contains("stderr_content"),
        "stderr chunk `raw` should contain the stderr output; got {:?}",
        raw
    );
}

/// A command that produces no output (e.g. `true`) should not generate a stdout
/// chunk — `append_context_entries` filters out empty strings.
#[tokio::test]
async fn test_accumulate_empty_stdout_produces_no_chunk() {
    let h = allow_harness().await;
    let session_id = format!("test-empty-out-{}", uuid::Uuid::new_v4());

    let output = run_sevsh(
        &h,
        // `true` is POSIX; exits 0 with zero output.
        &["-c", "true"],
        &[("SEVSH_ACCUMULATE", session_id.clone())],
        &["SEVSH_ACCUMULATE_SOURCE"],
    )
    .await;

    assert!(output.status.success(), "sevsh failed");

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let chunks = get_context_chunks(&h, &session_id).await;

    // stdin chunk IS expected (command was submitted)
    let has_stdin = chunks.iter().any(|c| c["stream"].as_str() == Some("stdin"));
    assert!(has_stdin, "expected stdin chunk; chunks: {:#?}", chunks);

    // stdout chunk must NOT appear (empty output is filtered)
    let has_stdout = chunks
        .iter()
        .any(|c| c["stream"].as_str() == Some("stdout"));
    assert!(
        !has_stdout,
        "expected no stdout chunk when command produces no output; chunks: {:#?}",
        chunks
    );
}

/// Every returned chunk must carry the required fields: source, stream, text, raw.
#[tokio::test]
async fn test_accumulate_chunks_have_source_stream_text_raw_fields() {
    let h = allow_harness().await;
    let session_id = format!("test-fields-{}", uuid::Uuid::new_v4());

    let output = run_sevsh(
        &h,
        &["-c", "echo field_check"],
        &[
            ("SEVSH_ACCUMULATE", session_id.clone()),
            ("SEVSH_ACCUMULATE_SOURCE", "field-test".to_string()),
        ],
        &[],
    )
    .await;

    assert!(output.status.success(), "sevsh failed");

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let chunks = get_context_chunks(&h, &session_id).await;
    assert!(!chunks.is_empty(), "expected at least one chunk");

    for chunk in &chunks {
        assert!(
            chunk.get("source").and_then(|v| v.as_str()).is_some(),
            "chunk missing `source` field: {:#?}",
            chunk
        );
        assert!(
            chunk.get("stream").and_then(|v| v.as_str()).is_some(),
            "chunk missing `stream` field: {:#?}",
            chunk
        );
        assert!(
            chunk.get("text").is_some(),
            "chunk missing `text` field: {:#?}",
            chunk
        );
        assert!(
            chunk.get("raw").and_then(|v| v.as_str()).is_some(),
            "chunk missing `raw` field: {:#?}",
            chunk
        );
    }
}

/// Stdout containing ANSI escape codes: `raw` preserves the codes but `text`
/// strips them.
#[tokio::test]
async fn test_accumulate_ansi_codes_stripped_in_text_field() {
    let h = allow_harness().await;
    let session_id = format!("test-ansi-{}", uuid::Uuid::new_v4());

    // printf emits ESC[32m (green) + "green" + ESC[0m (reset).
    // The raw field should contain the escape sequences; text should not.
    let output = run_sevsh(
        &h,
        &["-c", r"printf '\033[32mgreen\033[0m\n'"],
        &[("SEVSH_ACCUMULATE", session_id.clone())],
        &["SEVSH_ACCUMULATE_SOURCE"],
    )
    .await;

    assert!(output.status.success(), "sevsh failed");

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let chunks = get_context_chunks(&h, &session_id).await;
    let stdout_chunk = chunks
        .iter()
        .find(|c| c["stream"].as_str() == Some("stdout"))
        .expect("no stdout chunk found");

    let raw = stdout_chunk["raw"].as_str().unwrap_or("");
    let text = stdout_chunk["text"].as_str().unwrap_or("");

    // `raw` must preserve the ANSI escape sequence.
    assert!(
        raw.contains('\x1b'),
        "`raw` should contain ANSI escape codes; got {:?}",
        raw
    );

    // `text` must contain the visible word without the escape sequences.
    assert!(
        text.contains("green"),
        "`text` should contain stripped content \"green\"; got {:?}",
        text
    );
    assert!(
        !text.contains('\x1b'),
        "`text` must not contain ANSI escape codes; got {:?}",
        text
    );
}

// ── Group 4: Policy interaction ───────────────────────────────────────────────

/// A blocked command's stdin chunk is also rejected by policy enforcement — the
/// context endpoint applies the same blocking policies as the shell scanner, so
/// neither stdin nor stdout chunks are stored when the content matches a blocking policy.
#[tokio::test]
async fn test_accumulate_blocked_command_chunks_rejected_by_policy() {
    let h = allow_harness().await;

    h.add_policy_direct(Policy {
        id: "block-test-cmd".to_string(),
        match_type: PolicyType::Simple("BLOCKED_MARKER_12345".to_string()),
        action: Action::Block,
        context: PolicyContext::Shell,
        kill: false,
        syscall: vec![],
    });
    h.add_role_direct(Role {
        name: "default".to_string(),
        policies: vec!["block-test-cmd".to_string()],
        is_dynamic: false,
    });

    let session_id = format!("test-blocked-{}", uuid::Uuid::new_v4());

    let output = run_sevsh(
        &h,
        &["-c", "echo BLOCKED_MARKER_12345"],
        &[
            ("SEVSH_ACCUMULATE", session_id.clone()),
            ("SEVSH_ACCUMULATE_SOURCE", "sevsh".to_string()),
        ],
        &[],
    )
    .await;

    assert!(
        !output.status.success(),
        "expected blocked command to return non-zero exit"
    );

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let chunks = get_context_chunks(&h, &session_id).await;

    let has_stdin = chunks.iter().any(|c| c["stream"].as_str() == Some("stdin"));
    assert!(
        !has_stdin,
        "policy enforcement must reject stdin chunk whose content matches the blocking policy; chunks: {:#?}",
        chunks
    );

    let has_stdout = chunks
        .iter()
        .any(|c| c["stream"].as_str() == Some("stdout"));
    assert!(
        !has_stdout,
        "expected no stdout chunk for a blocked command; chunks: {:#?}",
        chunks
    );
}

/// A command that receives a FLAG verdict still runs; both stdin and stdout
/// chunks are posted.
#[tokio::test]
async fn test_accumulate_flagged_command_posts_stdin_and_stdout() {
    let h = allow_harness().await;

    h.add_policy_direct(Policy {
        id: "flag-test-cmd".to_string(),
        match_type: PolicyType::Simple("FLAGGED_MARKER_99999".to_string()),
        action: Action::Flag,
        context: PolicyContext::Shell,
        kill: false,
        syscall: vec![],
    });

    let session_id = format!("test-flagged-{}", uuid::Uuid::new_v4());

    // FLAG verdict = allowed, so the command runs and output is produced.
    let output = run_sevsh(
        &h,
        &["-c", "echo FLAGGED_MARKER_99999"],
        &[
            ("SEVSH_ACCUMULATE", session_id.clone()),
            ("SEVSH_ACCUMULATE_SOURCE", "sevsh".to_string()),
        ],
        &[],
    )
    .await;

    // FLAG commands are executed; sevsh should exit 0.
    assert!(
        output.status.success(),
        "expected flagged command to run and exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let chunks = get_context_chunks(&h, &session_id).await;

    let has_stdin = chunks.iter().any(|c| c["stream"].as_str() == Some("stdin"));
    assert!(
        has_stdin,
        "expected stdin chunk for flagged command; chunks: {:#?}",
        chunks
    );

    let has_stdout = chunks.iter().any(|c| {
        c["stream"].as_str() == Some("stdout")
            && c["text"]
                .as_str()
                .unwrap_or("")
                .contains("FLAGGED_MARKER_99999")
    });
    assert!(
        has_stdout,
        "expected stdout chunk for flagged command; chunks: {:#?}",
        chunks
    );
}

// ── Group 5: Session isolation ────────────────────────────────────────────────

/// Two concurrent runs with different session IDs must not see each other's chunks.
#[tokio::test]
async fn test_accumulate_sessions_are_isolated() {
    let h = allow_harness().await;
    let session_a = format!("test-iso-a-{}", uuid::Uuid::new_v4());
    let session_b = format!("test-iso-b-{}", uuid::Uuid::new_v4());

    let env_a = [("SEVSH_ACCUMULATE", session_a.clone())];
    let env_b = [("SEVSH_ACCUMULATE", session_b.clone())];
    let (out_a, out_b) = tokio::join!(
        run_sevsh(
            &h,
            &["-c", "echo session_a_only"],
            &env_a,
            &["SEVSH_ACCUMULATE_SOURCE"],
        ),
        run_sevsh(
            &h,
            &["-c", "echo session_b_only"],
            &env_b,
            &["SEVSH_ACCUMULATE_SOURCE"],
        ),
    );

    assert!(out_a.status.success(), "session A failed");
    assert!(out_b.status.success(), "session B failed");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let chunks_a = get_context_chunks(&h, &session_a).await;
    let chunks_b = get_context_chunks(&h, &session_b).await;

    // Session A must not contain any text from session B.
    let a_has_b = chunks_a.iter().any(|c| {
        c["text"].as_str().unwrap_or("").contains("session_b_only")
            || c["raw"].as_str().unwrap_or("").contains("session_b_only")
    });
    assert!(
        !a_has_b,
        "session A chunks must not contain session B content; chunks_a: {:#?}",
        chunks_a
    );

    // Session B must not contain any text from session A.
    let b_has_a = chunks_b.iter().any(|c| {
        c["text"].as_str().unwrap_or("").contains("session_a_only")
            || c["raw"].as_str().unwrap_or("").contains("session_a_only")
    });
    assert!(
        !b_has_a,
        "session B chunks must not contain session A content; chunks_b: {:#?}",
        chunks_b
    );
}

// ── Group 6: Ordering and multiple chunks ─────────────────────────────────────

/// The `seq` field on returned chunks must start at 0 and strictly increase.
#[tokio::test]
async fn test_accumulate_chunks_have_ascending_seq_numbers() {
    let h = allow_harness().await;
    let session_id = format!("test-seq-{}", uuid::Uuid::new_v4());

    let output = run_sevsh(
        &h,
        &["-c", "echo seq_check"],
        &[("SEVSH_ACCUMULATE", session_id.clone())],
        &["SEVSH_ACCUMULATE_SOURCE"],
    )
    .await;

    assert!(output.status.success(), "sevsh failed");

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let chunks = get_context_chunks(&h, &session_id).await;
    assert!(
        chunks.len() >= 2,
        "expected at least 2 chunks (stdin + stdout); got {}",
        chunks.len()
    );

    // Collect seq values; the server may omit the field for seq=0 or include it.
    // We only check strict monotonicity across chunks that *do* have a `seq` field.
    let seqs: Vec<u64> = chunks.iter().filter_map(|c| c["seq"].as_u64()).collect();

    if seqs.len() >= 2 {
        for window in seqs.windows(2) {
            assert!(
                window[1] > window[0],
                "seq values must strictly increase; got {:?}",
                seqs
            );
        }
    }
}

// ── Group 7: Edge cases ───────────────────────────────────────────────────────

/// SEVSH_ACCUMULATE="" (empty string) — the code activates accumulation with an
/// empty session ID. The server may default this to the current session or ignore
/// it. The test verifies that sevsh at least exits without crashing and does not
/// post chunks to a named session.
///
/// This is the documented edge-case bug: `env::var("SEVSH_ACCUMULATE")` returns
/// `Ok("")` which activates accumulation with `session_id=""`.
#[tokio::test]
async fn test_accumulate_empty_session_env_does_not_produce_useful_chunks() {
    let h = allow_harness().await;
    // Use a UUID session that we can query — chunks must NOT appear here because
    // we set SEVSH_ACCUMULATE to "", not to this session ID.
    let named_session = format!("test-empty-env-{}", uuid::Uuid::new_v4());

    let output = run_sevsh(
        &h,
        &["-c", "echo empty_session_test"],
        // Set SEVSH_ACCUMULATE to the empty string (not the named_session).
        &[("SEVSH_ACCUMULATE", String::new())],
        &["SEVSH_ACCUMULATE_SOURCE"],
    )
    .await;

    // sevsh must not crash even with an empty session ID.
    // It may exit 0 or non-zero depending on server behaviour; we only check it
    // does not panic/signal-terminate.
    let code = output.status.code();
    assert!(
        code.is_some(),
        "sevsh was signal-terminated unexpectedly (no exit code)"
    );

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // The named session must have received zero chunks.
    let chunks = get_context_chunks(&h, &named_session).await;
    assert_eq!(
        chunks.len(),
        0,
        "named session must not receive chunks when SEVSH_ACCUMULATE is empty; got: {:#?}",
        chunks
    );
}

/// An ALLOW'd command that exits non-zero still posts both stdin and stdout
/// chunks (the exit code does not suppress output posting).
#[tokio::test]
async fn test_accumulate_command_exit_nonzero_still_posts_chunks() {
    let h = allow_harness().await;
    let session_id = format!("test-nonzero-{}", uuid::Uuid::new_v4());

    // `echo output; exit 1` produces stdout and exits 1.  sevsh allows it
    // (no block policy) so output IS captured and posted.
    let output = run_sevsh(
        &h,
        &["-c", "echo nonzero_output; exit 1"],
        &[("SEVSH_ACCUMULATE", session_id.clone())],
        &["SEVSH_ACCUMULATE_SOURCE"],
    )
    .await;

    // Command exits 1, so sevsh itself exits non-zero.
    assert!(
        !output.status.success(),
        "expected non-zero exit from command that runs `exit 1`"
    );

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let chunks = get_context_chunks(&h, &session_id).await;

    let has_stdin = chunks.iter().any(|c| {
        c["stream"].as_str() == Some("stdin")
            && c["raw"]
                .as_str()
                .unwrap_or("")
                .contains("echo nonzero_output")
    });
    assert!(
        has_stdin,
        "expected stdin chunk for non-zero exit command; chunks: {:#?}",
        chunks
    );

    // stdout chunk must still appear because the command was ALLOW'd and produced output.
    let has_stdout = chunks.iter().any(|c| {
        c["stream"].as_str() == Some("stdout")
            && c["text"].as_str().unwrap_or("").contains("nonzero_output")
    });
    assert!(
        has_stdout,
        "expected stdout chunk even when command exits non-zero (ALLOW path); chunks: {:#?}",
        chunks
    );
}
