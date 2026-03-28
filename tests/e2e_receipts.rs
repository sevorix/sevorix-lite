// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix
#![cfg(feature = "pro")]

mod common;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use common::harness::TestHarness;
use serde_json::json;
use sevorix_watchtower::receipt::SignedReceipt;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Harness with a role set so that analyze_intent does not early-return BLOCK.
async fn harness_with_role() -> TestHarness {
    TestHarness::with_role(Some("tester".to_string())).await
}

/// Harness with a role and a DROP TABLE block policy loaded from disk
/// (uses add_policy + reload_policies so that policy_hash is computed).
async fn harness_with_block_policy() -> TestHarness {
    let h = TestHarness::with_role(Some("agent".to_string())).await;

    // Write policy and role to disk so reload_policies picks them up.
    h.add_policy(
        "block-drop",
        json!({
            "id": "block-drop",
            "type": "Simple",
            "pattern": "DROP TABLE",
            "action": "Block",
            "context": "All",
            "kill": false
        }),
    );
    h.add_role(
        "agent",
        json!({
            "name": "agent",
            "policies": ["block-drop"],
            "is_dynamic": false
        }),
    );

    // Reload from disk; this also computes and stores the policy_hash.
    h.reload_policies().await;
    h
}

async fn analyze(h: &TestHarness, payload: &str) {
    h.client
        .post(format!("{}/analyze", h.base_url()))
        .json(&json!({"payload": payload, "context": "Shell"}))
        .send()
        .await
        .unwrap();
}

async fn analyze_with_role(h: &TestHarness, payload: &str, role: &str) {
    h.client
        .post(format!("{}/analyze", h.base_url()))
        .json(&json!({"payload": payload, "context": "Shell", "role": role}))
        .send()
        .await
        .unwrap();
}

/// Read all lines from the JSONL log and parse them as SignedReceipt.
fn read_receipts(path: &std::path::Path) -> Vec<SignedReceipt> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    content
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str::<SignedReceipt>(l).ok())
        .collect()
}

// ── Test 1: Receipt written to log is a valid SignedReceipt ──────────────────

#[tokio::test]
async fn test_receipt_written_to_log_is_valid_signed_receipt() {
    let h = harness_with_role().await;
    analyze(&h, "safe text").await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let receipts = read_receipts(&h.state.traffic_log_path);
    assert!(
        !receipts.is_empty(),
        "should have at least one receipt in log"
    );

    let receipt = &receipts[receipts.len() - 1];

    assert_eq!(
        receipt.receipt_version, "1",
        "receipt_version should be '1'"
    );
    assert!(
        !receipt.sevorix_version.is_empty(),
        "sevorix_version should be non-empty"
    );

    let valid_decisions = ["ALLOW", "BLOCK", "FLAG", "KILL"];
    assert!(
        valid_decisions.contains(&receipt.payload.decision.as_str()),
        "decision '{}' should be one of ALLOW/BLOCK/FLAG/KILL",
        receipt.payload.decision
    );

    assert!(
        !receipt.payload.timestamp.is_empty(),
        "timestamp should be non-empty"
    );
    assert!(
        receipt.payload.delegation_chain.is_empty(),
        "delegation_chain should be empty vec"
    );
    assert!(
        !receipt.signature.is_empty(),
        "signature should be non-empty"
    );
    assert_eq!(
        receipt.public_key_fingerprint.len(),
        64,
        "public_key_fingerprint should be 64 hex chars"
    );
}

// ── Test 2: Signature is cryptographically valid ─────────────────────────────

#[tokio::test]
async fn test_receipt_signature_is_cryptographically_valid() {
    let h = harness_with_role().await;
    analyze(&h, "safe text for sig check").await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let receipts = read_receipts(&h.state.traffic_log_path);
    assert!(
        !receipts.is_empty(),
        "should have at least one receipt in log"
    );

    let receipt = &receipts[receipts.len() - 1];

    // Re-derive the canonical payload JSON (same as sign_and_log_traffic_event)
    let canonical = serde_json::to_string(&receipt.payload)
        .expect("ReceiptPayload serialization is infallible");

    // Compute SHA-256 of canonical JSON
    let payload_hash = sevorix_core::signing::compute_sha256(canonical.as_bytes());

    // Get the verifying key from AppState
    let verifying_key = h.state.signing_key.verifying_key();

    // Verify the signature
    let result =
        sevorix_core::signing::verify_signature(&verifying_key, &payload_hash, &receipt.signature);

    assert!(
        result.is_ok(),
        "verify_signature should not return an error: {:?}",
        result.err()
    );
    assert!(
        result.unwrap(),
        "signature should be cryptographically valid"
    );
}

// ── Test 3: GET /api/receipt/pubkey returns correct key ──────────────────────

#[tokio::test]
async fn test_receipt_pubkey_endpoint_returns_correct_key() {
    let h = TestHarness::new().await;

    let resp = h
        .client
        .get(format!("{}/api/receipt/pubkey", h.base_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "GET /api/receipt/pubkey should return 200"
    );

    let body: serde_json::Value = resp.json().await.unwrap();

    // public_key_b64 field checks
    let public_key_b64 = body
        .get("public_key_b64")
        .and_then(|v| v.as_str())
        .expect("response should have public_key_b64 string field");

    assert!(
        !public_key_b64.is_empty(),
        "public_key_b64 should be non-empty"
    );

    let decoded = B64
        .decode(public_key_b64)
        .expect("public_key_b64 should be valid base64");
    assert_eq!(decoded.len(), 32, "decoded public key should be 32 bytes");

    // fingerprint field checks
    let fingerprint = body
        .get("fingerprint")
        .and_then(|v| v.as_str())
        .expect("response should have fingerprint string field");

    assert_eq!(fingerprint.len(), 64, "fingerprint should be 64 hex chars");

    // Verify fingerprint matches public_key_fingerprint(decoded)
    let expected_fp = sevorix_core::signing::public_key_fingerprint(&decoded);
    assert_eq!(
        fingerprint, expected_fp,
        "fingerprint should match public_key_fingerprint of the decoded public key"
    );
}

// ── Test 4: policy_hash is consistent across receipts in same session ─────────

#[tokio::test]
async fn test_policy_hash_consistent_within_session() {
    // Use disk-based policy loading so that policy_hash is computed via reload.
    let h = harness_with_block_policy().await;

    analyze(&h, "first safe request").await;
    analyze(&h, "second safe request").await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let receipts = read_receipts(&h.state.traffic_log_path);
    assert!(
        receipts.len() >= 2,
        "should have at least two receipts, got {}",
        receipts.len()
    );

    let first_hash = &receipts[0].payload.policy_hash;
    let second_hash = &receipts[1].payload.policy_hash;

    assert!(
        !first_hash.is_empty(),
        "policy_hash in first receipt should be non-empty"
    );
    assert_eq!(
        first_hash, second_hash,
        "policy_hash should be identical across receipts in the same session"
    );
}

// ── Test 5: payload fields match the submitted event ─────────────────────────

#[tokio::test]
async fn test_receipt_payload_fields_match_event() {
    let h = harness_with_block_policy().await;

    let submitted_text = "DROP TABLE users";
    let submitted_role = "agent";

    analyze_with_role(&h, submitted_text, submitted_role).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let receipts = read_receipts(&h.state.traffic_log_path);
    assert!(!receipts.is_empty(), "should have at least one receipt");

    // Find the receipt matching the submitted payload
    let receipt = receipts
        .iter()
        .find(|r| r.payload.action_payload == submitted_text)
        .expect("should find a receipt with the submitted payload text");

    assert_eq!(
        receipt.payload.action_payload, submitted_text,
        "action_payload should match submitted text"
    );
    assert_eq!(
        receipt.payload.role.as_deref(),
        Some(submitted_role),
        "role should match submitted role"
    );
    assert_eq!(
        receipt.payload.decision, "BLOCK",
        "decision should be BLOCK for DROP TABLE"
    );
}
