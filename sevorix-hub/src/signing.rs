// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

//! Ed25519 signing helpers for the Hub service.
//!
//! The core primitives now live in `sevorix_core::signing`. This module
//! re-exports them and provides thin Hub-specific wrappers that map
//! `SigningError` to the Hub's `AppError` type.

use crate::error::{AppError, AppResult};
use ed25519_dalek::VerifyingKey;
pub use sevorix_core::{compute_sha256, public_key_fingerprint, SigningError};

/// Parse a base64-encoded Ed25519 public key (32 raw bytes after decoding).
///
/// Maps `SigningError` to `AppError::BadRequest`.
pub fn parse_public_key(b64: &str) -> AppResult<VerifyingKey> {
    sevorix_core::parse_public_key(b64).map_err(|e| AppError::BadRequest(e.to_string()))
}

/// Verify an Ed25519 signature.
///
/// The signed message is the UTF-8 bytes of `hash_hex`.
/// `sig_b64` is the base64-encoded 64-byte Ed25519 signature.
///
/// Returns `Ok(true)` if valid, `Ok(false)` if not.
/// Maps `SigningError` to `AppError::BadRequest`.
pub fn verify_signature(key: &VerifyingKey, hash_hex: &str, sig_b64: &str) -> AppResult<bool> {
    sevorix_core::verify_signature(key, hash_hex, sig_b64)
        .map_err(|e| AppError::BadRequest(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    // ---------------------------------------------------------------------------
    // compute_sha256
    // ---------------------------------------------------------------------------

    #[test]
    fn test_compute_sha256_empty_string() {
        let result = compute_sha256(b"");
        assert_eq!(
            result,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_compute_sha256_known_vector() {
        let result = compute_sha256(b"abc");
        assert_eq!(
            result,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_compute_sha256_output_is_64_chars() {
        let result = compute_sha256(b"hello world");
        assert_eq!(result.len(), 64);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_sha256_deterministic() {
        let a = compute_sha256(b"same input");
        let b = compute_sha256(b"same input");
        assert_eq!(a, b);
    }

    #[test]
    fn test_compute_sha256_different_inputs_differ() {
        let a = compute_sha256(b"input one");
        let b = compute_sha256(b"input two");
        assert_ne!(a, b);
    }

    // ---------------------------------------------------------------------------
    // public_key_fingerprint
    // ---------------------------------------------------------------------------

    #[test]
    fn test_public_key_fingerprint_deterministic() {
        let bytes = b"some arbitrary public key bytes";
        let fp1 = public_key_fingerprint(bytes);
        let fp2 = public_key_fingerprint(bytes);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_public_key_fingerprint_is_sha256_of_input() {
        let bytes = b"pubkey material";
        let expected = compute_sha256(bytes);
        assert_eq!(public_key_fingerprint(bytes), expected);
    }

    #[test]
    fn test_public_key_fingerprint_different_keys_differ() {
        let fp1 = public_key_fingerprint(b"key material A");
        let fp2 = public_key_fingerprint(b"key material B");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_public_key_fingerprint_output_is_64_hex_chars() {
        let fp = public_key_fingerprint(b"test key");
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ---------------------------------------------------------------------------
    // parse_public_key
    // ---------------------------------------------------------------------------

    fn make_valid_verifying_key_b64() -> (SigningKey, String) {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let b64 = STANDARD.encode(verifying_key.as_bytes());
        (signing_key, b64)
    }

    #[test]
    fn test_parse_public_key_valid() {
        let (_sk, b64) = make_valid_verifying_key_b64();
        let result = parse_public_key(&b64);
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    #[test]
    fn test_parse_public_key_invalid_base64() {
        let result = parse_public_key("not!!valid!!base64@@@@");
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("invalid public key encoding") || err.contains("base64"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn test_parse_public_key_wrong_length_31_bytes() {
        let short_bytes = vec![0u8; 31];
        let b64 = STANDARD.encode(&short_bytes);
        let result = parse_public_key(&b64);
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("32") || err.contains("length"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn test_parse_public_key_wrong_length_33_bytes() {
        let long_bytes = vec![0u8; 33];
        let b64 = STANDARD.encode(&long_bytes);
        let result = parse_public_key(&b64);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_public_key_empty_string() {
        let result = parse_public_key("");
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------------------
    // verify_signature
    // ---------------------------------------------------------------------------

    fn make_keypair_and_signature(content: &[u8]) -> (SigningKey, String, String) {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let hash_hex = compute_sha256(content);
        let signature = signing_key.sign(hash_hex.as_bytes());
        let sig_b64 = STANDARD.encode(signature.to_bytes());
        (signing_key, hash_hex, sig_b64)
    }

    #[test]
    fn test_verify_signature_valid() {
        let (signing_key, hash_hex, sig_b64) = make_keypair_and_signature(b"test content");
        let verifying_key = signing_key.verifying_key();
        let result = verify_signature(&verifying_key, &hash_hex, &sig_b64);
        assert!(result.is_ok());
        assert!(result.unwrap(), "expected signature to be valid");
    }

    #[test]
    fn test_verify_signature_corrupted_signature() {
        let (signing_key, hash_hex, mut sig_b64) = make_keypair_and_signature(b"test content");
        let verifying_key = signing_key.verifying_key();

        let mut sig_bytes = STANDARD.decode(&sig_b64).unwrap();
        sig_bytes[0] ^= 0xFF;
        sig_b64 = STANDARD.encode(&sig_bytes);

        let result = verify_signature(&verifying_key, &hash_hex, &sig_b64);
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "expected corrupted signature to be invalid"
        );
    }

    #[test]
    fn test_verify_signature_wrong_key() {
        let (signing_key, hash_hex, sig_b64) = make_keypair_and_signature(b"test content");
        let _ = signing_key.verifying_key();

        let mut csprng = OsRng;
        let wrong_signing_key = SigningKey::generate(&mut csprng);
        let wrong_verifying_key = wrong_signing_key.verifying_key();

        let result = verify_signature(&wrong_verifying_key, &hash_hex, &sig_b64);
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "expected verification with wrong key to fail"
        );
    }

    #[test]
    fn test_verify_signature_wrong_hash() {
        let (signing_key, _hash_hex, sig_b64) = make_keypair_and_signature(b"test content");
        let verifying_key = signing_key.verifying_key();
        let different_hash = compute_sha256(b"different content");

        let result = verify_signature(&verifying_key, &different_hash, &sig_b64);
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "expected verification with wrong hash to fail"
        );
    }

    #[test]
    fn test_verify_signature_invalid_base64() {
        let (signing_key, hash_hex, _) = make_keypair_and_signature(b"test content");
        let verifying_key = signing_key.verifying_key();
        let result = verify_signature(&verifying_key, &hash_hex, "not!!valid!!base64@@");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature_wrong_length() {
        let (signing_key, hash_hex, _) = make_keypair_and_signature(b"test content");
        let verifying_key = signing_key.verifying_key();
        let short_sig = STANDARD.encode(&[0u8; 32]);
        let result = verify_signature(&verifying_key, &hash_hex, &short_sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature_all_zeros_signature() {
        let (signing_key, hash_hex, _) = make_keypair_and_signature(b"test content");
        let verifying_key = signing_key.verifying_key();
        let zero_sig = STANDARD.encode(&[0u8; 64]);
        let result = verify_signature(&verifying_key, &hash_hex, &zero_sig);
        match result {
            Ok(valid) => assert!(!valid, "all-zeros signature should not be valid"),
            Err(_) => {}
        }
    }
}
