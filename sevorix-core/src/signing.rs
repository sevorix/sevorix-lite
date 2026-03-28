// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid key length: expected {expected} bytes, got {got}")]
    InvalidLength { expected: usize, got: usize },
    #[error("Ed25519 error: {0}")]
    Ed25519(#[from] ed25519_dalek::SignatureError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Compute the SHA-256 hash of `data` and return it as a 64-char lowercase hex string.
pub fn compute_sha256(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hex::encode(hash)
}

/// Compute the SHA-256 fingerprint of a public key's raw bytes as a 64-char hex string.
pub fn public_key_fingerprint(pubkey_bytes: &[u8]) -> String {
    compute_sha256(pubkey_bytes)
}

/// Parse a base64-encoded Ed25519 public key (32 raw bytes after decoding).
pub fn parse_public_key(b64: &str) -> Result<VerifyingKey, SigningError> {
    let bytes = STANDARD.decode(b64)?;
    let len = bytes.len();
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| SigningError::InvalidLength {
        expected: 32,
        got: len,
    })?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
}

/// Verify an Ed25519 signature.
///
/// The signed message is the UTF-8 bytes of `hash_hex` (the 64-char SHA-256 hex string).
/// `sig_b64` is the base64-encoded 64-byte Ed25519 signature.
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if it is not.
pub fn verify_signature(
    key: &VerifyingKey,
    hash_hex: &str,
    sig_b64: &str,
) -> Result<bool, SigningError> {
    let sig_bytes = STANDARD.decode(sig_b64)?;
    let len = sig_bytes.len();
    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| SigningError::InvalidLength {
            expected: 64,
            got: len,
        })?;
    let signature = Signature::from_bytes(&sig_bytes);
    Ok(key.verify(hash_hex.as_bytes(), &signature).is_ok())
}

/// Generate a new Ed25519 signing key using the OS random number generator.
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Load an Ed25519 signing key from `key_dir/signing.key` (raw 32-byte seed),
/// or generate and save one if the file does not exist.
///
/// The key file is written atomically via a temporary file and set to mode 0600.
pub fn load_or_create_keypair(key_dir: &Path) -> Result<SigningKey, SigningError> {
    use std::fs;
    use std::io::Write;

    let key_path = key_dir.join("signing.key");

    if key_path.exists() {
        let seed_bytes = fs::read(&key_path)?;
        let len = seed_bytes.len();
        let seed: [u8; 32] = seed_bytes
            .try_into()
            .map_err(|_| SigningError::InvalidLength {
                expected: 32,
                got: len,
            })?;
        return Ok(SigningKey::from_bytes(&seed));
    }

    // Generate a new key and save it atomically.
    let key = generate_signing_key();
    let seed = key.to_bytes();

    fs::create_dir_all(key_dir)?;

    let tmp_path = key_dir.join("signing.key.tmp");
    {
        let mut f = fs::File::create(&tmp_path)?;

        // Set permissions to 0600 before writing.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
        }

        f.write_all(&seed)?;
        f.flush()?;
    }

    fs::rename(&tmp_path, &key_path)?;

    Ok(key)
}

/// Sign `message` with `key` and return the base64-encoded 64-byte signature.
pub fn sign_bytes(key: &SigningKey, message: &[u8]) -> String {
    use ed25519_dalek::Signer;
    let signature = key.sign(message);
    STANDARD.encode(signature.to_bytes())
}

/// Return the base64-encoded 32-byte verifying (public) key for `key`.
pub fn verifying_key_b64(key: &SigningKey) -> String {
    STANDARD.encode(key.verifying_key().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn test_compute_sha256_known_vector() {
        let result = compute_sha256(b"abc");
        assert_eq!(
            result,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_public_key_fingerprint_is_sha256() {
        let bytes = b"pubkey material";
        assert_eq!(public_key_fingerprint(bytes), compute_sha256(bytes));
    }

    #[test]
    fn test_parse_public_key_roundtrip() {
        let key = generate_signing_key();
        let b64 = verifying_key_b64(&key);
        let parsed = parse_public_key(&b64).expect("parse should succeed");
        assert_eq!(parsed.as_bytes(), key.verifying_key().as_bytes());
    }

    #[test]
    fn test_parse_public_key_invalid_base64() {
        assert!(parse_public_key("not!!valid!!base64@@@@").is_err());
    }

    #[test]
    fn test_parse_public_key_wrong_length() {
        let b64 = STANDARD.encode(&[0u8; 31]);
        let err = parse_public_key(&b64).unwrap_err();
        assert!(matches!(
            err,
            SigningError::InvalidLength {
                expected: 32,
                got: 31
            }
        ));
    }

    #[test]
    fn test_verify_signature_valid() {
        let key = generate_signing_key();
        let hash_hex = compute_sha256(b"test content");
        let sig_b64 = sign_bytes(&key, hash_hex.as_bytes());
        let vk = key.verifying_key();
        assert!(verify_signature(&vk, &hash_hex, &sig_b64).unwrap());
    }

    #[test]
    fn test_verify_signature_wrong_key() {
        let key = generate_signing_key();
        let hash_hex = compute_sha256(b"test content");
        let sig_b64 = sign_bytes(&key, hash_hex.as_bytes());

        let other_key = generate_signing_key();
        let vk = other_key.verifying_key();
        assert!(!verify_signature(&vk, &hash_hex, &sig_b64).unwrap());
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let key = generate_signing_key();
        let message = b"hello, sevorix";
        let hash_hex = compute_sha256(message);
        let sig_b64 = sign_bytes(&key, hash_hex.as_bytes());
        let vk = key.verifying_key();
        assert!(verify_signature(&vk, &hash_hex, &sig_b64).unwrap());
    }

    #[test]
    fn test_verifying_key_b64_roundtrip() {
        let key = generate_signing_key();
        let b64 = verifying_key_b64(&key);
        let parsed = parse_public_key(&b64).unwrap();
        assert_eq!(parsed.as_bytes(), key.verifying_key().as_bytes());
    }

    #[test]
    fn test_load_or_create_keypair_creates_key() {
        let dir = tempfile::tempdir().unwrap();
        let key = load_or_create_keypair(dir.path()).expect("should create key");
        let key_file = dir.path().join("signing.key");
        assert!(key_file.exists());
        // Loading again should return the same key.
        let key2 = load_or_create_keypair(dir.path()).expect("should load key");
        assert_eq!(key.to_bytes(), key2.to_bytes());
    }
}
