use crate::error::{AppError, AppResult};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use sha2::{Digest, Sha256};

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
pub fn parse_public_key(b64: &str) -> AppResult<VerifyingKey> {
    let bytes = STANDARD
        .decode(b64)
        .map_err(|e| AppError::BadRequest(format!("invalid public key encoding: {e}")))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::BadRequest("public key must be exactly 32 bytes".to_string()))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| AppError::BadRequest(format!("invalid Ed25519 public key: {e}")))
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
) -> AppResult<bool> {
    let sig_bytes = STANDARD
        .decode(sig_b64)
        .map_err(|e| AppError::BadRequest(format!("invalid signature encoding: {e}")))?;
    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| AppError::BadRequest("signature must be exactly 64 bytes".to_string()))?;
    let signature = Signature::from_bytes(&sig_bytes);
    Ok(key.verify(hash_hex.as_bytes(), &signature).is_ok())
}
