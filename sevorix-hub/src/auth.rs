use anyhow::Result;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// User ID (UUID as string)
    pub sub: String,
    pub email: String,
    /// Expiry timestamp (Unix seconds)
    pub exp: usize,
}

pub fn create_token(user_id: Uuid, email: &str, secret: &str) -> Result<String> {
    let expiry = Utc::now() + Duration::days(30);
    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        exp: expiry.timestamp() as usize,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;
    Ok(token)
}

pub fn verify_token(token: &str, secret: &str) -> Result<Claims> {
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(data.claims)
}

/// Hash a password using Argon2.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?
        .to_string();
    Ok(hash)
}

/// Verify a password against an Argon2 hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| anyhow::anyhow!("Failed to parse password hash: {}", e))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_create_and_verify_token_roundtrip() {
        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let secret = "test-secret-key";

        let token = create_token(user_id, email, secret).expect("token creation should succeed");
        let claims = verify_token(&token, secret).expect("token verification should succeed");

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, email);
    }

    #[test]
    fn test_verify_token_wrong_secret_fails() {
        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let secret = "correct-secret";
        let wrong_secret = "wrong-secret";

        let token = create_token(user_id, email, secret).expect("token creation should succeed");
        let result = verify_token(&token, wrong_secret);

        assert!(result.is_err(), "verification with wrong secret should fail");
    }

    #[test]
    fn test_verify_token_malformed_fails() {
        let secret = "test-secret";
        let malformed_token = "not.a.valid.token";

        let result = verify_token(malformed_token, secret);
        assert!(result.is_err(), "verification of malformed token should fail");
    }

    #[test]
    fn test_verify_token_empty_fails() {
        let secret = "test-secret";
        let result = verify_token("", secret);
        assert!(result.is_err(), "verification of empty token should fail");
    }

    #[test]
    fn test_claims_contain_expected_fields() {
        let user_id = Uuid::new_v4();
        let email = "user@test.org";
        let secret = "secret";

        let token = create_token(user_id, email, secret).expect("token creation should succeed");
        let claims = verify_token(&token, secret).expect("verification should succeed");

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, email);
        // Token should have an expiry in the future
        let now = Utc::now().timestamp() as usize;
        assert!(claims.exp > now, "token should not be expired immediately after creation");
    }

    #[test]
    fn test_hash_password_creates_valid_hash() {
        let password = "my-secure-password";
        let hash = hash_password(password).expect("hashing should succeed");

        // Argon2 hashes start with $argon2
        assert!(hash.starts_with("$argon2"), "hash should be argon2 format");
        assert_ne!(hash, password, "hash should differ from plaintext");
    }

    #[test]
    fn test_hash_password_different_salts() {
        let password = "same-password";
        let hash1 = hash_password(password).expect("hashing should succeed");
        let hash2 = hash_password(password).expect("hashing should succeed");

        // Different salts should produce different hashes
        assert_ne!(hash1, hash2, "different salts should produce different hashes");
    }

    #[test]
    fn test_verify_password_correct() {
        let password = "correct-password";
        let hash = hash_password(password).expect("hashing should succeed");

        let result = verify_password(password, &hash).expect("verification should not error");
        assert!(result, "correct password should verify");
    }

    #[test]
    fn test_verify_password_wrong_fails() {
        let password = "correct-password";
        let wrong_password = "wrong-password";
        let hash = hash_password(password).expect("hashing should succeed");

        let result = verify_password(wrong_password, &hash).expect("verification should not error");
        assert!(!result, "wrong password should not verify");
    }

    #[test]
    fn test_verify_password_empty_hash_fails() {
        let result = verify_password("password", "");
        assert!(result.is_err(), "empty hash should cause error");
    }

    #[test]
    fn test_verify_password_invalid_hash_format_fails() {
        let result = verify_password("password", "not-a-valid-hash");
        assert!(result.is_err(), "invalid hash format should cause error");
    }

    #[test]
    fn test_hash_empty_password() {
        // Empty passwords should still hash (security decision: let app layer validate)
        let hash = hash_password("").expect("hashing empty password should succeed");
        let result = verify_password("", &hash).expect("verification should not error");
        assert!(result, "empty password should verify against its hash");
    }
}
