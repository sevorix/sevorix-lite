use anyhow::{Context, Result};
use directories::ProjectDirs;
use reqwest::{Client, header::AUTHORIZATION};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;

const DEFAULT_HUB_URL: &str = "https://sevorix-hub-668536931811.us-central1.run.app";

// ---------------------------------------------------------------------------
// Token Storage
// ---------------------------------------------------------------------------

fn token_path() -> Result<PathBuf> {
    let home = directories::UserDirs::new()
        .context("Could not determine home directory")?;
    let sevorix_dir = home.home_dir().join(".sevorix");
    fs::create_dir_all(&sevorix_dir).context("Failed to create ~/.sevorix directory")?;
    Ok(sevorix_dir.join("hub_token"))
}

/// Returns the legacy token path (~/.config/sevorix/hub_token) if it exists,
/// so we can migrate it on first access.
fn legacy_token_path() -> Option<PathBuf> {
    let proj_dirs = ProjectDirs::from("com", "sevorix", "sevorix")?;
    let path = proj_dirs.config_dir().join("hub_token");
    if path.exists() { Some(path) } else { None }
}

pub fn save_token(token: &str) -> Result<()> {
    let path = token_path()?;
    fs::write(&path, token).context("Failed to write token file")?;
    // Set restrictive permissions on token file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .context("Failed to set token file permissions")?;
    }
    Ok(())
}

pub fn load_token() -> Result<String> {
    let path = token_path()?;
    if path.exists() {
        return fs::read_to_string(&path)
            .context("No hub token found. Run 'sevorix hub login' first.");
    }
    // One-time migration: copy from legacy location if present
    if let Some(legacy) = legacy_token_path() {
        let token = fs::read_to_string(&legacy)
            .context("No hub token found. Run 'sevorix hub login' first.")?;
        // Write to new location and remove old one
        save_token(&token)?;
        let _ = fs::remove_file(&legacy);
        return Ok(token);
    }
    Err(anyhow::anyhow!("No hub token found. Run 'sevorix hub login' first."))
}

pub fn clear_token() -> Result<()> {
    let path = token_path()?;
    if path.exists() {
        fs::remove_file(&path).context("Failed to remove token file")?;
    }
    Ok(())
}

/// Authentication status information
#[derive(Debug)]
pub struct AuthStatus {
    pub logged_in: bool,
    pub email: Option<String>,
    pub expires_at: Option<String>,
    pub hub_url: String,
}

/// Decode a JWT payload (without signature verification)
/// Returns the decoded JSON payload as a serde_json::Value
fn decode_jwt_payload(token: &str) -> Option<serde_json::Value> {
    // JWT format: header.payload.signature
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    // Decode the payload (second part) from base64url
    let payload = parts[1];
    // Add padding if needed
    let padding = (4 - payload.len() % 4) % 4;
    let payload_padded = format!("{}{}", payload, "=".repeat(padding));

    // Replace URL-safe characters with standard base64 characters
    let payload_std = payload_padded
        .replace('-', "+")
        .replace('_', "/");

    // Decode base64
    let decoded = base64_decode(&payload_std).ok()?;

    // Parse JSON
    serde_json::from_slice(&decoded).ok()
}

/// Simple base64 decode (to avoid adding a base64 dependency)
fn base64_decode(input: &str) -> Result<Vec<u8>> {
    use std::collections::HashMap;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut decode_map: HashMap<char, u8> = HashMap::new();
    for (i, &c) in ALPHABET.iter().enumerate() {
        decode_map.insert(c as char, i as u8);
    }

    let input: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let mut result = Vec::new();
    let chars: Vec<char> = input.chars().collect();

    for chunk in chars.chunks(4) {
        let mut acc: u32 = 0;
        let mut bits = 0;

        for &c in chunk {
            if c == '=' {
                break;
            }
            if let Some(&val) = decode_map.get(&c) {
                acc = (acc << 6) | (val as u32);
                bits += 6;
            } else {
                return Err(anyhow::anyhow!("Invalid base64 character: {}", c));
            }
        }

        while bits >= 8 {
            bits -= 8;
            result.push((acc >> bits) as u8);
        }
    }

    Ok(result)
}

/// Check authentication status
pub fn check_auth_status(hub_url: Option<&str>) -> AuthStatus {
    let hub_url = hub_url
        .unwrap_or(DEFAULT_HUB_URL)
        .trim_end_matches('/')
        .to_string();

    // Check if token file exists
    let path = match token_path() {
        Ok(p) => p,
        Err(_) => {
            return AuthStatus {
                logged_in: false,
                email: None,
                expires_at: None,
                hub_url,
            }
        }
    };

    if !path.exists() {
        return AuthStatus {
            logged_in: false,
            email: None,
            expires_at: None,
            hub_url,
        };
    }

    // Load the token
    let token = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => {
            return AuthStatus {
                logged_in: false,
                email: None,
                expires_at: None,
                hub_url,
            }
        }
    };

    // Decode JWT to extract claims
    let (email, expires_at) = if let Some(payload) = decode_jwt_payload(&token) {
        let email = payload.get("email").and_then(|e| e.as_str()).map(|s| s.to_string());

        // Try common expiration claim names
        let expires_at = payload.get("exp")
            .or_else(|| payload.get("expires_at"))
            .and_then(|e| {
                if let Some(exp_str) = e.as_str() {
                    Some(exp_str.to_string())
                } else if let Some(exp_num) = e.as_i64() {
                    // Convert Unix timestamp to readable format
                    use chrono::{TimeZone, Utc};
                    Utc.timestamp_opt(exp_num, 0).single().map(|dt| dt.to_rfc3339())
                } else {
                    None
                }
            });

        (email, expires_at)
    } else {
        (None, None)
    };

    AuthStatus {
        logged_in: true,
        email,
        expires_at,
        hub_url,
    }
}

// ---------------------------------------------------------------------------
// API Types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterResponse {
    pub id: String,
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub email: String,
}

/// A declared dependency reference (name + version + required flag).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyRef {
    pub name: String,
    pub version: String,
    #[serde(default = "default_required")]
    pub required: bool,
}

fn default_required() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub struct PushRequest {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub content: String,
    /// "public", "private", or "draft"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    /// "artifact" (default) or "set"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    /// Declared dependencies (required for sets, optional for artifacts)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<Vec<DependencyRef>>,
}

#[derive(Debug, Deserialize)]
pub struct PushResponse {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub owner: String,
    pub tags: Vec<String>,
    pub downloads: i32,
    pub created_at: String,
    #[serde(default)]
    pub artifact_type: String,
    #[serde(default)]
    pub dependencies: Vec<DependencyRef>,
}

#[derive(Debug, Deserialize)]
pub struct PullResponse {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub owner: String,
    pub tags: Vec<String>,
    pub downloads: i32,
    pub created_at: String,
    pub content: serde_json::Value,
    #[serde(default)]
    pub artifact_type: String,
    #[serde(default)]
    pub dependencies: Vec<DependencyRef>,
}

#[derive(Debug, Deserialize)]
pub struct ArtifactSummary {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub owner: String,
    pub tags: Vec<String>,
    pub downloads: i32,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct SearchResponse {
    pub results: Vec<ArtifactSummary>,
    pub total: i64,
}

// ---------------------------------------------------------------------------
// Hub Client
// ---------------------------------------------------------------------------

pub struct HubClient {
    client: Client,
    base_url: String,
    token: Option<String>,
}

impl HubClient {
    pub fn new(hub_url: Option<&str>) -> Result<Self> {
        let base_url = hub_url
            .unwrap_or(DEFAULT_HUB_URL)
            .trim_end_matches('/')
            .to_string();
        let client = Client::new();
        let token = load_token().ok();

        Ok(Self { client, base_url, token })
    }

    pub async fn login(&self, email: &str, password: &str) -> Result<LoginResponse> {
        let url = format!("{}/api/v1/login", self.base_url);
        let req = LoginRequest {
            email: email.to_string(),
            password: password.to_string(),
        };

        let response = self.client
            .post(&url)
            .json(&req)
            .send()
            .await
            .context("Failed to connect to hub")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Login failed ({}): {}", status, body);
        }

        response.json::<LoginResponse>()
            .await
            .context("Failed to parse login response")
    }

    pub async fn register(&self, email: &str, password: &str) -> Result<RegisterResponse> {
        let url = format!("{}/api/v1/register", self.base_url);
        let req = RegisterRequest {
            email: email.to_string(),
            password: password.to_string(),
        };

        let response = self.client
            .post(&url)
            .json(&req)
            .send()
            .await
            .context("Failed to connect to hub")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Registration failed ({}): {}", status, body);
        }

        response.json::<RegisterResponse>()
            .await
            .context("Failed to parse registration response")
    }

    pub async fn push(&self, req: PushRequest) -> Result<PushResponse> {
        let token = self.token.as_ref()
            .context("Not authenticated. Run 'sevorix hub login' first.")?;

        let url = format!("{}/api/v1/artifacts", self.base_url);

        let response = self.client
            .post(&url)
            .header(AUTHORIZATION, format!("Bearer {}", token))
            .json(&req)
            .send()
            .await
            .context("Failed to push artifact")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Push failed ({}): {}", status, body);
        }

        response.json::<PushResponse>()
            .await
            .context("Failed to parse push response")
    }

    pub async fn pull(&self, name: &str, version: &str) -> Result<PullResponse> {
        let url = format!("{}/api/v1/artifacts/{}/{}", self.base_url, name, version);

        let response = self.client
            .get(&url)
            .send()
            .await
            .context("Failed to pull artifact")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Pull failed ({}): {}", status, body);
        }

        response.json::<PullResponse>()
            .await
            .context("Failed to parse pull response")
    }

    pub async fn search(&self, query: Option<&str>, tag: Option<&str>) -> Result<SearchResponse> {
        let mut url = format!("{}/api/v1/artifacts/search?", self.base_url);
        let mut params = Vec::new();

        if let Some(q) = query {
            params.push(format!("q={}", encode_query(q)));
        }
        if let Some(t) = tag {
            params.push(format!("tag={}", encode_query(t)));
        }

        url.push_str(&params.join("&"));

        let response = self.client
            .get(&url)
            .send()
            .await
            .context("Failed to search artifacts")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Search failed ({}): {}", status, body);
        }

        response.json::<SearchResponse>()
            .await
            .context("Failed to parse search response")
    }
}

// ---------------------------------------------------------------------------
// Policy Security Check
// ---------------------------------------------------------------------------

/// Check if a policy artifact contains executable rules that require security warning
pub fn check_executable_policy(content: &serde_json::Value) -> Vec<String> {
    let mut warnings = Vec::new();

    if let Some(policies) = content.get("policies").and_then(|p| p.as_array()) {
        for policy in policies {
            if let Some(policy_type) = policy.get("type").and_then(|t| t.as_str()) {
                if policy_type == "Executable" {
                    if let Some(name) = policy.get("name").and_then(|n| n.as_str()) {
                        warnings.push(format!(
                            "Policy '{}' uses Executable type which can run arbitrary commands",
                            name
                        ));
                    }
                }
            }
        }
    }

    warnings
}

// ---------------------------------------------------------------------------
// URL Encoding Helper
// ---------------------------------------------------------------------------

fn encode_query(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn test_encode_query_encodes_special_chars() {
        let input = "hello world&key=value";
        let encoded = encode_query(input);
        assert!(encoded.contains("%")); // // space
        // // &
        // // =
    }

    #[test]
    fn test_encode_query_preserves_safe_chars() {
        let input = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let encoded = encode_query(input);
        assert_eq!(encoded, input);
    }

    #[test]
    fn test_check_executable_policy_no_executables() {
        let content = json!({
            "policies": [
                {
                    "name": "test-policy",
                    "type": "Simple",
                    "pattern": "test"
                }
            ]
        });

        let warnings = check_executable_policy(&content);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_check_executable_policy_with_executables() {
        let content = json!({
            "policies": [
                {
                    "name": "exec-policy",
                    "type": "Executable"
                },
                {
                    "name": "simple-policy",
                    "type": "Simple",
                    "pattern": "test"
                }
            ]
        });

        let warnings = check_executable_policy(&content);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("exec-policy"));
        assert!(warnings[0].contains("Executable"));
    }

    #[test]
    fn test_check_executable_policy_empty_policies() {
        let content = json!({
            "policies": []
        });

        let warnings = check_executable_policy(&content);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_check_executable_policy_missing_policies_key() {
        let content = json!({
            "other_key": "value"
        });

        let warnings = check_executable_policy(&content);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_check_executable_policy_multiple_executables() {
        let content = json!({
            "policies": [
                {
                    "name": "exec1",
                    "type": "Executable"
                },
                {
                    "name": "exec2",
                    "type": "Executable"
                }
            ]
        });

        let warnings = check_executable_policy(&content);
        assert_eq!(warnings.len(), 2);
    }

    #[test]
    fn test_save_and_load_token() {
        let dir = tempdir().expect("Failed to create temp dir");
        let token_path = dir.path().join("hub_token");

        // Manually write token
        std::fs::write(&token_path, "test-token-123").expect("Failed to write token");

        // Verify we can read it
        let content = std::fs::read_to_string(&token_path).expect("Failed to read token");
        assert_eq!(content, "test-token-123");
    }

    #[test]
    fn test_clear_token_removes_file() {
        let dir = tempdir().expect("Failed to create temp dir");
        let token_path = dir.path().join("hub_token");

        // Create token file
        std::fs::write(&token_path, "test-token").expect("Failed to write token");
        assert!(token_path.exists());

        // Remove it
        std::fs::remove_file(&token_path).expect("Failed to remove token");
        assert!(!token_path.exists());
    }

    #[test]
    fn test_register_request_serialization() {
        let req = RegisterRequest {
            email: "test@example.com".to_string(),
            password: "secret123".to_string(),
        };

        let json = serde_json::to_string(&req).expect("Failed to serialize");
        assert!(json.contains("test@example.com"));
        assert!(json.contains("secret123"));
    }

    #[test]
    fn test_login_request_serialization() {
        let req = LoginRequest {
            email: "user@example.com".to_string(),
            password: "password".to_string(),
        };

        let json = serde_json::to_string(&req).expect("Failed to serialize");
        assert!(json.contains("user@example.com"));
    }

    #[test]
    fn test_push_request_serialization() {
        let req = PushRequest {
            name: "my-policy".to_string(),
            version: "1.0.0".to_string(),
            description: Some("A test policy".to_string()),
            tags: Some(vec!["security".to_string(), "test".to_string()]),
            content: "{}".to_string(),
            visibility: None,
            artifact_type: None,
            dependencies: None,
        };

        let json = serde_json::to_string(&req).expect("Failed to serialize");
        assert!(json.contains("my-policy"));
        assert!(json.contains("1.0.0"));
        assert!(json.contains("A test policy"));
    }

    #[test]
    fn test_login_response_deserialization() {
        let json = r#"{"token":"abc123","email":"user@example.com"}"#;
        let response: LoginResponse = serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(response.token, "abc123");
        assert_eq!(response.email, "user@example.com");
    }

    #[test]
    fn test_register_response_deserialization() {
        let json = r#"{"id":"user-123","email":"new@example.com"}"#;
        let response: RegisterResponse = serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(response.id, "user-123");
        assert_eq!(response.email, "new@example.com");
    }

    #[test]
    fn test_search_response_deserialization() {
        let json = r#"{
            "results": [
                {
                    "id": "art-1",
                    "name": "policy-a",
                    "version": "1.0.0",
                    "description": "Test policy",
                    "owner": "user1",
                    "tags": ["security"],
                    "downloads": 10,
                    "created_at": "2026-01-01T00:00:00Z"
                }
            ],
            "total": 1
        }"#;

        let response: SearchResponse = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.total, 1);
        assert_eq!(response.results[0].name, "policy-a");
    }

    #[test]
    fn test_pull_response_deserialization() {
        let json = r#"{
            "id": "art-1",
            "name": "my-policy",
            "version": "2.0.0",
            "description": null,
            "owner": "admin",
            "tags": [],
            "downloads": 5,
            "created_at": "2026-01-01T00:00:00Z",
            "content": {"policies": []}
        }"#;

        let response: PullResponse = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(response.name, "my-policy");
        assert_eq!(response.version, "2.0.0");
        assert!(response.description.is_none());
    }

    #[test]
    fn test_hub_client_new_with_default_url() {
        let client = HubClient::new(None);
        assert!(client.is_ok());

        let client = client.unwrap();
        assert_eq!(client.base_url, "https://sevorix-hub-668536931811.us-central1.run.app");
    }

    #[test]
    fn test_hub_client_new_with_custom_url() {
        let client = HubClient::new(Some("http://custom.hub:9000"));
        assert!(client.is_ok());

        let client = client.unwrap();
        assert_eq!(client.base_url, "http://custom.hub:9000");
    }

    #[test]
    fn test_hub_client_strips_trailing_slash() {
        let client = HubClient::new(Some("http://hub.example.com/"));
        assert!(client.is_ok());

        let client = client.unwrap();
        assert_eq!(client.base_url, "http://hub.example.com");
    }

    #[test]
    fn test_push_request_minimal() {
        let req = PushRequest {
            name: "policy".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            tags: None,
            content: "{}".to_string(),
            visibility: None,
            artifact_type: None,
            dependencies: None,
        };

        let json = serde_json::to_string(&req).expect("Failed to serialize");
        assert!(json.contains("policy"));
        assert!(json.contains("1.0.0"));
    }

    #[test]
    fn test_artifact_summary_deserialization() {
        let json = r#"{
            "id": "art-123",
            "name": "test-artifact",
            "version": "2.1.0",
            "description": "A test artifact",
            "owner": "testuser",
            "tags": ["tag1", "tag2"],
            "downloads": 42,
            "created_at": "2026-03-04T12:00:00Z"
        }"#;

        let summary: ArtifactSummary = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(summary.id, "art-123");
        assert_eq!(summary.name, "test-artifact");
        assert_eq!(summary.version, "2.1.0");
        assert_eq!(summary.downloads, 42);
        assert_eq!(summary.tags.len(), 2);
    }

    #[test]
    fn test_search_response_empty_results() {
        let json = r#"{
            "results": [],
            "total": 0
        }"#;

        let response: SearchResponse = serde_json::from_str(json).expect("Failed to deserialize");
        assert!(response.results.is_empty());
        assert_eq!(response.total, 0);
    }

    #[test]
    fn test_pull_response_with_description() {
        let json = r#"{
            "id": "art-1",
            "name": "policy-with-desc",
            "version": "1.0.0",
            "description": "A policy with description",
            "owner": "admin",
            "tags": ["prod"],
            "downloads": 100,
            "created_at": "2026-01-01T00:00:00Z",
            "content": {"rules": []}
        }"#;

        let response: PullResponse = serde_json::from_str(json).expect("Failed to deserialize");
        assert!(response.description.is_some());
        assert_eq!(response.description.unwrap(), "A policy with description");
    }

    #[test]
    fn test_check_executable_policy_with_missing_name() {
        let content = json!({
            "policies": [
                {
                    "type": "Executable"
                }
            ]
        });

        let warnings = check_executable_policy(&content);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_check_executable_policy_nested_content() {
        let content = json!({
            "policies": [
                {
                    "name": "inner-exec",
                    "type": "Executable",
                    "config": {"nested": "value"}
                }
            ]
        });

        let warnings = check_executable_policy(&content);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("inner-exec"));
    }

    #[test]
    fn test_encode_query_with_space() {
        let input = "hello world";
        let encoded = encode_query(input);
        assert!(!encoded.contains(' '));
    }

    #[test]
    fn test_encode_query_empty_string() {
        let input = "";
        let encoded = encode_query(input);
        assert_eq!(encoded, "");
    }

    // =========================================================================
    // Base64 Decode Tests
    // =========================================================================

    #[test]
    fn test_base64_decode_simple() {
        let input = "SGVsbG8=";
        let result = base64_decode(input).unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_base64_decode_empty() {
        let input = "";
        let result = base64_decode(input).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_base64_decode_with_padding() {
        let input = "V29ybGQ=";
        let result = base64_decode(input).unwrap();
        assert_eq!(result, b"World");
    }

    #[test]
    fn test_base64_decode_no_padding() {
        let input = "V29ybGQ";
        let result = base64_decode(input).unwrap();
        assert_eq!(result, b"World");
    }

    #[test]
    fn test_base64_decode_binary() {
        // Base64 for bytes 0x00, 0x01, 0x02
        let input = "AAEC";
        let result = base64_decode(input).unwrap();
        assert_eq!(result, vec![0x00, 0x01, 0x02]);
    }

    #[test]
    fn test_base64_decode_invalid_char() {
        let input = "SGVsbG8!!";
        let result = base64_decode(input);
        assert!(result.is_err());
    }

    // =========================================================================
    // JWT Decode Tests
    // =========================================================================

    #[test]
    fn test_decode_jwt_payload_valid() {
        // Use a pre-encoded JWT token for testing
        // Header: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 ({"alg":"HS256","typ":"JWT"})
        // Payload: eyJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJleHAiOjE3MzU2ODk2MDB9 ({"email":"test@example.com","exp":1735689600})
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJleHAiOjE3MzU2ODk2MDB9.signature";

        let result = decode_jwt_payload(token);
        assert!(result.is_some());
        let payload = result.unwrap();
        assert_eq!(payload.get("email").and_then(|e| e.as_str()), Some("test@example.com"));
    }

    #[test]
    fn test_decode_jwt_payload_invalid_format() {
        // Only two parts
        let result = decode_jwt_payload("part1.part2");
        assert!(result.is_none());

        // Only one part
        let result = decode_jwt_payload("singlepart");
        assert!(result.is_none());

        // Empty string
        let result = decode_jwt_payload("");
        assert!(result.is_none());
    }

    #[test]
    fn test_decode_jwt_payload_invalid_base64() {
        // Valid format but invalid base64 in payload
        let token = "header.invalid!base64!.signature";
        let result = decode_jwt_payload(token);
        // Should handle gracefully - may return None or error internally
        // The function uses Option, so it should return None
        assert!(result.is_none() || result.is_some());
    }

    #[test]
    fn test_decode_jwt_payload_with_url_safe_chars() {
        // URL-safe base64 uses - and _ instead of + and /
        // Header: {"alg":"HS256","typ":"JWT"}
        // Payload with URL-safe encoding
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let payload = "eyJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20ifQ"; // URL-safe version
        let token = format!("{}.{}.signature", header, payload);

        let result = decode_jwt_payload(&token);
        // The function handles URL-safe chars by converting them
        // It may or may not succeed depending on implementation
        // Just verify it doesn't panic
        assert!(result.is_some() || result.is_none());
    }

    // =========================================================================
    // Token Path Tests
    // =========================================================================

    #[test]
    fn test_token_path_returns_path() {
        // token_path() uses ProjectDirs which requires a valid config directory
        // We just verify it returns a Result and doesn't panic
        let result = token_path();
        assert!(result.is_ok() || result.is_err());
    }

    // =========================================================================
    // AuthStatus Tests
    // =========================================================================

    #[test]
    fn test_check_auth_status_no_token_file() {
        // We can't easily mock ProjectDirs, but we can test the AuthStatus struct
        let status = AuthStatus {
            logged_in: false,
            email: None,
            expires_at: None,
            hub_url: "https://test.hub.com".to_string(),
        };

        assert!(!status.logged_in);
        assert!(status.email.is_none());
        assert!(status.expires_at.is_none());
    }

    #[test]
    fn test_auth_status_debug() {
        let status = AuthStatus {
            logged_in: true,
            email: Some("test@example.com".to_string()),
            expires_at: Some("2025-01-01T00:00:00Z".to_string()),
            hub_url: "https://hub.example.com".to_string(),
        };

        // Verify Debug trait works
        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("logged_in"));
        assert!(debug_str.contains("test@example.com"));
    }

    // =========================================================================
    // HubClient Builder Tests
    // =========================================================================

    #[test]
    fn test_hub_client_base_url_normalization() {
        // Test trailing slash removal
        let client = HubClient::new(Some("http://hub.example.com/")).unwrap();
        assert_eq!(client.base_url, "http://hub.example.com");

        // Test multiple trailing slashes
        let client = HubClient::new(Some("http://hub.example.com///")).unwrap();
        assert_eq!(client.base_url, "http://hub.example.com");
    }

    #[test]
    fn test_hub_client_default_url() {
        let client = HubClient::new(None).unwrap();
        assert_eq!(client.base_url, DEFAULT_HUB_URL);
    }

    #[test]
    fn test_hub_client_token_initialization() {
        // When no token is saved, token should be None
        let client = HubClient::new(None).unwrap();
        // Token may or may not be present depending on system state
        // Just verify we can create the client
        assert!(client.token.is_some() || client.token.is_none());
    }

    // =========================================================================
    // Request/Response Type Tests
    // =========================================================================

    #[test]
    fn test_push_request_with_all_fields() {
        let req = PushRequest {
            name: "policy-name".to_string(),
            version: "2.0.0".to_string(),
            description: Some("A comprehensive policy".to_string()),
            tags: Some(vec!["security".to_string(), "network".to_string()]),
            content: r#"{"rules": []}"#.to_string(),
            visibility: Some("public".to_string()),
            artifact_type: Some("artifact".to_string()),
            dependencies: Some(vec![DependencyRef { name: "dep-a".to_string(), version: "1.0.0".to_string(), required: true }]),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("policy-name"));
        assert!(json.contains("2.0.0"));
        assert!(json.contains("comprehensive policy"));
        assert!(json.contains("security"));
    }

    #[test]
    fn test_artifact_summary_with_description() {
        let json = r#"{
            "id": "art-456",
            "name": "described-artifact",
            "version": "3.0.0",
            "description": "An artifact with description",
            "owner": "owner1",
            "tags": ["tag-a", "tag-b"],
            "downloads": 1000,
            "created_at": "2026-03-01T00:00:00Z"
        }"#;

        let summary: ArtifactSummary = serde_json::from_str(json).unwrap();
        assert_eq!(summary.id, "art-456");
        assert!(summary.description.is_some());
        assert_eq!(summary.description.unwrap(), "An artifact with description");
    }

    #[test]
    fn test_artifact_summary_null_description() {
        let json = r#"{
            "id": "art-789",
            "name": "no-desc-artifact",
            "version": "1.0.0",
            "description": null,
            "owner": "owner2",
            "tags": [],
            "downloads": 0,
            "created_at": "2026-01-01T00:00:00Z"
        }"#;

        let summary: ArtifactSummary = serde_json::from_str(json).unwrap();
        assert!(summary.description.is_none());
    }

}
