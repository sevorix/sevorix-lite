use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

/// Visibility levels for artifacts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    Public,
    Private,
    Draft,
}

impl Default for Visibility {
    fn default() -> Self {
        Self::Public
    }
}

impl std::fmt::Display for Visibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Visibility::Public => write!(f, "public"),
            Visibility::Private => write!(f, "private"),
            Visibility::Draft => write!(f, "draft"),
        }
    }
}

impl FromStr for Visibility {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "public" => Ok(Visibility::Public),
            "private" => Ok(Visibility::Private),
            "draft" => Ok(Visibility::Draft),
            _ => Err(format!("invalid visibility: {}", s)),
        }
    }
}

/// Type of artifact: regular artifact or a set (collection of member artifacts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactType {
    Artifact,
    Set,
}

impl Default for ArtifactType {
    fn default() -> Self {
        Self::Artifact
    }
}

impl std::fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactType::Artifact => write!(f, "artifact"),
            ArtifactType::Set => write!(f, "set"),
        }
    }
}

impl FromStr for ArtifactType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "artifact" => Ok(ArtifactType::Artifact),
            "set" => Ok(ArtifactType::Set),
            _ => Err(format!("invalid artifact type: {}", s)),
        }
    }
}

/// Endorsement levels for artifacts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndorsementLevel {
    Verified,
    TrustedAuthor,
    Official,
}

impl Default for EndorsementLevel {
    fn default() -> Self {
        Self::Verified
    }
}

impl std::fmt::Display for EndorsementLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EndorsementLevel::Verified => write!(f, "verified"),
            EndorsementLevel::TrustedAuthor => write!(f, "trusted_author"),
            EndorsementLevel::Official => write!(f, "official"),
        }
    }
}

impl FromStr for EndorsementLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "verified" => Ok(EndorsementLevel::Verified),
            "trusted_author" => Ok(EndorsementLevel::TrustedAuthor),
            "official" => Ok(EndorsementLevel::Official),
            _ => Err(format!("invalid endorsement level: {}", s)),
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub is_admin: bool,
    pub is_endorsed: bool,
    pub is_approved: bool,
    pub created_at: DateTime<Utc>,
}

/// Database row for artifacts (uses String for visibility)
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ArtifactRow {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub owner_id: Uuid,
    pub file_path: String,
    pub tags: Vec<String>,
    pub downloads: i32,
    pub visibility: String,
    pub created_at: DateTime<Utc>,
    pub content_hash: Option<String>,
    pub content_schema: Option<String>,
    pub signature: Option<String>,
    pub key_fingerprint: Option<String>,
    pub artifact_type: String,
    pub yanked: bool,
    pub yanked_reason: Option<String>,
    pub denied_pulls: i32,
}

impl ArtifactRow {
    pub fn into_artifact(self) -> Result<Artifact, String> {
        let visibility = Visibility::from_str(&self.visibility)?;
        let artifact_type = ArtifactType::from_str(&self.artifact_type)?;
        Ok(Artifact {
            id: self.id,
            name: self.name,
            version: self.version,
            description: self.description,
            owner_id: self.owner_id,
            file_path: self.file_path,
            tags: self.tags,
            downloads: self.downloads,
            visibility,
            created_at: self.created_at,
            content_hash: self.content_hash,
            content_schema: self.content_schema,
            signature: self.signature,
            key_fingerprint: self.key_fingerprint,
            artifact_type,
            yanked: self.yanked,
            yanked_reason: self.yanked_reason,
            denied_pulls: self.denied_pulls,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Artifact {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub owner_id: Uuid,
    pub file_path: String,
    pub tags: Vec<String>,
    pub downloads: i32,
    pub visibility: Visibility,
    pub created_at: DateTime<Utc>,
    pub content_hash: Option<String>,
    pub content_schema: Option<String>,
    pub signature: Option<String>,
    pub key_fingerprint: Option<String>,
    pub artifact_type: ArtifactType,
    pub yanked: bool,
    pub yanked_reason: Option<String>,
    pub denied_pulls: i32,
}

/// Database row for artifact with owner (uses String for visibility)
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ArtifactWithOwnerRow {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub owner_id: Uuid,
    pub file_path: String,
    pub tags: Vec<String>,
    pub downloads: i32,
    pub visibility: String,
    pub created_at: DateTime<Utc>,
    pub email: String,
    pub owner_is_endorsed: bool,
    pub content_hash: Option<String>,
    pub content_schema: Option<String>,
    pub signature: Option<String>,
    pub key_fingerprint: Option<String>,
    pub artifact_type: String,
    pub yanked: bool,
    pub yanked_reason: Option<String>,
    pub denied_pulls: i32,
}

impl ArtifactWithOwnerRow {
    pub fn into_artifact_with_owner(self) -> Result<ArtifactWithOwner, String> {
        let visibility = Visibility::from_str(&self.visibility)?;
        let artifact_type = ArtifactType::from_str(&self.artifact_type)?;
        Ok(ArtifactWithOwner {
            id: self.id,
            name: self.name,
            version: self.version,
            description: self.description,
            owner_id: self.owner_id,
            file_path: self.file_path,
            tags: self.tags,
            downloads: self.downloads,
            visibility,
            created_at: self.created_at,
            email: self.email,
            owner_is_endorsed: self.owner_is_endorsed,
            content_hash: self.content_hash,
            content_schema: self.content_schema,
            signature: self.signature,
            key_fingerprint: self.key_fingerprint,
            artifact_type,
            yanked: self.yanked,
            yanked_reason: self.yanked_reason,
            denied_pulls: self.denied_pulls,
        })
    }
}

/// Result of a JOIN query: artifact fields plus the owner's email.
#[derive(Debug, Clone)]
pub struct ArtifactWithOwner {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub owner_id: Uuid,
    pub file_path: String,
    pub tags: Vec<String>,
    pub downloads: i32,
    pub visibility: Visibility,
    pub created_at: DateTime<Utc>,
    pub email: String,
    pub owner_is_endorsed: bool,
    pub content_hash: Option<String>,
    pub content_schema: Option<String>,
    pub signature: Option<String>,
    pub key_fingerprint: Option<String>,
    pub artifact_type: ArtifactType,
    pub yanked: bool,
    pub yanked_reason: Option<String>,
    pub denied_pulls: i32,
}

/// Public-facing artifact summary (no file_path).
#[derive(Debug, Serialize, Deserialize)]
pub struct ArtifactSummary {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub owner: String,
    pub owner_is_endorsed: bool,
    pub tags: Vec<String>,
    pub downloads: i32,
    pub visibility: Visibility,
    pub created_at: DateTime<Utc>,
    pub yanked: bool,
    pub artifact_type: ArtifactType,
}

impl From<ArtifactWithOwner> for ArtifactSummary {
    fn from(a: ArtifactWithOwner) -> Self {
        ArtifactSummary {
            id: a.id,
            name: a.name,
            version: a.version,
            description: a.description,
            owner: a.email,
            owner_is_endorsed: a.owner_is_endorsed,
            tags: a.tags,
            downloads: a.downloads,
            visibility: a.visibility,
            created_at: a.created_at,
            yanked: a.yanked,
            artifact_type: a.artifact_type,
        }
    }
}

/// Database row for endorsements (uses String for level)
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EndorsementRow {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub user_id: Uuid,
    pub level: String,
    pub created_at: DateTime<Utc>,
}

impl EndorsementRow {
    pub fn into_endorsement(self) -> Result<Endorsement, String> {
        let level = EndorsementLevel::from_str(&self.level)?;
        Ok(Endorsement {
            id: self.id,
            artifact_id: self.artifact_id,
            user_id: self.user_id,
            level,
            created_at: self.created_at,
        })
    }
}

/// Endorsement record for an artifact.
#[derive(Debug, Clone, Serialize)]
pub struct Endorsement {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub user_id: Uuid,
    pub level: EndorsementLevel,
    pub created_at: DateTime<Utc>,
}

/// Database row for endorsement with user details
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EndorsementWithUserRow {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub user_id: Uuid,
    pub email: String,
    pub user_is_admin: bool,
    pub user_is_endorsed: bool,
    pub level: String,
    pub created_at: DateTime<Utc>,
}

impl EndorsementWithUserRow {
    pub fn into_endorsement_with_user(self) -> Result<EndorsementWithUser, String> {
        let level = EndorsementLevel::from_str(&self.level)?;
        Ok(EndorsementWithUser {
            id: self.id,
            artifact_id: self.artifact_id,
            user_id: self.user_id,
            email: self.email,
            user_is_admin: self.user_is_admin,
            user_is_endorsed: self.user_is_endorsed,
            level,
            created_at: self.created_at,
        })
    }
}

/// Endorsement with user details.
#[derive(Debug, Clone, Serialize)]
pub struct EndorsementWithUser {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub user_id: Uuid,
    pub email: String,
    pub user_is_admin: bool,
    pub user_is_endorsed: bool,
    pub level: EndorsementLevel,
    pub created_at: DateTime<Utc>,
}

/// Public user profile (no sensitive data).
#[derive(Debug, Serialize)]
pub struct UserProfile {
    pub id: Uuid,
    pub email: String,
    pub is_admin: bool,
    pub is_endorsed: bool,
    pub is_approved: bool,
    pub created_at: DateTime<Utc>,
}

/// Database row for a user signing key.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SigningKeyRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub public_key: String,
    pub fingerprint: String,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Public-facing signing key (raw public_key bytes omitted).
#[derive(Debug, Clone, Serialize)]
pub struct SigningKey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub fingerprint: String,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl From<SigningKeyRow> for SigningKey {
    fn from(r: SigningKeyRow) -> Self {
        SigningKey {
            id: r.id,
            user_id: r.user_id,
            fingerprint: r.fingerprint,
            label: r.label,
            created_at: r.created_at,
            revoked_at: r.revoked_at,
        }
    }
}

/// A declared dependency of an artifact.
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

/// Database row for artifact_dependencies.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ArtifactDependency {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub dep_name: String,
    pub dep_version: String,
    pub dep_required: bool,
}

impl From<ArtifactDependency> for DependencyRef {
    fn from(d: ArtifactDependency) -> Self {
        DependencyRef {
            name: d.dep_name,
            version: d.dep_version,
            required: d.dep_required,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Visibility tests
    // =========================================================================

    #[test]
    fn test_visibility_from_str_valid() {
        assert_eq!(Visibility::from_str("public").unwrap(), Visibility::Public);
        assert_eq!(Visibility::from_str("private").unwrap(), Visibility::Private);
        assert_eq!(Visibility::from_str("draft").unwrap(), Visibility::Draft);
    }

    #[test]
    fn test_visibility_from_str_invalid() {
        let result = Visibility::from_str("invalid");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid visibility"));
    }

    #[test]
    fn test_visibility_from_str_case_sensitive() {
        // Should be lowercase
        let result = Visibility::from_str("PUBLIC");
        assert!(result.is_err(), "uppercase should be invalid");
    }

    #[test]
    fn test_visibility_display() {
        assert_eq!(Visibility::Public.to_string(), "public");
        assert_eq!(Visibility::Private.to_string(), "private");
        assert_eq!(Visibility::Draft.to_string(), "draft");
    }

    #[test]
    fn test_visibility_default() {
        assert_eq!(Visibility::default(), Visibility::Public);
    }

    #[test]
    fn test_visibility_serialization() {
        let public = Visibility::Public;
        let json = serde_json::to_string(&public).unwrap();
        assert_eq!(json, "\"public\"");

        let private = Visibility::Private;
        let json = serde_json::to_string(&private).unwrap();
        assert_eq!(json, "\"private\"");

        let draft = Visibility::Draft;
        let json = serde_json::to_string(&draft).unwrap();
        assert_eq!(json, "\"draft\"");
    }

    #[test]
    fn test_visibility_deserialization() {
        let public: Visibility = serde_json::from_str("\"public\"").unwrap();
        assert_eq!(public, Visibility::Public);

        let private: Visibility = serde_json::from_str("\"private\"").unwrap();
        assert_eq!(private, Visibility::Private);

        let draft: Visibility = serde_json::from_str("\"draft\"").unwrap();
        assert_eq!(draft, Visibility::Draft);
    }

    // =========================================================================
    // EndorsementLevel tests
    // =========================================================================

    #[test]
    fn test_endorsement_level_from_str_valid() {
        assert_eq!(
            EndorsementLevel::from_str("verified").unwrap(),
            EndorsementLevel::Verified
        );
        assert_eq!(
            EndorsementLevel::from_str("trusted_author").unwrap(),
            EndorsementLevel::TrustedAuthor
        );
        assert_eq!(
            EndorsementLevel::from_str("official").unwrap(),
            EndorsementLevel::Official
        );
    }

    #[test]
    fn test_endorsement_level_from_str_invalid() {
        let result = EndorsementLevel::from_str("invalid");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid endorsement level"));
    }

    #[test]
    fn test_endorsement_level_display() {
        assert_eq!(EndorsementLevel::Verified.to_string(), "verified");
        assert_eq!(EndorsementLevel::TrustedAuthor.to_string(), "trusted_author");
        assert_eq!(EndorsementLevel::Official.to_string(), "official");
    }

    #[test]
    fn test_endorsement_level_default() {
        assert_eq!(EndorsementLevel::default(), EndorsementLevel::Verified);
    }

    #[test]
    fn test_endorsement_level_serialization() {
        let verified = EndorsementLevel::Verified;
        let json = serde_json::to_string(&verified).unwrap();
        assert_eq!(json, "\"verified\"");

        let trusted = EndorsementLevel::TrustedAuthor;
        let json = serde_json::to_string(&trusted).unwrap();
        assert_eq!(json, "\"trusted_author\"");

        let official = EndorsementLevel::Official;
        let json = serde_json::to_string(&official).unwrap();
        assert_eq!(json, "\"official\"");
    }

    #[test]
    fn test_endorsement_level_deserialization() {
        let verified: EndorsementLevel = serde_json::from_str("\"verified\"").unwrap();
        assert_eq!(verified, EndorsementLevel::Verified);

        let trusted: EndorsementLevel = serde_json::from_str("\"trusted_author\"").unwrap();
        assert_eq!(trusted, EndorsementLevel::TrustedAuthor);

        let official: EndorsementLevel = serde_json::from_str("\"official\"").unwrap();
        assert_eq!(official, EndorsementLevel::Official);
    }

    // =========================================================================
    // ArtifactRow conversion tests
    // =========================================================================

    #[test]
    fn test_artifact_row_into_artifact_success() {
        let row = ArtifactRow {
            id: Uuid::new_v4(),
            name: "test-artifact".to_string(),
            version: "1.0.0".to_string(),
            description: Some("A test artifact".to_string()),
            owner_id: Uuid::new_v4(),
            file_path: "/path/to/file.json".to_string(),
            tags: vec!["tag1".to_string(), "tag2".to_string()],
            downloads: 42,
            visibility: "public".to_string(),
            created_at: Utc::now(),
            content_hash: None,
            content_schema: None,
            signature: None,
            key_fingerprint: None,
            artifact_type: "artifact".to_string(),
            yanked: false,
            yanked_reason: None,
            denied_pulls: 0,
        };

        let artifact = row.into_artifact().expect("conversion should succeed");
        assert_eq!(artifact.visibility, Visibility::Public);
    }

    #[test]
    fn test_artifact_row_into_artifact_invalid_visibility() {
        let row = ArtifactRow {
            id: Uuid::new_v4(),
            name: "test".to_string(),
            version: "1.0".to_string(),
            description: None,
            owner_id: Uuid::new_v4(),
            file_path: "/path".to_string(),
            tags: vec![],
            downloads: 0,
            visibility: "invalid-visibility".to_string(),
            created_at: Utc::now(),
            content_hash: None,
            content_schema: None,
            signature: None,
            key_fingerprint: None,
            artifact_type: "artifact".to_string(),
            yanked: false,
            yanked_reason: None,
            denied_pulls: 0,
        };

        let result = row.into_artifact();
        assert!(result.is_err(), "invalid visibility should cause error");
    }

    // =========================================================================
    // EndorsementRow conversion tests
    // =========================================================================

    #[test]
    fn test_endorsement_row_into_endorsement_success() {
        let row = EndorsementRow {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            level: "verified".to_string(),
            created_at: Utc::now(),
        };

        let endorsement = row.into_endorsement().expect("conversion should succeed");
        assert_eq!(endorsement.level, EndorsementLevel::Verified);
    }

    #[test]
    fn test_endorsement_row_into_endorsement_invalid_level() {
        let row = EndorsementRow {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            level: "invalid-level".to_string(),
            created_at: Utc::now(),
        };

        let result = row.into_endorsement();
        assert!(result.is_err(), "invalid level should cause error");
    }

    // =========================================================================
    // ArtifactWithOwnerRow conversion tests
    // =========================================================================

    #[test]
    fn test_artifact_with_owner_row_conversion() {
        let row = ArtifactWithOwnerRow {
            id: Uuid::new_v4(),
            name: "artifact".to_string(),
            version: "2.0.0".to_string(),
            description: None,
            owner_id: Uuid::new_v4(),
            file_path: "/path".to_string(),
            tags: vec!["rust".to_string()],
            downloads: 100,
            visibility: "private".to_string(),
            created_at: Utc::now(),
            email: "owner@example.com".to_string(),
            owner_is_endorsed: true,
            content_hash: None,
            content_schema: None,
            signature: None,
            key_fingerprint: None,
            artifact_type: "artifact".to_string(),
            yanked: false,
            yanked_reason: None,
            denied_pulls: 0,
        };

        let artifact = row.into_artifact_with_owner().expect("conversion should succeed");
        assert_eq!(artifact.visibility, Visibility::Private);
        assert_eq!(artifact.email, "owner@example.com");
        assert!(artifact.owner_is_endorsed);
    }

    // =========================================================================
    // EndorsementWithUserRow conversion tests
    // =========================================================================

    #[test]
    fn test_endorsement_with_user_row_conversion() {
        let row = EndorsementWithUserRow {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            email: "endorser@example.com".to_string(),
            user_is_admin: false,
            user_is_endorsed: true,
            level: "official".to_string(),
            created_at: Utc::now(),
        };

        let endorsement = row.into_endorsement_with_user().expect("conversion should succeed");
        assert_eq!(endorsement.level, EndorsementLevel::Official);
        assert_eq!(endorsement.email, "endorser@example.com");
    }

    // =========================================================================
    // ArtifactSummary conversion tests
    // =========================================================================

    #[test]
    fn test_artifact_summary_from_artifact_with_owner() {
        let artifact = ArtifactWithOwner {
            id: Uuid::new_v4(),
            name: "my-artifact".to_string(),
            version: "1.0.0".to_string(),
            description: Some("Description".to_string()),
            owner_id: Uuid::new_v4(),
            file_path: "/path/to/artifact.json".to_string(),
            tags: vec!["security".to_string()],
            downloads: 50,
            visibility: Visibility::Public,
            created_at: Utc::now(),
            email: "owner@example.com".to_string(),
            owner_is_endorsed: false,
            content_hash: None,
            content_schema: None,
            signature: None,
            key_fingerprint: None,
            artifact_type: ArtifactType::Artifact,
            yanked: false,
            yanked_reason: None,
            denied_pulls: 0,
        };

        let summary = ArtifactSummary::from(artifact);
        assert_eq!(summary.name, "my-artifact");
        assert_eq!(summary.owner, "owner@example.com");
        // Note: file_path should NOT be in summary (security)
        // The ArtifactSummary struct doesn't have file_path field
    }
}
