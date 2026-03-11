use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use axum::extract::ConnectInfo;
use std::net::SocketAddr;

use crate::{
    audit,
    auth::{create_token, hash_password, verify_password, verify_token},
    error::{map_db_err, AppError, AppResult},
    models::{
        Artifact, ArtifactRow, ArtifactSummary, ArtifactWithOwner, ArtifactWithOwnerRow,
        EndorsementLevel, EndorsementRow, EndorsementWithUser, EndorsementWithUserRow,
        User, UserProfile, Visibility,
    },
    store::ArtifactStore,
    AppState,
};

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub id: Uuid,
    pub email: String,
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<RegisterRequest>,
) -> AppResult<(StatusCode, Json<RegisterResponse>)> {
    if req.email.is_empty() || req.password.is_empty() {
        return Err(AppError::BadRequest(
            "email and password are required".into(),
        ));
    }

    let password = req.password.clone();
    let hash = tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|e| anyhow::anyhow!("join error: {}", e))?
        .map_err(|e| anyhow::anyhow!("argon2 hash error: {}", e))?;

    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (email, password_hash, is_approved)
         VALUES ($1, $2, false)
         RETURNING *",
    )
    .bind(&req.email)
    .bind(&hash)
    .fetch_one(&state.db)
    .await
    .map_err(|e| map_db_err(e, format!("email '{}' is already registered", req.email)))?;

    // Audit log the registration
    audit::log_register(&user.email, Some(&addr.ip().to_string()));

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            id: user.id,
            email: user.email,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub email: String,
    pub is_admin: bool,
    pub is_endorsed: bool,
    /// True when this account's email was backfilled by migration and the user
    /// must provide a real email address before using the service normally.
    pub require_email_update: bool,
}

pub fn is_placeholder_email(email: &str) -> bool {
    email.ends_with("@legacy.placeholder.invalid")
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginRequest>,
) -> AppResult<Json<LoginResponse>> {
    let ip_str = addr.ip().to_string();

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(&req.email)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| {
            // Audit log: user not found
            audit::log_login_failure(&req.email, Some(&ip_str), "user not found");
            AppError::Unauthorized("invalid credentials".into())
        })?;

    let hash = user.password_hash.clone();
    let password = req.password.clone();
    let valid = tokio::task::spawn_blocking(move || verify_password(&password, &hash))
        .await
        .map_err(|e| anyhow::anyhow!("join error: {}", e))?
        .map_err(|e| anyhow::anyhow!("argon2 verify error: {}", e))?;

    if !valid {
        // Audit log: invalid password
        audit::log_login_failure(&req.email, Some(&ip_str), "invalid password");
        return Err(AppError::Unauthorized("invalid credentials".into()));
    }

    let token = create_token(user.id, &user.email, &state.jwt_secret)
        .map_err(|e| anyhow::anyhow!("token error: {}", e))?;

    // Audit log: successful login
    audit::log_login_success(&user.email, Some(&ip_str));

    let require_email_update = is_placeholder_email(&user.email);

    Ok(Json(LoginResponse {
        token,
        email: user.email,
        is_admin: user.is_admin,
        is_endorsed: user.is_endorsed,
        require_email_update,
    }))
}

// ---------------------------------------------------------------------------
// User Profile
// ---------------------------------------------------------------------------

pub async fn get_user_profile(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>,
) -> AppResult<Json<UserProfile>> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("user not found".into()))?;

    Ok(Json(UserProfile {
        id: user.id,
        email: user.email,
        is_admin: user.is_admin,
        is_endorsed: user.is_endorsed,
        is_approved: user.is_approved,
        created_at: user.created_at,
    }))
}

pub async fn get_current_user(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> AppResult<Json<UserProfile>> {
    let ip_str = addr.ip().to_string();
    let (user_id, _email) = extract_user_from_headers(&headers, &state, Some(&ip_str))?;

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::Unauthorized("user not found".into()))?;

    Ok(Json(UserProfile {
        id: user.id,
        email: user.email,
        is_admin: user.is_admin,
        is_endorsed: user.is_endorsed,
        is_approved: user.is_approved,
        created_at: user.created_at,
    }))
}

// ---------------------------------------------------------------------------
// Update email (for legacy placeholder accounts)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct UpdateEmailRequest {
    pub email: String,
}

#[derive(Serialize)]
pub struct UpdateEmailResponse {
    pub email: String,
    pub token: String,
}

pub async fn update_email(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<UpdateEmailRequest>,
) -> AppResult<Json<UpdateEmailResponse>> {
    let ip_str = addr.ip().to_string();
    let (user_id, _old_email) = extract_user_from_headers(&headers, &state, Some(&ip_str))?;

    let new_email = req.email.trim().to_lowercase();
    if new_email.is_empty() || !new_email.contains('@') {
        return Err(AppError::BadRequest("a valid email address is required".into()));
    }
    if is_placeholder_email(&new_email) {
        return Err(AppError::BadRequest("cannot set a placeholder email address".into()));
    }

    // Check the new email isn't already taken by another account.
    let existing = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM users WHERE email = $1 AND id != $2",
    )
    .bind(&new_email)
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;

    if existing > 0 {
        return Err(AppError::Conflict("email already in use".into()));
    }

    sqlx::query("UPDATE users SET email = $1 WHERE id = $2")
        .bind(&new_email)
        .bind(user_id)
        .execute(&state.db)
        .await?;

    // Issue a fresh token with the updated email.
    let token = create_token(user_id, &new_email, &state.jwt_secret)
        .map_err(|e| anyhow::anyhow!("token error: {}", e))?;

    audit::log_login_success(&new_email, Some(&ip_str));

    Ok(Json(UpdateEmailResponse { email: new_email, token }))
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Extract user ID and email from Authorization header.
/// Optionally logs token rejection events for audit purposes.
fn extract_user_from_headers(
    headers: &HeaderMap,
    state: &AppState,
    client_ip: Option<&str>,
) -> AppResult<(Uuid, String)> {
    let token = bearer_token(headers).ok_or_else(|| {
        audit::log_token_rejected("missing Authorization header", client_ip);
        AppError::Unauthorized("missing Authorization header".into())
    })?;

    let claims = verify_token(token, &state.jwt_secret).map_err(|_| {
        audit::log_token_rejected("invalid or expired token", client_ip);
        AppError::Unauthorized("invalid or expired token".into())
    })?;

    let user_id: Uuid = claims.sub.parse().map_err(|_| {
        audit::log_token_rejected("malformed token subject", client_ip);
        AppError::Unauthorized("malformed token subject".into())
    })?;

    Ok((user_id, claims.email))
}

/// Extract user from Authorization header for optional auth scenarios.
/// Does NOT log token rejections since anonymous access is allowed.
fn extract_user_optional(headers: &HeaderMap, state: &AppState) -> Option<(Uuid, String)> {
    let token = bearer_token(headers)?;
    let claims = verify_token(token, &state.jwt_secret).ok()?;
    let user_id: Uuid = claims.sub.parse().ok()?;
    Some((user_id, claims.email))
}

/// Check if a user can access an artifact based on visibility.
fn can_access_artifact(artifact: &Artifact, user_id: Option<Uuid>, is_admin: bool) -> bool {
    match artifact.visibility {
        Visibility::Public => true,
        Visibility::Draft | Visibility::Private => {
            // Owner can always access
            if let Some(uid) = user_id {
                if uid == artifact.owner_id {
                    return true;
                }
            }
            // Admins can access everything
            is_admin
        }
    }
}

// ---------------------------------------------------------------------------
// Push artifact
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct PushRequest {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    /// JSON content of the policy artifact.
    pub content: String,
    /// Visibility level: "public", "private", or "draft"
    #[serde(default)]
    pub visibility: Option<String>,
}

#[derive(Serialize)]
pub struct PushResponse {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub owner: String,
    pub tags: Vec<String>,
    pub visibility: Visibility,
    pub downloads: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub async fn push_artifact(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<PushRequest>,
) -> AppResult<(StatusCode, Json<PushResponse>)> {
    let ip_str = addr.ip().to_string();
    let (owner_id, email) = extract_user_from_headers(&headers, &state, Some(&ip_str))?;

    // Check if user is approved
    let is_approved: bool = sqlx::query_scalar("SELECT is_approved FROM users WHERE id = $1")
        .bind(owner_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::Unauthorized("user not found".into()))?;

    if !is_approved {
        return Err(AppError::Forbidden(
            "your account is pending admin approval".into(),
        ));
    }

    if req.name.is_empty() || req.version.is_empty() {
        return Err(AppError::BadRequest("name and version are required".into()));
    }

    // Validate content is valid JSON.
    serde_json::from_str::<serde_json::Value>(&req.content)
        .map_err(|_| AppError::BadRequest("content must be valid JSON".into()))?;

    // Parse visibility, default to public
    let visibility = match req.visibility.as_deref() {
        Some("private") => Visibility::Private,
        Some("draft") => Visibility::Draft,
        Some("public") | None => Visibility::Public,
        Some(v) => {
            return Err(AppError::BadRequest(format!(
                "invalid visibility '{}': must be 'public', 'private', or 'draft'",
                v
            )))
        }
    };

    let artifact_id = Uuid::new_v4();
    let file_path = state
        .store
        .store(&artifact_id.to_string(), req.content.as_bytes())
        .await?;

    let tags = req.tags.unwrap_or_default();
    let visibility_str = visibility.to_string();

    let artifact_row = sqlx::query_as::<_, ArtifactRow>(
        "INSERT INTO artifacts (id, name, version, description, owner_id, file_path, tags, visibility)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING *",
    )
    .bind(artifact_id)
    .bind(&req.name)
    .bind(&req.version)
    .bind(&req.description)
    .bind(owner_id)
    .bind(&file_path)
    .bind(&tags)
    .bind(&visibility_str)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        map_db_err(
            e,
            format!("artifact '{}@{}' already exists", req.name, req.version),
        )
    })?;
    let artifact = artifact_row
        .into_artifact()
        .map_err(AppError::BadRequest)?;

    let owner: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(owner_id)
        .fetch_one(&state.db)
        .await?;

    // Audit log the artifact push
    audit::log_artifact_push(&email, &artifact.name, &artifact.version, Some(&ip_str));

    Ok((
        StatusCode::CREATED,
        Json(PushResponse {
            id: artifact.id,
            name: artifact.name,
            version: artifact.version,
            description: artifact.description,
            owner,
            tags: artifact.tags,
            visibility: artifact.visibility,
            downloads: artifact.downloads,
            created_at: artifact.created_at,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Pull artifact
// ---------------------------------------------------------------------------

pub async fn pull_artifact(
    State(state): State<Arc<AppState>>,
    Path((name, version)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    // Try to extract user from headers (optional for public artifacts)
    let (user_id, _email) = match extract_user_optional(&headers, &state) {
        Some((uid, email)) => (Some(uid), Some(email)),
        None => (None, None),
    };

    // Check if user is admin
    let is_admin = if let Some(uid) = user_id {
        sqlx::query_scalar::<_, bool>("SELECT is_admin FROM users WHERE id = $1")
            .bind(uid)
            .fetch_optional(&state.db)
            .await?
            .unwrap_or(false)
    } else {
        false
    };

    // Fetch the artifact row without incrementing downloads yet.
    let artifact_row = sqlx::query_as::<_, ArtifactRow>(
        "SELECT * FROM artifacts WHERE name = $1 AND version = $2",
    )
    .bind(&name)
    .bind(&version)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("artifact '{}@{}' not found", name, version)))?;
    let artifact = artifact_row
        .into_artifact()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("{}", e)))?;

    // Check visibility access before incrementing download count.
    if !can_access_artifact(&artifact, user_id, is_admin) {
        return Err(AppError::NotFound(format!(
            "artifact '{}@{}' not found",
            name, version
        )));
    }

    // Access granted — increment download count.
    sqlx::query("UPDATE artifacts SET downloads = downloads + 1 WHERE id = $1")
        .bind(artifact.id)
        .execute(&state.db)
        .await?;

    let raw = state.store.retrieve(&artifact.file_path).await?;
    let content: serde_json::Value = serde_json::from_slice(&raw)?;

    let owner: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(artifact.owner_id)
        .fetch_one(&state.db)
        .await?;

    let owner_is_endorsed: bool =
        sqlx::query_scalar("SELECT is_endorsed FROM users WHERE id = $1")
            .bind(artifact.owner_id)
            .fetch_one(&state.db)
            .await?;

    Ok(Json(serde_json::json!({
        "id": artifact.id,
        "name": artifact.name,
        "version": artifact.version,
        "description": artifact.description,
        "owner": owner,
        "owner_is_endorsed": owner_is_endorsed,
        "tags": artifact.tags,
        "downloads": artifact.downloads,
        "visibility": artifact.visibility,
        "created_at": artifact.created_at,
        "content": content,
    })))
}

// ---------------------------------------------------------------------------
// Search artifacts
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SearchParams {
    pub q: Option<String>,
    pub tag: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Serialize)]
pub struct SearchResponse {
    pub results: Vec<ArtifactSummary>,
    pub total: i64,
}

pub async fn search_artifacts(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SearchParams>,
    headers: HeaderMap,
) -> AppResult<Json<SearchResponse>> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let offset = params.offset.unwrap_or(0).max(0);

    // Try to extract user from headers (optional)
    let (user_id, _email) = match extract_user_optional(&headers, &state) {
        Some((uid, email)) => (Some(uid), Some(email)),
        None => (None, None),
    };

    // Check if user is admin
    let is_admin = if let Some(uid) = user_id {
        sqlx::query_scalar::<_, bool>("SELECT is_admin FROM users WHERE id = $1")
            .bind(uid)
            .fetch_optional(&state.db)
            .await?
            .unwrap_or(false)
    } else {
        false
    };

    // Build visibility filter based on user access
    let visibility_filter = if is_admin {
        // Admins can see everything
        ""
    } else if let Some(_uid) = user_id {
        // Authenticated users can see public artifacts + their own private/draft
        " AND (a.visibility = 'public' OR a.owner_id = $4)"
    } else {
        // Anonymous users can only see public artifacts
        " AND a.visibility = 'public'"
    };

    let rows: Vec<ArtifactWithOwnerRow> = if let Some(ref tag) = params.tag {
        let query = format!(
            "SELECT a.*, u.email, u.is_endorsed as owner_is_endorsed
             FROM artifacts a
             JOIN users u ON a.owner_id = u.id
             WHERE $1 = ANY(a.tags){}
             ORDER BY a.created_at DESC
             LIMIT $2 OFFSET $3",
            visibility_filter
        );
        if user_id.is_some() && !is_admin {
            sqlx::query_as(&query)
                .bind(tag)
                .bind(limit)
                .bind(offset)
                .bind(user_id)
                .fetch_all(&state.db)
                .await?
        } else {
            sqlx::query_as(&query)
                .bind(tag)
                .bind(limit)
                .bind(offset)
                .fetch_all(&state.db)
                .await?
        }
    } else if let Some(ref q) = params.q {
        let pattern = format!("%{}%", q.to_lowercase());
        let query = format!(
            "SELECT a.*, u.email, u.is_endorsed as owner_is_endorsed
             FROM artifacts a
             JOIN users u ON a.owner_id = u.id
             WHERE (LOWER(a.name) LIKE $1
                OR LOWER(COALESCE(a.description, '')) LIKE $1){}
             ORDER BY a.created_at DESC
             LIMIT $2 OFFSET $3",
            visibility_filter
        );
        if user_id.is_some() && !is_admin {
            sqlx::query_as(&query)
                .bind(&pattern)
                .bind(limit)
                .bind(offset)
                .bind(user_id)
                .fetch_all(&state.db)
                .await?
        } else {
            sqlx::query_as(&query)
                .bind(&pattern)
                .bind(limit)
                .bind(offset)
                .fetch_all(&state.db)
                .await?
        }
    } else {
        let query = format!(
            "SELECT a.*, u.email, u.is_endorsed as owner_is_endorsed
             FROM artifacts a
             JOIN users u ON a.owner_id = u.id
             WHERE 1=1{}
             ORDER BY a.created_at DESC
             LIMIT $1 OFFSET $2",
            visibility_filter
        );
        if user_id.is_some() && !is_admin {
            sqlx::query_as(&query)
                .bind(limit)
                .bind(offset)
                .bind(user_id)
                .fetch_all(&state.db)
                .await?
        } else {
            sqlx::query_as(&query)
                .bind(limit)
                .bind(offset)
                .fetch_all(&state.db)
                .await?
        }
    };

    // Convert rows to domain types
    let artifacts: Vec<ArtifactWithOwner> = rows
        .into_iter()
        .filter_map(|r| r.into_artifact_with_owner().ok())
        .collect();

    // Count total (only public for anonymous, all for admin, public+own for authenticated)
    let total: i64 = if is_admin {
        sqlx::query_scalar("SELECT COUNT(*) FROM artifacts")
            .fetch_one(&state.db)
            .await?
    } else if let Some(uid) = user_id {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts WHERE visibility = 'public' OR owner_id = $1",
        )
        .bind(uid)
        .fetch_one(&state.db)
        .await?
    } else {
        sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE visibility = 'public'")
            .fetch_one(&state.db)
            .await?
    };

    Ok(Json(SearchResponse {
        results: artifacts.into_iter().map(ArtifactSummary::from).collect(),
        total,
    }))
}

// ---------------------------------------------------------------------------
// Endorsements
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateEndorsementRequest {
    /// Endorsement level: "verified", "trusted_author", or "official"
    #[serde(default)]
    pub level: Option<String>,
}

#[derive(Serialize)]
pub struct EndorsementResponse {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub user_id: Uuid,
    pub email: String,
    pub user_is_admin: bool,
    pub user_is_endorsed: bool,
    pub level: EndorsementLevel,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub async fn create_endorsement(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(artifact_id): Path<Uuid>,
    headers: HeaderMap,
    Json(req): Json<CreateEndorsementRequest>,
) -> AppResult<(StatusCode, Json<EndorsementResponse>)> {
    let ip_str = addr.ip().to_string();
    let (user_id, email) = extract_user_from_headers(&headers, &state, Some(&ip_str))?;

    // Check if artifact exists
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM artifacts WHERE id = $1)")
            .bind(artifact_id)
            .fetch_one(&state.db)
            .await?;

    if !exists {
        return Err(AppError::NotFound("artifact not found".into()));
    }

    // Get user details for response
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;

    // Check if user is approved
    if !user.is_approved {
        return Err(AppError::Forbidden(
            "your account is pending admin approval".into(),
        ));
    }

    // Parse endorsement level
    let level = match req.level.as_deref() {
        Some("verified") | None => EndorsementLevel::Verified,
        Some("trusted_author") => EndorsementLevel::TrustedAuthor,
        Some("official") => EndorsementLevel::Official,
        Some(v) => {
            return Err(AppError::BadRequest(format!(
                "invalid endorsement level '{}': must be 'verified', 'trusted_author', or 'official'",
                v
            )))
        }
    };

    let level_str = level.to_string();

    // Create endorsement
    let endorsement_row = sqlx::query_as::<_, EndorsementRow>(
        "INSERT INTO endorsements (artifact_id, user_id, level)
         VALUES ($1, $2, $3)
         RETURNING *",
    )
    .bind(artifact_id)
    .bind(user_id)
    .bind(&level_str)
    .fetch_one(&state.db)
    .await
    .map_err(|e| map_db_err(e, "you have already endorsed this artifact"))?;
    let endorsement = endorsement_row
        .into_endorsement()
        .map_err(AppError::BadRequest)?;

    Ok((
        StatusCode::CREATED,
        Json(EndorsementResponse {
            id: endorsement.id,
            artifact_id: endorsement.artifact_id,
            user_id: endorsement.user_id,
            email,
            user_is_admin: user.is_admin,
            user_is_endorsed: user.is_endorsed,
            level: endorsement.level,
            created_at: endorsement.created_at,
        }),
    ))
}

pub async fn list_endorsements(
    State(state): State<Arc<AppState>>,
    Path(artifact_id): Path<Uuid>,
) -> AppResult<Json<Vec<EndorsementWithUser>>> {
    // Check if artifact exists
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM artifacts WHERE id = $1)")
            .bind(artifact_id)
            .fetch_one(&state.db)
            .await?;

    if !exists {
        return Err(AppError::NotFound("artifact not found".into()));
    }

    let rows = sqlx::query_as::<_, EndorsementWithUserRow>(
        "SELECT e.*, u.email, u.is_admin as user_is_admin, u.is_endorsed as user_is_endorsed
         FROM endorsements e
         JOIN users u ON e.user_id = u.id
         WHERE e.artifact_id = $1
         ORDER BY e.created_at DESC",
    )
    .bind(artifact_id)
    .fetch_all(&state.db)
    .await?;

    let endorsements: Vec<EndorsementWithUser> = rows
        .into_iter()
        .filter_map(|r| r.into_endorsement_with_user().ok())
        .collect();

    Ok(Json(endorsements))
}

pub async fn delete_endorsement(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((artifact_id, endorsement_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> AppResult<StatusCode> {
    let ip_str = addr.ip().to_string();
    let (user_id, _) = extract_user_from_headers(&headers, &state, Some(&ip_str))?;

    // Check if user is admin
    let is_admin: bool = sqlx::query_scalar("SELECT is_admin FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;

    // Get the endorsement
    let endorsement_row = sqlx::query_as::<_, EndorsementRow>(
        "SELECT * FROM endorsements WHERE id = $1 AND artifact_id = $2",
    )
    .bind(endorsement_id)
    .bind(artifact_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("endorsement not found".into()))?;
    let endorsement = endorsement_row
        .into_endorsement()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("{}", e)))?;

    // Only the endorsement creator or an admin can delete
    if endorsement.user_id != user_id && !is_admin {
        return Err(AppError::Unauthorized(
            "you can only delete your own endorsements".into(),
        ));
    }

    sqlx::query("DELETE FROM endorsements WHERE id = $1")
        .bind(endorsement_id)
        .execute(&state.db)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Admin: Approve User
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct ApproveUserResponse {
    pub id: Uuid,
    pub email: String,
    pub is_approved: bool,
}

pub async fn approve_user(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(user_id): Path<Uuid>,
    headers: HeaderMap,
) -> AppResult<Json<ApproveUserResponse>> {
    let ip_str = addr.ip().to_string();
    let (admin_id, _) = extract_user_from_headers(&headers, &state, Some(&ip_str))?;

    // Check if requester is admin
    let is_admin: bool = sqlx::query_scalar("SELECT is_admin FROM users WHERE id = $1")
        .bind(admin_id)
        .fetch_one(&state.db)
        .await?;

    if !is_admin {
        return Err(AppError::Forbidden("admin access required".into()));
    }

    // Approve the user
    let user = sqlx::query_as::<_, User>(
        "UPDATE users SET is_approved = true WHERE id = $1 RETURNING *",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("user not found".into()))?;

    // Audit log the user approval
    audit::log_user_approved(&user.email, &admin_id.to_string());

    Ok(Json(ApproveUserResponse {
        id: user.id,
        email: user.email,
        is_approved: user.is_approved,
    }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, HeaderMap};
    use crate::auth::create_token;
    use uuid::Uuid;

    // =========================================================================
    // bearer_token tests
    // =========================================================================

    #[test]
    fn test_bearer_token_valid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer my-token-123".parse().unwrap(),
        );
        let token = bearer_token(&headers);
        assert_eq!(token, Some("my-token-123"));
    }

    #[test]
    fn test_bearer_token_missing_header() {
        let headers = HeaderMap::new();
        let token = bearer_token(&headers);
        assert!(token.is_none());
    }

    #[test]
    fn test_bearer_token_wrong_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Basic my-token-123".parse().unwrap(),
        );
        let token = bearer_token(&headers);
        assert!(token.is_none());
    }

    #[test]
    fn test_bearer_token_no_space_after_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearertoken".parse().unwrap(),
        );
        let token = bearer_token(&headers);
        assert!(token.is_none());
    }

    #[test]
    fn test_bearer_token_empty_token() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer ".parse().unwrap());
        let token = bearer_token(&headers);
        assert_eq!(token, Some(""));
    }

    #[test]
    fn test_bearer_token_with_special_chars() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U".parse().unwrap(),
        );
        let token = bearer_token(&headers);
        assert!(token.is_some());
        assert!(token.unwrap().contains("eyJ"));
    }

    // =========================================================================
    // can_access_artifact tests
    // =========================================================================

    fn create_test_artifact(visibility: Visibility, owner_id: Uuid) -> Artifact {
        Artifact {
            id: Uuid::new_v4(),
            name: "test-artifact".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            owner_id,
            file_path: "/path/to/file.json".to_string(),
            tags: vec![],
            downloads: 0,
            visibility,
            created_at: chrono::Utc::now(),
            content_hash: None,
            content_schema: None,
            signature: None,
            key_fingerprint: None,
            artifact_type: crate::models::ArtifactType::Artifact,
            yanked: false,
            yanked_reason: None,
            denied_pulls: 0,
        }
    }

    #[test]
    fn test_can_access_artifact_public_anonymous() {
        let owner_id = Uuid::new_v4();
        let artifact = create_test_artifact(Visibility::Public, owner_id);

        // Anonymous user can access public artifact
        assert!(can_access_artifact(&artifact, None, false));
    }

    #[test]
    fn test_can_access_artifact_public_authenticated() {
        let owner_id = Uuid::new_v4();
        let other_user = Uuid::new_v4();
        let artifact = create_test_artifact(Visibility::Public, owner_id);

        // Any authenticated user can access public artifact
        assert!(can_access_artifact(&artifact, Some(other_user), false));
    }

    #[test]
    fn test_can_access_artifact_private_owner() {
        let owner_id = Uuid::new_v4();
        let artifact = create_test_artifact(Visibility::Private, owner_id);

        // Owner can access private artifact
        assert!(can_access_artifact(&artifact, Some(owner_id), false));
    }

    #[test]
    fn test_can_access_artifact_private_non_owner() {
        let owner_id = Uuid::new_v4();
        let other_user = Uuid::new_v4();
        let artifact = create_test_artifact(Visibility::Private, owner_id);

        // Non-owner cannot access private artifact
        assert!(!can_access_artifact(&artifact, Some(other_user), false));
    }

    #[test]
    fn test_can_access_artifact_private_admin() {
        let owner_id = Uuid::new_v4();
        let other_user = Uuid::new_v4();
        let artifact = create_test_artifact(Visibility::Private, owner_id);

        // Admin can access private artifact
        assert!(can_access_artifact(&artifact, Some(other_user), true));
    }

    #[test]
    fn test_can_access_artifact_private_anonymous() {
        let owner_id = Uuid::new_v4();
        let artifact = create_test_artifact(Visibility::Private, owner_id);

        // Anonymous cannot access private artifact
        assert!(!can_access_artifact(&artifact, None, false));
    }

    #[test]
    fn test_can_access_artifact_draft_owner() {
        let owner_id = Uuid::new_v4();
        let artifact = create_test_artifact(Visibility::Draft, owner_id);

        // Owner can access draft artifact
        assert!(can_access_artifact(&artifact, Some(owner_id), false));
    }

    #[test]
    fn test_can_access_artifact_draft_non_owner() {
        let owner_id = Uuid::new_v4();
        let other_user = Uuid::new_v4();
        let artifact = create_test_artifact(Visibility::Draft, owner_id);

        // Non-owner cannot access draft artifact
        assert!(!can_access_artifact(&artifact, Some(other_user), false));
    }

    #[test]
    fn test_can_access_artifact_draft_admin() {
        let owner_id = Uuid::new_v4();
        let other_user = Uuid::new_v4();
        let artifact = create_test_artifact(Visibility::Draft, owner_id);

        // Admin can access draft artifact
        assert!(can_access_artifact(&artifact, Some(other_user), true));
    }

    #[test]
    fn test_can_access_artifact_draft_anonymous() {
        let owner_id = Uuid::new_v4();
        let artifact = create_test_artifact(Visibility::Draft, owner_id);

        // Anonymous cannot access draft artifact
        assert!(!can_access_artifact(&artifact, None, false));
    }

    #[test]
    fn test_can_access_artifact_admin_no_user() {
        let owner_id = Uuid::new_v4();
        let artifact = create_test_artifact(Visibility::Private, owner_id);

        // Admin without user_id can still access (admin flag is true)
        // Note: This tests the admin override, though in practice admin should have a user_id
        assert!(can_access_artifact(&artifact, None, true));
    }

    // =========================================================================
    // extract_user_from_headers tests
    // =========================================================================

    fn create_test_state(jwt_secret: &str) -> AppState {
        use crate::store::Store;
        AppState {
            db: sqlx::postgres::PgPool::connect_lazy("postgres://localhost/test").unwrap(),
            store: Store::filesystem("/tmp/test"),
            jwt_secret: jwt_secret.to_string(),
        }
    }

    #[tokio::test]
    async fn test_extract_user_missing_header() {
        let headers = HeaderMap::new();
        let state = create_test_state("test-secret");

        let result = extract_user_from_headers(&headers, &state, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Unauthorized(msg) => assert!(msg.contains("missing Authorization header")),
            _ => panic!("expected Unauthorized error"),
        }
    }

    #[tokio::test]
    async fn test_extract_user_invalid_token() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer invalid-token".parse().unwrap());
        let state = create_test_state("test-secret");

        let result = extract_user_from_headers(&headers, &state, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Unauthorized(msg) => assert!(msg.contains("invalid or expired token")),
            _ => panic!("expected Unauthorized error"),
        }
    }

    #[tokio::test]
    async fn test_extract_user_valid_token() {
        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let secret = "test-secret";

        let token = create_token(user_id, email, secret).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, format!("Bearer {}", token).parse().unwrap());
        let state = create_test_state(secret);

        let result = extract_user_from_headers(&headers, &state, None);
        assert!(result.is_ok());

        let (extracted_id, extracted_email) = result.unwrap();
        assert_eq!(extracted_id, user_id);
        assert_eq!(extracted_email, email);
    }

    #[tokio::test]
    async fn test_extract_user_wrong_secret() {
        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let secret = "correct-secret";
        let wrong_secret = "wrong-secret";

        let token = create_token(user_id, email, secret).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, format!("Bearer {}", token).parse().unwrap());
        let state = create_test_state(wrong_secret);

        let result = extract_user_from_headers(&headers, &state, None);
        assert!(result.is_err());
    }

    // =========================================================================
    // extract_user_optional tests
    // =========================================================================

    #[tokio::test]
    async fn test_extract_user_optional_no_header() {
        let headers = HeaderMap::new();
        let state = create_test_state("test-secret");

        let result = extract_user_optional(&headers, &state);
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_extract_user_optional_invalid_token() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer invalid-token".parse().unwrap());
        let state = create_test_state("test-secret");

        let result = extract_user_optional(&headers, &state);
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_extract_user_optional_valid_token() {
        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let secret = "test-secret";

        let token = create_token(user_id, email, secret).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, format!("Bearer {}", token).parse().unwrap());
        let state = create_test_state(secret);

        let result = extract_user_optional(&headers, &state);
        assert!(result.is_some());

        let (extracted_id, extracted_email) = result.unwrap();
        assert_eq!(extracted_id, user_id);
        assert_eq!(extracted_email, email);
    }

    // =========================================================================
    // Request/Response type tests
    // =========================================================================

    #[test]
    fn test_register_request_deserialization() {
        let json = r#"{"email": "user@example.com", "password": "secret123"}"#;
        let req: RegisterRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.email, "user@example.com");
        assert_eq!(req.password, "secret123");
    }

    #[test]
    fn test_register_request_missing_fields() {
        let json = r#"{"email": "user@example.com"}"#;
        let result: Result<RegisterRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());

        let json = r#"{"password": "secret123"}"#;
        let result: Result<RegisterRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_register_request_empty_values() {
        let json = r#"{"email": "", "password": ""}"#;
        let req: RegisterRequest = serde_json::from_str(json).unwrap();
        assert!(req.email.is_empty());
        assert!(req.password.is_empty());
    }

    #[test]
    fn test_login_request_deserialization() {
        let json = r#"{"email": "login@test.com", "password": "mypass"}"#;
        let req: LoginRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.email, "login@test.com");
        assert_eq!(req.password, "mypass");
    }

    #[test]
    fn test_push_request_deserialization() {
        let json = r#"{
            "name": "my-artifact",
            "version": "1.0.0",
            "description": "A test artifact",
            "tags": ["tag1", "tag2"],
            "content": "{\"key\": \"value\"}",
            "visibility": "public"
        }"#;
        let req: PushRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "my-artifact");
        assert_eq!(req.version, "1.0.0");
        assert_eq!(req.description, Some("A test artifact".to_string()));
        assert_eq!(req.tags, Some(vec!["tag1".to_string(), "tag2".to_string()]));
        assert_eq!(req.visibility, Some("public".to_string()));
    }

    #[test]
    fn test_push_request_minimal() {
        let json = r#"{
            "name": "minimal",
            "version": "0.1.0",
            "content": "{}"
        }"#;
        let req: PushRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "minimal");
        assert_eq!(req.version, "0.1.0");
        assert!(req.description.is_none());
        assert!(req.tags.is_none());
        assert!(req.visibility.is_none());
    }

    #[test]
    fn test_push_request_empty_name_version() {
        let json = r#"{"name": "", "version": "", "content": "{}"}"#;
        let req: PushRequest = serde_json::from_str(json).unwrap();
        assert!(req.name.is_empty());
        assert!(req.version.is_empty());
    }

    #[test]
    fn test_search_params_deserialization() {
        let json = r#"{"q": "search term", "tag": "rust", "limit": 50, "offset": 10}"#;
        let params: SearchParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.q, Some("search term".to_string()));
        assert_eq!(params.tag, Some("rust".to_string()));
        assert_eq!(params.limit, Some(50));
        assert_eq!(params.offset, Some(10));
    }

    #[test]
    fn test_search_params_empty() {
        let json = r#"{}"#;
        let params: SearchParams = serde_json::from_str(json).unwrap();
        assert!(params.q.is_none());
        assert!(params.tag.is_none());
        assert!(params.limit.is_none());
        assert!(params.offset.is_none());
    }

    #[test]
    fn test_create_endorsement_request_default_level() {
        let json = r#"{}"#;
        let req: CreateEndorsementRequest = serde_json::from_str(json).unwrap();
        assert!(req.level.is_none());
    }

    #[test]
    fn test_create_endorsement_request_with_level() {
        let json = r#"{"level": "official"}"#;
        let req: CreateEndorsementRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.level, Some("official".to_string()));
    }

    // =========================================================================
    // Response type tests
    // =========================================================================

    #[test]
    fn test_register_response_serialization() {
        let id = Uuid::new_v4();
        let resp = RegisterResponse {
            id,
            email: "test@example.com".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(&id.to_string()));
        assert!(json.contains("test@example.com"));
    }

    #[test]
    fn test_login_response_serialization() {
        let resp = LoginResponse {
            token: "jwt-token-here".to_string(),
            email: "user@test.com".to_string(),
            is_admin: true,
            is_endorsed: false,
            require_email_update: false,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("jwt-token-here"));
        assert!(json.contains("user@test.com"));
        assert!(json.contains("\"is_admin\":true"));
        assert!(json.contains("\"is_endorsed\":false"));
    }

    #[test]
    fn test_push_response_serialization() {
        let id = Uuid::new_v4();
        let created_at = chrono::Utc::now();
        let resp = PushResponse {
            id,
            name: "artifact".to_string(),
            version: "1.0.0".to_string(),
            description: Some("desc".to_string()),
            owner: "owner@test.com".to_string(),
            tags: vec!["tag1".to_string()],
            visibility: Visibility::Public,
            downloads: 0,
            created_at,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("artifact"));
        assert!(json.contains("1.0.0"));
        assert!(json.contains("\"visibility\":\"public\""));
    }

    #[test]
    fn test_search_response_serialization() {
        let summary = ArtifactSummary {
            id: Uuid::new_v4(),
            name: "artifact".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            owner: "owner".to_string(),
            owner_is_endorsed: false,
            tags: vec![],
            downloads: 5,
            visibility: Visibility::Public,
            created_at: chrono::Utc::now(),
            yanked: false,
            artifact_type: crate::models::ArtifactType::Artifact,
        };
        let resp = SearchResponse {
            results: vec![summary],
            total: 1,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"total\":1"));
        assert!(json.contains("\"results\""));
    }

    #[test]
    fn test_endorsement_response_serialization() {
        let id = Uuid::new_v4();
        let artifact_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let created_at = chrono::Utc::now();
        let resp = EndorsementResponse {
            id,
            artifact_id,
            user_id,
            email: "endorser@test.com".to_string(),
            user_is_admin: false,
            user_is_endorsed: true,
            level: EndorsementLevel::Verified,
            created_at,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("endorser@test.com"));
        assert!(json.contains("\"level\":\"verified\""));
    }

    #[test]
    fn test_approve_user_response_serialization() {
        let id = Uuid::new_v4();
        let resp = ApproveUserResponse {
            id,
            email: "approved@test.com".to_string(),
            is_approved: true,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("approved@test.com"));
        assert!(json.contains("\"is_approved\":true"));
    }

    // =========================================================================
    // Edge case tests
    // =========================================================================

    #[test]
    fn test_bearer_token_case_sensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "bearer token123".parse().unwrap());
        let token = bearer_token(&headers);
        // "bearer" (lowercase) is not "Bearer" (capitalized)
        assert!(token.is_none());
    }

    #[test]
    fn test_bearer_token_multiple_auth_headers() {
        // HeaderMap only keeps the last value for duplicate headers
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer token1".parse().unwrap());
        headers.append(header::AUTHORIZATION, "Bearer token2".parse().unwrap());
        let token = bearer_token(&headers);
        // Should get the first value
        assert!(token.is_some());
    }

    #[test]
    fn test_can_access_artifact_admin_override_private() {
        let owner_id = Uuid::new_v4();
        let artifact = create_test_artifact(Visibility::Private, owner_id);

        // Admin with no user_id should still access (edge case)
        assert!(can_access_artifact(&artifact, None, true));
    }

    #[test]
    fn test_can_access_artifact_admin_override_draft() {
        let owner_id = Uuid::new_v4();
        let artifact = create_test_artifact(Visibility::Draft, owner_id);

        // Admin should access draft
        assert!(can_access_artifact(&artifact, None, true));
    }

    #[test]
    fn test_search_params_limit_clamping() {
        // Test that limit would be clamped to 1-100 range
        // This tests the logic in search_artifacts, we verify the values
        let params: SearchParams = serde_json::from_str(r#"{"limit": 150}"#).unwrap();
        assert_eq!(params.limit, Some(150)); // Value is as parsed, clamping happens in handler

        let params: SearchParams = serde_json::from_str(r#"{"limit": 0}"#).unwrap();
        assert_eq!(params.limit, Some(0));

        let params: SearchParams = serde_json::from_str(r#"{"limit": -5}"#).unwrap();
        assert_eq!(params.limit, Some(-5));
    }
}
