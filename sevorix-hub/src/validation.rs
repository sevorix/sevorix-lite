use crate::error::{AppError, AppResult};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;

static NAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9\-_.]{0,127}$").unwrap());

static VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9\-_.+]{0,63}$").unwrap());

/// Validate an artifact name.
/// Rules: starts with alphanumeric, followed by alphanumeric/-/_/. only, 1–128 chars total.
pub fn validate_name(s: &str) -> AppResult<()> {
    if NAME_RE.is_match(s) {
        Ok(())
    } else {
        Err(AppError::BadRequest(format!(
            "invalid artifact name {:?}: must start with alphanumeric and contain only [a-zA-Z0-9\\-_.], 1–128 chars",
            s
        )))
    }
}

/// Validate an artifact version string.
/// Rules: starts with alphanumeric, followed by alphanumeric/-/_/./+ only, 1–64 chars total.
pub fn validate_version(s: &str) -> AppResult<()> {
    if VERSION_RE.is_match(s) {
        Ok(())
    } else {
        Err(AppError::BadRequest(format!(
            "invalid artifact version {:?}: must start with alphanumeric and contain only [a-zA-Z0-9\\-_.+], 1–64 chars",
            s
        )))
    }
}

/// Validate artifact tags.
/// Rules: at most 20 tags; each tag at most 64 chars.
pub fn validate_tags(tags: &[String]) -> AppResult<()> {
    if tags.len() > 20 {
        return Err(AppError::BadRequest(format!(
            "too many tags: {} (max 20)",
            tags.len()
        )));
    }
    for tag in tags {
        if tag.len() > 64 {
            return Err(AppError::BadRequest(format!(
                "tag {:?} is too long: {} chars (max 64)",
                tag,
                tag.len()
            )));
        }
    }
    Ok(())
}

/// Validate an artifact description.
/// Rules: at most 1000 chars.
pub fn validate_description(description: &Option<String>) -> AppResult<()> {
    if let Some(d) = description {
        if d.len() > 1000 {
            return Err(AppError::BadRequest(format!(
                "description too long: {} chars (max 1000)",
                d.len()
            )));
        }
    }
    Ok(())
}

/// Validate that artifact content does not exceed `max_bytes`.
pub fn validate_content_size(content: &str, max_bytes: usize) -> AppResult<()> {
    let size = content.len();
    if size > max_bytes {
        return Err(AppError::BadRequest(format!(
            "artifact content too large: {} bytes (max {})",
            size, max_bytes
        )));
    }
    Ok(())
}

/// Validate that `content` conforms to the provided JSON Schema.
/// Returns Ok(()) if valid, BadRequest with a message if not.
pub fn validate_json_schema(schema: &Value, content: &Value) -> AppResult<()> {
    let compiled = jsonschema::JSONSchema::compile(schema)
        .map_err(|e| AppError::BadRequest(format!("invalid JSON Schema: {e}")))?;
    let result = compiled.validate(content);
    if let Err(errors) = result {
        let messages: Vec<String> = errors.map(|e| e.to_string()).collect();
        return Err(AppError::BadRequest(format!(
            "content does not conform to schema: {}",
            messages.join("; ")
        )));
    }
    Ok(())
}
