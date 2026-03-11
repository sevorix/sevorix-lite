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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -------------------------------------------------------------------------
    // validate_name
    // -------------------------------------------------------------------------

    #[test]
    fn name_empty_is_err() {
        assert!(validate_name("").is_err());
    }

    #[test]
    fn name_one_char_is_ok() {
        assert!(validate_name("a").is_ok());
    }

    #[test]
    fn name_128_chars_is_ok() {
        // "a" + 127 "b"s = 128 chars total
        let s = "a".to_string() + &"b".repeat(127);
        assert_eq!(s.len(), 128);
        assert!(validate_name(&s).is_ok());
    }

    #[test]
    fn name_129_chars_is_err() {
        // "a" + 128 "b"s = 129 chars total
        let s = "a".to_string() + &"b".repeat(128);
        assert_eq!(s.len(), 129);
        assert!(validate_name(&s).is_err());
    }

    #[test]
    fn name_with_slash_is_err() {
        assert!(validate_name("abc/def").is_err());
    }

    #[test]
    fn name_with_space_is_err() {
        assert!(validate_name("abc def").is_err());
    }

    #[test]
    fn name_with_hyphen_underscore_dot_digits_is_ok() {
        assert!(validate_name("abc-def_1.2").is_ok());
    }

    // -------------------------------------------------------------------------
    // validate_version
    // -------------------------------------------------------------------------

    #[test]
    fn version_empty_is_err() {
        assert!(validate_version("").is_err());
    }

    #[test]
    fn version_single_digit_is_ok() {
        assert!(validate_version("1").is_ok());
    }

    #[test]
    fn version_semver_is_ok() {
        assert!(validate_version("1.0.0").is_ok());
    }

    #[test]
    fn version_semver_with_prerelease_and_build_is_ok() {
        assert!(validate_version("1.0.0-alpha+build").is_ok());
    }

    #[test]
    fn version_64_chars_is_ok() {
        // First char alnum, then 63 more alnum chars = 64 total
        let s = "a".to_string() + &"b".repeat(63);
        assert_eq!(s.len(), 64);
        assert!(validate_version(&s).is_ok());
    }

    #[test]
    fn version_65_chars_is_err() {
        // First char alnum, then 64 more alnum chars = 65 total
        let s = "a".to_string() + &"b".repeat(64);
        assert_eq!(s.len(), 65);
        assert!(validate_version(&s).is_err());
    }

    #[test]
    fn version_with_space_is_err() {
        assert!(validate_version("1 0").is_err());
    }

    // -------------------------------------------------------------------------
    // validate_tags
    // -------------------------------------------------------------------------

    #[test]
    fn tags_empty_vec_is_ok() {
        assert!(validate_tags(&[]).is_ok());
    }

    #[test]
    fn tags_20_tags_is_ok() {
        let tags: Vec<String> = (0..20).map(|i| format!("tag{}", i)).collect();
        assert!(validate_tags(&tags).is_ok());
    }

    #[test]
    fn tags_21_tags_is_err() {
        let tags: Vec<String> = (0..21).map(|i| format!("tag{}", i)).collect();
        assert!(validate_tags(&tags).is_err());
    }

    #[test]
    fn tags_tag_of_64_chars_is_ok() {
        let tags = vec!["a".repeat(64)];
        assert!(validate_tags(&tags).is_ok());
    }

    #[test]
    fn tags_tag_of_65_chars_is_err() {
        let tags = vec!["a".repeat(65)];
        assert!(validate_tags(&tags).is_err());
    }

    // -------------------------------------------------------------------------
    // validate_description
    // -------------------------------------------------------------------------

    #[test]
    fn description_none_is_ok() {
        assert!(validate_description(&None).is_ok());
    }

    #[test]
    fn description_some_empty_is_ok() {
        assert!(validate_description(&Some(String::new())).is_ok());
    }

    #[test]
    fn description_1000_chars_is_ok() {
        let s = "a".repeat(1000);
        assert!(validate_description(&Some(s)).is_ok());
    }

    #[test]
    fn description_1001_chars_is_err() {
        let s = "a".repeat(1001);
        assert!(validate_description(&Some(s)).is_err());
    }

    // -------------------------------------------------------------------------
    // validate_content_size
    // -------------------------------------------------------------------------

    #[test]
    fn content_size_exactly_max_is_ok() {
        let content = "a".repeat(10);
        assert!(validate_content_size(&content, 10).is_ok());
    }

    #[test]
    fn content_size_max_plus_one_is_err() {
        let content = "a".repeat(11);
        assert!(validate_content_size(&content, 10).is_err());
    }

    #[test]
    fn content_size_empty_max_zero_is_ok() {
        assert!(validate_content_size("", 0).is_ok());
    }

    #[test]
    fn content_size_empty_max_one_is_ok() {
        assert!(validate_content_size("", 1).is_ok());
    }

    // -------------------------------------------------------------------------
    // validate_json_schema
    // -------------------------------------------------------------------------

    #[test]
    fn json_schema_valid_schema_conforming_content_is_ok() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" }
            },
            "required": ["name"]
        });
        let content = json!({ "name": "hello" });
        assert!(validate_json_schema(&schema, &content).is_ok());
    }

    #[test]
    fn json_schema_valid_schema_non_conforming_content_is_err() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" }
            },
            "required": ["name"]
        });
        // Missing required "name" field
        let content = json!({ "age": 42 });
        assert!(validate_json_schema(&schema, &content).is_err());
    }

    #[test]
    fn json_schema_invalid_schema_is_err() {
        // A schema with an unknown $schema URI or invalid keyword that causes compile failure.
        // Using an invalid type value forces a compile error.
        let schema = json!({ "type": 12345 });
        assert!(validate_json_schema(&schema, &json!({})).is_err());
    }
}
