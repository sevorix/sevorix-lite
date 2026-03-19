//! Audit logging for security-sensitive events.
//!
//! This module provides structured audit logging for security-relevant actions
//! such as authentication events, artifact operations, and administrative actions.
//! All events are logged in JSON format for easy parsing and analysis.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Types of audit events that can be logged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// Successful user login.
    LoginSuccess,
    /// Failed login attempt.
    LoginFailure,
    /// New user registration.
    Register,
    /// User approved by admin.
    UserApproved,
    /// Artifact pushed to registry.
    ArtifactPush,
    /// JWT token rejected (invalid/expired).
    TokenRejected,
}

/// An audit log entry representing a security-relevant event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// ISO 8601 timestamp of the event.
    pub timestamp: DateTime<Utc>,
    /// Type of the event.
    pub event: AuditEventType,
    /// Username involved in the event (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// IP address of the client (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Additional context or reason for the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AuditEvent {
    /// Create a new audit event with the current timestamp.
    pub fn new(event: AuditEventType) -> Self {
        Self {
            timestamp: Utc::now(),
            event,
            username: None,
            ip: None,
            reason: None,
        }
    }

    /// Add username to the event.
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Add IP address to the event.
    pub fn ip(mut self, ip: impl Into<String>) -> Self {
        self.ip = Some(ip.into());
        self
    }

    /// Add IP address from an IpAddr.
    pub fn ip_addr(mut self, ip: IpAddr) -> Self {
        self.ip = Some(ip.to_string());
        self
    }

    /// Add reason/context to the event.
    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Log the event as JSON to the tracing system.
    pub fn log(&self) {
        let json = serde_json::to_string(self).unwrap_or_else(|e| {
            tracing::error!("failed to serialize audit event: {}", e);
            format!("{{\"error\": \"serialization failed\"}}")
        });
        tracing::info!(target: "audit", "{}", json);
    }
}

// ---------------------------------------------------------------------------
// Convenience functions for common events
// ---------------------------------------------------------------------------

/// Log a successful login event.
pub fn log_login_success(username: &str, ip: Option<&str>) {
    let mut event = AuditEvent::new(AuditEventType::LoginSuccess).username(username);
    if let Some(ip) = ip {
        event = event.ip(ip);
    }
    event.log();
}

/// Log a failed login attempt.
pub fn log_login_failure(username: &str, ip: Option<&str>, reason: &str) {
    let mut event = AuditEvent::new(AuditEventType::LoginFailure)
        .username(username)
        .reason(reason);
    if let Some(ip) = ip {
        event = event.ip(ip);
    }
    event.log();
}

/// Log a user registration event.
pub fn log_register(username: &str, ip: Option<&str>) {
    let mut event = AuditEvent::new(AuditEventType::Register).username(username);
    if let Some(ip) = ip {
        event = event.ip(ip);
    }
    event.log();
}

/// Log a user approval event (admin action).
pub fn log_user_approved(username: &str, approved_by: &str) {
    AuditEvent::new(AuditEventType::UserApproved)
        .username(username)
        .reason(format!("approved by {}", approved_by))
        .log();
}

/// Log an artifact push event.
pub fn log_artifact_push(username: &str, artifact_name: &str, version: &str, ip: Option<&str>) {
    let mut event = AuditEvent::new(AuditEventType::ArtifactPush)
        .username(username)
        .reason(format!("{}@{}", artifact_name, version));
    if let Some(ip) = ip {
        event = event.ip(ip);
    }
    event.log();
}

/// Log a token rejection event.
pub fn log_token_rejected(reason: &str, ip: Option<&str>) {
    let mut event = AuditEvent::new(AuditEventType::TokenRejected).reason(reason);
    if let Some(ip) = ip {
        event = event.ip(ip);
    }
    event.log();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent::new(AuditEventType::LoginSuccess)
            .username("testuser")
            .ip("192.168.1.1")
            .reason("password verified");

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event\":\"login_success\""));
        assert!(json.contains("\"username\":\"testuser\""));
        assert!(json.contains("\"ip\":\"192.168.1.1\""));
        assert!(json.contains("\"reason\":\"password verified\""));
        assert!(json.contains("\"timestamp\""));
    }

    #[test]
    fn test_audit_event_skip_none_fields() {
        let event = AuditEvent::new(AuditEventType::Register);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event\":\"register\""));
        assert!(!json.contains("\"username\""));
        assert!(!json.contains("\"ip\""));
        assert!(!json.contains("\"reason\""));
    }

    #[test]
    fn test_event_type_serialization() {
        assert_eq!(
            serde_json::to_string(&AuditEventType::LoginSuccess).unwrap(),
            "\"login_success\""
        );
        assert_eq!(
            serde_json::to_string(&AuditEventType::TokenRejected).unwrap(),
            "\"token_rejected\""
        );
    }

    #[test]
    fn test_all_event_types_serialize_correctly() {
        // Test all event types for completeness
        assert_eq!(
            serde_json::to_string(&AuditEventType::LoginSuccess).unwrap(),
            "\"login_success\""
        );
        assert_eq!(
            serde_json::to_string(&AuditEventType::LoginFailure).unwrap(),
            "\"login_failure\""
        );
        assert_eq!(
            serde_json::to_string(&AuditEventType::Register).unwrap(),
            "\"register\""
        );
        assert_eq!(
            serde_json::to_string(&AuditEventType::UserApproved).unwrap(),
            "\"user_approved\""
        );
        assert_eq!(
            serde_json::to_string(&AuditEventType::ArtifactPush).unwrap(),
            "\"artifact_push\""
        );
        assert_eq!(
            serde_json::to_string(&AuditEventType::TokenRejected).unwrap(),
            "\"token_rejected\""
        );
    }

    #[test]
    fn test_event_type_deserialization() {
        let event_type: AuditEventType = serde_json::from_str("\"login_success\"").unwrap();
        assert_eq!(event_type, AuditEventType::LoginSuccess);

        let event_type: AuditEventType = serde_json::from_str("\"artifact_push\"").unwrap();
        assert_eq!(event_type, AuditEventType::ArtifactPush);
    }

    #[test]
    fn test_event_type_equality() {
        assert_eq!(AuditEventType::LoginSuccess, AuditEventType::LoginSuccess);
        assert_ne!(AuditEventType::LoginSuccess, AuditEventType::LoginFailure);
    }

    #[test]
    fn test_audit_event_builder_pattern() {
        let event = AuditEvent::new(AuditEventType::LoginSuccess)
            .username("builder_user")
            .ip("10.0.0.1")
            .reason("test reason");

        assert_eq!(event.username, Some("builder_user".to_string()));
        assert_eq!(event.ip, Some("10.0.0.1".to_string()));
        assert_eq!(event.reason, Some("test reason".to_string()));
    }

    #[test]
    fn test_audit_event_ip_addr_ipv4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let event = AuditEvent::new(AuditEventType::LoginSuccess).ip_addr(ip);

        assert_eq!(event.ip, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_audit_event_ip_addr_ipv6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let event = AuditEvent::new(AuditEventType::LoginSuccess).ip_addr(ip);

        assert_eq!(event.ip, Some("2001:db8::1".to_string()));
    }

    #[test]
    fn test_audit_event_has_timestamp() {
        let before = Utc::now();
        let event = AuditEvent::new(AuditEventType::Register);
        let after = Utc::now();

        assert!(event.timestamp >= before);
        assert!(event.timestamp <= after);
    }

    #[test]
    fn test_audit_event_partial_fields() {
        // Only username
        let event = AuditEvent::new(AuditEventType::LoginFailure).username("partial_user");
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"username\":\"partial_user\""));
        assert!(!json.contains("\"ip\""));
        assert!(!json.contains("\"reason\""));

        // Only IP
        let event = AuditEvent::new(AuditEventType::TokenRejected).ip("1.2.3.4");
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("\"username\""));
        assert!(json.contains("\"ip\":\"1.2.3.4\""));

        // Only reason
        let event = AuditEvent::new(AuditEventType::TokenRejected).reason("expired");
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("\"username\""));
        assert!(json.contains("\"reason\":\"expired\""));
    }

    #[test]
    fn test_audit_event_debug_impl() {
        let event = AuditEvent::new(AuditEventType::LoginSuccess).username("debug_user");
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("LoginSuccess"));
        assert!(debug_str.contains("debug_user"));
    }

    #[test]
    fn test_audit_event_clone() {
        let event = AuditEvent::new(AuditEventType::ArtifactPush)
            .username("clone_user")
            .reason("artifact@1.0.0");
        let cloned = event.clone();

        assert_eq!(event.event, cloned.event);
        assert_eq!(event.username, cloned.username);
        assert_eq!(event.reason, cloned.reason);
    }

    #[test]
    fn test_audit_event_deserialization_full() {
        let json = r#"{
            "timestamp": "2024-01-15T10:30:00Z",
            "event": "login_success",
            "username": "deser_user",
            "ip": "203.0.113.50",
            "reason": "password ok"
        }"#;

        let event: AuditEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event, AuditEventType::LoginSuccess);
        assert_eq!(event.username, Some("deser_user".to_string()));
        assert_eq!(event.ip, Some("203.0.113.50".to_string()));
        assert_eq!(event.reason, Some("password ok".to_string()));
    }

    #[test]
    fn test_convenience_log_login_success() {
        // These functions call log() internally, which uses tracing.
        // We can't easily verify the log output, but we can verify they don't panic.
        log_login_success("testuser", Some("192.168.1.1"));
        log_login_success("testuser2", None);
    }

    #[test]
    fn test_convenience_log_login_failure() {
        log_login_failure("baduser", Some("10.0.0.1"), "wrong password");
        log_login_failure("baduser2", None, "user not found");
    }

    #[test]
    fn test_convenience_log_register() {
        log_register("newuser", Some("172.16.0.1"));
        log_register("newuser2", None);
    }

    #[test]
    fn test_convenience_log_user_approved() {
        log_user_approved("approved_user", "admin@example.com");
    }

    #[test]
    fn test_convenience_log_artifact_push() {
        log_artifact_push("publisher", "my-artifact", "1.0.0", Some("192.168.1.50"));
        log_artifact_push("publisher2", "another-artifact", "2.0.0", None);
    }

    #[test]
    fn test_convenience_log_token_rejected() {
        log_token_rejected("invalid signature", Some("203.0.113.100"));
        log_token_rejected("expired token", None);
    }
}
