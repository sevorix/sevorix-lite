use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug)]
pub enum AppError {
    Internal(anyhow::Error),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    Conflict(String),
    BadRequest(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AppError::Internal(e) => {
                tracing::error!("internal error: {:#}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            }
            AppError::Unauthorized(s) => (StatusCode::UNAUTHORIZED, s),
            AppError::Forbidden(s) => (StatusCode::FORBIDDEN, s),
            AppError::NotFound(s) => (StatusCode::NOT_FOUND, s),
            AppError::Conflict(s) => (StatusCode::CONFLICT, s),
            AppError::BadRequest(s) => (StatusCode::BAD_REQUEST, s),
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self {
        AppError::Internal(e.into())
    }
}

/// Map a sqlx unique-violation error to Conflict, others to Internal.
pub fn map_db_err(e: sqlx::Error, conflict_msg: impl Into<String>) -> AppError {
    if let sqlx::Error::Database(ref db_err) = e {
        if db_err.code().as_deref() == Some("23505") {
            return AppError::Conflict(conflict_msg.into());
        }
    }
    AppError::Internal(e.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn test_app_error_unauthorized_response() {
        let error = AppError::Unauthorized("not logged in".to_string());
        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_app_error_forbidden_response() {
        let error = AppError::Forbidden("admin access required".to_string());
        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_app_error_not_found_response() {
        let error = AppError::NotFound("user not found".to_string());
        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_app_error_conflict_response() {
        let error = AppError::Conflict("email already registered".to_string());
        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn test_app_error_bad_request_response() {
        let error = AppError::BadRequest("invalid input".to_string());
        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_app_error_internal_response() {
        let error = AppError::Internal(anyhow::anyhow!("database connection failed"));
        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_app_error_from_anyhow() {
        let err: AppError = anyhow::anyhow!("something went wrong").into();
        match err {
            AppError::Internal(e) => {
                assert!(e.to_string().contains("something went wrong"));
            }
            _ => panic!("expected Internal error"),
        }
    }

    #[test]
    fn test_app_result_ok() {
        let result: AppResult<String> = Ok("success".to_string());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
    }

    #[test]
    fn test_app_result_err() {
        let result: AppResult<String> = Err(AppError::NotFound("not here".to_string()));
        assert!(result.is_err());
    }

    // =========================================================================
    // map_db_err tests
    // =========================================================================

    #[test]
    fn test_map_db_err_non_database_error() {
        // Test that non-database errors are wrapped as Internal
        let err = sqlx::Error::PoolTimedOut;
        let result = map_db_err(err, "conflict message");
        match result {
            AppError::Internal(_) => (),
            _ => panic!("expected Internal error for non-database error"),
        }
    }

    #[test]
    fn test_map_db_err_connection_error() {
        // Connection errors should map to Internal
        let err = sqlx::Error::Io(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused"));
        let result = map_db_err(err, "conflict message");
        match result {
            AppError::Internal(_) => (),
            _ => panic!("expected Internal error for connection error"),
        }
    }

    #[test]
    fn test_map_db_err_row_not_found() {
        // RowNotFound should map to Internal
        let err = sqlx::Error::RowNotFound;
        let result = map_db_err(err, "conflict message");
        match result {
            AppError::Internal(_) => (),
            _ => panic!("expected Internal error for RowNotFound"),
        }
    }

    // Note: Testing the unique violation (23505) path requires constructing a
    // sqlx::Error::Database with the correct code, which is complex without
    // a real database. This path is tested via integration tests.
}
