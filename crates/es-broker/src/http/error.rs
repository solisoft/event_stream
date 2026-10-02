use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use es_protocol::ApiError;

use crate::dataplane::DataError;
use crate::groups::GroupError;
use crate::producers::AdmitError;

#[derive(Debug)]
pub struct AppError {
    pub status: StatusCode,
    pub message: String,
    /// Seconds a rate-limited client should wait (sent as `Retry-After`).
    pub retry_after: Option<f64>,
}

impl AppError {
    fn new(status: StatusCode, msg: impl Into<String>) -> Self {
        Self {
            status,
            message: msg.into(),
            retry_after: None,
        }
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, msg)
    }
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg)
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, msg)
    }
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, msg)
    }
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, msg)
    }
    pub fn too_many_requests(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, msg)
    }

    /// A server-side failure. The detail (file paths, io errors, anyhow
    /// chains) goes to the log; the client gets a generic message and an id
    /// to quote. Sending the chain back told any caller where the data
    /// directory lives and what the filesystem was doing.
    pub fn internal(detail: impl std::fmt::Display) -> Self {
        let id = rand::random::<u32>();
        tracing::error!(error_id = format!("{id:08x}"), error = %detail, "request failed");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("internal error (id {id:08x})"),
        )
    }
}

impl From<DataError> for AppError {
    fn from(e: DataError) -> Self {
        match e {
            DataError::Forbidden(m) => Self::forbidden(m),
            DataError::NotFound(m) => Self::not_found(m),
            DataError::BadRequest(m) => Self::bad_request(m),
            DataError::RateLimited(s) => Self {
                retry_after: Some(s),
                ..Self::too_many_requests(format!("rate limit exceeded; retry in {:.1}s", s))
            },
            DataError::Internal(e) => Self::from(e),
        }
    }
}

impl From<GroupError> for AppError {
    fn from(e: GroupError) -> Self {
        match e {
            GroupError::Forbidden(m) => Self::forbidden(m),
            GroupError::Invalid(m) | GroupError::Limit(m) => Self::bad_request(m),
        }
    }
}

/// Messages that describe a problem with the request rather than with the
/// server. Validation errors are plain `anyhow` messages throughout the
/// broker; these phrases are how they read.
const CLIENT_ERROR_PHRASES: &[&str] = &[
    "out of range",
    "must ",
    "may only",
    "length must",
    "must have",
    "is reserved",
    "limit reached",
    "not valid",
    "unknown cleanup_policy",
    "incompatible",
    "at most",
    "already owns",
    "not leader",
];

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        if let Some(g) = e.downcast_ref::<GroupError>() {
            return match g {
                GroupError::Forbidden(m) => Self::forbidden(m.clone()),
                GroupError::Invalid(m) | GroupError::Limit(m) => Self::bad_request(m.clone()),
            };
        }
        if let Some(a) = e.downcast_ref::<AdmitError>() {
            return match a {
                AdmitError::Forbidden(m) => Self::forbidden(m.clone()),
                AdmitError::Invalid(m) | AdmitError::Limit(m) => Self::bad_request(m.clone()),
            };
        }
        // Only the outermost message is shown to the client; the context
        // chain below it is where paths and io detail live.
        let top = e.to_string();
        if top.contains("already exists") {
            Self::conflict(top)
        } else if top.contains("not found") {
            Self::not_found(top)
        } else if CLIENT_ERROR_PHRASES.iter().any(|p| top.contains(p)) {
            Self::bad_request(top)
        } else {
            Self::internal(format!("{:#}", e))
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        Self::internal(format!("io: {}", e))
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let retry = self.retry_after;
        let body = Json(ApiError {
            error: self.message,
        });
        let mut resp = (self.status, body).into_response();
        if let Some(s) = retry {
            if let Ok(v) = axum::http::HeaderValue::from_str(&(s.ceil() as u64).max(1).to_string())
            {
                resp.headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, v);
            }
        }
        resp
    }
}

pub type AppResult<T> = Result<T, AppError>;
