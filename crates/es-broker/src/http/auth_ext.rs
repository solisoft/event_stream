use std::sync::Arc;

use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::auth::{ApiKey, AuthMode, ANONYMOUS_ADMIN};
use crate::broker::Broker;

use super::error::AppError;

/// The authenticated principal for the current request. Always present in
/// handlers: when auth is disabled, the shared anonymous admin key is used so
/// the rest of the code can call `.can()` uniformly.
pub struct AuthedKey(pub Arc<ApiKey>);

#[async_trait]
impl FromRequestParts<Arc<Broker>> for AuthedKey {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, broker: &Arc<Broker>) -> Result<Self, AppError> {
        match broker.config.auth_mode {
            AuthMode::Disabled => Ok(AuthedKey(ANONYMOUS_ADMIN.clone())),
            AuthMode::Required => {
                let token = extract_bearer(parts)?;
                let key = broker
                    .keys
                    .authenticate(&token)
                    .ok_or_else(|| AppError::unauthorized("invalid or unknown api key"))?;
                Ok(AuthedKey(key))
            }
        }
    }
}

fn extract_bearer(parts: &Parts) -> Result<String, AppError> {
    if let Some(v) = parts.headers.get("authorization") {
        let s = v
            .to_str()
            .map_err(|_| AppError::unauthorized("invalid Authorization header encoding"))?;
        if let Some(rest) = s.strip_prefix("Bearer ") {
            return Ok(rest.to_string());
        }
        return Err(AppError::unauthorized(
            "Authorization header must use Bearer scheme",
        ));
    }
    if let Some(v) = parts.headers.get("x-es-key") {
        return Ok(v
            .to_str()
            .map_err(|_| AppError::unauthorized("invalid X-Es-Key header encoding"))?
            .to_string());
    }
    Err(AppError::unauthorized(
        "missing Authorization or X-Es-Key header",
    ))
}
