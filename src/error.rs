use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use serde::Serialize;
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Authorization error: {0}")]
    Forbidden(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Internal server error: {0}")]
    InternalServerError(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Environment error: {0}")]
    EnvError(#[from] std::env::VarError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),

    #[error("Argon2 error: {0}")]
    Argon2Error(String),

    #[error("Signal Protocol error: {0}")]
    SignalProtocolError(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),
}

#[derive(Serialize)]
struct ErrorResponse {
    status: String,
    message: String,
}

impl ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Error::Auth(_) => StatusCode::UNAUTHORIZED,
            Error::Forbidden(_) => StatusCode::FORBIDDEN,
            Error::NotFound(_) => StatusCode::NOT_FOUND,
            Error::BadRequest(_) => StatusCode::BAD_REQUEST,
            Error::RateLimitExceeded(_) => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        // Don't expose internal error details in production
        let message = match self {
            Error::Auth(_) | Error::Forbidden(_) | Error::NotFound(_) | Error::BadRequest(_) | Error::RateLimitExceeded(_) => {
                self.to_string()
            }
            _ => {
                // Log the actual error for debugging
                log::error!("Internal error: {:?}", self);
                "An internal server error occurred".to_string()
            }
        };

        let status = match self.status_code() {
            StatusCode::UNAUTHORIZED => "unauthorized",
            StatusCode::FORBIDDEN => "forbidden",
            StatusCode::NOT_FOUND => "not_found",
            StatusCode::BAD_REQUEST => "bad_request",
            StatusCode::TOO_MANY_REQUESTS => "rate_limited",
            _ => "error",
        };

        HttpResponse::build(self.status_code()).json(json!({
            "status": status,
            "message": message
        }))
    }
}