//! API error envelope mirroring paykit-server's `http/error.rs` shape
//! (`{"error":{"code","message"}}`) so the gateway is wire-indistinguishable
//! from the service it impersonates.

use axum::{
    http::{header::RETRY_AFTER, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiError {
    InvalidRequest,
    InvalidSignature,
    RateLimited,
    NotFound,
    LockNotFound,
    InvoiceConflict,
    /// `return_origin` is not an exact `https://` origin on the deployment's
    /// `BUYER_RETURN_ORIGINS` allowlist.
    InvalidReturnOrigin,
    /// Fiat processing unavailable (no processor configured, processor down,
    /// or persistence failure). Non-409 invoice failures fail the proof-bundle
    /// submission upstream, which is the designed fail-closed behavior.
    Unavailable,
    /// A checkout database call got no slot, or no checkout pool connection
    /// (free or newly opened), within the admission wait; or a second
    /// expired processor replay arrived in one request. Answered with
    /// `Retry-After: 1`.
    Busy,
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    const fn details(self) -> (StatusCode, &'static str, &'static str) {
        match self {
            Self::InvalidRequest => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request is invalid",
            ),
            Self::InvalidSignature => (
                StatusCode::UNAUTHORIZED,
                "invalid_signature",
                "request authentication failed",
            ),
            Self::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "request rate limit exceeded",
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "requested resource was not found",
            ),
            Self::LockNotFound => (
                StatusCode::NOT_FOUND,
                "lock_not_found",
                "lock resource was not found",
            ),
            Self::InvoiceConflict => (
                StatusCode::CONFLICT,
                "invoice_conflict",
                "invoice binding conflicts with an existing invoice",
            ),
            Self::InvalidReturnOrigin => (
                StatusCode::BAD_REQUEST,
                "invalid_return_origin",
                "return_origin is not an allowlisted buyer return origin",
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "fiat_unavailable",
                "fiat payment processing is unavailable",
            ),
            Self::Busy => (
                StatusCode::SERVICE_UNAVAILABLE,
                "busy",
                "checkout is busy; retry shortly",
            ),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = self.details();
        let mut response = (
            status,
            Json(ErrorEnvelope {
                error: ErrorBody { code, message },
            }),
        )
            .into_response();
        if self == Self::Busy {
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from_static("1"));
        }
        response
    }
}
