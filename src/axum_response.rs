//! axum 适配（feature `axum`）：把 `AuthError` 变成统一响应，并提供"授权或返回响应"的助手。
//!
//! 中间件本身留在各服务里 —— 它需要服务自己的 `State`（peer 地址、policy）。

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use http::HeaderMap;

use crate::error::AuthError;
use crate::policy::{AuthPolicy, Scope};

/// 授权；失败时直接给出可返回的 `Response`（401/403/429，均 `no-store`）。
pub fn authorize_or_response(
    policy: &AuthPolicy,
    required: Scope,
    headers: &HeaderMap,
    client_key: &str,
) -> Result<Scope, Response> {
    policy
        .authorize(headers, client_key, required)
        .map_err(error_response)
}

/// `AuthError` → HTTP 响应。
pub fn error_response(err: AuthError) -> Response {
    let status =
        StatusCode::from_u16(err.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = (
        status,
        Json(serde_json::json!({
            "error": { "code": err.code(), "message": err.message() }
        })),
    )
        .into_response();

    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    if let Some(secs) = err.retry_after_secs() {
        response.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from_str(&secs.to_string()).unwrap_or(HeaderValue::from_static("60")),
        );
    }

    response
}
