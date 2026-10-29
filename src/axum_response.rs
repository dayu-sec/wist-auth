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
///
/// axum `Response` 作为 Err 载荷是刻意设计：调用方直接 `if let Err(response) = ... { return response; }`。
#[allow(clippy::result_large_err)]
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
    let status = StatusCode::from_u16(err.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::TokenConfig;
    use http::HeaderValue;

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    fn policy() -> AuthPolicy {
        AuthPolicy::new(
            TokenConfig::from_plain("admin-secret"),
            TokenConfig::from_plain("viewer-secret"),
            false,
        )
        .expect("policy")
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("header"),
        );
        headers
    }

    #[tokio::test]
    async fn missing_token_maps_to_401_no_store() {
        let response = error_response(AuthError::MissingToken);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert!(response.headers().get(header::RETRY_AFTER).is_none());
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "missing_bearer_token");
        assert!(!body["error"]["message"].as_str().unwrap_or("").is_empty());
    }

    #[tokio::test]
    async fn invalid_token_maps_to_401() {
        let response = error_response(AuthError::InvalidToken);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_bearer_token");
    }

    #[tokio::test]
    async fn forbidden_maps_to_403() {
        let response = error_response(AuthError::Forbidden);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "insufficient_scope");
    }

    #[tokio::test]
    async fn rate_limited_maps_to_429_with_retry_after() {
        let response = error_response(AuthError::RateLimited {
            retry_after_secs: 42,
        });
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "42");
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "auth_rate_limited");
    }

    #[test]
    fn authorize_or_response_passes_the_scope_through() {
        let scope =
            authorize_or_response(&policy(), Scope::Admin, &bearer("admin-secret"), "1.1.1.1")
                .expect("authorized");
        assert_eq!(scope, Scope::Admin);
    }

    #[test]
    fn authorize_or_response_returns_a_ready_response_on_failure() {
        let response =
            authorize_or_response(&policy(), Scope::Admin, &bearer("viewer-secret"), "1.1.1.1")
                .expect_err("must fail");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
