//! 鉴权错误：只描述语义与稳定 code，HTTP 映射见 `axum_response`（feature `axum`）。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    MissingToken,
    InvalidToken,
    Forbidden,
    RateLimited { retry_after_secs: u64 },
}

impl AuthError {
    /// 稳定错误码（对外契约，新增可兼容，改名属破坏性变更）。
    pub fn code(self) -> &'static str {
        match self {
            AuthError::MissingToken => "missing_bearer_token",
            AuthError::InvalidToken => "invalid_bearer_token",
            AuthError::Forbidden => "insufficient_scope",
            AuthError::RateLimited { .. } => "auth_rate_limited",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            AuthError::MissingToken => "missing bearer token",
            AuthError::InvalidToken => "invalid bearer token",
            AuthError::Forbidden => "token scope is not sufficient for this operation",
            AuthError::RateLimited { .. } => "too many failed authentication attempts",
        }
    }

    /// 对应的 HTTP 状态码。
    pub fn status(self) -> u16 {
        match self {
            AuthError::MissingToken | AuthError::InvalidToken => 401,
            AuthError::Forbidden => 403,
            AuthError::RateLimited { .. } => 429,
        }
    }

    pub fn retry_after_secs(self) -> Option<u64> {
        match self {
            AuthError::RateLimited { retry_after_secs } => Some(retry_after_secs),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_and_stable() {
        let all = [
            AuthError::MissingToken,
            AuthError::InvalidToken,
            AuthError::Forbidden,
            AuthError::RateLimited {
                retry_after_secs: 1,
            },
        ];
        let mut codes: Vec<_> = all.iter().map(|e| e.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
    }

    #[test]
    fn status_mapping() {
        assert_eq!(AuthError::MissingToken.status(), 401);
        assert_eq!(AuthError::Forbidden.status(), 403);
        assert_eq!(
            AuthError::RateLimited {
                retry_after_secs: 30
            }
            .status(),
            429
        );
    }
}
