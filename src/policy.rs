//! 作用域与鉴权策略。

use http::HeaderMap;

use crate::error::AuthError;
use crate::ratelimit::FailureLimiter;
use crate::token::{bearer_token, constant_time_eq, sha256_hex};

/// 有序作用域：`Viewer < Admin`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    Viewer,
    Admin,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Viewer => "viewer",
            Scope::Admin => "admin",
        }
    }
}

/// token 配置（明文或已存的 sha256 hex，二选一）。
#[derive(Debug, Clone, Default)]
pub struct TokenConfig {
    pub token: Option<String>,
    pub token_hash: Option<String>,
}

impl TokenConfig {
    pub fn from_plain(token: impl Into<String>) -> Self {
        Self {
            token: Some(token.into()),
            token_hash: None,
        }
    }

    pub fn from_hash(hash: impl Into<String>) -> Self {
        Self {
            token: None,
            token_hash: Some(hash.into()),
        }
    }

    fn resolve(&self, role: &str) -> Result<Option<String>, String> {
        let plain = self.token.as_deref().filter(|v| !v.trim().is_empty());
        let hash = self.token_hash.as_deref().filter(|v| !v.trim().is_empty());
        match (plain, hash) {
            (Some(_), Some(_)) => Err(format!("auth.{role}_token 与 {role}_token_hash 只能配一个")),
            (Some(plain), None) => Ok(Some(sha256_hex(plain))),
            (None, Some(hash)) => {
                let hash = hash.trim().to_ascii_lowercase();
                if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(format!(
                        "auth.{role}_token_hash 必须是 sha256 小写 hex（64 位）"
                    ));
                }
                Ok(Some(hash))
            }
            (None, None) => Ok(None),
        }
    }
}

#[derive(Debug)]
pub struct AuthPolicy {
    admin_hash: Option<String>,
    viewer_hash: Option<String>,
    allow_anonymous: bool,
    limiter: FailureLimiter<String>,
}

impl AuthPolicy {
    pub fn new(
        admin: TokenConfig,
        viewer: TokenConfig,
        allow_anonymous: bool,
    ) -> Result<Self, String> {
        let admin_hash = admin.resolve("admin")?;
        let viewer_hash = viewer.resolve("viewer")?;

        if admin_hash.is_none() && !allow_anonymous {
            return Err(
                "未配置管理面 token：设置 admin_token（或 admin_token_hash），\
                 或显式 allow_anonymous = true（仅限开发）"
                    .to_string(),
            );
        }

        Ok(Self {
            admin_hash,
            viewer_hash,
            allow_anonymous,
            limiter: FailureLimiter::default(),
        })
    }

    pub fn allow_anonymous(&self) -> bool {
        self.allow_anonymous
    }

    pub fn authorize(
        &self,
        headers: &HeaderMap,
        client_key: &str,
        required: Scope,
    ) -> Result<Scope, AuthError> {
        if let Some(retry_after_secs) = self.limiter.blocked_for(&client_key.to_string()) {
            return Err(AuthError::RateLimited { retry_after_secs });
        }

        let Some(token) = bearer_token(headers) else {
            // 缺 token 属"未认证"而不是"猜错"，不计入暴力尝试。
            return if self.allow_anonymous {
                Ok(Scope::Viewer)
            } else {
                Err(AuthError::MissingToken)
            };
        };

        let presented = sha256_hex(token);
        let granted = if matches_hash(self.admin_hash.as_deref(), &presented) {
            Some(Scope::Admin)
        } else if matches_hash(self.viewer_hash.as_deref(), &presented) {
            Some(Scope::Viewer)
        } else {
            None
        };

        let Some(granted) = granted else {
            self.limiter.record_failure(&client_key.to_string());
            return Err(AuthError::InvalidToken);
        };
        self.limiter.clear(&client_key.to_string());

        if granted < required {
            return Err(AuthError::Forbidden);
        }
        Ok(granted)
    }
}

fn matches_hash(expected: Option<&str>, presented: &str) -> bool {
    expected.is_some_and(|expected| constant_time_eq(presented.as_bytes(), expected.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn headers(token: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("header"),
        );
        map
    }

    fn policy() -> AuthPolicy {
        AuthPolicy::new(
            TokenConfig::from_plain("admin-secret"),
            TokenConfig::from_plain("viewer-secret"),
            false,
        )
        .expect("policy")
    }

    #[test]
    fn admin_grants_both_scopes() {
        let p = policy();
        assert_eq!(
            p.authorize(&headers("admin-secret"), "1.2.3.4", Scope::Admin),
            Ok(Scope::Admin)
        );
        assert_eq!(
            p.authorize(&headers("admin-secret"), "1.2.3.4", Scope::Viewer),
            Ok(Scope::Admin)
        );
    }

    #[test]
    fn viewer_cannot_escalate() {
        let p = policy();
        assert_eq!(
            p.authorize(&headers("viewer-secret"), "1.2.3.4", Scope::Viewer),
            Ok(Scope::Viewer)
        );
        assert_eq!(
            p.authorize(&headers("viewer-secret"), "1.2.3.4", Scope::Admin),
            Err(AuthError::Forbidden)
        );
    }

    #[test]
    fn missing_and_invalid_are_distinct() {
        let p = policy();
        assert_eq!(
            p.authorize(&HeaderMap::new(), "1.2.3.4", Scope::Viewer),
            Err(AuthError::MissingToken)
        );
        assert_eq!(
            p.authorize(&headers("nope"), "1.2.3.4", Scope::Viewer),
            Err(AuthError::InvalidToken)
        );
    }

    #[test]
    fn five_failures_block() {
        let p = policy();
        for _ in 0..5 {
            let _ = p.authorize(&headers("nope"), "9.9.9.9", Scope::Viewer);
        }
        assert!(matches!(
            p.authorize(&headers("admin-secret"), "9.9.9.9", Scope::Viewer),
            Err(AuthError::RateLimited { .. })
        ));
    }

    #[test]
    fn requires_a_token_unless_anonymous() {
        assert!(AuthPolicy::new(TokenConfig::default(), TokenConfig::default(), false).is_err());
        assert!(AuthPolicy::new(TokenConfig::default(), TokenConfig::default(), true).is_ok());
    }

    #[test]
    fn accepts_prehashed_tokens() {
        let p = AuthPolicy::new(
            TokenConfig::from_hash(sha256_hex("admin-secret")),
            TokenConfig::default(),
            false,
        )
        .expect("policy");
        assert_eq!(
            p.authorize(&headers("admin-secret"), "1.2.3.4", Scope::Admin),
            Ok(Scope::Admin)
        );
    }

    #[test]
    fn rejects_plain_and_hash_together() {
        let mut cfg = TokenConfig::from_plain("x");
        cfg.token_hash = Some(sha256_hex("x"));
        assert!(AuthPolicy::new(cfg, TokenConfig::default(), false).is_err());
    }
}
