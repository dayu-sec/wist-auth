//! 作用域与鉴权策略。

use std::fmt;

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
#[derive(Clone, Default)]
pub struct TokenConfig {
    pub token: Option<String>,
    pub token_hash: Option<String>,
}

impl fmt::Debug for TokenConfig {
    /// 不打印明文/摘要本身，只说明配了哪一侧。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenConfig")
            .field("has_plain", &self.token.is_some())
            .field("has_hash", &self.token_hash.is_some())
            .finish()
    }
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
            (Some(plain), None) => Ok(Some(sha256_hex(plain.trim()))),
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

pub struct AuthPolicy {
    admin_hash: Option<String>,
    viewer_hash: Option<String>,
    allow_anonymous: bool,
    limiter: FailureLimiter<String>,
}

impl fmt::Debug for AuthPolicy {
    /// 不把 token 摘要打进日志：只报告"配没配"。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthPolicy")
            .field("admin_configured", &self.admin_hash.is_some())
            .field("viewer_configured", &self.viewer_hash.is_some())
            .field("allow_anonymous", &self.allow_anonymous)
            .finish_non_exhaustive()
    }
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

    /// 是否配置了任何凭据。
    pub fn has_credentials(&self) -> bool {
        self.admin_hash.is_some() || self.viewer_hash.is_some()
    }

    /// 匿名（dev）模式的作用域：只能到 Viewer，**不能**绕过路由所需作用域。
    fn anonymous_scope(&self, required: Scope) -> Result<Scope, AuthError> {
        if Scope::Viewer < required {
            Err(AuthError::Forbidden)
        } else {
            Ok(Scope::Viewer)
        }
    }

    pub fn authorize(
        &self,
        headers: &HeaderMap,
        client_key: &str,
        required: Scope,
    ) -> Result<Scope, AuthError> {
        let client_key = client_key.to_string();

        if let Some(retry_after_secs) = self.limiter.blocked_for(&client_key) {
            return Err(AuthError::RateLimited { retry_after_secs });
        }

        let Some(token) = bearer_token(headers) else {
            // 缺 token 属"未认证"而不是"猜错"，不计入暴力尝试。
            return if self.allow_anonymous {
                self.anonymous_scope(required)
            } else {
                Err(AuthError::MissingToken)
            };
        };

        // dev 模式（显式匿名且一个凭据都没配）：与 center 一致 —— 不看 header，一律放行只读。
        // 配了凭据时，错的 token 仍然要 401（不能因为开了匿名就当成匿名请求）。
        if self.allow_anonymous && !self.has_credentials() {
            return self.anonymous_scope(required);
        }

        let presented = sha256_hex(token);
        let granted = if matches_hash(self.admin_hash.as_deref(), &presented) {
            Some(Scope::Admin)
        } else if matches_hash(self.viewer_hash.as_deref(), &presented) {
            Some(Scope::Viewer)
        } else {
            None
        };

        let Some(granted) = granted else {
            self.limiter.record_failure(&client_key);
            return Err(AuthError::InvalidToken);
        };
        self.limiter.clear(&client_key);

        if granted < required {
            // 凭据有效但权限不足：不是暴力破解，不计失败、也不清已有计数（已在上面 clear）。
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

    fn raw_header(value: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(value).expect("header"),
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

    fn admin_only() -> AuthPolicy {
        AuthPolicy::new(
            TokenConfig::from_plain("admin-secret"),
            TokenConfig::default(),
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
    fn insufficient_scope_is_not_counted_as_brute_force() {
        let p = policy();
        for _ in 0..10 {
            assert_eq!(
                p.authorize(&headers("viewer-secret"), "7.7.7.7", Scope::Admin),
                Err(AuthError::Forbidden)
            );
        }
        // 仍然是 Forbidden，而不是被封禁。
        assert_eq!(
            p.authorize(&headers("viewer-secret"), "7.7.7.7", Scope::Admin),
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
    fn missing_token_does_not_count_toward_the_block() {
        let p = admin_only();
        for _ in 0..(crate::ratelimit::DEFAULT_MAX_FAILURES + 3) {
            assert_eq!(
                p.authorize(&HeaderMap::new(), "8.8.8.8", Scope::Viewer),
                Err(AuthError::MissingToken)
            );
        }
        // 缺 token 不计失败：正确 token 仍可用。
        assert_eq!(
            p.authorize(&headers("admin-secret"), "8.8.8.8", Scope::Viewer),
            Ok(Scope::Admin)
        );
    }

    #[test]
    fn five_failures_block_even_the_right_token() {
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
    fn a_successful_auth_resets_the_counter() {
        let p = policy();
        for _ in 0..4 {
            let _ = p.authorize(&headers("nope"), "5.5.5.5", Scope::Viewer);
        }
        assert_eq!(
            p.authorize(&headers("viewer-secret"), "5.5.5.5", Scope::Viewer),
            Ok(Scope::Viewer)
        );
        // 计数被清零：再错 4 次也不会封禁。
        for _ in 0..4 {
            let _ = p.authorize(&headers("nope"), "5.5.5.5", Scope::Viewer);
        }
        assert_eq!(
            p.authorize(&headers("viewer-secret"), "5.5.5.5", Scope::Viewer),
            Ok(Scope::Viewer)
        );
    }

    #[test]
    fn block_is_per_client() {
        let p = policy();
        for _ in 0..5 {
            let _ = p.authorize(&headers("nope"), "10.0.0.1", Scope::Viewer);
        }
        assert!(matches!(
            p.authorize(&headers("admin-secret"), "10.0.0.1", Scope::Viewer),
            Err(AuthError::RateLimited { .. })
        ));
        // 另一个客户端不受影响。
        assert_eq!(
            p.authorize(&headers("admin-secret"), "10.0.0.2", Scope::Viewer),
            Ok(Scope::Admin)
        );
    }

    #[test]
    fn requires_a_token_unless_anonymous() {
        assert!(AuthPolicy::new(TokenConfig::default(), TokenConfig::default(), false).is_err());
        assert!(AuthPolicy::new(TokenConfig::default(), TokenConfig::default(), true).is_ok());
    }

    #[test]
    fn viewer_alone_is_not_enough_to_start() {
        // 只配 viewer 也算"没配管理面 token"：必须显式匿名才行。
        assert!(
            AuthPolicy::new(TokenConfig::default(), TokenConfig::from_plain("v"), false).is_err()
        );
    }

    #[test]
    fn anonymous_without_credentials_accepts_anything_read_only() {
        let p =
            AuthPolicy::new(TokenConfig::default(), TokenConfig::default(), true).expect("policy");
        assert_eq!(
            p.authorize(&HeaderMap::new(), "1.1.1.1", Scope::Viewer),
            Ok(Scope::Viewer)
        );
        // center 的 dev 模式不看 header：给个乱 token 也一样放行只读。
        assert_eq!(
            p.authorize(&headers("garbage"), "1.1.1.1", Scope::Viewer),
            Ok(Scope::Viewer)
        );
        // 但永远拿不到 admin（无论给不给 token）。
        assert_eq!(
            p.authorize(&headers("garbage"), "1.1.1.1", Scope::Admin),
            Err(AuthError::Forbidden)
        );
        assert_eq!(
            p.authorize(&HeaderMap::new(), "1.1.1.1", Scope::Admin),
            Err(AuthError::Forbidden)
        );
    }

    #[test]
    fn anonymous_with_credentials_still_rejects_a_wrong_token() {
        let p = AuthPolicy::new(
            TokenConfig::from_plain("admin-secret"),
            TokenConfig::default(),
            true,
        )
        .expect("policy");
        assert_eq!(
            p.authorize(&headers("garbage"), "2.2.2.2", Scope::Viewer),
            Err(AuthError::InvalidToken)
        );
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
    fn prehashed_token_is_case_insensitive_on_the_stored_side() {
        let p = AuthPolicy::new(
            TokenConfig::from_hash(sha256_hex("admin-secret").to_ascii_uppercase()),
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

    #[test]
    fn rejects_a_malformed_hash() {
        for bad in ["", "abc", &"z".repeat(64), &"a".repeat(63)] {
            assert!(
                AuthPolicy::new(TokenConfig::from_hash(bad), TokenConfig::default(), false)
                    .is_err(),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn plain_token_is_trimmed() {
        // 配置里带尾随空格不应改变语义（避免 .env 里多敲一个空格就登不上）。
        let p = AuthPolicy::new(
            TokenConfig::from_plain(" admin-secret "),
            TokenConfig::default(),
            false,
        )
        .expect("policy");
        assert_eq!(
            p.authorize(&headers("admin-secret"), "1.2.3.4", Scope::Viewer),
            Ok(Scope::Admin)
        );
    }

    #[test]
    fn empty_tokens_are_treated_as_unconfigured() {
        assert!(
            AuthPolicy::new(
                TokenConfig::from_plain("   "),
                TokenConfig::default(),
                false
            )
            .is_err()
        );
    }

    #[test]
    fn header_variants_are_rejected_consistently() {
        let p = admin_only();
        // 与 center/gateway 一致：scheme 必须是大写 `Bearer ` + 一个空格。
        for raw in [
            "bearer admin-secret",
            "BEARER admin-secret",
            "Bearer",
            "Bearer ",
            "Basic admin-secret",
            "Token admin-secret",
        ] {
            assert_eq!(
                p.authorize(&raw_header(raw), "3.3.3.3", Scope::Viewer),
                Err(AuthError::MissingToken),
                "raw={raw:?}"
            );
        }
    }

    #[test]
    fn extra_spaces_after_scheme_are_tolerated() {
        let p = admin_only();
        assert_eq!(
            p.authorize(
                &raw_header("Bearer   admin-secret  "),
                "4.4.4.4",
                Scope::Viewer
            ),
            Ok(Scope::Admin)
        );
    }

    #[test]
    fn debug_does_not_leak_hashes_or_tokens() {
        let p = policy();
        let text = format!("{p:?}");
        assert!(text.contains("admin_configured"));
        assert!(!text.contains(&sha256_hex("admin-secret")));
        assert!(!text.contains("admin-secret"));
    }
}
