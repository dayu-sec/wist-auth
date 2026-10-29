//! 各服务共用的 `[auth]` 配置块（feature `serde`）。
//!
//! 语义由服务自己决定：center 允许空 token（= 不鉴权），ingest 要求必须配置（fail-closed）。
//! 本结构只负责解析，`allow_anonymous` 是显式开关。

use serde::{Deserialize, Serialize};

use crate::policy::{AuthPolicy, TokenConfig};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    /// 可读可写。明文只在内存里转成 sha256；落盘建议用下面的 hash。
    pub admin_token: Option<String>,
    /// `admin_token` 的 sha256 小写 hex。
    pub admin_token_hash: Option<String>,
    /// 只读 token（可选）；不配时 admin token 同时具备读权限。
    pub viewer_token: Option<String>,
    pub viewer_token_hash: Option<String>,
    /// 显式关闭鉴权（仅开发）。默认 false。
    pub allow_anonymous: bool,
}

impl AuthConfig {
    pub fn into_policy(self) -> Result<AuthPolicy, String> {
        AuthPolicy::new(
            TokenConfig {
                token: self.admin_token,
                token_hash: self.admin_token_hash,
            },
            TokenConfig {
                token: self.viewer_token,
                token_hash: self.viewer_token_hash,
            },
            self.allow_anonymous,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Scope;
    use crate::token::sha256_hex;
    use http::HeaderValue;

    fn parse(text: &str) -> AuthConfig {
        toml::from_str(text).expect("parse")
    }

    #[test]
    fn parses_the_shared_block() {
        let cfg = parse(
            r#"
admin_token = "a"
viewer_token = "v"
allow_anonymous = false
"#,
        );
        assert_eq!(cfg.admin_token.as_deref(), Some("a"));
        assert!(cfg.into_policy().is_ok());
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = toml::from_str::<AuthConfig>("admin_tokn = \"x\"").unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn empty_config_is_fail_closed() {
        assert!(AuthConfig::default().into_policy().is_err());
    }

    #[test]
    fn anonymous_without_credentials_is_allowed_when_explicit() {
        let cfg = parse("allow_anonymous = true");
        let policy = cfg.into_policy().expect("policy");
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("ignored"),
        );
        assert_eq!(
            policy.authorize(&headers, "1.2.3.4", Scope::Viewer),
            Ok(Scope::Viewer)
        );
    }

    #[test]
    fn hash_only_config_works() {
        let hash = sha256_hex("admin-secret");
        let cfg = parse(&format!("admin_token_hash = \"{hash}\""));
        let policy = cfg.into_policy().expect("policy");
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer admin-secret"),
        );
        assert_eq!(
            policy.authorize(&headers, "1.2.3.4", Scope::Admin),
            Ok(Scope::Admin)
        );
    }

    #[test]
    fn plain_and_hash_for_the_same_role_conflict() {
        let cfg = parse(&format!(
            r#"
admin_token = "x"
admin_token_hash = "{}"
"#,
            sha256_hex("x")
        ));
        assert!(cfg.into_policy().is_err());
    }

    #[test]
    fn malformed_hash_is_rejected_with_a_clear_message() {
        let cfg = parse("admin_token_hash = \"not-a-hash\"");
        let err = cfg.into_policy().unwrap_err();
        assert!(err.contains("sha256"), "unexpected error: {err}");
    }

    #[test]
    fn serializes_the_same_keys_it_parses() {
        let cfg = parse(
            r#"
admin_token = "a"
allow_anonymous = true
"#,
        );
        let text = toml::to_string(&cfg).expect("serialize");
        // 配过的字段必须出现；`None` 字段被 TOML 序列化成“不写”，不会产生空键。
        assert!(text.contains("admin_token"));
        assert!(text.contains("allow_anonymous"));
        assert!(!text.contains("viewer_token"));
    }
}
