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

    #[test]
    fn parses_the_shared_block() {
        let cfg: AuthConfig = toml::from_str(
            r#"
admin_token = "a"
viewer_token = "v"
allow_anonymous = false
"#,
        )
        .expect("parse");
        assert_eq!(cfg.admin_token.as_deref(), Some("a"));
        assert!(cfg.into_policy().is_ok());
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = toml::from_str::<AuthConfig>("admin_tokn = \"x\"").unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }
}
