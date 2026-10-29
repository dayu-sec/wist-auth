//! 管理面鉴权的可复用部分，口径来自 `wist-center/src/api/{admin_auth,rate_limit}.rs`。
//!
//! - Bearer token，配置里存 **sha256 hex**，比较用常数时间；
//! - 缺 token = 未认证（**不计入**暴力尝试）；错 token = 认证失败（计入并可能封禁）；
//! - 每客户端 5 次失败 / 60s → 封 60s（`Retry-After`）；
//! - 作用域是**有序**的：`viewer < admin`，admin 天然具备 viewer 权限。
//!
//! 本 crate **不依赖日志门面**：只返回结构化错误，让调用方用它自己的 `log` / `tracing` /
//! `eprintln!` 记录，避免把某个 logger 拖进所有消费方。

pub mod error;
pub mod policy;
pub mod ratelimit;
pub mod token;

#[cfg(feature = "serde")]
pub mod config;

#[cfg(feature = "axum")]
pub mod axum_response;

pub use error::AuthError;
pub use policy::TokenConfig;
pub use policy::{AuthPolicy, Scope};
pub use ratelimit::FailureLimiter;
pub use token::{bearer_token, constant_time_eq, sha256_hex, token_matches};

#[cfg(feature = "serde")]
pub use config::AuthConfig;

#[cfg(feature = "axum")]
pub use axum_response::{authorize_or_response, error_response};
