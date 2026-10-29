# Changelog

## [0.1.0] - 2026-10-29

### Added

- 抽自 `wist-center/src/api/{admin_auth,rate_limit}.rs` 与 `wist-ingest-ctrl/src/auth.rs`：
  - `AuthPolicy`：Bearer token、sha256 hex、常数时间比较；
  - `Scope`（`Viewer < Admin` 有序）；
  - `FailureLimiter`：5 次失败 / 60s → 封 60s，桶数上限淘汰；
  - `AuthError` + 稳定错误码（`missing_bearer_token` / `invalid_bearer_token` / `insufficient_scope` / `auth_rate_limited`）；
  - feature `serde`：共享 `[auth]` 配置块；
  - feature `axum`：`authorize_or_response`（`no-store` + `Retry-After`）。
- 不依赖日志门面，不绑定具体路由与 token 来源。
