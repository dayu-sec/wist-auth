# Changelog

## [0.1.0] - 2026-10-29

### Fixed（5 轮 review 发现）

- **匿名模式可以越权**：`allow_anonymous` 下请求 admin 作用域会返回 `Ok(Viewer)` 而不是 403，
  等于绕过路由所需作用域。现在匿名路径也走作用域检查。
- **封禁会被窗口过期提前解除**：`block_duration > failure_window` 时，窗口一到就丢掉桶。
  现在先看 `blocked_until`，再看窗口。
- **窗口不会在 `record_failure` 时重置**：持续低频失败可以无限累积到封禁。
  现在与 center/gateway 一致，窗口过期后重新计数。
- `token_matches` 对格式非法的期望摘要直接返回 false，且比较前统一小写。
- 明文 token 配置两端空白被裁剪（避免 `.env` 里多敲空格就登不上）。
- `AuthPolicy` / `TokenConfig` 的 `Debug` 不再打印摘要或明文。

### Added

- 抽自 `wist-center/src/api/{admin_auth,rate_limit}.rs` 与 `wist-ingest-ctrl/src/auth.rs`：
  - `AuthPolicy`：Bearer token、sha256 hex、常数时间比较；
  - `Scope`（`Viewer < Admin` 有序）；
  - `FailureLimiter`：5 次失败 / 60s → 封 60s，桶数上限淘汰；
  - `AuthError` + 稳定错误码（`missing_bearer_token` / `invalid_bearer_token` / `insufficient_scope` / `auth_rate_limited`）；
  - feature `serde`：共享 `[auth]` 配置块；
  - feature `axum`：`authorize_or_response`（`no-store` + `Retry-After`）。
- 测试从 19 增加到 **61**（含时间语义、header 边界、错误映射、Debug 泄漏防护）。
- 不依赖日志门面，不绑定具体路由与 token 来源。
