# wist-auth

管理面鉴权的可复用层。口径直接来自 `wist-center/src/api/{admin_auth,rate_limit}.rs`
和 `wist-ingest-ctrl` 的实现，**行为逐条对齐**：

| 语义 | 规则 |
|---|---|
| 凭据 | `Authorization: Bearer <token>`；配置里存参数字的 **sha256 小写 hex** |
| 比较 | 常数时间（长度也参与比较）；摘要大小写不敏感 |
| 缺 token | `MissingToken`（401），**不计入**失败次数 |
| 错 token | `InvalidToken`（401），计入失败次数 |
| 作用域 | `Viewer < Admin` 有序；admin 天然具备 viewer 权限 |
| 越权 | `Forbidden`（403），**不计入**失败次数 |
| 限流 | 每客户端 5 次失败 / 60s → 封 60s，`RateLimited { retry_after_secs }`（429） |
| 窗口 | 从窗口内**第一次**失败算起；过期后重新计数 |
| 封禁 | **不因窗口过期提前解除**（`block_duration > failure_window` 时也成立） |
| 匿名 | 只有显式 `allow_anonymous = true` 才生效；且**只能拿到 Viewer**，不能绕过路由所需作用域 |
| dev 模式 | 匿名且一个凭据都没配时，与 center 一致：不看 header，一律只读放行 |

## 设计边界

- **不依赖日志门面**：只返回结构化错误，调用方用自己的 `log` / `tracing` / `eprintln!` 记录。
- **不决定 token 来源**：环境变量 / 文件 / 配置的优先级由各服务自己定。
- **不决定允许匿名**：`allow_anonymous` 只是开关；center 用它表示"空 token = 不鉴权"，
  ingest 用它表示"仅开发可关"，默认值由服务选。
- **不绑定路由**：路由 → 所需作用域的映射留在服务里。

## 用法

```rust
use wist_auth::{AuthPolicy, Scope, TokenConfig};

let policy = AuthPolicy::new(
    TokenConfig::from_plain(admin_token),       // 或 TokenConfig::from_hash(sha256_hex)
    TokenConfig::from_plain(viewer_token),
    false,                                       // allow_anonymous
)?;

// 在中间件里：
let scope = policy.authorize(req.headers(), &client_ip, Scope::Admin)?;
```

带 `axum` feature 时：

```rust
let scope = wist_auth::authorize_or_response(&policy, Scope::Admin, headers, &client_ip)?;
// Err(Response)：401/403/429，均带 Cache-Control: no-store；429 另带 Retry-After
```

`serde` feature 提供共享配置块：

```toml
[auth]
admin_token_hash = "<64 hex>"
viewer_token_hash = "<64 hex>"
allow_anonymous = false
```

## 测试

```bash
cargo test --features serde,axum     # 61 个用例
```

覆盖：作用域升降、缺/错/越权 token 的区分、5 次失败封禁、成功清零、按客户端隔离、
窗口过期重算、**封禁不因窗口过期提前解除**、桶上限淘汰、明文与 hash 互斥、hash 格式与大小写、
header 变体（大小写/多空格/非 UTF-8）、非 UTF-8 header、匿名模式不能越权、
错误码/状态/`no-store`/`Retry-After` 映射、Debug 不泄漏摘要。

## 迁移状态

- ✅ `wist-ingest-ctrl`（行为与切换前逐条一致，已用真 mTLS + 真 token 回归）。
- ✅ `wist-center`：`api/admin_auth.rs` + `api/rate_limit.rs` + `gateway_ops.rs` 里的 link-token 校验改用本 crate；
  `RateLimitState` 变成 `FailureLimiter<String>`（key = `"{scope}:{client}"`），public API 不变；错误码与 `ApiError` 仍在 center。
- ✅ `wist-gateway`：同上（保留 `OptionalConnectInfo` 与它自己的 429 响应形态）。
- `wist-gwlinkd` 无 bearer 管理面（mTLS-only），不涉及。

保留在各服务侧的只有**策略差异**：center 空 token = 不鉴权、gateway 必须配 token、错误码词表、路由→作用域映射。
