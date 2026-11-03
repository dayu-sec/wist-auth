# Changelog

## [0.3.0] - 2026-11-03

### Added（授权记录签名：Ed25519）

- 新特性 `signing`：授权记录的签名契约。签发方（`wist-cred`）对每条记录签名，
  验证方（X）在**收到时**和**从磁盘加载时**各验一次。
  - 规范字节固定、字段带长度前缀、角色/资源排序去重，避免两端序列化差异。
  - 签名覆盖凭据指纹、主体、角色、资源、受众、有效期、版本号与撤销状态 ——
    改 `roles` / 延长 `expires_at` / 清掉 `revoked_at` 都会被识别。
  - 提供 `sign` / `verify` / `public_key_from_pkcs8` / `parse_public_key_hex`；
    私钥用 PKCS#8（v1/v2 都接受，OpenSSL 默认产出的 v1 也能用）。
  - 支持**多把公钥**（轮换期同时信任新旧）；`verify` 任一验过即通过。
  - 覆盖测试：换摘要、撤销状态回滚、异钥撤销、多钥轮换 —— 都必须被发现。

### Changed（`credential`）

- `CredentialEntry` 新增 `signature: Option<String>`（小写 hex）。
- `StoreParams` 新增 `require_signature` 与 `issuer_public_keys`（裸 32 字节 Ed25519 公钥）。
  `require_signature = true` 时：`register` 缺签名/验不过直接拒收；加载时验不过的记录丢弃，
  可通过 `CredentialStore::rejected_on_load()` 查看条数。
- **裁剪时机前移**：磁盘上存签发方签过的**原始**授权（含签名），角色 / TTL / 资源裁剪
  改为在 `verify` 时应用。这样本服务的策略变化不需要签发方重签。
- TTL 上限改为相对 `issued_at` 计算（此前相对“登记时刻”，每次加载都会把过期时间往后推）。
- `CredentialStore::revoke` 新增 `signature` 参数：撤销也要签发方签名，签名覆盖“已撤销”的记录。

> 0.x 的破坏性变更：`CredentialEntry` / `StoreParams` 的字段新增、`revoke` 的参数新增。

## [0.2.0] - 2026-11-03

### Added

- 新特性 `credential`：**验证侧的凭据登记表**，用来本地校验凭据服务推送来的 token（配套
  `wist-cred` 的签发侧）。开启后服务可以自己判定一张 token 还能不能用，不需要回调签发方。
  - 只存 `sha256` 摘要，明文永不落盘；登记表 `0640`，写入是临时文件 + rename。
  - 撤销即时生效且**重启不会复活**；重复登记幂等，旧消息不会覆盖新状态。
  - 按本服务自己的配置裁剪：不认识的角色直接丢掉，有效期按角色上限收紧，
    资源范围可选取交集（默认不裁，留给业务层判）。
  - 校验失败有稳定的错误码（未登记 / 跨服务使用 / 已撤销 / 已过期），可直接映射成 401。
- 示例 `verify_credential`：拿一张登记表和一条 token 就能判定能否使用，可当接入参考。

### Fixed

- **登记表落盘失败时，内存与磁盘不再分叉**：撤销不会在重启后“复活”（而签发方已经认为撤成功），
  登记也不会只存在于内存。两条路径失败时都会回滚。

## [0.1.1] - 2026-10-29

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

- 测试从 19 增加到 **61**（含时间语义、header 边界、错误映射、Debug 泄漏防护）。

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
