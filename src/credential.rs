//! 凭据登记表（**验证侧**）：收 `register` / `revoke`，本地按摘要查表。
//!
//! 语义来自 `wist-design/doc/design/foundation/auth-token-verification.md`：
//!
//! - **只存 `sha256` 摘要**，明文从不落盘（D5）；
//! - `revision` 单调，低 revision 的 `register` 被拒（防撤销后复活，D12）；
//! - **X 裁剪 C 的提议**：roles 取交集、TTL 取 min、resources 可取交集（D9）；
//! - `audience` 必校（防跨服务重放）；
//! - 撤销是点对点标记，记录留到 `expires_at`。
//!
//! 验证**纯本地**：一次 `verify` 不产生任何网络往返。

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::token::{constant_time_eq, sha256_hex};

/// 一条登记项。字段与 `wist-cred` 推来的 `register` 载荷一致；
/// 对端多带的字段（`owner` / `purpose` 等）在反序列化时被忽略。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialEntry {
    pub credential_id: String,
    /// `sha256:<hex>` 或裸 `<hex>`；构造后统一规范化为小写 hex。
    pub digest: String,
    pub subject: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub resources: BTreeMap<String, Vec<String>>,
    pub audience: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revision: u64,
    #[serde(default)]
    pub revoked_at: Option<i64>,
    /// 签发方对**本条授权记录**的 Ed25519 签名（小写 hex，64 字节）。
    /// `None` = 未签名；验证方开了 `require_signature` 时会被拒收 / 加载时丢弃。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// 验证通过后的主体。服务侧只依赖这个形状。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCredential {
    pub credential_id: String,
    pub subject: String,
    pub roles: Vec<String>,
    pub resources: BTreeMap<String, Vec<String>>,
    pub audience: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    /// 载荷字段缺失或时间倒挂。
    Malformed(String),
    /// 收到的 `revision` 不大于本地记录。
    RevisionStale {
        current: u64,
        incoming: u64,
    },
    /// 凭据不是发给本服务的。
    WrongAudience {
        expected: String,
        actual: String,
    },
    /// 摘要不在表里（含"从未签发过"和"已被清理"）。
    Unknown,
    Expired,
    Revoked,
    /// 落的盘 / 读盘失败。
    Store(String),
    /// 签名缺失或不匹配（授权内容被改过，或不是签发方签的）。
    BadSignature,
}

impl CredentialError {
    /// 稳定错误码（对外契约）。
    pub fn code(&self) -> &'static str {
        match self {
            CredentialError::Malformed(_) => "credential_malformed",
            CredentialError::RevisionStale { .. } => "credential_revision_stale",
            CredentialError::WrongAudience { .. } => "audience_mismatch",
            CredentialError::Unknown => "invalid_token",
            CredentialError::Expired => "token_expired",
            CredentialError::Revoked => "token_revoked",
            CredentialError::Store(_) => "credential_store_unavailable",
            CredentialError::BadSignature => "credential_signature_invalid",
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            CredentialError::WrongAudience { .. } => 400,
            CredentialError::RevisionStale { .. } => 409,
            CredentialError::Store(_) => 503,
            CredentialError::BadSignature => 400,
            _ => 401,
        }
    }
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialError::Malformed(reason) => write!(f, "malformed credential: {reason}"),
            CredentialError::RevisionStale { current, incoming } => write!(
                f,
                "credential revision is stale: current {current}, incoming {incoming}"
            ),
            CredentialError::WrongAudience { expected, actual } => {
                write!(
                    f,
                    "credential audience mismatch: expected {expected}, got {actual}"
                )
            }
            CredentialError::Unknown => write!(f, "credential not registered"),
            CredentialError::Expired => write!(f, "credential expired"),
            CredentialError::Revoked => write!(f, "credential revoked"),
            CredentialError::Store(reason) => write!(f, "credential store unavailable: {reason}"),
            CredentialError::BadSignature => {
                write!(f, "credential signature is missing or does not match")
            }
        }
    }
}

impl std::error::Error for CredentialError {}

/// X 侧的裁剪策略（D9）。
#[derive(Debug, Clone, Default)]
pub struct StoreParams {
    /// 本服务认识的角色。**不在其中的角色会被丢掉**；空 = 全部丢掉（fail-closed）。
    pub known_roles: Vec<String>,
    /// 角色 → TTL 上限（秒）。命中多条时取最小。
    pub max_ttl_by_role: BTreeMap<String, i64>,
    /// 本服务可见的资源。`None` = 不裁剪（留给业务层判）；`Some` = 取交集。
    pub visible_resources: Option<BTreeMap<String, Vec<String>>>,
    /// 时钟偏移（秒），默认 60。
    pub clock_skew_seconds: i64,
    /// 是否要求每条授权记录都带签发方签名。
    ///
    /// - `register`：没有签名或验不过 → 拒收（`credential_signature_invalid`）；
    /// - 从磁盘加载：验不过的记录**直接丢弃**（并计入 `rejected_on_load`）。
    pub require_signature: bool,
    /// 信任的签发方 Ed25519 公钥（裸 32 字节）。空 = 一把都不信（fail-closed）。
    /// 支持同时放多把，用于轮换期。
    pub issuer_public_keys: Vec<Vec<u8>>,
}

impl StoreParams {
    pub fn with_clock_skew(mut self, seconds: i64) -> Self {
        self.clock_skew_seconds = seconds;
        self
    }

    fn skew(&self) -> i64 {
        if self.clock_skew_seconds == 0 {
            60
        } else {
            self.clock_skew_seconds
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct FileData {
    #[serde(default)]
    revision: u64,
    #[serde(default)]
    credentials: Vec<CredentialEntry>,
}

/// 摘要表。`path = None` 时为纯内存（测试 / 单进程）。
pub struct CredentialStore {
    path: Option<PathBuf>,
    params: StoreParams,
    state: RwLock<FileData>,
    /// 加载时因签名不合格被丢弃的条数（给（运维日志看）。
    rejected_on_load: usize,
}

impl CredentialStore {
    /// 从落盘文件加载（不存在则视作空表）。
    ///
    /// **开 `require_signature` 时逐条验签**：不符合的表示磁盘上的授权内容被改过，
    /// 直接丢弃（不让它进内存），并计入 [`Self::rejected_on_load`]。
    /// 不做 revision 单调校验——那是 `register` 的事。
    pub fn open(path: impl Into<PathBuf>, params: StoreParams) -> Result<Self, CredentialError> {
        let path = path.into();
        let data = match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str::<FileData>(&text).map_err(|err| {
                CredentialError::Store(format!("parse {}: {err}", path.display()))
            })?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => FileData::default(),
            Err(err) => {
                return Err(CredentialError::Store(format!(
                    "read {}: {err}",
                    path.display()
                )));
            }
        };
        let mut store = Self {
            path: Some(path),
            params,
            state: RwLock::new(FileData::default()),
            rejected_on_load: 0,
        };
        let mut rejected = 0;
        {
            let mut state = store.write_state();
            for entry in data.credentials {
                if store.params.require_signature
                    && !crate::signing::verify(
                        &entry,
                        entry.signature.as_deref().unwrap_or_default(),
                        &store.params.issuer_public_keys,
                    )
                {
                    rejected += 1;
                    continue;
                }
                // 规范化字段（digest 去前缀 / 签名小写），但**不裁剪**：
                // 存的是签发方签过的原始授权，裁剪在 `verify` 时应用。
                let entry = match store.normalize(entry) {
                    Ok(entry) => entry,
                    Err(_) => {
                        rejected += 1;
                        continue;
                    }
                };
                store.upsert(&mut state, entry);
            }
            state.revision = data.revision;
        }
        store.rejected_on_load = rejected;
        Ok(store)
    }

    pub fn in_memory(params: StoreParams) -> Self {
        Self {
            path: None,
            params,
            state: RwLock::new(FileData::default()),
            rejected_on_load: 0,
        }
    }

    /// 加载时因签名不合格被丢弃的条数。调用方应当把它写进启动日志。
    pub fn rejected_on_load(&self) -> usize {
        self.rejected_on_load
    }

    /// 登记一条凭据，返回**裁剪后的实际生效值**（对应 `register` 的 `effective` 回告）。
    ///
    /// 开 `require_signature` 时：签名缺失 / 验不过 → `credential_signature_invalid`，不落盘。
    /// 存的是**签发方签过的原始记录**；裁剪（角色 / TTL / 资源）在 `verify` 时应用。
    ///
    /// 落盘失败会**回滚内存**：否则会变成“X 在验、C 以为没交付、重启后又消失”。
    pub fn register(&self, entry: CredentialEntry) -> Result<CredentialEntry, CredentialError> {
        let entry = self.normalize(entry)?;
        self.check_signature(&entry)?;
        let mut state = self.write_state();
        if let Some(existing) = state
            .credentials
            .iter()
            .find(|item| item.credential_id == entry.credential_id)
            && entry.revision <= existing.revision
        {
            return Err(CredentialError::RevisionStale {
                current: existing.revision,
                incoming: entry.revision,
            });
        }
        let effective = self.effective_entry(&entry);
        let slot = state
            .credentials
            .iter()
            .position(|item| item.credential_id == entry.credential_id);
        let previous = slot.map(|index| state.credentials[index].clone());
        let previous_revision = state.revision;

        // 存原始记录（含签名）；`effective` 只是回告。
        self.upsert(&mut state, entry);
        state.revision += 1;
        if let Err(error) = self.persist(&state) {
            match (slot, previous) {
                (Some(index), Some(previous)) => state.credentials[index] = previous,
                // `upsert` 是新条目时追加在末尾。
                (None, _) => {
                    state.credentials.pop();
                }
                // 槽位在、旧值不在：不会发生，保守地不动。
                _ => {}
            }
            state.revision = previous_revision;
            return Err(error);
        }
        Ok(effective)
    }

    /// 撤销：幂等；`revision` 必须大于本地记录。
    ///
    /// 落盘失败会**回滚内存**：否则内存里已撤、磁盘上没撤，重启后 token 会“复活”——
    /// 而 C 那边已经认为撤销成功了（它不回滚本地状态，D12）。
    pub fn revoke(
        &self,
        credential_id: &str,
        revision: u64,
        at: i64,
        signature: Option<String>,
    ) -> Result<Option<CredentialEntry>, CredentialError> {
        let mut state = self.write_state();
        let Some(index) = state
            .credentials
            .iter()
            .position(|item| item.credential_id == credential_id)
        else {
            return Ok(None);
        };
        if state.credentials[index].revoked_at.is_some() {
            return Ok(Some(state.credentials[index].clone()));
        }
        if revision <= state.credentials[index].revision {
            return Err(CredentialError::RevisionStale {
                current: state.credentials[index].revision,
                incoming: revision,
            });
        }
        let previous = state.credentials[index].clone();
        let previous_revision = state.revision;
        let mut revoked = previous.clone();
        revoked.revoked_at = Some(at);
        revoked.revision = revision;
        revoked.signature = signature;
        self.check_signature(&revoked)?;
        state.credentials[index] = revoked;
        state.revision += 1;
        if let Err(error) = self.persist(&state) {
            state.credentials[index] = previous;
            state.revision = previous_revision;
            return Err(error);
        }
        Ok(Some(state.credentials[index].clone()))
    }

    /// 验一张凭据：**纯本地**，无网络往返。
    pub fn verify(
        &self,
        token: &str,
        audience: &str,
    ) -> Result<VerifiedCredential, CredentialError> {
        if token.trim().is_empty() {
            return Err(CredentialError::Unknown);
        }
        let digest = sha256_hex(token);
        let state = self.read_state();
        let entry = state
            .credentials
            .iter()
            .find(|item| constant_time_eq(digest.as_bytes(), item.digest.as_bytes()))
            .ok_or(CredentialError::Unknown)?;

        if entry.audience != audience {
            return Err(CredentialError::WrongAudience {
                expected: audience.to_string(),
                actual: entry.audience.clone(),
            });
        }
        if entry.revoked_at.is_some() {
            return Err(CredentialError::Revoked);
        }
        // 裁剪在**使用时**应用：磁盘上存的是签发方签过的原始授权，
        // 角色范围 / TTL 上限 / 资源交集是本验证方的策略，改了不需要重签。
        let effective = self.effective_entry(entry);
        if now_secs() > effective.expires_at + self.params.skew() {
            return Err(CredentialError::Expired);
        }
        Ok(VerifiedCredential {
            credential_id: effective.credential_id,
            subject: effective.subject,
            roles: effective.roles,
            resources: effective.resources,
            audience: effective.audience,
            expires_at: effective.expires_at,
        })
    }

    /// 当前表内容（调试 / 导出用）。
    pub fn entries(&self) -> Vec<CredentialEntry> {
        self.read_state().credentials.clone()
    }

    fn normalize(&self, mut entry: CredentialEntry) -> Result<CredentialEntry, CredentialError> {
        if entry.credential_id.trim().is_empty() {
            return Err(CredentialError::Malformed("credential_id is empty".into()));
        }
        if entry.subject.trim().is_empty() {
            return Err(CredentialError::Malformed("subject is empty".into()));
        }
        if entry.audience.trim().is_empty() {
            return Err(CredentialError::Malformed("audience is empty".into()));
        }
        if entry.expires_at <= entry.issued_at {
            return Err(CredentialError::Malformed(
                "expires_at must be after issued_at".into(),
            ));
        }
        entry.digest = normalize_digest(&entry.digest)
            .ok_or_else(|| CredentialError::Malformed("digest must be sha256 hex".into()))?;
        if let Some(signature) = entry.signature.as_ref() {
            let normalized = signature.trim().to_ascii_lowercase();
            if normalized.len() != 128 || !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(CredentialError::Malformed(
                    "signature must be 64-byte Ed25519 hex".into(),
                ));
            }
            entry.signature = Some(normalized);
        }
        Ok(entry)
    }

    /// 验签（仅在 `require_signature` 时）。
    fn check_signature(&self, entry: &CredentialEntry) -> Result<(), CredentialError> {
        if !self.params.require_signature {
            return Ok(());
        }
        let Some(signature) = entry.signature.as_deref() else {
            return Err(CredentialError::BadSignature);
        };
        if crate::signing::verify(entry, signature, &self.params.issuer_public_keys) {
            Ok(())
        } else {
            Err(CredentialError::BadSignature)
        }
    }

    /// D9 的裁剪：roles ∩ known_roles、TTL 取 min、resources 可选取交集。
    ///
    /// 只用于**使用**（回告 / 验证），不写回磁盘，所以不影响签名。
    fn effective_entry(&self, entry: &CredentialEntry) -> CredentialEntry {
        let mut entry = entry.clone();
        entry.signature = None;
        entry
            .roles
            .retain(|role| self.params.known_roles.iter().any(|known| known == role));
        entry.roles.sort_unstable();
        entry.roles.dedup();

        if let Some(cap) = entry
            .roles
            .iter()
            .filter_map(|role| self.params.max_ttl_by_role.get(role).copied())
            .min()
        {
            // 上限相对**签发时间**，不是相对“现在”：否则每次加载 / 每次验证都会把
            // 过期时间往后推，TTL 上限就形同虚设。
            let ceiling = entry.issued_at + cap;
            if entry.expires_at > ceiling {
                entry.expires_at = ceiling;
            }
        }

        if let Some(visible) = &self.params.visible_resources {
            let mut kept: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for (kind, values) in &entry.resources {
                let Some(allowed) = visible.get(kind) else {
                    continue;
                };
                let values: Vec<String> = values
                    .iter()
                    .filter(|value| allowed.iter().any(|item| item == *value))
                    .cloned()
                    .collect();
                if !values.is_empty() {
                    kept.insert(kind.clone(), values);
                }
            }
            entry.resources = kept;
        }
        entry
    }

    fn upsert(&self, state: &mut FileData, entry: CredentialEntry) {
        match state
            .credentials
            .iter_mut()
            .find(|item| item.credential_id == entry.credential_id)
        {
            Some(slot) => *slot = entry,
            None => state.credentials.push(entry),
        }
    }

    fn persist(&self, state: &FileData) -> Result<(), CredentialError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            fs::create_dir_all(parent)
                .map_err(|err| CredentialError::Store(format!("mkdir {parent:?}: {err}")))?;
        }
        let text = serde_json::to_string_pretty(state)
            .map_err(|err| CredentialError::Store(format!("serialize: {err}")))?;
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, text)
            .map_err(|err| CredentialError::Store(format!("write {}: {err}", tmp.display())))?;
        set_perms(&tmp)?;
        fs::rename(&tmp, path)
            .map_err(|err| CredentialError::Store(format!("rename {}: {err}", path.display())))?;
        Ok(())
    }

    fn read_state(&self) -> std::sync::RwLockReadGuard<'_, FileData> {
        self.state.read().unwrap_or_else(|err| err.into_inner())
    }

    fn write_state(&self) -> std::sync::RwLockWriteGuard<'_, FileData> {
        self.state.write().unwrap_or_else(|err| err.into_inner())
    }
}

/// `sha256:<hex>` 或 `<hex>` → 小写 hex；不是 64 位十六进制则返回 `None`。
fn normalize_digest(raw: &str) -> Option<String> {
    let hex = raw
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(raw.trim())
        .to_ascii_lowercase();
    if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hex)
    } else {
        None
    }
}

/// 登记表本身不是秘密，但角色/资源范围属于运维信息：`0640`。
#[cfg(unix)]
fn set_perms(path: &Path) -> Result<(), CredentialError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o640))
        .map_err(|err| CredentialError::Store(format!("chmod {}: {err}", path.display())))
}

#[cfg(not(unix))]
fn set_perms(_path: &Path) -> Result<(), CredentialError> {
    Ok(())
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "wcr_test_token_value";

    fn params() -> StoreParams {
        let mut caps = BTreeMap::new();
        caps.insert("read".to_string(), 3_600);
        caps.insert("investigation:run".to_string(), 86_400);
        StoreParams {
            known_roles: vec!["read".to_string(), "investigation:run".to_string()],
            max_ttl_by_role: caps,
            visible_resources: None,
            clock_skew_seconds: 60,
            require_signature: false,
            issuer_public_keys: Vec::new(),
        }
    }

    fn entry(revision: u64) -> CredentialEntry {
        let now = now_secs();
        CredentialEntry {
            credential_id: "cred_1".to_string(),
            digest: format!("sha256:{}", sha256_hex(TOKEN)),
            subject: "ci-nightly".to_string(),
            roles: vec!["investigation:run".to_string(), "unknown:role".to_string()],
            resources: BTreeMap::new(),
            audience: "wist-center".to_string(),
            issued_at: now,
            expires_at: now + 10_000,
            revision,
            revoked_at: None,
            signature: None,
        }
    }

    #[test]
    fn register_then_verify_succeeds_and_trims_roles() {
        let store = CredentialStore::in_memory(params());
        let effective = store.register(entry(1)).expect("register");
        assert_eq!(effective.roles, vec!["investigation:run".to_string()]);

        let verified = store.verify(TOKEN, "wist-center").expect("verify");
        assert_eq!(verified.subject, "ci-nightly");
        assert_eq!(verified.roles, vec!["investigation:run".to_string()]);
    }

    #[test]
    fn verify_unknown_token_fails() {
        let store = CredentialStore::in_memory(params());
        store.register(entry(1)).unwrap();
        assert_eq!(
            store.verify("wcr_nope", "wist-center").unwrap_err(),
            CredentialError::Unknown
        );
    }

    #[test]
    fn verify_wrong_audience_fails() {
        let store = CredentialStore::in_memory(params());
        store.register(entry(1)).unwrap();
        let error = store.verify(TOKEN, "wist-ingest").unwrap_err();
        assert_eq!(
            error,
            CredentialError::WrongAudience {
                expected: "wist-ingest".to_string(),
                actual: "wist-center".to_string(),
            }
        );
        assert_eq!(error.status(), 400);
    }

    #[test]
    fn revoked_token_fails() {
        let store = CredentialStore::in_memory(params());
        store.register(entry(1)).unwrap();
        store
            .revoke("cred_1", 2, now_secs(), None)
            .unwrap()
            .expect("revoked");
        assert_eq!(
            store.verify(TOKEN, "wist-center").unwrap_err(),
            CredentialError::Revoked
        );
    }

    #[test]
    fn revoke_is_idempotent() {
        let store = CredentialStore::in_memory(params());
        store.register(entry(1)).unwrap();
        let first = store
            .revoke("cred_1", 2, 1_000, None)
            .unwrap()
            .expect("revoked");
        let second = store
            .revoke("cred_1", 3, 2_000, None)
            .unwrap()
            .expect("revoked");
        assert_eq!(first.revoked_at, Some(1_000));
        assert_eq!(
            second.revoked_at,
            Some(1_000),
            "second revoke must not move the time"
        );
    }

    #[test]
    fn stale_register_is_rejected() {
        let store = CredentialStore::in_memory(params());
        store.register(entry(2)).unwrap();
        let error = store.register(entry(1)).unwrap_err();
        assert_eq!(
            error,
            CredentialError::RevisionStale {
                current: 2,
                incoming: 1
            }
        );
        assert_eq!(error.status(), 409);
    }

    #[test]
    fn late_low_revision_register_cannot_resurrect_a_revoked_credential() {
        let store = CredentialStore::in_memory(params());
        store.register(entry(1)).unwrap();
        store.revoke("cred_1", 2, now_secs(), None).unwrap();
        // 迟到的 register 带着低 revision，必须被挡住
        let error = store.register(entry(1)).unwrap_err();
        assert!(matches!(error, CredentialError::RevisionStale { .. }));
        assert_eq!(
            store.verify(TOKEN, "wist-center").unwrap_err(),
            CredentialError::Revoked
        );
    }

    #[test]
    fn expired_token_fails() {
        let store = CredentialStore::in_memory(params());
        let mut expired = entry(1);
        expired.issued_at = now_secs() - 10_000;
        expired.expires_at = now_secs() - 3_600;
        store.register(expired).unwrap();
        assert_eq!(
            store.verify(TOKEN, "wist-center").unwrap_err(),
            CredentialError::Expired
        );
    }

    #[test]
    fn ttl_is_clamped_by_role_cap() {
        let store = CredentialStore::in_memory(params());
        let mut long = entry(1);
        long.issued_at = now_secs();
        long.expires_at = now_secs() + 999_999;
        let effective = store.register(long).unwrap();
        let cap = now_secs() + 86_400;
        assert!(
            effective.expires_at <= cap + 2,
            "expires_at={}",
            effective.expires_at
        );
    }

    #[test]
    fn resources_are_intersected_when_visibility_is_configured() {
        let mut params = params();
        let mut visible = BTreeMap::new();
        visible.insert("agents".to_string(), vec!["agent-7f3".to_string()]);
        params.visible_resources = Some(visible);

        let store = CredentialStore::in_memory(params);
        let mut entry = entry(1);
        entry.resources.insert(
            "agents".to_string(),
            vec!["agent-7f3".to_string(), "agent-9a1".to_string()],
        );
        entry
            .resources
            .insert("gateways".to_string(), vec!["gw-001".to_string()]);

        let effective = store.register(entry).unwrap();
        assert_eq!(
            effective.resources.get("agents"),
            Some(&vec!["agent-7f3".to_string()])
        );
        assert!(!effective.resources.contains_key("gateways"));
    }

    #[test]
    fn bare_hex_digest_is_accepted_and_normalized() {
        let store = CredentialStore::in_memory(params());
        let mut entry = entry(1);
        entry.digest = sha256_hex(TOKEN).to_ascii_uppercase();
        let effective = store.register(entry).unwrap();
        assert_eq!(effective.digest, sha256_hex(TOKEN));
        assert!(store.verify(TOKEN, "wist-center").is_ok());
    }

    #[test]
    fn rejects_non_sha256_digest() {
        let store = CredentialStore::in_memory(params());
        let mut entry = entry(1);
        entry.digest = "md5:abcd".to_string();
        assert!(matches!(
            store.register(entry).unwrap_err(),
            CredentialError::Malformed(_)
        ));
    }

    #[test]
    fn persists_and_reloads() {
        let dir = std::env::temp_dir().join(format!("wist-auth-cred-{}", std::process::id()));
        let path = dir.join("credentials.json");
        let _ = fs::remove_dir_all(&dir);

        {
            let store = CredentialStore::open(&path, params()).unwrap();
            store.register(entry(1)).unwrap();
        }
        let reloaded = CredentialStore::open(&path, params()).unwrap();
        assert!(reloaded.verify(TOKEN, "wist-center").is_ok());

        // 落盘只有摘要，没有明文
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains(TOKEN));
        assert!(text.contains(&sha256_hex(TOKEN)));

        let _ = fs::remove_dir_all(&dir);
    }

    /// 让 `persist` 注定失败：用一个同名目录占住 `<file>.tmp`。
    fn blocked_store(tag: &str) -> (PathBuf, PathBuf, CredentialStore) {
        let dir = std::env::temp_dir().join(format!(
            "wist-auth-cred-blocked-{tag}-{}",
            std::process::id()
        ));
        let path = dir.join("credentials.json");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let store = CredentialStore::open(&path, params()).unwrap();
        fs::create_dir(path.with_extension("tmp")).unwrap();
        (dir, path, store)
    }

    #[test]
    fn a_failed_persist_rolls_back_a_registration() {
        // 落盘失败时不能“内存里已经生效”：否则 C 认为没交付，重启后它又消失。
        let (dir, _path, store) = blocked_store("register");
        let error = store.register(entry(1)).expect_err("persist must fail");
        assert!(matches!(error, CredentialError::Store(_)), "{error:?}");
        assert!(
            store.entries().is_empty(),
            "registration must be rolled back"
        );
        assert!(store.verify(TOKEN, "wist-center").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_persist_rolls_back_a_revocation() {
        // 更严重的一条：内存已撤、磁盘没撤 → 重启后 token 复活，而 C 已认为撤成功。
        let (dir, path, store) = blocked_store("revoke");
        let tmp = path.with_extension("tmp");
        fs::remove_dir(&tmp).unwrap();
        store.register(entry(1)).expect("register");
        fs::create_dir(&tmp).unwrap(); // 从这里开始落盘失败

        let error = store
            .revoke("cred_1", 2, now_secs(), None)
            .expect_err("persist must fail");
        assert!(matches!(error, CredentialError::Store(_)), "{error:?}");
        let kept = &store.entries()[0];
        assert_eq!(kept.revoked_at, None, "revocation must be rolled back");
        assert_eq!(kept.revision, 1);
        assert!(store.verify(TOKEN, "wist-center").is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    // ── 签名（Ed25519）：授权内容被改过就必须被发现 ──────────────────────────

    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;

    use crate::signing::{public_key_from_pkcs8, sign};

    /// 生成一对 Ed25519 钥：返回 `(PKCS#8 私钥, 裸公钥)`。
    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("keypair");
        let public = public_key_from_pkcs8(pkcs8.as_ref()).expect("public");
        (pkcs8.as_ref().to_vec(), public)
    }

    fn signed_params(public: Vec<u8>) -> StoreParams {
        StoreParams {
            require_signature: true,
            issuer_public_keys: vec![public],
            ..params()
        }
    }

    fn signed_entry(revision: u64, private_key: &[u8]) -> CredentialEntry {
        let mut entry = entry(revision);
        // 与真实推送一致：落盘前 digest 已经是裸 hex。
        entry.digest = normalize_digest(&entry.digest).expect("digest");
        entry.signature = Some(sign(&entry, private_key).expect("sign"));
        entry
    }

    #[test]
    fn unsigned_entry_is_rejected_when_a_signature_is_required() {
        let (_, public) = keypair();
        let store = CredentialStore::in_memory(signed_params(public));
        let error = store.register(entry(1)).expect_err("must reject");
        assert_eq!(error, CredentialError::BadSignature);
        assert!(store.entries().is_empty());
    }

    #[test]
    fn signed_entry_is_accepted_and_roles_are_still_trimmed_at_use() {
        let (private, public) = keypair();
        let store = CredentialStore::in_memory(signed_params(public));
        store.register(signed_entry(1, &private)).expect("register");
        let verified = store.verify(TOKEN, "wist-center").expect("verify");
        // 存的是原始记录，验证时应用本服务策略：未知角色被裁掉。
        assert_eq!(verified.roles, vec!["investigation:run".to_string()]);
    }

    #[test]
    fn tampering_with_roles_is_detected_on_load() {
        let (private, public) = keypair();
        let dir = std::env::temp_dir().join(format!(
            "wist-auth-sig-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("credentials.json");

        // 一份带合法签名的记录。
        let signed = signed_entry(1, &private);
        let file = FileData {
            revision: 1,
            credentials: vec![signed.clone()],
        };
        fs::write(&path, serde_json::to_string_pretty(&file).unwrap()).unwrap();
        let store = CredentialStore::open(&path, signed_params(public.clone())).expect("open");
        assert_eq!(store.rejected_on_load(), 0);
        assert!(store.verify(TOKEN, "wist-center").is_ok());
        drop(store);

        // 改磁盘上的角色（签名不变）：加载时必须丢弃。
        let mut tampered = signed;
        tampered.roles.push("read".to_string());
        let file = FileData {
            revision: 1,
            credentials: vec![tampered],
        };
        fs::write(&path, serde_json::to_string_pretty(&file).unwrap()).unwrap();
        let store = CredentialStore::open(&path, signed_params(public)).expect("open");
        assert_eq!(store.rejected_on_load(), 1);
        assert!(store.entries().is_empty());
        assert_eq!(
            store.verify(TOKEN, "wist-center").unwrap_err(),
            CredentialError::Unknown
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn extending_the_expiry_is_detected_on_load() {
        let (private, public) = keypair();
        let signed = signed_entry(1, &private);
        let mut tampered = signed.clone();
        tampered.expires_at = signed.expires_at + 10 * 365 * 24 * 3600;

        let dir = std::env::temp_dir().join(format!(
            "wist-auth-sig-exp-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("credentials.json");
        let file = FileData {
            revision: 1,
            credentials: vec![tampered],
        };
        fs::write(&path, serde_json::to_string_pretty(&file).unwrap()).unwrap();
        let store = CredentialStore::open(&path, signed_params(public)).expect("open");
        assert_eq!(store.rejected_on_load(), 1);
        assert!(store.entries().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn revoke_requires_a_signature_over_the_revoked_record() {
        let (private, public) = keypair();
        let store = CredentialStore::in_memory(signed_params(public));
        store.register(signed_entry(1, &private)).expect("register");

        // 不带签名：拒。
        let error = store
            .revoke("cred_1", 2, 1_000, None)
            .expect_err("must reject");
        assert_eq!(error, CredentialError::BadSignature);

        // 用旧签名（覆盖的是未撤销状态）：拒。
        let stale = store.entries()[0].signature.clone();
        let error = store
            .revoke("cred_1", 2, 1_000, stale)
            .expect_err("must reject");
        assert_eq!(error, CredentialError::BadSignature);

        // 对“已撤销”的记录重新签名：通过。
        let mut revoked = store.entries()[0].clone();
        revoked.revoked_at = Some(1_000);
        revoked.revision = 2;
        revoked.signature = Some(sign(&revoked, &private).expect("sign"));
        let done = store
            .revoke("cred_1", 2, 1_000, revoked.signature.clone())
            .expect("revoke")
            .expect("present");
        assert_eq!(done.revoked_at, Some(1_000));
        assert_eq!(
            store.verify(TOKEN, "wist-center").unwrap_err(),
            CredentialError::Revoked
        );
    }

    fn temp_store_file(
        tag: &str,
        entries: Vec<CredentialEntry>,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "wist-auth-sig-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("credentials.json");
        let file = FileData {
            revision: 1,
            credentials: entries,
        };
        fs::write(&path, serde_json::to_string_pretty(&file).unwrap()).unwrap();
        (dir, path)
    }

    #[test]
    fn substituting_the_digest_is_detected_on_load() {
        // 最关键的一条：把摘要换成攻击者自己的 token，签名必须不成立。
        let (private, public) = keypair();
        let mut tampered = signed_entry(1, &private);
        tampered.digest = "bb".repeat(32);

        let (dir, path) = temp_store_file("digest", vec![tampered]);
        let store = CredentialStore::open(&path, signed_params(public)).expect("open");
        assert_eq!(store.rejected_on_load(), 1);
        assert!(store.entries().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn un_revoking_on_disk_is_detected_on_load() {
        // 把 revoked_at 改回 null、却留着“已撤销”的签名：必须被发现。
        let (private, public) = keypair();
        let mut revoked = signed_entry(1, &private);
        revoked.revoked_at = Some(1_000);
        revoked.revision = 2;
        revoked.signature = Some(sign(&revoked, &private).expect("sign"));

        // 合法状态：能加载，且验不过（已撤销）。
        let (dir, path) = temp_store_file("revoked", vec![revoked.clone()]);
        let store = CredentialStore::open(&path, signed_params(public.clone())).expect("open");
        assert_eq!(store.rejected_on_load(), 0);
        assert_eq!(
            store.verify(TOKEN, "wist-center").unwrap_err(),
            CredentialError::Revoked
        );
        drop(store);

        // 篡改：revoked_at 置回 None，签名不动 → 加载时丢弃。
        let mut un_revoked = revoked;
        un_revoked.revoked_at = None;
        fs::write(
            &path,
            serde_json::to_string_pretty(&FileData {
                revision: 1,
                credentials: vec![un_revoked],
            })
            .unwrap(),
        )
        .unwrap();
        let store = CredentialStore::open(&path, signed_params(public)).expect("open");
        assert_eq!(store.rejected_on_load(), 1);
        assert_eq!(
            store.verify(TOKEN, "wist-center").unwrap_err(),
            CredentialError::Unknown
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn multiple_issuer_keys_are_accepted_during_rotation() {
        let (old_private, _old_public) = keypair();
        let (new_private, new_public) = keypair();
        let (_current_private, current_public) = keypair();

        // 新旧两把都信任；旧钥签的记录仍能登记。
        let two_keys = StoreParams {
            require_signature: true,
            issuer_public_keys: vec![current_public.clone(), new_public],
            ..params()
        };
        let store = CredentialStore::in_memory(two_keys);
        store
            .register(signed_entry(1, &new_private))
            .expect("register");

        // 完全不在白名单里的钥：拒。
        let store = CredentialStore::in_memory(StoreParams {
            require_signature: true,
            issuer_public_keys: vec![current_public],
            ..params()
        });
        assert_eq!(
            store
                .register(signed_entry(1, &old_private))
                .expect_err("must reject"),
            CredentialError::BadSignature
        );
    }

    fn assert_tampered_field_is_rejected(
        tag: &str,
        private: &[u8],
        public: Vec<u8>,
        mutate: fn(&mut CredentialEntry),
    ) {
        let mut tampered = signed_entry(1, private);
        mutate(&mut tampered);
        let (dir, path) = temp_store_file(tag, vec![tampered]);
        let store = CredentialStore::open(&path, signed_params(public)).expect("open");
        assert_eq!(store.rejected_on_load(), 1, "{tag} must be rejected");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampering_with_other_authorization_fields_is_detected() {
        let (private, public) = keypair();
        assert_tampered_field_is_rejected("field-subject", &private, public.clone(), |entry| {
            entry.subject = "someone-else".to_string();
        });
        assert_tampered_field_is_rejected("field-audience", &private, public.clone(), |entry| {
            entry.audience = "wist-ingest".to_string();
        });
        assert_tampered_field_is_rejected("field-resources", &private, public, |entry| {
            entry
                .resources
                .insert("agents".to_string(), vec!["agent-x".to_string()]);
        });
    }

    #[test]
    fn a_malformed_signature_is_rejected_at_registration() {
        let (private, public) = keypair();
        let store = CredentialStore::in_memory(signed_params(public));
        let mut broken = signed_entry(1, &private);
        broken.signature = Some("ab".to_string());
        let error = store.register(broken).expect_err("must reject");
        assert!(
            matches!(error, CredentialError::Malformed(_)),
            "unexpected: {error:?}"
        );
    }

    #[test]
    fn unsigned_entries_are_kept_when_signatures_are_not_required() {
        // 升级窗口 / 旧数据：没开验签时，旧的未签名记录照常可用。
        let (dir, path) = temp_store_file("unsigned-compat", vec![entry(1)]);
        let store = CredentialStore::open(
            &path,
            StoreParams {
                require_signature: false,
                issuer_public_keys: Vec::new(),
                ..params()
            },
        )
        .expect("open");
        assert_eq!(store.rejected_on_load(), 0);
        assert!(store.verify(TOKEN, "wist-center").is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_revoke_signed_by_another_key_is_rejected() {
        let (private, public) = keypair();
        let (other_private, _other_public) = keypair();
        let store = CredentialStore::in_memory(signed_params(public));
        store.register(signed_entry(1, &private)).expect("register");

        let mut revoked = store.entries()[0].clone();
        revoked.revoked_at = Some(1_000);
        revoked.revision = 2;
        revoked.signature = Some(sign(&revoked, &other_private).expect("sign"));
        assert_eq!(
            store
                .revoke("cred_1", 2, 1_000, revoked.signature.clone())
                .expect_err("must reject"),
            CredentialError::BadSignature
        );
    }
}
