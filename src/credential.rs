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
    /// 落盘 / 读盘失败。
    Store(String),
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
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            CredentialError::WrongAudience { .. } => 400,
            CredentialError::RevisionStale { .. } => 409,
            CredentialError::Store(_) => 503,
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
}

impl CredentialStore {
    /// 从落盘文件加载（不存在则视作空表）。加载时**同样应用裁剪**，但它只是种子：
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
        let store = Self {
            path: Some(path),
            params,
            state: RwLock::new(FileData::default()),
        };
        {
            let mut state = store.write_state();
            for entry in data.credentials {
                let effective = store.trim(entry);
                store.upsert(&mut state, effective);
            }
            state.revision = data.revision;
        }
        Ok(store)
    }

    pub fn in_memory(params: StoreParams) -> Self {
        Self {
            path: None,
            params,
            state: RwLock::new(FileData::default()),
        }
    }

    /// 登记一条凭据，返回**裁剪后的实际生效值**（对应 `register` 的 `effective` 回告）。
    ///
    /// 落盘失败会**回滚内存**：否则会变成“X 在验、C 以为没交付、重启后又消失”。
    pub fn register(&self, entry: CredentialEntry) -> Result<CredentialEntry, CredentialError> {
        let entry = self.normalize(entry)?;
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
        let effective = self.trim(entry);
        let slot = state
            .credentials
            .iter()
            .position(|item| item.credential_id == effective.credential_id);
        let previous = slot.map(|index| state.credentials[index].clone());
        let previous_revision = state.revision;

        self.upsert(&mut state, effective.clone());
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
        state.credentials[index].revoked_at = Some(at);
        state.credentials[index].revision = revision;
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
        if now_secs() > entry.expires_at + self.params.skew() {
            return Err(CredentialError::Expired);
        }
        Ok(VerifiedCredential {
            credential_id: entry.credential_id.clone(),
            subject: entry.subject.clone(),
            roles: entry.roles.clone(),
            resources: entry.resources.clone(),
            audience: entry.audience.clone(),
            expires_at: entry.expires_at,
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
        Ok(entry)
    }

    /// D9 的裁剪：roles ∩ known_roles、TTL 取 min、resources 可选取交集。
    fn trim(&self, mut entry: CredentialEntry) -> CredentialEntry {
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
            let ceiling = now_secs() + cap;
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
            .revoke("cred_1", 2, now_secs())
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
        let first = store.revoke("cred_1", 2, 1_000).unwrap().expect("revoked");
        let second = store.revoke("cred_1", 3, 2_000).unwrap().expect("revoked");
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
        store.revoke("cred_1", 2, now_secs()).unwrap();
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
            .revoke("cred_1", 2, now_secs())
            .expect_err("persist must fail");
        assert!(matches!(error, CredentialError::Store(_)), "{error:?}");
        let kept = &store.entries()[0];
        assert_eq!(kept.revoked_at, None, "revocation must be rolled back");
        assert_eq!(kept.revision, 1);
        assert!(store.verify(TOKEN, "wist-center").is_ok());
        let _ = fs::remove_dir_all(&dir);
    }
}
