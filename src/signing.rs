//! 授权记录的**签名契约**（Ed25519）。
//!
//! 谁签：签发方（`wist-cred`）。谁验：验证方（X）。签的是**授权内容本身**：
//! 凭据指纹、主体、角色、资源、受众、有效期、版本号、撤销状态。
//!
//! 为什么必须有它：登记表落盘后可被改。没有签名，改 `roles` / `expires_at` /
//! 清掉 `revoked_at` 就能凭空提权；有了签名，验证方在**收到时**和**从磁盘加载时**
//! 各验一次，改过的记录直接丢弃。
//!
//! ## 规范字节（唯一契约）
//!
//! 签发与验证必须用同一份字节。为了避免字段里出现分隔符导致歧义，每个字段都写成
//! `<长度>:<内容>\n`；角色与资源按确定顺序排列（排序 + 去重）。
//! 固定顺序见 [`canonical_message`]。
//!
//! ## 它挡不住什么
//!
//! **回放**：把一份旧的、签名仍然有效的记录（比如撤销前的版本）恢复回来，签名能过。
//! 处置靠「撤销墓碑 + 单调 revision」：撤销记录不删；验证方只接受更高 revision 的推送。
//! 整目录回滚的检测需要外部锚点（签发方的当前版本），不在本模块范围内。

use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

use crate::credential::CredentialEntry;

/// 规范串的版本前缀。改契约必须换版本号，否则新旧两端会各说各话。
pub const SIGNATURE_VERSION: &str = "wist-cred-sig-v1";

/// 把一条授权记录折成**可签名的规范字节**。
///
/// 不含 `signature` 字段本身（避免自引用），也不含任何展示字段。
pub fn canonical_message(entry: &CredentialEntry) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    field(&mut out, SIGNATURE_VERSION.as_bytes());
    field(&mut out, entry.credential_id.as_bytes());
    field(&mut out, normalize_digest(&entry.digest).as_bytes());
    field(&mut out, entry.subject.as_bytes());
    field(&mut out, entry.audience.as_bytes());
    field(&mut out, entry.issued_at.to_string().as_bytes());
    field(&mut out, entry.expires_at.to_string().as_bytes());
    field(&mut out, entry.revision.to_string().as_bytes());
    match entry.revoked_at {
        Some(at) => field(&mut out, at.to_string().as_bytes()),
        None => field(&mut out, b"-"),
    }

    let mut roles = entry.roles.clone();
    roles.sort_unstable();
    roles.dedup();
    field(&mut out, roles.len().to_string().as_bytes());
    for role in &roles {
        field(&mut out, role.as_bytes());
    }

    // `BTreeMap` 的键本身有序；每个值再排序，避免推送方顺序不同导致签名不匹配。
    field(&mut out, entry.resources.len().to_string().as_bytes());
    for (kind, values) in &entry.resources {
        field(&mut out, kind.as_bytes());
        let mut values = values.clone();
        values.sort_unstable();
        values.dedup();
        field(&mut out, values.len().to_string().as_bytes());
        for value in &values {
            field(&mut out, value.as_bytes());
        }
    }
    out
}

/// 用 PKCS#8 私钥（PEM/DER 的 DER 部分）签一条记录，返回小写 hex。
pub fn sign(entry: &CredentialEntry, private_key_pkcs8: &[u8]) -> Result<String, String> {
    // OpenSSL `genpkey -algorithm ed25519` 产出 PKCS#8 **v1**（不含公钥）；
    // ring 的 `from_pkcs8` 只收 v2，所以这里用 v1/v2 都收的入口。
    let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(private_key_pkcs8)
        .map_err(|err| format!("invalid Ed25519 private key: {err}"))?;
    Ok(encode_hex(pair.sign(&canonical_message(entry)).as_ref()))
}

/// 验一条记录。`public_keys` 里任意一把验过即通过（支持轮换期同时信任新旧钥）。
///
/// **失败即视为不可信**：调用方应当拒收（register）或丢弃（加载）。
pub fn verify(entry: &CredentialEntry, signature_hex: &str, public_keys: &[Vec<u8>]) -> bool {
    let Some(signature) = decode_hex(signature_hex) else {
        return false;
    };
    if signature.len() != 64 || public_keys.is_empty() {
        return false;
    }
    let message = canonical_message(entry);
    public_keys.iter().any(|key| {
        key.len() == 32
            && UnparsedPublicKey::new(&ED25519, key)
                .verify(&message, &signature)
                .is_ok()
    })
}

/// 从 PKCS#8 私钥导出裸公钥（32 字节），用于随接入包分发给验证方。
pub fn public_key_from_pkcs8(private_key_pkcs8: &[u8]) -> Result<Vec<u8>, String> {
    let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(private_key_pkcs8)
        .map_err(|err| format!("invalid Ed25519 private key: {err}"))?;
    Ok(pair.public_key().as_ref().to_vec())
}

/// 公钥文件的文本格式：32 字节裸公钥的小写 hex（允许前后空白）。
pub fn parse_public_key_hex(text: &str) -> Result<Vec<u8>, String> {
    let key = decode_hex(text.trim()).ok_or_else(|| "public key must be hex".to_string())?;
    if key.len() != 32 {
        return Err(format!(
            "Ed25519 public key must be 32 bytes, got {}",
            key.len()
        ));
    }
    Ok(key)
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let high = hex_value(bytes[index])?;
        let low = hex_value(bytes[index + 1])?;
        out.push((high << 4) | low);
        index += 2;
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(value.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(value);
    out.push(b'\n');
}

fn normalize_digest(raw: &str) -> String {
    raw.trim()
        .strip_prefix("sha256:")
        .unwrap_or(raw.trim())
        .to_ascii_lowercase()
}
