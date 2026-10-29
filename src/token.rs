use http::HeaderMap;

/// 从 `Authorization: Bearer <token>` 取 token（空串视为缺失）。
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// 与 center 的 `admin_token_hash` 同口径：sha256 小写 hex。
pub fn sha256_hex(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// 明文 token 是否匹配已存的 sha256 hex（常数时间）。
pub fn token_matches(presented: &str, expected_hash: &str) -> bool {
    constant_time_eq(sha256_hex(presented).as_bytes(), expected_hash.as_bytes())
}

/// 常数时间比较（长度也参与比较）。用于比较两个已计算的 hex 摘要。
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= (left_byte ^ right_byte) as usize;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_lowercase_hex() {
        let hash = sha256_hex("abc");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn extracts_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer secret"),
        );
        assert_eq!(bearer_token(&headers), Some("secret"));
    }

    #[test]
    fn rejects_other_schemes() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Basic abc"),
        );
        assert_eq!(bearer_token(&headers), None);
    }
}
