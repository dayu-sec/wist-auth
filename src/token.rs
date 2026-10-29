use http::HeaderMap;

/// 从 `Authorization: Bearer <token>` 取 token（空串视为缺失）。
///
/// 与 wist-center / wist-gateway 的行为保持一致：**scheme 区分大小写**（必须是
/// `Bearer ` 前缀），token 两端空白会被裁掉。RFC 7235 说 scheme 不区分大小写，
/// 但这里刻意沿用既有服务的口径 —— 行为变更要先改三个服务，不能只改这里。
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

/// 明文 token 是否匹配已存的 sha256 hex（常数时间，摘要大小写不敏感）。
pub fn token_matches(presented: &str, expected_hash: &str) -> bool {
    if expected_hash.len() != 64 {
        // 长度不对的直接 false；仍然走一次常数时间比较，避免早退泄漏"格式对不对"。
        let _ = constant_time_eq(sha256_hex(presented).as_bytes(), expected_hash.as_bytes());
        return false;
    }
    constant_time_eq(
        sha256_hex(presented).as_bytes(),
        expected_hash.to_ascii_lowercase().as_bytes(),
    )
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

    fn header(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(value).expect("header"),
        );
        headers
    }

    #[test]
    fn hashes_are_lowercase_hex() {
        let hash = sha256_hex("abc");
        assert_eq!(hash.len(), 64);
        assert!(
            hash.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn known_vector_matches_sha256() {
        // `sha256("abc")` 的标准向量，防止实现被无意换掉。
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn extracts_bearer_token() {
        assert_eq!(bearer_token(&header("Bearer secret")), Some("secret"));
        assert_eq!(bearer_token(&header("Bearer   secret  ")), Some("secret"));
    }

    #[test]
    fn rejects_other_schemes() {
        for raw in [
            "Basic abc",
            "bearer abc",
            "BEARER abc",
            "Bearer",
            "Bearer ",
            "",
        ] {
            assert_eq!(bearer_token(&header(raw)), None, "raw={raw:?}");
        }
    }

    #[test]
    fn missing_header_is_none() {
        assert_eq!(bearer_token(&HeaderMap::new()), None);
    }

    #[test]
    fn non_utf8_header_is_none() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_bytes(b"Bearer \xFF").expect("header"),
        );
        assert_eq!(bearer_token(&headers), None);
    }

    #[test]
    fn token_matches_only_the_same_secret() {
        let hash = sha256_hex("s3cret");
        assert!(token_matches("s3cret", &hash));
        assert!(!token_matches("s3cret ", &hash));
        assert!(!token_matches("S3cret", &hash));
        assert!(!token_matches("", &hash));
    }

    #[test]
    fn token_matches_is_case_insensitive_on_the_stored_hash() {
        let hash = sha256_hex("s3cret").to_ascii_uppercase();
        assert!(token_matches("s3cret", &hash));
    }

    #[test]
    fn token_matches_rejects_malformed_hashes() {
        for bad in ["", "abc", "zzzz", &"a".repeat(63), &"a".repeat(65)] {
            assert!(!token_matches("s3cret", bad), "accepted {bad:?}");
        }
    }

    #[test]
    fn constant_time_eq_handles_length_mismatch() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }
}
