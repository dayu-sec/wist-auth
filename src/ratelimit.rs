//! 鉴权失败限流：每客户端 N 次失败 / 窗口 → 封禁一段时间。
//!
//! 与 `wist-center/src/api/rate_limit.rs` 同口径（5 次 / 60s → 60s），但 key 由调用方决定：
//! center / ingest 都用 peer IP，且**不信任** `X-Real-IP` / `X-Forwarded-For`。

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const DEFAULT_MAX_FAILURES: u32 = 5;
pub const DEFAULT_FAILURE_WINDOW: Duration = Duration::from_secs(60);
pub const DEFAULT_BLOCK_DURATION: Duration = Duration::from_secs(60);
/// 桶数上限，防止轮换 key 的攻击者无限增长 map；按最旧优先淘汰。
pub const DEFAULT_MAX_BUCKETS: usize = 4096;

#[derive(Debug)]
struct Bucket {
    failures: u32,
    first_failure_at: Instant,
    blocked_until: Option<Instant>,
}

#[derive(Debug)]
pub struct FailureLimiter<K> {
    buckets: Mutex<HashMap<K, Bucket>>,
    max_failures: u32,
    failure_window: Duration,
    block_duration: Duration,
    max_buckets: usize,
}

impl<K> Default for FailureLimiter<K> {
    fn default() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            max_failures: DEFAULT_MAX_FAILURES,
            failure_window: DEFAULT_FAILURE_WINDOW,
            block_duration: DEFAULT_BLOCK_DURATION,
            max_buckets: DEFAULT_MAX_BUCKETS,
        }
    }
}

impl<K> FailureLimiter<K>
where
    K: Eq + Hash + Clone,
{
    /// 覆盖默认阈值（5 次 / 60s → 封 60s）。
    pub fn with(max_failures: u32, failure_window: Duration, block_duration: Duration) -> Self {
        Self {
            max_failures: max_failures.max(1),
            failure_window,
            block_duration,
            ..Self::default()
        }
    }

    /// 已被封禁时返回剩余秒数（≥1）。
    pub fn blocked_for(&self, key: &K) -> Option<u64> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().ok()?;
        let bucket = buckets.get_mut(key)?;
        if now.duration_since(bucket.first_failure_at) > self.failure_window {
            buckets.remove(key);
            return None;
        }
        let blocked_until = bucket.blocked_until?;
        if blocked_until > now {
            Some(blocked_until.duration_since(now).as_secs().max(1))
        } else {
            None
        }
    }

    pub fn record_failure(&self, key: &K) -> u32 {
        let now = Instant::now();
        let Ok(mut buckets) = self.buckets.lock() else {
            return 0;
        };
        if buckets.len() >= self.max_buckets
            && !buckets.contains_key(key)
            && let Some(oldest) = buckets
                .iter()
                .min_by_key(|(_, b)| b.first_failure_at)
                .map(|(k, _)| k.clone())
        {
            buckets.remove(&oldest);
        }
        let bucket = buckets.entry(key.clone()).or_insert(Bucket {
            failures: 0,
            first_failure_at: now,
            blocked_until: None,
        });
        bucket.failures += 1;
        if bucket.failures >= self.max_failures {
            bucket.blocked_until = Some(now + self.block_duration);
        }
        bucket.failures
    }

    pub fn clear(&self, key: &K) {
        if let Ok(mut buckets) = self.buckets.lock() {
            buckets.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_the_threshold() {
        let limiter: FailureLimiter<String> = FailureLimiter::default();
        let key = "1.2.3.4".to_string();
        for _ in 0..DEFAULT_MAX_FAILURES {
            limiter.record_failure(&key);
        }
        assert!(limiter.blocked_for(&key).is_some());
    }

    #[test]
    fn success_clears_failures() {
        let limiter: FailureLimiter<String> = FailureLimiter::default();
        let key = "1.2.3.4".to_string();
        limiter.record_failure(&key);
        limiter.clear(&key);
        for _ in 0..(DEFAULT_MAX_FAILURES - 1) {
            limiter.record_failure(&key);
        }
        assert!(limiter.blocked_for(&key).is_none());
    }

    #[test]
    fn keys_are_independent() {
        let limiter: FailureLimiter<String> = FailureLimiter::default();
        for _ in 0..DEFAULT_MAX_FAILURES {
            limiter.record_failure(&"a".to_string());
        }
        assert!(limiter.blocked_for(&"a".to_string()).is_some());
        assert!(limiter.blocked_for(&"b".to_string()).is_none());
    }

    #[test]
    fn bucket_map_stays_bounded() {
        let limiter: FailureLimiter<String> = FailureLimiter::default();
        for index in 0..(DEFAULT_MAX_BUCKETS + 50) {
            limiter.record_failure(&format!("client-{index}"));
        }
        let tracked = limiter.buckets.lock().expect("lock").len();
        assert!(tracked <= DEFAULT_MAX_BUCKETS, "tracked={tracked}");
    }

    #[test]
    fn custom_threshold_is_honoured() {
        let limiter: FailureLimiter<String> =
            FailureLimiter::with(2, Duration::from_secs(60), Duration::from_secs(30));
        let key = "9.9.9.9".to_string();
        limiter.record_failure(&key);
        assert!(limiter.blocked_for(&key).is_none());
        limiter.record_failure(&key);
        let retry = limiter.blocked_for(&key).expect("blocked");
        assert!(retry <= 30);
    }
}
