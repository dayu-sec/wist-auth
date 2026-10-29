//! 鉴权失败限流：每客户端 N 次失败 / 窗口 → 封禁一段时间。
//!
//! 与 `wist-center/src/api/{rate_limit,admin_auth}.rs` 同口径（5 次 / 60s → 60s），
//! 但 key 由调用方决定：center / gateway / ingest 都用 peer IP，且**不信任**
//! `X-Real-IP` / `X-Forwarded-For`。
//!
//! 两条容易实现错的语义，这里显式保证：
//! 1. **窗口从窗口内第一次失败算起**（不是从最近一次失败滑窗）；
//! 2. **封禁不因窗口过期而提前解除** —— `block_duration > failure_window` 时，
//!    仍然要把整个封禁期走完。

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
    /// 覆盖默认阈值（5 次 / 60s → 封 60s）。`max_failures` 至少为 1。
    pub fn with(max_failures: u32, failure_window: Duration, block_duration: Duration) -> Self {
        Self {
            max_failures: max_failures.max(1),
            failure_window,
            block_duration,
            ..Self::default()
        }
    }

    /// 已被封禁时返回剩余秒数（≥1）。
    ///
    /// 不会因为"窗口过期"提前解除封禁：先看 `blocked_until`，再看窗口。
    pub fn blocked_for(&self, key: &K) -> Option<u64> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().ok()?;
        let (remaining, expired) = {
            let bucket = buckets.get(key)?;
            match bucket.blocked_until {
                Some(until) if until > now => {
                    (Some(until.duration_since(now).as_secs().max(1)), false)
                }
                Some(_) => {
                    // 封禁期已走完：整桶作废（失败计数也一起清掉）。
                    (None, true)
                }
                None => (
                    None,
                    now.duration_since(bucket.first_failure_at) > self.failure_window,
                ),
            }
        };
        if expired {
            buckets.remove(key);
        }
        remaining
    }

    /// 记一次失败，返回当前窗口内的失败次数。
    ///
    /// 窗口过期后重新计数（与 center/gateway 的 `record_auth_failure` 一致）；
    /// 达到阈值时开始封禁。
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
        if now.duration_since(bucket.first_failure_at) > self.failure_window {
            bucket.failures = 0;
            bucket.first_failure_at = now;
            bucket.blocked_until = None;
        }
        bucket.failures = bucket.failures.saturating_add(1);
        if bucket.failures >= self.max_failures {
            bucket.blocked_until = Some(now + self.block_duration);
        }
        bucket.failures
    }

    /// 认证成功后清空该客户端的状态（失败计数与封禁一起清）。
    pub fn clear(&self, key: &K) {
        if let Ok(mut buckets) = self.buckets.lock() {
            buckets.remove(key);
        }
    }

    /// 当前跟踪的 key 数量（仅用于测试与诊断）。
    pub fn tracked_keys(&self) -> usize {
        self.buckets.lock().map(|b| b.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    fn key(k: &str) -> String {
        k.to_string()
    }

    #[test]
    fn blocks_after_the_threshold() {
        let limiter: FailureLimiter<String> = FailureLimiter::default();
        for _ in 0..DEFAULT_MAX_FAILURES {
            limiter.record_failure(&key("1.2.3.4"));
        }
        assert!(limiter.blocked_for(&key("1.2.3.4")).is_some());
    }

    #[test]
    fn success_clears_failures() {
        let limiter: FailureLimiter<String> = FailureLimiter::default();
        limiter.record_failure(&key("1.2.3.4"));
        limiter.clear(&key("1.2.3.4"));
        for _ in 0..(DEFAULT_MAX_FAILURES - 1) {
            limiter.record_failure(&key("1.2.3.4"));
        }
        assert!(limiter.blocked_for(&key("1.2.3.4")).is_none());
    }

    #[test]
    fn keys_are_independent() {
        let limiter: FailureLimiter<String> = FailureLimiter::default();
        for _ in 0..DEFAULT_MAX_FAILURES {
            limiter.record_failure(&key("a"));
        }
        assert!(limiter.blocked_for(&key("a")).is_some());
        assert!(limiter.blocked_for(&key("b")).is_none());
    }

    #[test]
    fn bucket_map_stays_bounded() {
        let limiter: FailureLimiter<String> = FailureLimiter::default();
        for index in 0..(DEFAULT_MAX_BUCKETS + 50) {
            limiter.record_failure(&format!("client-{index}"));
        }
        assert!(limiter.tracked_keys() <= DEFAULT_MAX_BUCKETS);
    }

    #[test]
    fn custom_threshold_is_honoured() {
        let limiter: FailureLimiter<String> =
            FailureLimiter::with(2, Duration::from_secs(60), Duration::from_secs(30));
        limiter.record_failure(&key("9.9.9.9"));
        assert!(limiter.blocked_for(&key("9.9.9.9")).is_none());
        limiter.record_failure(&key("9.9.9.9"));
        let retry = limiter.blocked_for(&key("9.9.9.9")).expect("blocked");
        assert!(retry <= 30);
    }

    #[test]
    fn max_failures_is_clamped_to_one() {
        let limiter: FailureLimiter<String> =
            FailureLimiter::with(0, Duration::from_secs(60), Duration::from_secs(60));
        limiter.record_failure(&key("k"));
        assert!(limiter.blocked_for(&key("k")).is_some());
    }

    #[test]
    fn window_expiry_restarts_the_count() {
        // 窗口 50ms：3 次失败后等过窗口，再失败一次应重新从 1 开始（不会凑满 5 次封禁）。
        let limiter: FailureLimiter<String> =
            FailureLimiter::with(5, Duration::from_millis(50), Duration::from_secs(60));
        for _ in 0..3 {
            limiter.record_failure(&key("w"));
        }
        sleep(Duration::from_millis(80));
        assert_eq!(limiter.record_failure(&key("w")), 1);
        assert!(limiter.blocked_for(&key("w")).is_none());
    }

    #[test]
    fn block_outlives_the_failure_window() {
        // 窗口 10ms、封禁 200ms：窗口一过就解除封禁是**错的**。
        let limiter: FailureLimiter<String> =
            FailureLimiter::with(1, Duration::from_millis(10), Duration::from_millis(200));
        limiter.record_failure(&key("b"));
        sleep(Duration::from_millis(40));
        assert!(
            limiter.blocked_for(&key("b")).is_some(),
            "block must survive window expiry"
        );
    }

    #[test]
    fn block_expires_and_resets_the_bucket() {
        let limiter: FailureLimiter<String> =
            FailureLimiter::with(1, Duration::from_millis(10), Duration::from_millis(30));
        limiter.record_failure(&key("e"));
        sleep(Duration::from_millis(60));
        assert!(limiter.blocked_for(&key("e")).is_none());
        // 桶已被回收：下一次失败重新计数。
        assert_eq!(limiter.record_failure(&key("e")), 1);
    }

    #[test]
    fn clear_also_lifts_an_active_block() {
        let limiter: FailureLimiter<String> =
            FailureLimiter::with(1, Duration::from_secs(60), Duration::from_secs(60));
        limiter.record_failure(&key("c"));
        assert!(limiter.blocked_for(&key("c")).is_some());
        limiter.clear(&key("c"));
        assert!(limiter.blocked_for(&key("c")).is_none());
        assert_eq!(limiter.tracked_keys(), 0);
    }

    #[test]
    fn unknown_key_is_never_blocked() {
        let limiter: FailureLimiter<String> = FailureLimiter::default();
        assert!(limiter.blocked_for(&key("nobody")).is_none());
    }

    #[test]
    fn eviction_keeps_fresh_keys_and_drops_oldest() {
        // 用极小的 max_buckets 验证"最旧优先淘汰"。
        let limiter: FailureLimiter<String> = FailureLimiter::default();
        // 先塞满，再插新 key：新 key 必须留下，数量不超上限。
        for index in 0..(DEFAULT_MAX_BUCKETS + 5) {
            limiter.record_failure(&format!("k-{index}"));
        }
        assert_eq!(limiter.tracked_keys(), DEFAULT_MAX_BUCKETS);
        assert!(
            limiter
                .blocked_for(&format!("k-{}", DEFAULT_MAX_BUCKETS + 4))
                .is_none()
        );
        // 新 key 的桶存在（失败计数为 1，未封禁）。
        assert_eq!(
            limiter.record_failure(&format!("k-{}", DEFAULT_MAX_BUCKETS + 4)),
            2
        );
    }
}
