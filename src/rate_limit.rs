//! Token buckets for request and outbound-pull budgets (same fractional-refill
//! shape as paykit-server's signed-request limiter).

use std::sync::Mutex;
use std::time::Instant;

pub struct TokenBucket {
    inner: Mutex<Bucket>,
}

struct Bucket {
    rate_per_second: u64,
    burst: u64,
    tokens: u64,
    remainder: u128,
    last: Instant,
}

impl TokenBucket {
    pub fn new(rate_per_second: u64, burst: u64) -> Self {
        Self {
            inner: Mutex::new(Bucket {
                rate_per_second,
                burst,
                tokens: burst,
                remainder: 0,
                last: Instant::now(),
            }),
        }
    }

    pub fn try_take(&self) -> bool {
        let mut bucket = self.inner.lock().expect("rate limiter mutex not poisoned");
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(bucket.last);
        bucket.last = now;
        if bucket.tokens == bucket.burst {
            bucket.remainder = 0;
        } else {
            let accrued = elapsed
                .as_nanos()
                .saturating_mul(u128::from(bucket.rate_per_second))
                .saturating_add(bucket.remainder);
            let added = accrued / 1_000_000_000;
            bucket.remainder = accrued % 1_000_000_000;
            bucket.tokens = bucket
                .tokens
                .saturating_add(u64::try_from(added).unwrap_or(u64::MAX))
                .min(bucket.burst);
            if bucket.tokens == bucket.burst {
                bucket.remainder = 0;
            }
        }
        if bucket.tokens == 0 {
            return false;
        }
        bucket.tokens -= 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausts_burst_then_refuses() {
        let bucket = TokenBucket::new(1, 2);
        assert!(bucket.try_take());
        assert!(bucket.try_take());
        assert!(!bucket.try_take());
    }
}
