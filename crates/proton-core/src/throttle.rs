//! Bandwidth throttle — limits bytes-per-second throughput.
use std::time::Instant;

/// Token-bucket bandwidth limiter.
pub struct Throttle {
    bytes_per_sec: f64,
    tokens: f64,
    last: Instant,
}

impl Throttle {
    /// Create a new throttle. `bytes_per_sec` = 0 means unlimited.
    pub fn new(bytes_per_sec: u64) -> Self {
        Self {
            bytes_per_sec: bytes_per_sec as f64,
            tokens: bytes_per_sec as f64,
            last: Instant::now(),
        }
    }

    /// Wait (via `tokio::time::sleep`) so that `byte_count` bytes
    /// can be transmitted without exceeding the rate limit.
    pub async fn acquire(&mut self, byte_count: usize) {
        if self.bytes_per_sec <= 0.0 {
            return;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.bytes_per_sec).min(self.bytes_per_sec);
        self.last = now;

        let needed = byte_count as f64;
        if self.tokens < needed {
            let wait = (needed - self.tokens) / self.bytes_per_sec;
            tokio::time::sleep(std::time::Duration::from_secs_f64(wait)).await;
            self.tokens = 0.0;
            self.last = Instant::now();
        } else {
            self.tokens -= needed;
        }
    }
}
