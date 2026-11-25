//! Per-IP connection rate limiter (anti-bot-flood / anti-Slowloris).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct IpRateLimiter {
    limit_per_sec: u32,
    windows: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl IpRateLimiter {
    pub fn new(limit_per_sec: u32) -> Self {
        Self {
            limit_per_sec,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` if the connection from `ip` is allowed in the current 1-second window.
    pub fn allow(&self, ip: IpAddr) -> bool {
        if self.limit_per_sec == 0 {
            return true;
        }
        let now = Instant::now();
        let mut map = self.windows.lock().unwrap();
        if map.len() > 8192 {
            map.retain(|_, (ts, _)| now.duration_since(*ts) < Duration::from_secs(2));
        }
        let entry = map.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= Duration::from_secs(1) {
            *entry = (now, 1);
            return true;
        }
        if entry.1 >= self.limit_per_sec {
            return false;
        }
        entry.1 += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_per_ip_limit() {
        let limiter = IpRateLimiter::new(3);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(!limiter.allow(ip));
    }
}
