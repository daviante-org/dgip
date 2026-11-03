//! Bounded LRU sliding-window per-IP rate limiter with live DB reconfiguration.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub limit: usize,
    pub remaining: usize,
    pub reset_epoch: u64,
    pub retry_after: u64,
}

impl RateLimitDecision {
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        let mut h = vec![
            ("X-RateLimit-Limit", self.limit.to_string()),
            ("X-RateLimit-Remaining", self.remaining.to_string()),
            ("X-RateLimit-Reset", self.reset_epoch.to_string()),
        ];
        if !self.allowed {
            h.push(("Retry-After", self.retry_after.max(1).to_string()));
        }
        h
    }
}

struct Entry {
    hits: VecDeque<f64>,
    prev: Option<String>,
    next: Option<String>,
}

struct Inner {
    limit: usize,
    window: f64,
    max_keys: usize,
    origin: Instant,
    map: HashMap<String, Entry>,
    head: Option<String>, // LRU oldest
    tail: Option<String>, // MRU newest
}

impl Inner {
    fn detach(&mut self, key: &str) {
        let (prev, next) = match self.map.get(key) {
            Some(e) => (e.prev.clone(), e.next.clone()),
            None => return,
        };
        if let Some(ref p) = prev {
            if let Some(pe) = self.map.get_mut(p) {
                pe.next = next.clone();
            }
        } else {
            self.head = next.clone();
        }
        if let Some(ref n) = next {
            if let Some(ne) = self.map.get_mut(n) {
                ne.prev = prev.clone();
            }
        } else {
            self.tail = prev;
        }
        if let Some(e) = self.map.get_mut(key) {
            e.prev = None;
            e.next = None;
        }
    }

    fn attach_tail(&mut self, key: &str) {
        let old_tail = self.tail.clone();
        if let Some(ref ot) = old_tail {
            if let Some(ote) = self.map.get_mut(ot) {
                ote.next = Some(key.to_string());
            }
        } else {
            self.head = Some(key.to_string());
        }
        if let Some(e) = self.map.get_mut(key) {
            e.prev = old_tail;
            e.next = None;
        }
        self.tail = Some(key.to_string());
    }

    fn pop_lru(&mut self) {
        if let Some(oldest_key) = self.head.clone() {
            self.detach(&oldest_key);
            self.map.remove(&oldest_key);
        }
    }
}

pub struct SlidingWindowRateLimiter {
    inner: Mutex<Inner>,
}

impl SlidingWindowRateLimiter {
    pub fn new(limit_per_window: usize, window_seconds: f64, max_keys: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                limit: limit_per_window.max(1),
                window: window_seconds.max(1.0),
                max_keys: max_keys.max(128),
                origin: Instant::now(),
                map: HashMap::new(),
                head: None,
                tail: None,
            }),
        }
    }

    pub fn reconfigure(&self, limit_per_window: usize, window_seconds: f64, max_keys: usize) {
        let mut g = self.inner.lock().unwrap();
        g.limit = limit_per_window.max(1);
        g.window = window_seconds.max(1.0);
        g.max_keys = max_keys.max(128);
        while g.map.len() > g.max_keys {
            g.pop_lru();
        }
    }

    pub fn check(&self, key: &str) -> RateLimitDecision {
        self.check_at(key, None)
    }

    pub fn check_at(&self, key: &str, now_override: Option<f64>) -> RateLimitDecision {
        let mut g = self.inner.lock().unwrap();
        let mono_now = now_override.unwrap_or_else(|| g.origin.elapsed().as_secs_f64());
        let wall_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let cutoff = mono_now - g.window;

        if g.map.contains_key(key) {
            if let Some(entry) = g.map.get_mut(key) {
                while let Some(&front) = entry.hits.front() {
                    if front <= cutoff {
                        entry.hits.pop_front();
                    } else {
                        break;
                    }
                }
            }
            g.detach(key);
            g.attach_tail(key);
        } else {
            if g.map.len() >= g.max_keys {
                g.pop_lru();
            }
            g.map.insert(
                key.to_string(),
                Entry {
                    hits: VecDeque::new(),
                    prev: None,
                    next: None,
                },
            );
            g.attach_tail(key);
        }

        let limit = g.limit;
        let window = g.window;
        let entry = g.map.get_mut(key).unwrap();

        if entry.hits.len() >= limit {
            let oldest = entry.hits[0];
            let wait_secs = ((oldest + window) - mono_now).ceil().max(1.0) as u64;
            return RateLimitDecision {
                allowed: false,
                limit,
                remaining: 0,
                reset_epoch: (wall_now + wait_secs as f64) as u64,
                retry_after: wait_secs,
            };
        }

        entry.hits.push_back(mono_now);
        let remaining = limit.saturating_sub(entry.hits.len());
        let reset_secs = ((entry.hits[0] + window) - mono_now).ceil().max(1.0) as u64;
        RateLimitDecision {
            allowed: true,
            limit,
            remaining,
            reset_epoch: (wall_now + reset_secs as f64) as u64,
            retry_after: 0,
        }
    }
}
