// limitare de rata pentru handshake-uri (token bucket)
//
// fiecare msg1 costa serverul pana la 8 operatii DH (rekey + 3 ferestre TOTP, cate 2 DH),
// deci un flood de msg1 poate ocupa tot procesorul. limita e aplicata dupa mac1
// (care respinge ieftin pe cine nu stie cheia publica a serverului) si inainte de DH.
//
// doua niveluri: per IP sursa si global. cel global e cel care conteaza: adresele
// UDP pot fi falsificate, deci limita per IP singura nu ajunge. numarul de IP-uri
// urmarite e limitat ca un flood cu surse aleatoare sa nu umple memoria

use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

const PER_IP_RATE: f64 = 2.0; // handshake-uri pe secunda
const PER_IP_BURST: f64 = 5.0;
const GLOBAL_RATE: f64 = 20.0;
const GLOBAL_BURST: f64 = 50.0;
const MAX_TRACKED_IPS: usize = 10_000;
const CLEANUP_EVERY: Duration = Duration::from_secs(60);

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn full(burst: f64, now: Instant) -> Self {
        Self {
            tokens: burst,
            last: now,
        }
    }

    fn refill(&mut self, now: Instant, rate: f64, burst: f64) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate).min(burst);
        self.last = now;
    }

    fn take(&mut self, now: Instant, rate: f64, burst: f64) -> bool {
        self.refill(now, rate, burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct RateLimiter {
    per_ip: HashMap<IpAddr, Bucket>,
    global: Bucket,
    last_cleanup: Instant,
}

impl RateLimiter {
    pub fn new(now: Instant) -> Self {
        Self {
            per_ip: HashMap::new(),
            global: Bucket::full(GLOBAL_BURST, now),
            last_cleanup: now,
        }
    }

    // true = handshake-ul poate fi procesat
    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        self.cleanup(now);
        if !self.per_ip.contains_key(&ip) && self.per_ip.len() >= MAX_TRACKED_IPS {
            // tabela plina (probabil flood cu surse falsificate): ramane doar limita globala
            return self.global.take(now, GLOBAL_RATE, GLOBAL_BURST);
        }
        let bucket = self.per_ip.entry(ip).or_insert_with(|| Bucket::full(PER_IP_BURST, now));
        bucket.take(now, PER_IP_RATE, PER_IP_BURST) && self.global.take(now, GLOBAL_RATE, GLOBAL_BURST)
    }

    // IP-urile care si-au refacut complet bucket-ul nu mai trebuie tinute minte
    fn cleanup(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_cleanup) < CLEANUP_EVERY {
            return;
        }
        self.per_ip.retain(|_, b| {
            b.refill(now, PER_IP_RATE, PER_IP_BURST);
            b.tokens < PER_IP_BURST
        });
        self.last_cleanup = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    #[test]
    fn burst_then_rate_per_ip() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::new(t0);
        for _ in 0..PER_IP_BURST as usize {
            assert!(rl.allow(ip(1), t0));
        }
        assert!(!rl.allow(ip(1), t0));
        // alt IP nu e afectat
        assert!(rl.allow(ip(2), t0));
        // dupa 1s se refac PER_IP_RATE jetoane
        let t1 = t0 + Duration::from_secs(1);
        assert!(rl.allow(ip(1), t1));
        assert!(rl.allow(ip(1), t1));
        assert!(!rl.allow(ip(1), t1));
    }

    #[test]
    fn global_limit_with_many_sources() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::new(t0);
        // flood din surse diferite: fiecare IP e sub limita lui, dar totalul e limitat
        let allowed = (0..200u32)
            .filter(|i| rl.allow(IpAddr::from((0x0a00_0000 + i).to_be_bytes()), t0))
            .count();
        assert_eq!(allowed, GLOBAL_BURST as usize);
    }

    #[test]
    fn tracked_ips_bounded() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::new(t0);
        for i in 0..(MAX_TRACKED_IPS as u32 + 500) {
            rl.allow(IpAddr::from((0x0a00_0000 + i).to_be_bytes()), t0);
        }
        assert!(rl.per_ip.len() <= MAX_TRACKED_IPS);
    }

    #[test]
    fn idle_ips_forgotten() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::new(t0);
        rl.allow(ip(1), t0);
        assert_eq!(rl.per_ip.len(), 1);
        rl.allow(ip(2), t0 + CLEANUP_EVERY + Duration::from_secs(1));
        // ip(1) si-a refacut bucket-ul si a fost uitat, ip(2) tocmai a consumat un jeton
        assert!(!rl.per_ip.contains_key(&ip(1)));
        assert!(rl.per_ip.contains_key(&ip(2)));
    }
}
