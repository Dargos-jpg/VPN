#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    #[error("pachet malformat")]
    Malformed,
    #[error("handshake respins")]
    Rejected,
    #[error("mac1 invalid")]
    BadMac,
    #[error("replay detectat")]
    Replay,
    #[error("timestamp handshake prea departe de ceasul serverului")]
    Stale,
    #[error("counter epuizat, sesiunea trebuie refacuta")]
    Exhausted,
    #[error("sesiune expirata, e nevoie de handshake nou")]
    Expired,
}
