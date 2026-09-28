#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    #[error("pachet malformat")]
    Malformed,
    #[error("handshake respins")]
    Rejected,
    #[error("replay detectat")]
    Replay,
    #[error("counter epuizat, sesiunea trebuie refacuta")]
    Exhausted,
}
