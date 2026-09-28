// chei statice X25519, stocate base64 in config

use base64::{engine::general_purpose::STANDARD, Engine};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{error::Error, handshake::params};

pub const KEY_LEN: usize = 32;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Keypair {
    pub private: [u8; KEY_LEN],
    pub public: [u8; KEY_LEN],
}

impl Keypair {
    pub fn generate() -> Result<Self, Error> {
        let kp = snow::Builder::new(params()).generate_keypair()?;
        Ok(Self {
            private: to_key(&kp.private)?,
            public: to_key(&kp.public)?,
        })
    }
}

pub fn encode_key(key: &[u8; KEY_LEN]) -> String {
    STANDARD.encode(key)
}

pub fn decode_key(s: &str) -> Result<[u8; KEY_LEN], Error> {
    let raw = STANDARD.decode(s.trim()).map_err(|_| Error::Malformed)?;
    to_key(&raw)
}

fn to_key(raw: &[u8]) -> Result<[u8; KEY_LEN], Error> {
    raw.try_into().map_err(|_| Error::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_roundtrip() {
        let kp = Keypair::generate().unwrap();
        assert_eq!(decode_key(&encode_key(&kp.public)).unwrap(), kp.public);
        assert!(decode_key("prea-scurt").is_err());
    }
}
