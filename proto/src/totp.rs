// TOTP dupa RFC 6238 (HMAC-SHA1, pas de 30s, 6 cifre) - compatibil cu orice app de autentificare

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha1::Sha1;

pub const STEP_SECS: u64 = 30;
pub const DIGITS: u32 = 6;
// 160 biti, lungimea recomandata in RFC 4226
pub const SECRET_LEN: usize = 20;

pub fn generate_secret() -> [u8; SECRET_LEN] {
    let mut s = [0u8; SECRET_LEN];
    OsRng.fill_bytes(&mut s);
    s
}

pub fn step_at(unix_secs: u64) -> u64 {
    unix_secs / STEP_SECS
}

pub fn code(secret: &[u8], step: u64, digits: u32) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("hmac accepta chei de orice lungime");
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();

    // dynamic truncation, RFC 4226 sectiunea 5.3
    let off = (h[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    let val = bin % 10u32.pow(digits);
    format!("{:0width$}", val, width = digits as usize)
}

// pasul curent primul, apoi vecinii - absoarbe decalajul de ceas telefon/server
pub fn candidate_steps(now_unix: u64, skew: u64) -> Vec<u64> {
    let cur = step_at(now_unix);
    let mut steps = vec![cur];
    for d in 1..=skew {
        if cur >= d {
            steps.push(cur - d);
        }
        steps.push(cur + d);
    }
    steps
}

pub fn encode_secret(secret: &[u8]) -> String {
    BASE32_NOPAD.encode(secret)
}

pub fn decode_secret(s: &str) -> Option<Vec<u8>> {
    let clean: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    BASE32_NOPAD.decode(clean.as_bytes()).ok()
}

// formatul citit de Google Authenticator / Authy / etc
pub fn otpauth_uri(secret: &[u8], issuer: &str, account: &str) -> String {
    let issuer = issuer.replace(' ', "%20");
    let account = account.replace(' ', "%20");
    format!(
        "otpauth://totp/{issuer}:{account}?secret={}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        encode_secret(secret)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // vectori de test din RFC 6238 anexa B, varianta SHA1
    #[test]
    fn rfc6238_vectors() {
        let secret = b"12345678901234567890";
        let cases = [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ];
        for (t, expected) in cases {
            assert_eq!(code(secret, step_at(t), 8), expected, "t = {t}");
        }
    }

    #[test]
    fn six_digits_zero_padded() {
        let c = code(b"12345678901234567890", step_at(1111111109), 6);
        assert_eq!(c, "081804");
    }

    #[test]
    fn secret_roundtrip() {
        let s = generate_secret();
        let enc = encode_secret(&s);
        assert_eq!(decode_secret(&enc.to_lowercase()).unwrap(), s);
    }

    #[test]
    fn candidates_with_skew() {
        let steps = candidate_steps(3000, 1);
        assert_eq!(steps, vec![100, 99, 101]);
    }
}
