// psk pentru noise derivat din codul TOTP
//
// codul are doar ~20 biti de entropie, hkdf nu schimba asta. rezistenta la
// brute force offline vine din faptul ca psk-ul se amesteca dupa DH-urile
// es si ss (IKpsk1) - fara cheile statice private nu poti verifica o incercare.
// info leaga psk-ul de perechea client/server, nu poate fi mutat pe alta identitate.

use hkdf::Hkdf;
use sha2::Sha256;

const SALT: &[u8] = b"vpn-totp psk v1";

pub fn derive_psk(code: &str, client_public: &[u8; 32], server_public: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(SALT), code.as_bytes());
    let mut info = [0u8; 64];
    info[..32].copy_from_slice(client_public);
    info[32..].copy_from_slice(server_public);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).expect("32 bytes e sub limita hkdf");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_to_code_and_keys() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let base = derive_psk("123456", &a, &b);
        assert_eq!(base, derive_psk("123456", &a, &b));
        assert_ne!(base, derive_psk("123457", &a, &b));
        assert_ne!(base, derive_psk("123456", &b, &a));
    }
}
