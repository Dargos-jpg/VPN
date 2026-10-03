// psk-uri pentru noise
//
// 1. din codul TOTP, la conectare. codul are doar ~20 biti de entropie, hkdf nu schimba asta.
//    rezistenta la brute force offline vine din faptul ca psk-ul se amesteca dupa DH-urile
//    es si ss (IKpsk1) - fara cheile statice private nu poti verifica o incercare.
// 2. din secretul de lant al sesiunii curente, la rekey (fara interventia userului).
//    secretul de lant e 32 bytes aleatori trimisi criptat in msg2, deci il are doar cine
//    a trecut de un handshake autentificat cu TOTP
//
// salt-uri diferite (domain separation): un psk de rekey nu poate fi niciodata egal
// cu unul de TOTP. info leaga psk-ul de perechea client/server

use hkdf::Hkdf;
use sha2::Sha256;

const SALT_TOTP: &[u8] = b"vpn-totp psk v1";
const SALT_REKEY: &[u8] = b"vpn-totp rekey psk v1";

pub fn derive_psk(code: &str, client_public: &[u8; 32], server_public: &[u8; 32]) -> [u8; 32] {
    derive(SALT_TOTP, code.as_bytes(), client_public, server_public)
}

pub fn derive_rekey_psk(chain_secret: &[u8; 32], client_public: &[u8; 32], server_public: &[u8; 32]) -> [u8; 32] {
    derive(SALT_REKEY, chain_secret, client_public, server_public)
}

fn derive(salt: &[u8], ikm: &[u8], client_public: &[u8; 32], server_public: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
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

    #[test]
    fn rekey_separated_from_totp() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        // acelasi material de intrare, salt diferit => psk diferit
        let mut secret = [0u8; 32];
        secret[..6].copy_from_slice(b"123456");
        let rekey = derive_rekey_psk(&secret, &a, &b);
        assert_ne!(rekey, derive(SALT_TOTP, &secret, &a, &b));
        assert_ne!(rekey, derive_rekey_psk(&[9u8; 32], &a, &b));
    }
}
