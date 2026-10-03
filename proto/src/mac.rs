// mac1: MAC ieftin la finalul fiecarui msg1, ca la WireGuard
//
// cheia e derivata din cheia PUBLICA a serverului, deci nu e un secret: orice client legitim
// o poate calcula. dar un scanner care nu stie cheia publica nu poate produce un msg1
// cu mac1 valid, iar serverul il respinge cu un singur BLAKE2s (microsecunde), inainte de
// orice operatie DH. protejeaza procesorul serverului si pastreaza invizibilitatea la scanare

use blake2::{
    digest::{consts::U16, Mac},
    Blake2s256, Blake2sMac, Digest,
};

pub const MAC_LEN: usize = 16;
const LABEL: &[u8] = b"vpn-totp mac1 v1";

pub fn mac1_key(server_public: &[u8; 32]) -> [u8; 32] {
    Blake2s256::new()
        .chain_update(LABEL)
        .chain_update(server_public)
        .finalize()
        .into()
}

pub fn mac1(key: &[u8; 32], msg: &[u8]) -> [u8; MAC_LEN] {
    let mut m = <Blake2sMac<U16> as Mac>::new_from_slice(key).expect("cheie de 32 bytes");
    m.update(msg);
    m.finalize().into_bytes().into()
}

// comparatie in timp constant
pub fn verify_mac1(key: &[u8; 32], msg: &[u8], tag: &[u8]) -> bool {
    let mut m = <Blake2sMac<U16> as Mac>::new_from_slice(key).expect("cheie de 32 bytes");
    m.update(msg);
    m.verify_slice(tag).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_roundtrip() {
        let key = mac1_key(&[7u8; 32]);
        let tag = mac1(&key, b"mesaj");
        assert!(verify_mac1(&key, b"mesaj", &tag));
        assert!(!verify_mac1(&key, b"mesaJ", &tag));
        assert!(!verify_mac1(&mac1_key(&[8u8; 32]), b"mesaj", &tag));
        assert!(!verify_mac1(&key, b"mesaj", &tag[..15]));
    }

    // acelasi rezultat ca BLAKE2s cu cheie din RFC 7693 (hashlib.blake2s(msg, key=k, digest_size=16)),
    // ca testele din scripts/ sa poata construi pachete in python
    #[test]
    fn matches_rfc7693_keyed_blake2s() {
        let key = [0u8; 32];
        let tag = mac1(&key, b"");
        // python3 -c "import hashlib; print(hashlib.blake2s(b'', key=bytes(32), digest_size=16).hexdigest())"
        assert_eq!(
            tag,
            [0x4b, 0x1f, 0xb0, 0x82, 0xa7, 0x28, 0xa8, 0x7c, 0x3b, 0x6c, 0x6a, 0xa8, 0x7b, 0x87, 0x74, 0x41]
        );
    }
}
