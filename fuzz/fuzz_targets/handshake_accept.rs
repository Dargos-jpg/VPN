// serverul primeste msg1 de la oricine: bytes arbitrari nu au voie sa produca panic
// si nu au voie sa fie acceptati ca handshake valid - nici ca TOTP, nici ca rekey
// (serverul are o sesiune activa, deci incearca si psk-ul de rekey)

#![no_main]

#[path = "common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut r = common::responder();
    assert!(r.accept_chained(data, common::NOW, Some(common::chain())).is_err());
});
