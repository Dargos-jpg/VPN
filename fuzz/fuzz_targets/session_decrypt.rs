// dupa handshake, orice pachet de date venit din retea trece prin decrypt:
// bytes arbitrari nu au voie sa produca panic si nu au voie sa treaca de AEAD

#![no_main]

#[path = "common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (mut srv, _) = common::session_pair();
    assert!(srv.decrypt(data).is_err());
});
