// pornind de la un pachet de date valid: orice bit schimbat, oriunde (header, counter,
// ciphertext, tag) trebuie respins. inputul fuzzer-ului = payload (primul byte = lungime)
// + masca de XOR pentru pachetul criptat

#![no_main]

#[path = "common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&len, rest)) = data.split_first() else {
        return;
    };
    let (payload, mask) = rest.split_at((len as usize).min(rest.len()));

    let (mut srv, mut cli) = common::session_pair();
    let mut pkt = cli.encrypt(payload).unwrap();
    let mut changed = false;
    for (b, m) in pkt.iter_mut().zip(mask) {
        *b ^= m;
        changed |= *m != 0;
    }

    match srv.decrypt(&pkt) {
        Ok(pt) => {
            assert!(!changed, "pachet modificat acceptat");
            assert_eq!(pt, payload);
        }
        Err(e) => assert!(changed, "pachet nemodificat respins: {e}"),
    }
});
