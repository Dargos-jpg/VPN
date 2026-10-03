// pornind de la un msg1 valid: orice bit schimbat dupa header-ul de 8 bytes (mesaj noise
// sau mac1) trebuie sa faca handshake-ul sa esueze. inputul fuzzer-ului e masca de XOR.
// (si header-ul e acoperit de mac1, dar mac1 se poate recalcula de oricine stie cheia
// publica a serverului, deci nu e o garantie criptografica - de aceea masca incepe la 8)

#![no_main]

#[path = "common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;

const HDR: usize = 8;

fuzz_target!(|mask: &[u8]| {
    let (_, mut msg1) = common::valid_msg1();
    let mut changed = false;
    for (b, m) in msg1[HDR..].iter_mut().zip(mask) {
        *b ^= m;
        changed |= *m != 0;
    }

    let result = common::responder().accept(&msg1, common::NOW);
    if changed {
        assert!(result.is_err(), "msg1 modificat acceptat");
    } else {
        assert!(result.is_ok(), "msg1 nemodificat respins");
    }
});
