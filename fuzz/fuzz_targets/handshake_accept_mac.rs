// ca handshake_accept, dar cu mac1 valid calculat peste inputul fuzzer-ului:
// altfel aproape orice input e oprit de mac1 si codul de handshake de dupa (DH, noise,
// timestamp) nu mai e atins. simuleaza un atacator care stie cheia publica a serverului

#![no_main]

#[path = "common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;
use vpn_proto::{mac, packet};

fuzz_target!(|data: &[u8]| {
    let Some((sender, noise)) = data.split_first_chunk::<4>() else {
        return;
    };
    let f = common::fixture();
    let mut pkt = packet::encode_init(u32::from_be_bytes(*sender), noise, &[0u8; mac::MAC_LEN]);
    let tag = mac::mac1(&mac::mac1_key(&f.server.public), packet::init_mac_input(&pkt));
    let len = pkt.len();
    pkt[len - mac::MAC_LEN..].copy_from_slice(&tag);

    let mut r = common::responder();
    assert!(r.check_mac1(&pkt) || noise.is_empty());
    assert!(r.accept_chained(&pkt, common::NOW, Some(common::chain())).is_err());
});
