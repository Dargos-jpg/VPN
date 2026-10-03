// parser-ul de pachete si cititorul de header IP primesc bytes direct din retea:
// nu au voie sa intre in panic, iar orice pachet acceptat trebuie sa se re-encodeze identic

#![no_main]

use libfuzzer_sys::fuzz_target;
use vpn_proto::{
    ip,
    packet::{self, Packet},
};

fuzz_target!(|data: &[u8]| {
    let _ = ip::source(data);
    let _ = ip::destination(data);

    if let Ok(p) = packet::parse(data) {
        let again = match p {
            Packet::Init { sender, noise, mac1 } => packet::encode_init(sender, noise, mac1.try_into().unwrap()),
            Packet::Resp { sender, receiver, noise } => packet::encode_resp(sender, receiver, noise),
            Packet::Data {
                receiver,
                counter,
                payload,
            } => packet::encode_data(receiver, counter, payload),
        };
        // formatul nu are ambiguitati: aceiasi bytes inapoi
        assert_eq!(again, data);
    }
});
