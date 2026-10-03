// chei si secret TOTP generate o singura data, refolosite de toate iteratiile

#![allow(dead_code)]

use std::sync::OnceLock;

use vpn_proto::{session::Chain, totp, Initiator, Keypair, Responder, Session};

pub const NOW: u64 = 1_700_000_000;
pub const TS: u64 = NOW * 1_000_000_000;

pub struct Fixture {
    pub server: Keypair,
    pub client: Keypair,
    pub secret: Vec<u8>,
}

pub fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| Fixture {
        server: Keypair::generate().unwrap(),
        client: Keypair::generate().unwrap(),
        secret: totp::generate_secret().to_vec(),
    })
}

pub fn responder() -> Responder {
    let f = fixture();
    Responder::new(f.server.clone(), f.client.public, f.secret.clone(), 1)
}

pub fn valid_msg1() -> (Initiator, Vec<u8>) {
    let f = fixture();
    let code = totp::code(&f.secret, totp::step_at(NOW), totp::DIGITS);
    Initiator::start(&f.client, &f.server.public, &code, TS).unwrap()
}

// lantul unei sesiuni stabilite, ca serverul sa incerce si psk-ul de rekey
pub fn chain() -> &'static Chain {
    static C: OnceLock<Chain> = OnceLock::new();
    C.get_or_init(|| session_pair().0.chain().clone())
}

// sesiune completa: (server, client)
pub fn session_pair() -> (Session, Session) {
    let (init, msg1) = valid_msg1();
    let (srv, msg2) = responder().accept(&msg1, NOW).unwrap();
    let cli = init.finish(&msg2).unwrap();
    (srv, cli)
}
