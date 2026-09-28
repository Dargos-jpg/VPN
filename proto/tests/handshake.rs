// test cap-coada: handshake + date in ambele sensuri, fara retea

use vpn_proto::{totp, Error, Initiator, Keypair, Responder};

const NOW: u64 = 1_700_000_000;

struct Setup {
    server: Keypair,
    client: Keypair,
    secret: Vec<u8>,
}

fn setup() -> Setup {
    Setup {
        server: Keypair::generate().unwrap(),
        client: Keypair::generate().unwrap(),
        secret: totp::generate_secret().to_vec(),
    }
}

fn responder(s: &Setup) -> Responder {
    Responder::new(s.server.clone(), s.client.public, s.secret.clone(), 1)
}

fn code_at(s: &Setup, unix: u64) -> String {
    totp::code(&s.secret, totp::step_at(unix), totp::DIGITS)
}

#[test]
fn full_handshake_and_data() {
    let s = setup();
    let mut resp = responder(&s);

    let (init, msg1) = Initiator::start(&s.client, &s.server.public, &code_at(&s, NOW), 1).unwrap();
    let (mut srv, msg2) = resp.accept(&msg1, NOW).unwrap();
    let mut cli = init.finish(&msg2).unwrap();

    let p = cli.encrypt(b"ping").unwrap();
    assert_eq!(srv.decrypt(&p).unwrap(), b"ping");
    let p = srv.encrypt(b"pong").unwrap();
    assert_eq!(cli.decrypt(&p).unwrap(), b"pong");
}

#[test]
fn data_replay_and_reorder() {
    let s = setup();
    let mut resp = responder(&s);
    let (init, msg1) = Initiator::start(&s.client, &s.server.public, &code_at(&s, NOW), 1).unwrap();
    let (mut srv, msg2) = resp.accept(&msg1, NOW).unwrap();
    let mut cli = init.finish(&msg2).unwrap();

    let a = cli.encrypt(b"a").unwrap();
    let b = cli.encrypt(b"b").unwrap();
    assert_eq!(srv.decrypt(&b).unwrap(), b"b");
    assert_eq!(srv.decrypt(&a).unwrap(), b"a"); // reordonat, acceptat
    assert!(matches!(srv.decrypt(&a), Err(Error::Replay)));

    // un bit schimbat in ciphertext => AEAD pica
    let mut c = cli.encrypt(b"c").unwrap();
    let last = c.len() - 1;
    c[last] ^= 1;
    assert!(srv.decrypt(&c).is_err());
}

#[test]
fn wrong_code_rejected() {
    let s = setup();
    let mut resp = responder(&s);
    let good = code_at(&s, NOW);
    let bad = if good == "000000" { "000001" } else { "000000" };
    let (_, msg1) = Initiator::start(&s.client, &s.server.public, bad, 1).unwrap();
    assert!(matches!(resp.accept(&msg1, NOW), Err(Error::Rejected)));
}

#[test]
fn clock_skew_tolerance() {
    let s = setup();
    let mut resp = responder(&s);

    // telefonul e cu o fereastra in urma - acceptat
    let (_, msg1) = Initiator::start(&s.client, &s.server.public, &code_at(&s, NOW - 30), 1).unwrap();
    assert!(resp.accept(&msg1, NOW).is_ok());

    // trei ferestre in urma - respins
    let (_, msg1) = Initiator::start(&s.client, &s.server.public, &code_at(&s, NOW - 90), 2).unwrap();
    assert!(matches!(resp.accept(&msg1, NOW), Err(Error::Rejected)));
}

#[test]
fn handshake_replay_rejected() {
    let s = setup();
    let mut resp = responder(&s);
    let (_, msg1) = Initiator::start(&s.client, &s.server.public, &code_at(&s, NOW), 5).unwrap();
    assert!(resp.accept(&msg1, NOW).is_ok());
    assert!(matches!(resp.accept(&msg1, NOW), Err(Error::Replay)));
}

#[test]
fn unknown_client_key_rejected() {
    let s = setup();
    let mut resp = responder(&s);
    let intruder = Keypair::generate().unwrap();
    // chiar cu codul TOTP corect, fara cheia statica a clientului nu intra
    let (_, msg1) = Initiator::start(&intruder, &s.server.public, &code_at(&s, NOW), 1).unwrap();
    assert!(resp.accept(&msg1, NOW).is_err());
}

#[test]
fn wrong_server_key_rejected() {
    let s = setup();
    let mut resp = responder(&s);
    let fake_server = Keypair::generate().unwrap();
    let (_, msg1) = Initiator::start(&s.client, &fake_server.public, &code_at(&s, NOW), 1).unwrap();
    assert!(resp.accept(&msg1, NOW).is_err());
}
