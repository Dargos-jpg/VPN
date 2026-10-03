// test cap-coada: handshake + date in ambele sensuri, fara retea

use std::time::{Duration, Instant};

use vpn_proto::{
    handshake::MAX_CLOCK_DIFF_SECS,
    session::{AUTH_MAX_AGE, KEY_MAX_AGE},
    totp, Error, Initiator, Keypair, Responder, Session,
};

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

// timestamp in ns, la `extra_ns` dupa NOW
fn ts(extra_ns: u64) -> u64 {
    NOW * 1_000_000_000 + extra_ns
}

#[test]
fn full_handshake_and_data() {
    let s = setup();
    let mut resp = responder(&s);

    let (init, msg1) = Initiator::start(&s.client, &s.server.public, &code_at(&s, NOW), ts(1)).unwrap();
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
    let (init, msg1) = Initiator::start(&s.client, &s.server.public, &code_at(&s, NOW), ts(1)).unwrap();
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
    let (_, msg1) = Initiator::start(&s.client, &s.server.public, bad, ts(1)).unwrap();
    assert!(matches!(resp.accept(&msg1, NOW), Err(Error::Rejected)));
}

#[test]
fn clock_skew_tolerance() {
    let s = setup();
    let mut resp = responder(&s);

    // telefonul e cu o fereastra in urma - acceptat
    let (_, msg1) = Initiator::start(&s.client, &s.server.public, &code_at(&s, NOW - 30), ts(1)).unwrap();
    assert!(resp.accept(&msg1, NOW).is_ok());

    // trei ferestre in urma - respins
    let (_, msg1) = Initiator::start(&s.client, &s.server.public, &code_at(&s, NOW - 90), ts(2)).unwrap();
    assert!(matches!(resp.accept(&msg1, NOW), Err(Error::Rejected)));
}

#[test]
fn handshake_replay_rejected() {
    let s = setup();
    let mut resp = responder(&s);
    let (_, msg1) = Initiator::start(&s.client, &s.server.public, &code_at(&s, NOW), ts(5)).unwrap();
    assert!(resp.accept(&msg1, NOW).is_ok());
    assert!(matches!(resp.accept(&msg1, NOW), Err(Error::Replay)));
}

// BUG-004: dupa restart last_timestamp e 0, doar limita de varsta opreste replay-ul
#[test]
fn replay_after_restart_rejected() {
    let s = setup();
    let (_, msg1) = Initiator::start(&s.client, &s.server.public, &code_at(&s, NOW), ts(0)).unwrap();
    assert!(responder(&s).accept(&msg1, NOW).is_ok());

    // server "repornit" (last_timestamp = 0) cu skew mare, ca codul TOTP sa fie inca acceptat
    // => doar verificarea de varsta mai poate opri mesajul
    let later = NOW + MAX_CLOCK_DIFF_SECS + 1;
    assert!(totp::step_at(later) - totp::step_at(NOW) <= 5);
    let mut fresh = Responder::new(s.server.clone(), s.client.public, s.secret.clone(), 5);
    assert!(matches!(fresh.accept(&msg1, later), Err(Error::Stale)));
}

#[test]
fn future_timestamp_rejected() {
    let s = setup();
    let mut resp = responder(&s);
    let far = ts((MAX_CLOCK_DIFF_SECS + 1) * 1_000_000_000);
    let (_, msg1) = Initiator::start(&s.client, &s.server.public, &code_at(&s, NOW), far).unwrap();
    assert!(matches!(resp.accept(&msg1, NOW), Err(Error::Stale)));
}

// conectare cu TOTP: (resp, server, client)
fn connect(s: &Setup) -> (Responder, Session, Session) {
    let mut resp = responder(s);
    let (init, msg1) = Initiator::start(&s.client, &s.server.public, &code_at(s, NOW), ts(1)).unwrap();
    let (srv, msg2) = resp.accept(&msg1, NOW).unwrap();
    let cli = init.finish(&msg2).unwrap();
    (resp, srv, cli)
}

// rekey pe lantul sesiunii curente a clientului: (server nou, client nou)
fn rekey(s: &Setup, resp: &mut Responder, srv: &Session, cli: &Session, t: u64) -> Result<(Session, Session), Error> {
    let (init, msg1) = Initiator::start_rekey(&s.client, &s.server.public, cli.chain(), ts(t)).unwrap();
    let a = resp.accept_chained(&msg1, NOW, Some(srv.chain()))?;
    assert!(a.rekey);
    Ok((a.session, init.finish(&a.reply)?))
}

#[test]
fn keys_expire_before_auth() {
    let (_, srv, cli) = connect(&setup());
    let now = Instant::now();
    assert!(!cli.is_expired(now));
    assert!(!srv.is_expired(now + KEY_MAX_AGE - Duration::from_secs(5)));
    // cheile expira la 3 min, autentificarea abia la 12h
    assert!(cli.key_expired(now + KEY_MAX_AGE));
    assert!(!cli.auth_expired(now + KEY_MAX_AGE));
    assert!(srv.is_expired(now + KEY_MAX_AGE));
    assert!(cli.auth_expired(now + AUTH_MAX_AGE));
}

#[test]
fn rekey_without_totp() {
    let s = setup();
    let (mut resp, srv, cli) = connect(&s);

    // dupa rekey: chei noi, functionale in ambele sensuri, fara niciun cod TOTP
    let (mut srv2, mut cli2) = rekey(&s, &mut resp, &srv, &cli, 2).unwrap();
    let p = cli2.encrypt(b"dupa rekey").unwrap();
    assert_eq!(srv2.decrypt(&p).unwrap(), b"dupa rekey");
    let p = srv2.encrypt(b"pong").unwrap();
    assert_eq!(cli2.decrypt(&p).unwrap(), b"pong");

    // lantul avanseaza: inca un rekey pe sesiunea noua merge
    assert!(rekey(&s, &mut resp, &srv2, &cli2, 3).is_ok());
}

#[test]
fn rekey_keeps_auth_time() {
    let s = setup();
    let (mut resp, srv, cli) = connect(&s);
    let (srv2, cli2) = rekey(&s, &mut resp, &srv, &cli, 2).unwrap();

    // cheile noi sunt proaspete, dar limita de 12h se masoara tot de la conectarea cu TOTP
    let now = Instant::now();
    assert!(!cli2.key_expired(now + KEY_MAX_AGE - Duration::from_secs(5)));
    assert!(cli2.auth_expired(now + AUTH_MAX_AGE));
    assert!(srv2.auth_expired(now + AUTH_MAX_AGE));
}

#[test]
fn old_keys_do_not_decrypt_new_session() {
    let s = setup();
    let (mut resp, mut srv, mut cli) = connect(&s);
    let (mut srv2, mut cli2) = rekey(&s, &mut resp, &srv, &cli, 2).unwrap();

    // pachet al sesiunii noi nu e acceptat de cea veche si invers
    let p_new = cli2.encrypt(b"nou").unwrap();
    assert!(srv.decrypt(&p_new).is_err());
    let p_old = cli.encrypt(b"vechi").unwrap();
    assert!(srv2.decrypt(&p_old).is_err());
    // sesiunea veche ramane valida pentru pachetele inca pe drum
    assert_eq!(srv.decrypt(&p_old).unwrap(), b"vechi");
}

#[test]
fn rekey_with_stale_chain_rejected() {
    let s = setup();
    let (mut resp, srv, cli) = connect(&s);
    let (srv2, _cli2) = rekey(&s, &mut resp, &srv, &cli, 2).unwrap();

    // dupa rekey serverul accepta doar lantul sesiunii noi, nu pe cel vechi
    assert!(matches!(rekey(&s, &mut resp, &srv2, &cli, 3), Err(Error::Rejected)));
}

#[test]
fn rekey_without_server_session_rejected() {
    let s = setup();
    let (_, _srv, cli) = connect(&s);
    // server restartat: nu are lantul, iar msg1 de rekey nu e un cod TOTP valid
    let mut fresh = responder(&s);
    let (_, msg1) = Initiator::start_rekey(&s.client, &s.server.public, cli.chain(), ts(2)).unwrap();
    assert!(matches!(fresh.accept_chained(&msg1, NOW, None), Err(Error::Rejected)));
}

#[test]
fn rekey_by_other_client_key_rejected() {
    let s = setup();
    let (mut resp, srv, cli) = connect(&s);
    // cineva cu secretul de lant dar fara cheia statica a clientului
    let intruder = Keypair::generate().unwrap();
    let (_, msg1) = Initiator::start_rekey(&intruder, &s.server.public, cli.chain(), ts(2)).unwrap();
    assert!(resp.accept_chained(&msg1, NOW, Some(srv.chain())).is_err());
}

#[test]
fn totp_still_works_with_active_session() {
    let s = setup();
    let (mut resp, srv, _cli) = connect(&s);
    // clientul repornit (a pierdut lantul) se conecteaza din nou cu TOTP cat serverul inca are sesiunea
    let (init, msg1) = Initiator::start(&s.client, &s.server.public, &code_at(&s, NOW), ts(2)).unwrap();
    let a = resp.accept_chained(&msg1, NOW, Some(srv.chain())).unwrap();
    assert!(!a.rekey);
    assert!(init.finish(&a.reply).is_ok());
}

#[test]
fn only_authenticated_packets_count_as_alive() {
    let s = setup();
    let mut resp = responder(&s);
    let (init, msg1) = Initiator::start(&s.client, &s.server.public, &code_at(&s, NOW), ts(1)).unwrap();
    let (mut srv, msg2) = resp.accept(&msg1, NOW).unwrap();
    let mut cli = init.finish(&msg2).unwrap();

    std::thread::sleep(Duration::from_millis(50));
    let idle_before = srv.since_last_recv(Instant::now());
    assert!(idle_before >= Duration::from_millis(50));

    // pachet falsificat: nu reseteaza timer-ul
    let mut forged = cli.encrypt(b"x").unwrap();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    assert!(srv.decrypt(&forged).is_err());
    assert!(srv.since_last_recv(Instant::now()) >= idle_before);

    // keepalive valid (payload gol): reseteaza timer-ul
    let ka = cli.encrypt(&[]).unwrap();
    assert_eq!(srv.decrypt(&ka).unwrap(), b"");
    assert!(srv.since_last_recv(Instant::now()) < idle_before);
}

#[test]
fn unknown_client_key_rejected() {
    let s = setup();
    let mut resp = responder(&s);
    let intruder = Keypair::generate().unwrap();
    // chiar cu codul TOTP corect, fara cheia statica a clientului nu intra
    let (_, msg1) = Initiator::start(&intruder, &s.server.public, &code_at(&s, NOW), ts(1)).unwrap();
    assert!(resp.accept(&msg1, NOW).is_err());
}

#[test]
fn wrong_server_key_rejected() {
    let s = setup();
    let mut resp = responder(&s);
    let fake_server = Keypair::generate().unwrap();
    let (_, msg1) = Initiator::start(&s.client, &fake_server.public, &code_at(&s, NOW), ts(1)).unwrap();
    // mac1 e calculat cu cheia publica gresita => oprit inainte de DH
    assert!(!resp.check_mac1(&msg1));
    assert!(matches!(resp.accept(&msg1, NOW), Err(Error::BadMac)));
}

#[test]
fn mac1_checked_before_handshake() {
    let s = setup();
    let mut resp = responder(&s);
    let (_, mut msg1) = Initiator::start(&s.client, &s.server.public, &code_at(&s, NOW), ts(1)).unwrap();
    assert!(resp.check_mac1(&msg1));

    // un bit schimbat in mac1 => respins ca BadMac, desi restul handshake-ului e valid
    let last = msg1.len() - 1;
    msg1[last] ^= 1;
    assert!(!resp.check_mac1(&msg1));
    assert!(matches!(resp.accept(&msg1, NOW), Err(Error::BadMac)));

    // la fel pentru un bit schimbat in header (indexul sender e acoperit de mac1)
    msg1[last] ^= 1;
    msg1[4] ^= 1;
    assert!(matches!(resp.accept(&msg1, NOW), Err(Error::BadMac)));
}
