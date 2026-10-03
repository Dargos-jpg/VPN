// handshake Noise IKpsk1
//
// msg1 (client -> server): e, es, s, ss, psk + payload = timestamp
// msg2 (server -> client): e, ee, se       + payload = secret de lant pentru urmatorul rekey
//
// - clientul stie dinainte cheia statica a serverului (pinning), serverul pe a clientului
// - la conectare psk = derivat din codul TOTP; la rekey psk = derivat din secretul de lant
//   al sesiunii curente (fara cod, fara interventia userului)
// - psk-ul intra la finalul msg1 => serverul verifica psk-ul din primul pachet si poate
//   sa nu raspunda deloc daca e gresit
// - timestamp-ul din msg1 trebuie sa creasca strict, un msg1 capturat nu poate fi
//   retrimis ca sa reseteze sesiunea

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rand::{rngs::OsRng, RngCore};
use snow::{params::NoiseParams, Builder, HandshakeState};
use zeroize::Zeroizing;

use crate::{
    error::Error,
    keys::Keypair,
    mac::{self, MAC_LEN},
    packet::{self, Packet},
    psk,
    session::{Chain, Session, CHAIN_SECRET_LEN},
    totp,
};

pub const NOISE_PARAMS: &str = "Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s";
const MAX_MSG: usize = 65535;
const TS_LEN: usize = 8;
const NS_PER_SEC: u64 = 1_000_000_000;
// diferenta maxima acceptata intre ceasul laptopului si al serverului
pub const MAX_CLOCK_DIFF_SECS: u64 = 120;

pub(crate) fn params() -> NoiseParams {
    NOISE_PARAMS.parse().expect("parametrii noise sunt constanti si valizi")
}

fn random_index() -> u32 {
    OsRng.next_u32()
}

// nanosecunde de la epoch
pub fn timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("ceas inainte de 1970")
        .as_nanos() as u64
}

pub struct Initiator {
    state: HandshakeState,
    local_index: u32,
    // la rekey se pastreaza momentul autentificarii TOTP initiale
    auth_time: Option<Instant>,
}

impl Initiator {
    // conectare: code = cele 6 cifre citite de pe telefon
    pub fn start(
        local: &Keypair,
        server_public: &[u8; 32],
        code: &str,
        timestamp: u64,
    ) -> Result<(Self, Vec<u8>), Error> {
        let psk = Zeroizing::new(psk::derive_psk(code, &local.public, server_public));
        Self::start_with_psk(local, server_public, &psk, timestamp, None)
    }

    // rekey: psk din secretul de lant al sesiunii curente
    pub fn start_rekey(
        local: &Keypair,
        server_public: &[u8; 32],
        chain: &Chain,
        timestamp: u64,
    ) -> Result<(Self, Vec<u8>), Error> {
        let psk = Zeroizing::new(psk::derive_rekey_psk(&chain.secret, &local.public, server_public));
        Self::start_with_psk(local, server_public, &psk, timestamp, Some(chain.auth_time))
    }

    fn start_with_psk(
        local: &Keypair,
        server_public: &[u8; 32],
        psk: &[u8; 32],
        timestamp: u64,
        auth_time: Option<Instant>,
    ) -> Result<(Self, Vec<u8>), Error> {
        let mut state = Builder::new(params())
            .local_private_key(&local.private)
            .remote_public_key(server_public)
            .psk(1, psk)
            .build_initiator()?;

        let local_index = random_index();
        let mut buf = vec![0u8; MAX_MSG];
        let n = state.write_message(&timestamp.to_be_bytes(), &mut buf)?;
        // mac1 calculat peste header + mesaj noise, apoi pus pe ultimii 16 bytes
        let mut pkt = packet::encode_init(local_index, &buf[..n], &[0u8; MAC_LEN]);
        let tag = mac::mac1(&mac::mac1_key(server_public), packet::init_mac_input(&pkt));
        let len = pkt.len();
        pkt[len - MAC_LEN..].copy_from_slice(&tag);
        Ok((
            Self {
                state,
                local_index,
                auth_time,
            },
            pkt,
        ))
    }

    pub fn finish(mut self, pkt: &[u8]) -> Result<Session, Error> {
        let Packet::Resp {
            sender,
            receiver,
            noise,
        } = packet::parse(pkt)?
        else {
            return Err(Error::Malformed);
        };
        if receiver != self.local_index {
            return Err(Error::Malformed);
        }

        let mut payload = Zeroizing::new(vec![0u8; MAX_MSG]);
        let n = self.state.read_message(noise, &mut payload)?;
        if n != CHAIN_SECRET_LEN {
            return Err(Error::Malformed);
        }
        let chain = Chain {
            secret: Zeroizing::new(payload[..CHAIN_SECRET_LEN].try_into().unwrap()),
            auth_time: self.auth_time.unwrap_or_else(Instant::now),
        };
        let transport = self.state.into_stateless_transport_mode()?;
        Ok(Session::new(transport, self.local_index, sender, chain))
    }
}

// rezultatul unui handshake reusit pe server
pub struct Accepted {
    pub session: Session,
    pub reply: Vec<u8>,
    // true = rekey pe lantul sesiunii curente, false = conectare noua cu TOTP
    pub rekey: bool,
}

pub struct Responder {
    local: Keypair,
    client_public: [u8; 32],
    totp_secret: Zeroizing<Vec<u8>>,
    skew_steps: u64,
    last_timestamp: u64,
    mac1_key: [u8; 32],
}

impl Responder {
    pub fn new(local: Keypair, client_public: [u8; 32], totp_secret: Vec<u8>, skew_steps: u64) -> Self {
        let mac1_key = mac::mac1_key(&local.public);
        Self {
            local,
            client_public,
            totp_secret: Zeroizing::new(totp_secret),
            skew_steps,
            last_timestamp: 0,
            mac1_key,
        }
    }

    // verificare ieftina (un BLAKE2s), fara DH: apelantul o poate face inainte de limitarea de rata
    pub fn check_mac1(&self, pkt: &[u8]) -> bool {
        match packet::parse(pkt) {
            Ok(Packet::Init { mac1, .. }) => mac::verify_mac1(&self.mac1_key, packet::init_mac_input(pkt), mac1),
            _ => false,
        }
    }

    // doar conectare cu TOTP
    pub fn accept(&mut self, pkt: &[u8], now_unix: u64) -> Result<(Session, Vec<u8>), Error> {
        let a = self.accept_chained(pkt, now_unix, None)?;
        Ok((a.session, a.reply))
    }

    // incearca intai rekey pe lantul sesiunii curente (daca exista), apoi fiecare fereastra
    // TOTP acceptata. la Err apelantul nu trimite nimic inapoi
    pub fn accept_chained(&mut self, pkt: &[u8], now_unix: u64, chain: Option<&Chain>) -> Result<Accepted, Error> {
        let Packet::Init { sender, noise, .. } = packet::parse(pkt)? else {
            return Err(Error::Malformed);
        };
        // inainte de orice DH: cine nu stie cheia publica a serverului e oprit aici
        if !self.check_mac1(pkt) {
            return Err(Error::BadMac);
        }

        // (psk, momentul autentificarii TOTP pe care il mosteneste sesiunea, e rekey)
        let mut candidates: Vec<(Zeroizing<[u8; 32]>, Option<Instant>, bool)> = Vec::new();
        if let Some(c) = chain {
            let psk = psk::derive_rekey_psk(&c.secret, &self.client_public, &self.local.public);
            candidates.push((Zeroizing::new(psk), Some(c.auth_time), true));
        }
        for step in totp::candidate_steps(now_unix, self.skew_steps) {
            let code = Zeroizing::new(totp::code(&self.totp_secret, step, totp::DIGITS));
            let psk = psk::derive_psk(&code, &self.client_public, &self.local.public);
            candidates.push((Zeroizing::new(psk), None, false));
        }

        let mut payload = Zeroizing::new(vec![0u8; MAX_MSG]);
        for (psk, auth_time, rekey) in candidates {
            let mut state = Builder::new(params())
                .local_private_key(&self.local.private)
                .psk(1, &psk[..])
                .build_responder()?;

            // AEAD pe payload pica daca psk-ul nu se potriveste - nu exista comparatie de coduri
            let Ok(n) = state.read_message(noise, &mut payload) else {
                continue;
            };

            if state.get_remote_static() != Some(&self.client_public[..]) {
                return Err(Error::Rejected);
            }
            if n != TS_LEN {
                return Err(Error::Malformed);
            }
            let ts = u64::from_be_bytes(payload[..TS_LEN].try_into().unwrap());
            // last_timestamp se pierde la restart, deci limita de varsta e cea care
            // opreste un msg1 capturat inainte de restart (BUG-004)
            let now_ns = now_unix.saturating_mul(NS_PER_SEC);
            if ts.abs_diff(now_ns) > MAX_CLOCK_DIFF_SECS * NS_PER_SEC {
                return Err(Error::Stale);
            }
            if ts <= self.last_timestamp {
                return Err(Error::Replay);
            }
            self.last_timestamp = ts;

            // secret de lant nou la fiecare handshake: un rekey nu poate fi facut de doua ori
            // pe acelasi secret, iar cel vechi nu mai e acceptat dupa ce sesiunea e inlocuita
            let mut secret = Zeroizing::new([0u8; CHAIN_SECRET_LEN]);
            OsRng.fill_bytes(&mut secret[..]);

            let local_index = random_index();
            let mut buf = vec![0u8; MAX_MSG];
            let m = state.write_message(&secret[..], &mut buf)?;
            let transport = state.into_stateless_transport_mode()?;
            let chain = Chain {
                secret,
                auth_time: auth_time.unwrap_or_else(Instant::now),
            };
            return Ok(Accepted {
                session: Session::new(transport, local_index, sender, chain),
                reply: packet::encode_resp(local_index, sender, &buf[..m]),
                rekey,
            });
        }
        Err(Error::Rejected)
    }
}
