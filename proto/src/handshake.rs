// handshake Noise IKpsk1
//
// msg1 (client -> server): e, es, s, ss, psk + payload = timestamp
// msg2 (server -> client): e, ee, se
//
// - clientul stie dinainte cheia statica a serverului (pinning), serverul pe a clientului
// - psk = derivat din codul TOTP, intra la finalul msg1 => serverul verifica TOTP-ul
//   din primul pachet si poate sa nu raspunda deloc daca e gresit
// - timestamp-ul din msg1 trebuie sa creasca strict, un msg1 capturat nu poate fi
//   retrimis in fereastra TOTP ca sa reseteze sesiunea

use std::time::{SystemTime, UNIX_EPOCH};

use rand::{rngs::OsRng, RngCore};
use snow::{params::NoiseParams, Builder, HandshakeState};
use zeroize::Zeroizing;

use crate::{
    error::Error,
    keys::Keypair,
    packet::{self, Packet},
    psk,
    session::Session,
    totp,
};

pub const NOISE_PARAMS: &str = "Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s";
const MAX_MSG: usize = 65535;
const TS_LEN: usize = 8;

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
}

impl Initiator {
    // code = cele 6 cifre citite de pe telefon
    pub fn start(
        local: &Keypair,
        server_public: &[u8; 32],
        code: &str,
        timestamp: u64,
    ) -> Result<(Self, Vec<u8>), Error> {
        let psk = Zeroizing::new(psk::derive_psk(code, &local.public, server_public));
        let mut state = Builder::new(params())
            .local_private_key(&local.private)
            .remote_public_key(server_public)
            .psk(1, &psk[..])
            .build_initiator()?;

        let local_index = random_index();
        let mut buf = vec![0u8; MAX_MSG];
        let n = state.write_message(&timestamp.to_be_bytes(), &mut buf)?;
        let pkt = packet::encode_init(local_index, &buf[..n]);
        Ok((Self { state, local_index }, pkt))
    }

    pub fn finish(mut self, pkt: &[u8]) -> Result<Session, Error> {
        let Packet::Resp { sender, receiver, noise } = packet::parse(pkt)? else {
            return Err(Error::Malformed);
        };
        if receiver != self.local_index {
            return Err(Error::Malformed);
        }

        let mut buf = vec![0u8; MAX_MSG];
        self.state.read_message(noise, &mut buf)?;
        let transport = self.state.into_stateless_transport_mode()?;
        Ok(Session::new(transport, self.local_index, sender))
    }
}

pub struct Responder {
    local: Keypair,
    client_public: [u8; 32],
    totp_secret: Zeroizing<Vec<u8>>,
    skew_steps: u64,
    last_timestamp: u64,
}

impl Responder {
    pub fn new(local: Keypair, client_public: [u8; 32], totp_secret: Vec<u8>, skew_steps: u64) -> Self {
        Self {
            local,
            client_public,
            totp_secret: Zeroizing::new(totp_secret),
            skew_steps,
            last_timestamp: 0,
        }
    }

    // incearca fiecare fereastra TOTP acceptata. la Err apelantul nu trimite nimic inapoi
    pub fn accept(&mut self, pkt: &[u8], now_unix: u64) -> Result<(Session, Vec<u8>), Error> {
        let Packet::Init { sender, noise } = packet::parse(pkt)? else {
            return Err(Error::Malformed);
        };

        let mut payload = Zeroizing::new(vec![0u8; MAX_MSG]);
        for step in totp::candidate_steps(now_unix, self.skew_steps) {
            let code = Zeroizing::new(totp::code(&self.totp_secret, step, totp::DIGITS));
            let psk = Zeroizing::new(psk::derive_psk(&code, &self.client_public, &self.local.public));
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
            if ts <= self.last_timestamp {
                return Err(Error::Replay);
            }
            self.last_timestamp = ts;

            let local_index = random_index();
            let mut buf = vec![0u8; MAX_MSG];
            let m = state.write_message(&[], &mut buf)?;
            let transport = state.into_stateless_transport_mode()?;
            let resp = packet::encode_resp(local_index, sender, &buf[..m]);
            return Ok((Session::new(transport, local_index, sender), resp));
        }
        Err(Error::Rejected)
    }
}
