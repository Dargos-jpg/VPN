// sesiune dupa handshake: ChaCha20-Poly1305 cu nonce explicit = counter din pachet
// transport stateless pentru ca pe UDP pachetele pot veni reordonate sau pierdute
//
// doua ceasuri separate:
// - varsta cheilor (`created`): rekey la REKEY_AFTER_TIME, refuzate dupa KEY_MAX_AGE
// - varsta autentificarii TOTP (`auth_time`): se pastreaza peste rekey-uri,
//   dupa AUTH_MAX_AGE e nevoie de cod TOTP nou

use std::time::{Duration, Instant};

use snow::StatelessTransportState;
use zeroize::Zeroizing;

use crate::{
    error::Error,
    packet::{self, Packet},
    replay::ReplayWindow,
};

const TAG_LEN: usize = 16;
// aceeasi limita ca la WireGuard, nonce-ul nu are voie sa se repete niciodata
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);
// clientul porneste rekey-ul dupa atat timp (ca la WireGuard)
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
// cheile unei sesiuni nu mai sunt folosite dupa atat timp, chiar daca rekey-ul a esuat
pub const KEY_MAX_AGE: Duration = Duration::from_secs(180);
// dupa atat timp de la autentificarea cu TOTP e nevoie de cod nou, oricate rekey-uri ar fi fost
pub const AUTH_MAX_AGE: Duration = Duration::from_secs(12 * 60 * 60);

pub const CHAIN_SECRET_LEN: usize = 32;

// ce mosteneste urmatorul rekey de la sesiunea curenta
#[derive(Clone)]
pub struct Chain {
    pub(crate) secret: Zeroizing<[u8; CHAIN_SECRET_LEN]>,
    pub(crate) auth_time: Instant,
}

pub struct Session {
    transport: StatelessTransportState,
    local_index: u32,
    remote_index: u32,
    send_counter: u64,
    replay: ReplayWindow,
    created: Instant,
    last_recv: Instant,
    last_send: Instant,
    chain: Chain,
}

impl Session {
    pub(crate) fn new(transport: StatelessTransportState, local_index: u32, remote_index: u32, chain: Chain) -> Self {
        let now = Instant::now();
        Self {
            transport,
            local_index,
            remote_index,
            send_counter: 0,
            replay: ReplayWindow::default(),
            created: now,
            last_recv: now,
            last_send: now,
            chain,
        }
    }

    pub fn local_index(&self) -> u32 {
        self.local_index
    }

    pub fn remote_index(&self) -> u32 {
        self.remote_index
    }

    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    // varsta cheilor
    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.created)
    }

    pub fn key_expired(&self, now: Instant) -> bool {
        self.age(now) >= KEY_MAX_AGE
    }

    pub fn auth_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.chain.auth_time) >= AUTH_MAX_AGE
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        self.key_expired(now) || self.auth_expired(now)
    }

    // cat timp a trecut de la ultimul pachet autentificat primit
    pub fn since_last_recv(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_recv)
    }

    pub fn since_last_send(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_send)
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let now = Instant::now();
        if self.is_expired(now) {
            return Err(Error::Expired);
        }
        if self.send_counter >= REJECT_AFTER_MESSAGES {
            return Err(Error::Exhausted);
        }
        let counter = self.send_counter;
        self.send_counter += 1;

        let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
        let n = self.transport.write_message(counter, plaintext, &mut ct)?;
        self.last_send = now;
        Ok(packet::encode_data(self.remote_index, counter, &ct[..n]))
    }

    pub fn decrypt(&mut self, pkt: &[u8]) -> Result<Vec<u8>, Error> {
        let now = Instant::now();
        if self.is_expired(now) {
            return Err(Error::Expired);
        }
        let Packet::Data {
            receiver,
            counter,
            payload,
        } = packet::parse(pkt)?
        else {
            return Err(Error::Malformed);
        };
        if receiver != self.local_index {
            return Err(Error::Malformed);
        }
        if counter >= REJECT_AFTER_MESSAGES || !self.replay.check(counter) {
            return Err(Error::Replay);
        }

        let mut pt = vec![0u8; payload.len()];
        let n = self.transport.read_message(counter, payload, &mut pt)?;
        self.replay.update(counter);
        // doar pachetele care trec de AEAD conteaza ca semn de viata
        self.last_recv = now;
        pt.truncate(n);
        Ok(pt)
    }
}
