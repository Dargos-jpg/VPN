// sesiune dupa handshake: ChaCha20-Poly1305 cu nonce explicit = counter din pachet
// transport stateless pentru ca pe UDP pachetele pot veni reordonate sau pierdute

use snow::StatelessTransportState;

use crate::{
    error::Error,
    packet::{self, Packet},
    replay::ReplayWindow,
};

const TAG_LEN: usize = 16;
// aceeasi limita ca la WireGuard, nonce-ul nu are voie sa se repete niciodata
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

pub struct Session {
    transport: StatelessTransportState,
    local_index: u32,
    remote_index: u32,
    send_counter: u64,
    replay: ReplayWindow,
}

impl Session {
    pub(crate) fn new(transport: StatelessTransportState, local_index: u32, remote_index: u32) -> Self {
        Self {
            transport,
            local_index,
            remote_index,
            send_counter: 0,
            replay: ReplayWindow::default(),
        }
    }

    pub fn local_index(&self) -> u32 {
        self.local_index
    }

    pub fn remote_index(&self) -> u32 {
        self.remote_index
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        if self.send_counter >= REJECT_AFTER_MESSAGES {
            return Err(Error::Exhausted);
        }
        let counter = self.send_counter;
        self.send_counter += 1;

        let mut ct = vec![0u8; plaintext.len() + TAG_LEN];
        let n = self.transport.write_message(counter, plaintext, &mut ct)?;
        Ok(packet::encode_data(self.remote_index, counter, &ct[..n]))
    }

    pub fn decrypt(&mut self, pkt: &[u8]) -> Result<Vec<u8>, Error> {
        let Packet::Data { receiver, counter, payload } = packet::parse(pkt)? else {
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
        pt.truncate(n);
        Ok(pt)
    }
}
