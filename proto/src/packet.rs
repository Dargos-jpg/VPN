// framing pe fir, toate campurile big endian
//
// init: [type=1][0 0 0][sender u32][mesaj noise 1][mac1 16]
// resp: [type=2][0 0 0][sender u32][receiver u32][mesaj noise 2]
// data: [type=3][0 0 0][receiver u32][counter u64][ciphertext + tag]
//
// indexurile identifica sesiunea fara sa depinda de ip:port (roaming, multi-client mai tarziu)
// mac1 acopera tot ce e inaintea lui (vezi mac.rs)

use crate::{error::Error, mac::MAC_LEN};

pub const TYPE_INIT: u8 = 1;
pub const TYPE_RESP: u8 = 2;
pub const TYPE_DATA: u8 = 3;

const INIT_HDR: usize = 8;
const RESP_HDR: usize = 12;
const DATA_HDR: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum Packet<'a> {
    Init {
        sender: u32,
        noise: &'a [u8],
        mac1: &'a [u8],
    },
    Resp {
        sender: u32,
        receiver: u32,
        noise: &'a [u8],
    },
    Data {
        receiver: u32,
        counter: u64,
        payload: &'a [u8],
    },
}

pub fn parse(buf: &[u8]) -> Result<Packet<'_>, Error> {
    if buf.len() < 4 || buf[1..4] != [0, 0, 0] {
        return Err(Error::Malformed);
    }
    match buf[0] {
        TYPE_INIT if buf.len() > INIT_HDR + MAC_LEN => Ok(Packet::Init {
            sender: u32_at(buf, 4),
            noise: &buf[INIT_HDR..buf.len() - MAC_LEN],
            mac1: &buf[buf.len() - MAC_LEN..],
        }),
        TYPE_RESP if buf.len() > RESP_HDR => Ok(Packet::Resp {
            sender: u32_at(buf, 4),
            receiver: u32_at(buf, 8),
            noise: &buf[RESP_HDR..],
        }),
        TYPE_DATA if buf.len() >= DATA_HDR => Ok(Packet::Data {
            receiver: u32_at(buf, 4),
            counter: u64::from_be_bytes(buf[8..16].try_into().unwrap()),
            payload: &buf[DATA_HDR..],
        }),
        _ => Err(Error::Malformed),
    }
}

pub fn encode_init(sender: u32, noise: &[u8], mac1: &[u8; MAC_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(INIT_HDR + noise.len() + MAC_LEN);
    out.extend_from_slice(&[TYPE_INIT, 0, 0, 0]);
    out.extend_from_slice(&sender.to_be_bytes());
    out.extend_from_slice(noise);
    out.extend_from_slice(mac1);
    out
}

// transport TCP: fiecare pachet precedat de lungimea lui (u16 big endian), continutul identic cu UDP
pub const MAX_FRAME: usize = u16::MAX as usize;

pub fn frame(pkt: &[u8]) -> Result<Vec<u8>, Error> {
    if pkt.is_empty() || pkt.len() > MAX_FRAME {
        return Err(Error::Malformed);
    }
    let mut out = Vec::with_capacity(2 + pkt.len());
    out.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
    out.extend_from_slice(pkt);
    Ok(out)
}

// bytes acoperiti de mac1 intr-un pachet init: tot in afara de ultimii 16
pub fn init_mac_input(pkt: &[u8]) -> &[u8] {
    &pkt[..pkt.len().saturating_sub(MAC_LEN)]
}

pub fn encode_resp(sender: u32, receiver: u32, noise: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(RESP_HDR + noise.len());
    out.extend_from_slice(&[TYPE_RESP, 0, 0, 0]);
    out.extend_from_slice(&sender.to_be_bytes());
    out.extend_from_slice(&receiver.to_be_bytes());
    out.extend_from_slice(noise);
    out
}

pub fn encode_data(receiver: u32, counter: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DATA_HDR + payload.len());
    out.extend_from_slice(&[TYPE_DATA, 0, 0, 0]);
    out.extend_from_slice(&receiver.to_be_bytes());
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn u32_at(buf: &[u8], i: usize) -> u32 {
    u32::from_be_bytes(buf[i..i + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let p = encode_init(7, b"abc", &[5u8; MAC_LEN]);
        assert_eq!(
            parse(&p).unwrap(),
            Packet::Init {
                sender: 7,
                noise: b"abc",
                mac1: &[5u8; MAC_LEN]
            }
        );
        assert_eq!(init_mac_input(&p), &p[..p.len() - MAC_LEN]);

        let p = encode_resp(1, 2, b"xy");
        assert_eq!(
            parse(&p).unwrap(),
            Packet::Resp {
                sender: 1,
                receiver: 2,
                noise: b"xy"
            }
        );

        let p = encode_data(9, u64::MAX - 1, b"");
        assert_eq!(
            parse(&p).unwrap(),
            Packet::Data {
                receiver: 9,
                counter: u64::MAX - 1,
                payload: b""
            }
        );
    }

    #[test]
    fn stream_framing() {
        let f = frame(b"abc").unwrap();
        assert_eq!(f, [0, 3, b'a', b'b', b'c']);
        assert!(frame(&[]).is_err());
        assert!(frame(&vec![0u8; MAX_FRAME + 1]).is_err());
        assert_eq!(frame(&vec![1u8; MAX_FRAME]).unwrap().len(), MAX_FRAME + 2);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[TYPE_INIT, 0, 0, 0, 1, 2, 3, 4]).is_err()); // fara mesaj noise
        assert!(parse(&[&[TYPE_INIT, 0, 0, 0, 1, 2, 3, 4][..], &[0u8; MAC_LEN]].concat()).is_err()); // doar mac1
        assert!(parse(&[TYPE_DATA, 1, 0, 0]).is_err()); // bytes rezervati nenuli
        assert!(parse(&[9, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }
}
