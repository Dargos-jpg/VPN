// framing pe fir, toate campurile big endian
//
// init: [type=1][0 0 0][sender u32][mesaj noise 1]
// resp: [type=2][0 0 0][sender u32][receiver u32][mesaj noise 2]
// data: [type=3][0 0 0][receiver u32][counter u64][ciphertext + tag]
//
// indexurile identifica sesiunea fara sa depinda de ip:port (roaming, multi-client mai tarziu)

use crate::error::Error;

pub const TYPE_INIT: u8 = 1;
pub const TYPE_RESP: u8 = 2;
pub const TYPE_DATA: u8 = 3;

const INIT_HDR: usize = 8;
const RESP_HDR: usize = 12;
const DATA_HDR: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum Packet<'a> {
    Init { sender: u32, noise: &'a [u8] },
    Resp { sender: u32, receiver: u32, noise: &'a [u8] },
    Data { receiver: u32, counter: u64, payload: &'a [u8] },
}

pub fn parse(buf: &[u8]) -> Result<Packet<'_>, Error> {
    if buf.len() < 4 || buf[1..4] != [0, 0, 0] {
        return Err(Error::Malformed);
    }
    match buf[0] {
        TYPE_INIT if buf.len() > INIT_HDR => Ok(Packet::Init {
            sender: u32_at(buf, 4),
            noise: &buf[INIT_HDR..],
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

pub fn encode_init(sender: u32, noise: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(INIT_HDR + noise.len());
    out.extend_from_slice(&[TYPE_INIT, 0, 0, 0]);
    out.extend_from_slice(&sender.to_be_bytes());
    out.extend_from_slice(noise);
    out
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
        let p = encode_init(7, b"abc");
        assert_eq!(parse(&p).unwrap(), Packet::Init { sender: 7, noise: b"abc" });

        let p = encode_resp(1, 2, b"xy");
        assert_eq!(parse(&p).unwrap(), Packet::Resp { sender: 1, receiver: 2, noise: b"xy" });

        let p = encode_data(9, u64::MAX - 1, b"");
        assert_eq!(parse(&p).unwrap(), Packet::Data { receiver: 9, counter: u64::MAX - 1, payload: b"" });
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[TYPE_INIT, 0, 0, 0, 1, 2, 3, 4]).is_err()); // fara mesaj noise
        assert!(parse(&[TYPE_DATA, 1, 0, 0]).is_err()); // bytes rezervati nenuli
        assert!(parse(&[9, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }
}
