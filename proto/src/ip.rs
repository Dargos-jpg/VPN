// citire minima de header IP din pachetele de pe TUN
// folosit ca filtru anti-spoofing: dupa decriptare, sursa trebuie sa fie ip-ul de tunel
// al peer-ului, altfel un client autentificat ar putea injecta trafic in numele altora

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const V4_HDR_MIN: usize = 20;
const V6_HDR: usize = 40;

pub fn source(pkt: &[u8]) -> Option<IpAddr> {
    match version(pkt)? {
        4 if pkt.len() >= V4_HDR_MIN => Some(IpAddr::V4(v4_at(pkt, 12))),
        6 if pkt.len() >= V6_HDR => Some(IpAddr::V6(v6_at(pkt, 8))),
        _ => None,
    }
}

pub fn destination(pkt: &[u8]) -> Option<IpAddr> {
    match version(pkt)? {
        4 if pkt.len() >= V4_HDR_MIN => Some(IpAddr::V4(v4_at(pkt, 16))),
        6 if pkt.len() >= V6_HDR => Some(IpAddr::V6(v6_at(pkt, 24))),
        _ => None,
    }
}

fn version(pkt: &[u8]) -> Option<u8> {
    pkt.first().map(|b| b >> 4)
}

fn v4_at(pkt: &[u8], i: usize) -> Ipv4Addr {
    let b: [u8; 4] = pkt[i..i + 4].try_into().unwrap();
    Ipv4Addr::from(b)
}

fn v6_at(pkt: &[u8], i: usize) -> Ipv6Addr {
    let b: [u8; 16] = pkt[i..i + 16].try_into().unwrap();
    Ipv6Addr::from(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_packet(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p
    }

    #[test]
    fn ipv4_addresses() {
        let p = v4_packet([10, 8, 0, 2], [10, 8, 0, 1]);
        assert_eq!(source(&p), Some("10.8.0.2".parse().unwrap()));
        assert_eq!(destination(&p), Some("10.8.0.1".parse().unwrap()));
    }

    #[test]
    fn ipv6_addresses() {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[23] = 1; // src ::1
        p[39] = 2; // dst ::2
        assert_eq!(source(&p), Some("::1".parse().unwrap()));
        assert_eq!(destination(&p), Some("::2".parse().unwrap()));
    }

    #[test]
    fn garbage() {
        assert_eq!(source(&[]), None);
        assert_eq!(source(&[0x45, 0, 0]), None); // header trunchiat
        assert_eq!(source(&[0x10; 40]), None); // versiune 1
    }
}
