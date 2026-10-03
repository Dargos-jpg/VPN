// transport TCP optional, pentru retele care blocheaza UDP
// fiecare pachet = [lungime u16 big endian][pachet], acelasi continut ca pe UDP
//
// compromisuri fata de UDP (de aceea UDP ramane implicit):
// - un port TCP deschis raspunde la SYN, deci serverul nu mai e invizibil la scanare
// - TCP peste TCP: retransmisiile tunelului si ale conexiunilor din el se pot amplifica
//
// aparari specifice TCP:
// - max MAX_CONNS conexiuni simultane
// - primul pachet trebuie sa fie un msg1 cu mac1 valid, trimis in FIRST_FRAME_TIMEOUT -
//   altfel conexiunea e inchisa (nimeni nu poate tine socket-uri deschise fara sa stie
//   cheia publica a serverului)
// - conexiune fara niciun pachet IDLE_TIMEOUT => inchisa (clientul trimite keepalive la 25s)
// - coada de iesire limitata: un client lent pierde pachete, nu blocheaza serverul

use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{tcp::OwnedReadHalf, TcpListener, TcpStream},
    sync::mpsc,
    time,
};
use vpn_proto::{
    mac,
    packet::{self, Packet},
};

pub const MAX_CONNS: usize = 64;
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
// pachete in asteptare spre un client; peste asta se arunca, ca pe UDP
pub const OUT_QUEUE: usize = 256;

// un pachet primit pe TCP, cu canalul pe care se raspunde
pub struct Incoming {
    pub pkt: Vec<u8>,
    pub addr: SocketAddr,
    pub tx: mpsc::Sender<Vec<u8>>,
}

pub async fn accept_loop(listener: TcpListener, mac1_key: [u8; 32], to_main: mpsc::Sender<Incoming>) {
    let conns = Arc::new(AtomicUsize::new(0));
    loop {
        let Ok((stream, addr)) = listener.accept().await else {
            continue;
        };
        if conns.load(Ordering::Relaxed) >= MAX_CONNS {
            continue; // stream e inchis la drop
        }
        conns.fetch_add(1, Ordering::Relaxed);
        let conns = conns.clone();
        let to_main = to_main.clone();
        tokio::spawn(async move {
            handle(stream, addr, mac1_key, to_main).await;
            conns.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn read_frame(rd: &mut OwnedReadHalf) -> io::Result<Vec<u8>> {
    let len = rd.read_u16().await? as usize;
    if len == 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut buf = vec![0u8; len];
    rd.read_exact(&mut buf).await?;
    Ok(buf)
}

fn valid_first_frame(pkt: &[u8], mac1_key: &[u8; 32]) -> bool {
    match packet::parse(pkt) {
        Ok(Packet::Init { mac1, .. }) => mac::verify_mac1(mac1_key, packet::init_mac_input(pkt), mac1),
        _ => false,
    }
}

async fn handle(stream: TcpStream, addr: SocketAddr, mac1_key: [u8; 32], to_main: mpsc::Sender<Incoming>) {
    let _ = stream.set_nodelay(true);
    let (mut rd, mut wr) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(OUT_QUEUE);
    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if wr.write_all(&frame).await.is_err() {
                break;
            }
        }
    });

    let mut first = true;
    loop {
        let limit = if first { FIRST_FRAME_TIMEOUT } else { IDLE_TIMEOUT };
        let Ok(Ok(pkt)) = time::timeout(limit, read_frame(&mut rd)).await else {
            break;
        };
        if first && !valid_first_frame(&pkt, &mac1_key) {
            break;
        }
        first = false;
        if to_main
            .send(Incoming {
                pkt,
                addr,
                tx: tx.clone(),
            })
            .await
            .is_err()
        {
            break;
        }
    }
    writer.abort();
}
