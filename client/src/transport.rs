// transportul clientului: UDP (implicit) sau TCP (retele care blocheaza UDP)
// pe TCP fiecare pachet = [lungime u16 big endian][pachet], ca pe server
//
// pe TCP citirea si scrierea ruleaza in task-uri separate legate prin canale:
// - recv() e folosit in tokio::select!, deci trebuie sa poata fi intrerupt oricand fara sa
//   piarda date. un read_exact intrerupt la jumatatea unui pachet ar desincroniza framing-ul;
//   citirea dintr-un canal nu are problema asta
// - cand conexiunea TCP se inchide, recv() asteapta la nesfarsit in loc sa intoarca erori
//   in bucla; pierderea e detectata de timeout-ul de dead peer, iar reconectarea deschide
//   o conexiune noua

use std::{io, net::SocketAddr};

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{mpsc, Mutex},
};
use vpn_proto::packet;

#[derive(Deserialize, Default, PartialEq, Clone, Copy, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Udp,
    Tcp,
}

pub enum Transport {
    Udp(UdpSocket),
    Tcp {
        out: mpsc::Sender<Vec<u8>>,
        inc: Mutex<mpsc::Receiver<Vec<u8>>>,
    },
}

const QUEUE: usize = 256;

impl Transport {
    pub async fn open(kind: Kind, server: SocketAddr) -> Result<Self> {
        match kind {
            Kind::Udp => {
                let bind: SocketAddr = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse()?;
                let sock = UdpSocket::bind(bind).await?;
                sock.connect(server).await?;
                Ok(Transport::Udp(sock))
            }
            Kind::Tcp => {
                let stream = TcpStream::connect(server)
                    .await
                    .with_context(|| format!("nu ma pot conecta prin TCP la {server}"))?;
                let _ = stream.set_nodelay(true);
                let (mut rd, mut wr) = stream.into_split();
                let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(QUEUE);
                let (inc_tx, inc_rx) = mpsc::channel::<Vec<u8>>(QUEUE);
                tokio::spawn(async move {
                    while let Some(frame) = out_rx.recv().await {
                        if wr.write_all(&frame).await.is_err() {
                            break;
                        }
                    }
                });
                tokio::spawn(async move {
                    while let Ok(len) = rd.read_u16().await {
                        let mut buf = vec![0u8; len as usize];
                        if len == 0 || rd.read_exact(&mut buf).await.is_err() {
                            break;
                        }
                        if inc_tx.send(buf).await.is_err() {
                            break;
                        }
                    }
                });
                Ok(Transport::Tcp {
                    out: out_tx,
                    inc: Mutex::new(inc_rx),
                })
            }
        }
    }

    pub async fn send(&self, pkt: &[u8]) -> io::Result<()> {
        match self {
            Transport::Udp(sock) => sock.send(pkt).await.map(|_| ()),
            Transport::Tcp { out, .. } => {
                let frame = packet::frame(pkt).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
                // conexiune inchisa = la fel ca un server oprit pe UDP: eroare temporara
                out.send(frame)
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::ConnectionReset))
            }
        }
    }

    // sigur de folosit in tokio::select! (poate fi intrerupt fara pierdere de date)
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Transport::Udp(sock) => sock.recv(buf).await,
            Transport::Tcp { inc, .. } => match inc.lock().await.recv().await {
                Some(pkt) if pkt.len() <= buf.len() => {
                    buf[..pkt.len()].copy_from_slice(&pkt);
                    Ok(pkt.len())
                }
                Some(_) => Err(io::ErrorKind::InvalidData.into()),
                // conexiune inchisa: asteptam, dead peer-ul declanseaza reconectarea
                None => std::future::pending().await,
            },
        }
    }
}
