// server VPN - deocamdata doar handshake + echo criptat peste UDP, fara TUN

use std::{
    io::ErrorKind,
    net::{SocketAddr, UdpSocket},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use qrcode::{render::unicode::Dense1x2, QrCode};
use serde::Deserialize;
use vpn_proto::{
    keys,
    packet::{self, Packet},
    totp, Keypair, Responder, Session,
};

#[derive(Parser)]
#[command(name = "vpn-server")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// genereaza perechea de chei statice a serverului
    Keygen,
    /// genereaza secretul TOTP si QR-ul de scanat cu aplicatia de autentificare
    Enroll {
        #[arg(long, default_value = "client")]
        account: String,
    },
    /// porneste serverul
    Run {
        #[arg(long, default_value = "server.toml")]
        config: PathBuf,
    },
}

#[derive(Deserialize)]
struct Config {
    listen: SocketAddr,
    private_key: String,
    public_key: String,
    client_public_key: String,
    totp_secret: String,
    #[serde(default = "default_skew")]
    skew_steps: u64,
}

fn default_skew() -> u64 {
    1
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen => keygen(),
        Cmd::Enroll { account } => enroll(&account),
        Cmd::Run { config } => run(&config),
    }
}

fn keygen() -> Result<()> {
    let kp = Keypair::generate()?;
    println!("private_key = \"{}\"", keys::encode_key(&kp.private));
    println!("public_key = \"{}\"", keys::encode_key(&kp.public));
    Ok(())
}

fn enroll(account: &str) -> Result<()> {
    let secret = totp::generate_secret();
    let uri = totp::otpauth_uri(&secret, "vpn-totp", account);
    let qr = QrCode::new(uri.as_bytes())?
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .build();

    println!("{qr}");
    println!("scaneaza QR-ul o singura data, apoi pune linia de mai jos in server.toml:\n");
    println!("totp_secret = \"{}\"", totp::encode_secret(&secret));
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn run(path: &PathBuf) -> Result<()> {
    let text = std::fs::read_to_string(path).with_context(|| format!("nu pot citi {}", path.display()))?;
    let cfg: Config = toml::from_str(&text)?;

    let local = Keypair {
        private: keys::decode_key(&cfg.private_key).context("private_key invalid")?,
        public: keys::decode_key(&cfg.public_key).context("public_key invalid")?,
    };
    let client_public = keys::decode_key(&cfg.client_public_key).context("client_public_key invalid")?;
    let secret = totp::decode_secret(&cfg.totp_secret).context("totp_secret invalid")?;
    let mut responder = Responder::new(local, client_public, secret, cfg.skew_steps);

    let sock = UdpSocket::bind(cfg.listen)?;
    eprintln!("ascult pe {}", cfg.listen);

    let mut peer: Option<(SocketAddr, Session)> = None;
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(r) => r,
            // pe windows un ICMP port unreachable apare ca eroare la recv
            Err(e) if e.kind() == ErrorKind::ConnectionReset => continue,
            Err(e) => return Err(e.into()),
        };
        let pkt = &buf[..n];

        match packet::parse(pkt) {
            Ok(Packet::Init { .. }) => match responder.accept(pkt, unix_now()) {
                Ok((session, resp)) => {
                    sock.send_to(&resp, from)?;
                    eprintln!("sesiune noua cu {from}");
                    peer = Some((from, session));
                }
                // niciun raspuns pe fir, doar log local
                Err(e) => eprintln!("handshake respins de la {from}: {e}"),
            },
            Ok(Packet::Data { .. }) => {
                let Some((addr, session)) = peer.as_mut() else {
                    continue;
                };
                match session.decrypt(pkt) {
                    Ok(pt) => {
                        // adresa se actualizeaza doar dupa un pachet autentificat (roaming)
                        *addr = from;
                        println!("{from}: {}", String::from_utf8_lossy(&pt));
                        match session.encrypt(&pt) {
                            Ok(reply) => {
                                sock.send_to(&reply, from)?;
                            }
                            Err(e) => eprintln!("nu pot cripta raspunsul: {e}"),
                        }
                    }
                    Err(e) => eprintln!("pachet de date respins de la {from}: {e}"),
                }
            }
            _ => {}
        }
    }
}
