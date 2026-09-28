// client VPN - deocamdata handshake + mesaje text criptate, serverul le trimite inapoi

use std::{
    io::{self, BufRead, Write},
    net::{SocketAddr, UdpSocket},
    path::PathBuf,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use vpn_proto::{handshake, keys, Initiator, Keypair};

#[derive(Parser)]
#[command(name = "vpn-client")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// genereaza perechea de chei statice a clientului
    Keygen,
    /// conectare la server, cere codul TOTP
    Connect {
        #[arg(long, default_value = "client.toml")]
        config: PathBuf,
    },
}

#[derive(Deserialize)]
struct Config {
    server: SocketAddr,
    private_key: String,
    public_key: String,
    server_public_key: String,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen => keygen(),
        Cmd::Connect { config } => connect(&config),
    }
}

fn keygen() -> Result<()> {
    let kp = Keypair::generate()?;
    println!("private_key = \"{}\"", keys::encode_key(&kp.private));
    println!("public_key = \"{}\"", keys::encode_key(&kp.public));
    Ok(())
}

fn read_code() -> Result<String> {
    print!("cod TOTP: ");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    let code = line.trim().to_string();
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        bail!("codul trebuie sa aiba exact 6 cifre");
    }
    Ok(code)
}

fn connect(path: &PathBuf) -> Result<()> {
    let text = std::fs::read_to_string(path).with_context(|| format!("nu pot citi {}", path.display()))?;
    let cfg: Config = toml::from_str(&text)?;

    let local = Keypair {
        private: keys::decode_key(&cfg.private_key).context("private_key invalid")?,
        public: keys::decode_key(&cfg.public_key).context("public_key invalid")?,
    };
    let server_public = keys::decode_key(&cfg.server_public_key).context("server_public_key invalid")?;

    let code = read_code()?;

    let bind: SocketAddr = if cfg.server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse()?;
    let sock = UdpSocket::bind(bind)?;
    sock.connect(cfg.server)?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;

    let (init, msg1) = Initiator::start(&local, &server_public, &code, handshake::timestamp_now())?;
    sock.send(&msg1)?;

    let mut buf = vec![0u8; 65535];
    // serverul tace la cod gresit, deci singurul semnal e timeout-ul
    let n = sock
        .recv(&mut buf)
        .context("niciun raspuns - cod gresit/expirat, chei gresite sau server oprit")?;
    let mut session = init.finish(&buf[..n])?;
    println!("conectat la {}. scrie mesaje, ctrl+c pentru iesire", cfg.server);

    for line in io::stdin().lock().lines() {
        let line = line?;
        sock.send(&session.encrypt(line.as_bytes())?)?;
        match sock.recv(&mut buf) {
            Ok(n) => match session.decrypt(&buf[..n]) {
                Ok(pt) => println!("echo: {}", String::from_utf8_lossy(&pt)),
                Err(e) => eprintln!("pachet respins: {e}"),
            },
            Err(e) => eprintln!("fara raspuns: {e}"),
        }
    }
    Ok(())
}
