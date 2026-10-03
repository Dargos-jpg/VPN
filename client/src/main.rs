// client VPN
//
// - `connect`: tunelul din terminal, cere codul TOTP la tastatura
// - `daemon`:  tunelul ca serviciu (admin/root), condus de interfata grafica sau de `ctl` pe un canal local
// - `ctl`:     comenzi catre daemon din linia de comanda (status, connect, disconnect, watch)
//
// logica tunelului e in engine.rs (split/full tunnel, rekey, reconectare), comuna pentru toate

mod config;
mod daemon;
mod engine;
mod routes;
mod transport;

use std::{
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use config::Config;
use engine::{Identity, Reporter};
use tokio::{
    io::{AsyncBufRead, BufReader},
    sync::mpsc,
    time,
};
use tokio_util::sync::CancellationToken;
use vpn_control::{read_msg, valid_code, write_msg, Event, Request, State, Status, DEFAULT_ENDPOINT};
use vpn_proto::{keys, Keypair};

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
    /// conectare din terminal, cere codul TOTP (cere drepturi de admin pentru TUN)
    Connect {
        #[arg(long, default_value = "client.toml")]
        config: PathBuf,
    },
    /// ruleaza ca serviciu (admin/root) si asteapta comenzi de la interfata grafica / ctl
    Daemon {
        #[arg(long, default_value = "client.toml")]
        config: PathBuf,
        /// canalul local (implicit: named pipe pe windows, /run/vpn-totp.sock pe linux)
        #[arg(long)]
        endpoint: Option<String>,
        /// linux: grupul care poate folosi socket-ul (ex. userii care pornesc interfata)
        #[arg(long)]
        group: Option<String>,
    },
    /// comenzi catre daemon
    Ctl {
        #[arg(long)]
        endpoint: Option<String>,
        #[command(subcommand)]
        action: CtlAction,
    },
}

#[derive(Subcommand)]
enum CtlAction {
    /// starea curenta (JSON)
    Status,
    /// conectare cu codul TOTP de pe telefon (sau cod nou dupa o sesiune pierduta)
    Connect { code: String },
    /// deconectare
    Disconnect,
    /// afiseaza evenimentele pe masura ce apar
    Watch,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen => keygen(),
        Cmd::Connect { config } => cli_connect(&config).await,
        Cmd::Daemon {
            config,
            endpoint,
            group,
        } => {
            let cfg = Config::load(&config)?;
            daemon::serve(cfg, endpoint.unwrap_or_else(|| DEFAULT_ENDPOINT.into()), group).await
        }
        Cmd::Ctl { endpoint, action } => ctl(&endpoint.unwrap_or_else(|| DEFAULT_ENDPOINT.into()), action).await,
    }
}

fn keygen() -> Result<()> {
    let kp = Keypair::generate()?;
    println!("private_key = \"{}\"", keys::encode_key(&kp.private));
    println!("public_key = \"{}\"", keys::encode_key(&kp.public));
    Ok(())
}

// ctrl+c sau SIGTERM (kill, systemd): iesire curata, ca rutele de full tunnel sa fie sterse
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            },
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn prompt() {
    print!("cod TOTP: ");
    let _ = io::stdout().flush();
}

// citeste coduri de la tastatura pe un thread separat (citirea blocheaza si nu poate fi
// intrerupta; un thread obisnuit nu tine procesul in viata la iesire)
fn stdin_reader(tx: mpsc::Sender<String>) {
    let stdin = io::stdin();
    loop {
        let mut line = String::new();
        if stdin.lock().read_line(&mut line).unwrap_or(0) == 0 {
            return; // stdin inchis: canalul se inchide odata cu tx
        }
        let code = line.trim();
        if valid_code(code) {
            if tx.blocking_send(code.to_string()).is_err() {
                return;
            }
        } else {
            println!("codul trebuie sa aiba exact 6 cifre");
            prompt();
        }
    }
}

async fn cli_connect(path: &Path) -> Result<()> {
    let cfg = Config::load(path)?;
    let id = Identity::from_config(&cfg)?;
    let rep = Reporter::new(&cfg);

    let stop = CancellationToken::new();
    {
        let stop = stop.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            stop.cancel();
        });
    }

    let (tx, mut rx) = mpsc::channel(4);
    std::thread::spawn(move || stdin_reader(tx));

    // mesajele motorului afisate in terminal; promptul reapare cand e nevoie de cod nou
    let mut sub = rep.subscribe();
    let printer = tokio::spawn(async move {
        let mut last = State::Disconnected;
        loop {
            match sub.recv().await {
                Ok(Event::Log { message }) | Ok(Event::Error { message }) => println!("{message}"),
                Ok(Event::Status(s)) => {
                    if s.state == State::NeedCode && last != State::NeedCode {
                        prompt();
                    }
                    last = s.state;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
    });

    prompt();
    let result = engine::run(&cfg, &id, &mut rx, &rep, &stop, None).await;
    // inchide canalul de evenimente si lasa ultimele mesaje sa fie afisate
    drop(rep);
    let _ = time::timeout(Duration::from_secs(1), printer).await;
    result
}

async fn ctl(endpoint: &str, action: CtlAction) -> Result<()> {
    let stream = vpn_control::connect(endpoint)
        .await
        .with_context(|| format!("daemon-ul nu raspunde pe {endpoint}"))?;
    let (rd, mut wr) = tokio::io::split(stream);
    let mut rd = BufReader::new(rd);

    // primul mesaj de la daemon e mereu starea curenta
    let Some(Event::Status(initial)) = read_msg::<_, Event>(&mut rd).await? else {
        bail!("raspuns neasteptat de la daemon");
    };

    match action {
        CtlAction::Status => println!("{}", serde_json::to_string_pretty(&initial)?),
        CtlAction::Watch => {
            println!("{}", serde_json::to_string(&Event::Status(initial))?);
            while let Some(ev) = read_msg::<_, Event>(&mut rd).await? {
                println!("{}", serde_json::to_string(&ev)?);
            }
        }
        CtlAction::Connect { code } => {
            write_msg(&mut wr, &Request::Connect { code }).await?;
            let s = time::timeout(Duration::from_secs(15), wait_for(&mut rd, State::Connected))
                .await
                .context("timeout: conexiunea nu s-a stabilit")??;
            println!("conectat la {} ({}, {})", s.server, s.transport, s.mode);
        }
        CtlAction::Disconnect => {
            if initial.state == State::Disconnected {
                bail!("nu e conectat");
            }
            write_msg(&mut wr, &Request::Disconnect).await?;
            time::timeout(Duration::from_secs(10), wait_for(&mut rd, State::Disconnected))
                .await
                .context("timeout: deconectarea nu s-a terminat")??;
            println!("deconectat");
        }
    }
    Ok(())
}

// asteapta starea ceruta; o eroare de la daemon intrerupe asteptarea
async fn wait_for<R: AsyncBufRead + Unpin>(rd: &mut R, target: State) -> Result<Status> {
    loop {
        match read_msg::<_, Event>(rd).await? {
            Some(Event::Status(s)) if s.state == target => return Ok(s),
            Some(Event::Error { message }) => bail!(message),
            Some(_) => continue,
            None => bail!("daemon-ul a inchis conexiunea"),
        }
    }
}
