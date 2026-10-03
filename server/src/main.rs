// server VPN: handshake IKpsk1 cu TOTP, apoi pachete IP intre UDP (sau TCP) si interfata TUN

mod ratelimit;
mod tcp;

use std::{
    fmt,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use qrcode::{render::unicode::Dense1x2, QrCode};
use ratelimit::RateLimiter;
use serde::Deserialize;
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::mpsc,
    time,
};
use tun_rs::{AsyncDevice, DeviceBuilder};
use vpn_proto::{
    ip, keys, mac,
    packet::{self, Packet},
    totp, Keypair, Responder, Session,
};

// pe unde vorbeste serverul cu clientul: UDP (adresa) sau o conexiune TCP (canalul ei de iesire)
#[derive(Clone)]
enum Link {
    Udp(SocketAddr),
    Tcp(SocketAddr, mpsc::Sender<Vec<u8>>),
}

impl Link {
    fn addr(&self) -> SocketAddr {
        match self {
            Link::Udp(a) | Link::Tcp(a, _) => *a,
        }
    }

    async fn send(&self, sock: &UdpSocket, pkt: &[u8]) -> std::result::Result<(), String> {
        match self {
            Link::Udp(a) => sock.send_to(pkt, a).await.map(|_| ()).map_err(|e| e.to_string()),
            // try_send: un client TCP lent pierde pachete (ca pe UDP), nu blocheaza bucla serverului
            Link::Tcp(_, tx) => {
                let frame = packet::frame(pkt).map_err(|e| e.to_string())?;
                tx.try_send(frame)
                    .map_err(|_| "coada TCP plina sau conexiune inchisa".to_string())
            }
        }
    }
}

impl fmt::Display for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Link::Udp(a) => write!(f, "{a}"),
            Link::Tcp(a, _) => write!(f, "{a} (tcp)"),
        }
    }
}

const BUF_LEN: usize = 65535;
// cat de des se verifica timeout-urile sesiunii
const TICK: Duration = Duration::from_secs(1);
// cat de des se raporteaza handshake-urile aruncate (un flood nu trebuie sa umple logul)
const DROP_REPORT_EVERY: Duration = Duration::from_secs(10);

// apararea handshake-ului inainte de DH: mac1, apoi limita de rata
struct Guard {
    limiter: RateLimiter,
    bad_mac: u64,
    rate_limited: u64,
    last_report: Instant,
}

impl Guard {
    fn report(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_report) < DROP_REPORT_EVERY {
            return;
        }
        if self.bad_mac > 0 || self.rate_limited > 0 {
            eprintln!(
                "handshake-uri aruncate inainte de DH: {} cu mac1 invalid, {} peste limita de rata",
                self.bad_mac, self.rate_limited
            );
        }
        self.bad_mac = 0;
        self.rate_limited = 0;
        self.last_report = now;
    }
}

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
    /// porneste serverul (cere root / CAP_NET_ADMIN pentru TUN)
    Run {
        #[arg(long, default_value = "server.toml")]
        config: PathBuf,
    },
}

#[derive(Deserialize)]
struct Config {
    listen: SocketAddr,
    // transport TCP optional (retele care blocheaza UDP), ex "0.0.0.0:51900"
    listen_tcp: Option<SocketAddr>,
    private_key: String,
    public_key: String,
    client_public_key: String,
    totp_secret: String,
    #[serde(default = "default_skew")]
    skew_steps: u64,

    #[serde(default = "default_tun_name")]
    tun_name: String,
    tun_address: Ipv4Addr,
    #[serde(default = "default_prefix")]
    tun_prefix: u8,
    client_tunnel_ip: Ipv4Addr,
    #[serde(default = "default_mtu")]
    mtu: u16,

    // sesiunea e stearsa daca clientul nu trimite nimic atat timp
    #[serde(default = "default_idle")]
    session_idle_secs: u64,
}

fn default_skew() -> u64 {
    1
}
fn default_tun_name() -> String {
    "vpn0".into()
}
fn default_prefix() -> u8 {
    24
}
// 1500 - 40 (ipv6) - 8 (udp) - 16 (header data) - 16 (tag), ca la WireGuard
fn default_mtu() -> u16 {
    1420
}
// clientul trimite keepalive la 25s, deci 180s = ~7 keepalive-uri pierdute
fn default_idle() -> u64 {
    180
}

struct Peer {
    link: Link,
    current: Session,
    // sesiunea dinaintea ultimului rekey, doar pentru decriptare pana ii expira cheile
    previous: Option<Session>,
    // a venit macar un pachet pe `current`? pana atunci clientul poate inca sa nu aiba cheile noi
    confirmed: bool,
}

impl Peer {
    // dupa rekey se trimite pe cheile vechi pana clientul confirma ca le are pe cele noi
    fn sending(&mut self) -> &mut Session {
        if !self.confirmed {
            if let Some(prev) = self.previous.as_mut().filter(|s| !s.key_expired(Instant::now())) {
                return prev;
            }
        }
        &mut self.current
    }

    fn since_last_recv(&self, now: Instant) -> Duration {
        let cur = self.current.since_last_recv(now);
        match &self.previous {
            Some(prev) => cur.min(prev.since_last_recv(now)),
            None => cur,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen => keygen(),
        Cmd::Enroll { account } => enroll(&account),
        Cmd::Run { config } => run(&config).await,
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

// ctrl+c sau SIGTERM (systemctl stop): iesire curata, interfata TUN e stearsa la drop
async fn shutdown_signal() {
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

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

// configul contine cheia privata si secretul TOTP: refuzat daca il pot citi si alti useri (ca ssh)
#[cfg(unix)]
fn check_permissions(path: &PathBuf) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "{} are permisiuni {:o}, accesibil si altor useri; ruleaza: chmod 600 {}",
            path.display(),
            mode & 0o777,
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &PathBuf) -> Result<()> {
    Ok(())
}

async fn run(path: &PathBuf) -> Result<()> {
    check_permissions(path)?;
    let text = std::fs::read_to_string(path).with_context(|| format!("nu pot citi {}", path.display()))?;
    let cfg: Config = toml::from_str(&text)?;

    let local = Keypair {
        private: keys::decode_key(&cfg.private_key).context("private_key invalid")?,
        public: keys::decode_key(&cfg.public_key).context("public_key invalid")?,
    };
    let client_public = keys::decode_key(&cfg.client_public_key).context("client_public_key invalid")?;
    let secret = totp::decode_secret(&cfg.totp_secret).context("totp_secret invalid")?;
    let local_public = local.public;
    let mut responder = Responder::new(local, client_public, secret, cfg.skew_steps);

    let sock = UdpSocket::bind(cfg.listen).await?;
    // pachetele de pe TCP ajung in bucla principala prin canalul asta; `_tcp_keep` tine canalul
    // deschis si cand TCP e dezactivat, ca recv() sa nu se termine niciodata
    let (tcp_tx, mut tcp_rx) = mpsc::channel::<tcp::Incoming>(tcp::OUT_QUEUE);
    let _tcp_keep = tcp_tx.clone();
    if let Some(addr) = cfg.listen_tcp {
        let listener = TcpListener::bind(addr).await?;
        tokio::spawn(tcp::accept_loop(listener, mac::mac1_key(&local_public), tcp_tx));
        eprintln!("ascult si pe TCP {addr}");
    }
    let tun = DeviceBuilder::new()
        .name(&cfg.tun_name)
        .ipv4(cfg.tun_address, cfg.tun_prefix, None)
        .mtu(cfg.mtu)
        .build_async()
        .context("nu pot crea interfata TUN (e nevoie de root / CAP_NET_ADMIN)")?;
    eprintln!(
        "ascult pe {}, tunel {} = {}/{}",
        cfg.listen, cfg.tun_name, cfg.tun_address, cfg.tun_prefix
    );

    let client_ip = IpAddr::V4(cfg.client_tunnel_ip);
    let idle_timeout = Duration::from_secs(cfg.session_idle_secs);
    let mut peer: Option<Peer> = None;
    let mut guard = Guard {
        limiter: RateLimiter::new(Instant::now()),
        bad_mac: 0,
        rate_limited: 0,
        last_report: Instant::now(),
    };
    let io = Io {
        sock: &sock,
        tun: &tun,
        client_ip,
    };
    let mut net_buf = vec![0u8; BUF_LEN];
    let mut tun_buf = vec![0u8; BUF_LEN];
    let mut tick = time::interval(TICK);

    loop {
        tokio::select! {
            r = sock.recv_from(&mut net_buf) => {
                let (n, from) = match r {
                    Ok(r) => r,
                    // pe windows un ICMP port unreachable apare ca eroare la recv (BUG-003)
                    Err(e) if e.kind() == ErrorKind::ConnectionReset => continue,
                    Err(e) => return Err(e.into()),
                };
                on_network(&net_buf[..n], Link::Udp(from), &io, &mut responder, &mut guard, &mut peer).await;
            }
            Some(inc) = tcp_rx.recv() => {
                let link = Link::Tcp(inc.addr, inc.tx);
                on_network(&inc.pkt, link, &io, &mut responder, &mut guard, &mut peer).await;
            }
            r = tun.recv(&mut tun_buf) => {
                let n = r?;
                on_tun(&tun_buf[..n], &sock, &mut peer, client_ip).await;
            }
            _ = tick.tick() => {
                check_timeouts(&mut peer, idle_timeout);
                guard.report(Instant::now());
            }
            _ = shutdown_signal() => {
                eprintln!("oprire");
                return Ok(());
            }
        }
    }
}

fn check_timeouts(peer: &mut Option<Peer>, idle_timeout: Duration) {
    let Some(p) = peer.as_mut() else {
        return;
    };
    let now = Instant::now();
    // sesiunea anterioara traieste doar cat sa primeasca pachetele inca pe drum
    if p.previous.as_ref().is_some_and(|s| s.key_expired(now)) {
        p.previous = None;
    }
    let reason = if p.current.auth_expired(now) {
        "au trecut 12h de la autentificarea TOTP"
    } else if p.current.key_expired(now) {
        "chei expirate, clientul nu a facut rekey"
    } else if p.since_last_recv(now) > idle_timeout {
        "inactiva"
    } else {
        return;
    };
    eprintln!("sesiune cu {} inchisa: {reason}", p.link);
    *peer = None;
}

// ce nu se schimba pe durata rularii
struct Io<'a> {
    sock: &'a UdpSocket,
    tun: &'a AsyncDevice,
    client_ip: IpAddr,
}

async fn on_network(
    pkt: &[u8],
    from: Link,
    io: &Io<'_>,
    responder: &mut Responder,
    guard: &mut Guard,
    peer: &mut Option<Peer>,
) {
    let Io { sock, tun, client_ip } = *io;
    match packet::parse(pkt) {
        Ok(Packet::Init { .. }) => {
            // 1. mac1 (un BLAKE2s): scannerele care nu stiu cheia publica a serverului
            if !responder.check_mac1(pkt) {
                guard.bad_mac += 1;
                return;
            }
            // 2. limita de rata: un flood cu mac1 valid tot nu poate ocupa procesorul cu DH
            if !guard.limiter.allow(from.addr().ip(), Instant::now()) {
                guard.rate_limited += 1;
                return;
            }
            // 3. abia acum handshake-ul complet (pana la 8 DH)
            let chain = peer.as_ref().map(|p| p.current.chain().clone());
            match responder.accept_chained(pkt, unix_now(), chain.as_ref()) {
                Ok(a) => {
                    if let Err(e) = from.send(sock, &a.reply).await {
                        eprintln!("nu pot trimite raspunsul de handshake: {e}");
                        return;
                    }
                    let previous = match peer.take() {
                        // rekey: sesiunea veche ramane pentru pachetele inca pe drum
                        Some(old) if a.rekey => {
                            eprintln!("chei reinnoite cu {from}");
                            Some(old.current)
                        }
                        _ => {
                            eprintln!("sesiune noua cu {from}");
                            None
                        }
                    };
                    *peer = Some(Peer {
                        link: from,
                        current: a.session,
                        // conectare noua: nimic de confirmat; rekey: se asteapta primul pachet pe cheile noi
                        confirmed: previous.is_none(),
                        previous,
                    });
                }
                // niciun raspuns pe fir, doar log local
                Err(e) => eprintln!("handshake respins de la {from}: {e}"),
            }
        }
        Ok(Packet::Data { receiver, .. }) => {
            let Some(p) = peer.as_mut() else {
                return;
            };
            // sesiunea se alege dupa indexul din pachet
            let on_current = receiver == p.current.local_index();
            let session = if on_current {
                &mut p.current
            } else if let Some(prev) = p.previous.as_mut().filter(|s| s.local_index() == receiver) {
                prev
            } else {
                return;
            };
            let pt = match session.decrypt(pkt) {
                Ok(pt) => pt,
                Err(e) => {
                    eprintln!("pachet de date respins de la {from}: {e}");
                    return;
                }
            };
            // primul pachet autentificat pe cheile noi confirma rekey-ul: de acum se trimite pe ele
            if on_current {
                p.confirmed = true;
            }
            // adresa (si transportul) se actualizeaza doar dupa un pachet autentificat (roaming)
            p.link = from;
            if pt.is_empty() {
                // keepalive: raspuns tot cu keepalive, ca clientul sa stie ca serverul traieste
                send_encrypted(sock, p, &[]).await;
                return;
            }
            match ip::source(&pt) {
                Some(src) if src == client_ip => {}
                Some(src) => {
                    eprintln!("pachet din tunel cu sursa {src} (asteptat {client_ip}), aruncat");
                    return;
                }
                None => {
                    eprintln!("pachet din tunel fara header IP valid, aruncat");
                    return;
                }
            }
            if let Err(e) = tun.send(&pt).await {
                eprintln!("scriere pe TUN esuata: {e}");
            }
        }
        _ => {}
    }
}

async fn on_tun(pkt: &[u8], sock: &UdpSocket, peer: &mut Option<Peer>, client_ip: IpAddr) {
    let Some(p) = peer.as_mut() else {
        return;
    };
    // un singur client deocamdata, restul (broadcast, multicast) nu are unde sa mearga
    if ip::destination(pkt) != Some(client_ip) {
        return;
    }
    send_encrypted(sock, p, pkt).await;
}

async fn send_encrypted(sock: &UdpSocket, p: &mut Peer, plaintext: &[u8]) {
    match p.sending().encrypt(plaintext) {
        Ok(ct) => {
            if let Err(e) = p.link.send(sock, &ct).await {
                eprintln!("trimitere catre {} esuata: {e}", p.link);
            }
        }
        // sesiunea expirata e stearsa la urmatorul tick
        Err(e) => eprintln!("nu pot cripta: {e}"),
    }
}
