// logica tunelului, independenta de cine o conduce: terminalul (`connect`) sau daemon-ul
// (interfata grafica). primeste coduri TOTP pe un canal, raporteaza starea prin `Reporter`,
// se opreste cand `stop` e anulat
//
// ciclul: asteapta cod -> handshake -> TUN + rute -> sesiune (rekey automat, keepalive)
//         -> sesiune pierduta: TUN ramane, asteapta cod nou -> handshake -> ...

use std::{
    io::{self, ErrorKind},
    net::{IpAddr, SocketAddr},
    process::Command,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use tokio::{
    sync::{broadcast, mpsc},
    time,
};
use tokio_util::sync::CancellationToken;
use tun_rs::{AsyncDevice, DeviceBuilder};
use vpn_control::{Event, State, Status};
use vpn_proto::{
    handshake, ip, keys,
    packet::{self, Packet},
    Error, Initiator, Keypair, Session,
};

use crate::{
    config::{Config, Mode},
    routes,
    transport::Transport,
};

const BUF_LEN: usize = 65535;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
// cat de des se verifica keepalive-ul, rekey-ul si timeout-urile
const TICK: Duration = Duration::from_secs(1);
// un rekey fara raspuns se reincearca dupa atat timp
const REKEY_RETRY: Duration = Duration::from_secs(5);

// tot ce trebuie pentru un handshake, la conectare sau la rekey
pub struct Identity {
    local: Keypair,
    server_public: [u8; 32],
}

impl Identity {
    pub fn from_config(cfg: &Config) -> Result<Self> {
        Ok(Self {
            local: Keypair {
                private: keys::decode_key(&cfg.private_key).context("private_key invalid")?,
                public: keys::decode_key(&cfg.public_key).context("public_key invalid")?,
            },
            server_public: keys::decode_key(&cfg.server_public_key).context("server_public_key invalid")?,
        })
    }
}

// starea vizibila din afara: snapshot pentru interfata, evenimente pentru terminal / interfata
pub struct Reporter {
    status: Mutex<Status>,
    connected_at: Mutex<Option<Instant>>,
    events: broadcast::Sender<Event>,
    tx: AtomicU64,
    rx: AtomicU64,
    rekeys: AtomicU64,
}

impl Reporter {
    pub fn new(cfg: &Config) -> Self {
        let status = Status {
            server: cfg.server.to_string(),
            mode: format!("{:?}", cfg.mode).to_lowercase(),
            transport: format!("{:?}", cfg.transport).to_lowercase(),
            tunnel_address: format!("{}/{}", cfg.tunnel_address, cfg.tun_prefix),
            ..Status::default()
        };
        Self {
            status: Mutex::new(status),
            connected_at: Mutex::new(None),
            events: broadcast::channel(64).0,
            tx: AtomicU64::new(0),
            rx: AtomicU64::new(0),
            rekeys: AtomicU64::new(0),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub fn snapshot(&self) -> Status {
        let mut s = self.status.lock().unwrap().clone();
        s.connected_secs = self.connected_at.lock().unwrap().map(|t| t.elapsed().as_secs());
        s.tx_bytes = self.tx.load(Ordering::Relaxed);
        s.rx_bytes = self.rx.load(Ordering::Relaxed);
        s.rekeys = self.rekeys.load(Ordering::Relaxed);
        s
    }

    pub fn state(&self) -> State {
        self.status.lock().unwrap().state
    }

    pub fn publish(&self) {
        let _ = self.events.send(Event::Status(self.snapshot()));
    }

    pub fn set_state(&self, state: State, reason: Option<String>) {
        {
            let mut s = self.status.lock().unwrap();
            s.state = state;
            s.reason = reason;
        }
        *self.connected_at.lock().unwrap() = (state == State::Connected).then(Instant::now);
        self.publish();
    }

    pub fn log(&self, message: impl Into<String>) {
        let _ = self.events.send(Event::Log {
            message: message.into(),
        });
    }

    pub fn error(&self, message: impl Into<String>) {
        let _ = self.events.send(Event::Error {
            message: message.into(),
        });
    }

    fn reset_counters(&self) {
        self.tx.store(0, Ordering::Relaxed);
        self.rx.store(0, Ordering::Relaxed);
        self.rekeys.store(0, Ordering::Relaxed);
    }
}

// cheile active ale clientului
struct Keys {
    current: Session,
    // sesiunea dinaintea ultimului rekey: serverul o mai poate folosi pana primeste confirmarea
    previous: Option<Session>,
    // rekey trimis, asteapta raspuns
    pending: Option<(Initiator, Instant)>,
}

impl Keys {
    fn new(current: Session) -> Self {
        Self {
            current,
            previous: None,
            pending: None,
        }
    }

    fn since_last_recv(&self, now: Instant) -> Duration {
        let cur = self.current.since_last_recv(now);
        match &self.previous {
            Some(prev) => cur.min(prev.since_last_recv(now)),
            None => cur,
        }
    }
}

// de ce s-a terminat o sesiune
enum End {
    Quit,
    Lost(&'static str),
}

// erori de socket care nu inseamna ca ceva e stricat local: serverul e oprit momentan
// si kernelul a primit ICMP port unreachable (windows: reset, linux: refused)
fn transient(e: &io::Error) -> bool {
    matches!(e.kind(), ErrorKind::ConnectionReset | ErrorKind::ConnectionRefused)
}

// None = oprire ceruta; eroare = nu mai pot veni coduri (stdin inchis)
async fn next_code(codes: &mut mpsc::Receiver<String>, stop: &CancellationToken) -> Result<Option<String>> {
    tokio::select! {
        c = codes.recv() => c.map(Some).ok_or_else(|| anyhow!("nu mai pot primi coduri TOTP (stdin inchis)")),
        _ = stop.cancelled() => Ok(None),
    }
}

async fn handshake(sock: &Transport, id: &Identity, code: &str) -> Result<Session> {
    let (init, msg1) = Initiator::start(&id.local, &id.server_public, code, handshake::timestamp_now())?;
    sock.send(&msg1).await?;

    let deadline = time::Instant::now() + HANDSHAKE_TIMEOUT;
    let mut buf = vec![0u8; BUF_LEN];
    loop {
        // serverul tace la cod gresit, deci singurul semnal e timeout-ul
        let n = match time::timeout_at(deadline, sock.recv(&mut buf)).await {
            Err(_) => bail!("niciun raspuns - cod gresit/expirat, chei gresite sau server oprit"),
            Ok(Err(e)) if transient(&e) => continue,
            Ok(r) => r?,
        };
        // la reconectare pot veni pachete de date intarziate din sesiunea veche
        if matches!(packet::parse(&buf[..n]), Ok(Packet::Resp { .. })) {
            return Ok(init.finish(&buf[..n])?);
        }
    }
}

async fn connect_once(cfg: &Config, id: &Identity, code: &str) -> Result<(Transport, Session)> {
    let sock = Transport::open(cfg.transport, cfg.server).await?;
    let session = handshake(&sock, id, code).await?;
    Ok((sock, session))
}

fn create_tun(cfg: &Config) -> Result<AsyncDevice> {
    #[allow(unused_mut)]
    let mut builder = DeviceBuilder::new()
        .name(&cfg.tun_name)
        .ipv4(cfg.tunnel_address, cfg.tun_prefix, None)
        .mtu(cfg.mtu);
    #[cfg(windows)]
    if let Some(dll) = &cfg.wintun_dll {
        builder = builder.wintun_file(dll.clone());
    }
    builder.build_async().map_err(|e| anyhow!(tun_error_hint(&e)))
}

// erorile sistemului de operare la crearea TUN, traduse in ce are de facut userul
//
// tun-rs impacheteaza eroarea windows: textul exterior e doar "LoadLibraryExW failed", codul
// (126 etc) e in eroarea interioara - de aceea se parcurge tot lantul `source()` (BUG-011)
fn tun_error_hint(e: &io::Error) -> String {
    let mut text = e.to_string();
    let mut codes = vec![e.raw_os_error()];
    let mut src = std::error::Error::source(e);
    while let Some(s) = src {
        text.push_str(&format!(": {s}"));
        if let Some(io) = s.downcast_ref::<io::Error>() {
            codes.push(io.raw_os_error());
        }
        src = s.source();
    }
    let has = |code: i32| codes.contains(&Some(code)) || text.contains(&format!("os error {code})"));
    // windows: 126 = ERROR_MOD_NOT_FOUND (LoadLibrary nu gaseste wintun.dll),
    // 193 = ERROR_BAD_EXE_FORMAT (dll pentru alta arhitectura), 5 = ERROR_ACCESS_DENIED
    let missing_dll = has(126);
    let wrong_arch = has(193);
    let denied = e.kind() == ErrorKind::PermissionDenied || has(5);
    if cfg!(windows) && missing_dll {
        "lipseste wintun.dll: descarca-l de pe https://www.wintun.net, copiaza wintun/bin/amd64/wintun.dll \
         langa vpn-client.exe (sau seteaza wintun_dll in client.toml)"
            .into()
    } else if cfg!(windows) && wrong_arch {
        "wintun.dll e pentru alta arhitectura: foloseste varianta din wintun/bin/amd64/".into()
    } else if cfg!(windows) && text.contains("LoadLibrary") {
        format!("nu pot incarca wintun.dll ({text})")
    } else if denied && cfg!(windows) {
        "crearea interfetei de retea cere drepturi de administrator: porneste vpn-client (daemon) ca administrator"
            .into()
    } else if denied {
        "crearea interfetei TUN cere root sau CAP_NET_ADMIN".into()
    } else {
        format!("nu pot crea interfata TUN: {text}")
    }
}

fn add_route(cidr: &str, dev: &str) -> Result<()> {
    let status = if cfg!(windows) {
        Command::new("netsh")
            .args(["interface", "ipv4", "add", "route"])
            .arg(format!("prefix={cidr}"))
            .arg(format!("interface={dev}"))
            .arg("store=active")
            .status()?
    } else {
        Command::new("ip").args(["route", "add", cidr, "dev", dev]).status()?
    };
    if !status.success() {
        bail!("nu pot adauga ruta {cidr} prin {dev}");
    }
    Ok(())
}

#[cfg_attr(not(windows), allow(unused_variables))]
fn setup_full_tunnel(cfg: &Config, tun: &AsyncDevice, dev: &str) -> Result<routes::FullTunnel> {
    let SocketAddr::V4(server) = cfg.server else {
        bail!("full tunnel cere un server IPv4");
    };
    // windows: interfata cu metrica mica e preferata, DNS-ul se seteaza direct pe ea
    #[cfg(windows)]
    {
        tun.set_metric(1).context("nu pot seta metrica interfetei")?;
        if !cfg.dns.is_empty() {
            let dns: Vec<IpAddr> = cfg.dns.iter().map(|d| IpAddr::V4(*d)).collect();
            tun.set_dns_servers(&dns).context("nu pot seta DNS-ul tunelului")?;
        }
    }
    routes::setup(*server.ip(), dev, &cfg.dns)
}

// un ciclu complet: de la primul cod pana la oprire. `first_code` vine direct de la daemon
// (cererea connect), in terminal codurile vin toate pe `codes`
//
// prima conectare esuata => Err si motorul se opreste (terminalul iese, daemon-ul raporteaza
// si porneste alt ciclu la urmatoarea cerere). un motor care ar ramane pornit asteptand cod
// ar bloca daemon-ul in "conectare in curs" (BUG-008)
pub async fn run(
    cfg: &Config,
    id: &Identity,
    codes: &mut mpsc::Receiver<String>,
    rep: &Reporter,
    stop: &CancellationToken,
    first_code: Option<String>,
) -> Result<()> {
    rep.reset_counters();

    // 1. prima conectare; TUN abia dupa handshake reusit, un cod gresit nu lasa interfete in urma
    let code = match first_code {
        Some(c) => c,
        None => match next_code(codes, stop).await? {
            Some(c) => c,
            None => return Ok(()),
        },
    };
    rep.set_state(State::Connecting, None);
    let (mut sock, session) = connect_once(cfg, id, &code).await?;
    let mut keys = Keys::new(session);

    // 2. interfata si rutele; rutele de full tunnel se sterg cand `_full` iese din scope
    let tun = create_tun(cfg)?;
    let dev = tun.name()?;
    for r in &cfg.routes {
        add_route(r, &dev)?;
    }
    let _full = match cfg.mode {
        Mode::Split => None,
        Mode::Full => Some(setup_full_tunnel(cfg, &tun, &dev)?),
    };
    rep.set_state(State::Connected, None);
    rep.log(format!(
        "conectat la {} ({:?}), tunel {} = {}/{} ({}), ctrl+c pentru iesire",
        cfg.server,
        cfg.transport,
        dev,
        cfg.tunnel_address,
        cfg.tun_prefix,
        if cfg.mode == Mode::Full {
            "full tunnel"
        } else {
            "split tunnel"
        }
    ));

    // 3. sesiunea; la pierdere se cere cod nou, interfata TUN ramane
    loop {
        match run_session(&sock, &tun, &mut keys, id, cfg, rep, stop).await? {
            End::Quit => {
                rep.log("deconectat");
                rep.set_state(State::Disconnected, None);
                return Ok(());
            }
            End::Lost(reason) => {
                rep.log(format!("sesiune pierduta ({reason}), e nevoie de un cod TOTP nou"));
                rep.set_state(State::NeedCode, Some(reason.into()));
                let session = loop {
                    let Some(code) = next_code(codes, stop).await? else {
                        rep.log("deconectat");
                        rep.set_state(State::Disconnected, None);
                        return Ok(());
                    };
                    rep.set_state(State::Connecting, Some(reason.into()));
                    // transport nou: pe TCP conexiunea veche e probabil moarta, pe UDP nu strica
                    let attempt = match Transport::open(cfg.transport, cfg.server).await {
                        Ok(t) => {
                            sock = t;
                            handshake(&sock, id, &code).await
                        }
                        Err(e) => Err(e),
                    };
                    match attempt {
                        Ok(s) => break s,
                        Err(e) => {
                            rep.error(format!("{e:#}"));
                            rep.set_state(State::NeedCode, Some(reason.into()));
                        }
                    }
                };
                keys = Keys::new(session);
                rep.set_state(State::Connected, None);
                rep.log(format!("reconectat la {}", cfg.server));
            }
        }
    }
}

async fn send(sock: &Transport, pkt: &[u8]) {
    if let Err(e) = sock.send(pkt).await {
        if !transient(&e) {
            eprintln!("trimitere esuata: {e}");
        }
    }
}

async fn run_session(
    sock: &Transport,
    tun: &AsyncDevice,
    keys: &mut Keys,
    id: &Identity,
    cfg: &Config,
    rep: &Reporter,
    stop: &CancellationToken,
) -> Result<End> {
    let keepalive = Duration::from_secs(cfg.keepalive_secs);
    let dead_peer = Duration::from_secs(cfg.dead_peer_secs);
    let rekey_after = Duration::from_secs(cfg.rekey_secs);
    let mut net_buf = vec![0u8; BUF_LEN];
    let mut tun_buf = vec![0u8; BUF_LEN];
    let mut tick = time::interval(TICK);

    loop {
        tokio::select! {
            r = tun.recv(&mut tun_buf) => {
                let n = r?;
                // tunelul e doar IPv4; OS-ul trimite singur IPv6 link-local pe orice interfata noua (BUG-006)
                if !matches!(ip::source(&tun_buf[..n]), Some(IpAddr::V4(_))) {
                    continue;
                }
                match keys.current.encrypt(&tun_buf[..n]) {
                    Ok(ct) => {
                        rep.tx.fetch_add(n as u64, Ordering::Relaxed);
                        send(sock, &ct).await;
                    }
                    Err(Error::Expired | Error::Exhausted) => return Ok(End::Lost("chei expirate")),
                    Err(e) => return Err(e.into()),
                }
            }
            r = sock.recv(&mut net_buf) => {
                let n = match r {
                    Ok(n) => n,
                    Err(e) if transient(&e) => continue,
                    Err(e) => return Err(e.into()),
                };
                on_network(&net_buf[..n], sock, tun, keys, rep).await;
            }
            _ = tick.tick() => {
                let now = Instant::now();
                if keys.current.auth_expired(now) {
                    return Ok(End::Lost("au trecut 12h de la autentificarea TOTP"));
                }
                if keys.current.key_expired(now) {
                    return Ok(End::Lost("rekey esuat, chei expirate"));
                }
                if keys.since_last_recv(now) > dead_peer {
                    return Ok(End::Lost("serverul nu mai raspunde"));
                }
                if keys.previous.as_ref().is_some_and(|s| s.key_expired(now)) {
                    keys.previous = None;
                }
                // rekey cand cheile curente au imbatranit; reincercat daca raspunsul nu vine
                let retry = keys.pending.as_ref().is_none_or(|(_, sent)| now.duration_since(*sent) >= REKEY_RETRY);
                if keys.current.age(now) >= rekey_after && retry {
                    let (init, msg1) =
                        Initiator::start_rekey(&id.local, &id.server_public, keys.current.chain(), handshake::timestamp_now())?;
                    send(sock, &msg1).await;
                    keys.pending = Some((init, now));
                }
                // pachet gol criptat = keepalive, trimis doar daca nu a plecat nimic altceva
                if keys.current.since_last_send(now) >= keepalive {
                    let ct = keys.current.encrypt(&[])?;
                    send(sock, &ct).await;
                }
                // statistici pentru interfata
                rep.publish();
            }
            _ = stop.cancelled() => return Ok(End::Quit),
        }
    }
}

async fn on_network(pkt: &[u8], sock: &Transport, tun: &AsyncDevice, keys: &mut Keys, rep: &Reporter) {
    match packet::parse(pkt) {
        // raspunsul la rekey
        Ok(Packet::Resp { .. }) => {
            let Some((init, _)) = keys.pending.take() else {
                return;
            };
            match init.finish(pkt) {
                Ok(new) => {
                    let old = std::mem::replace(&mut keys.current, new);
                    keys.previous = Some(old);
                    // primul pachet pe cheile noi ii confirma serverului ca le avem
                    if let Ok(ct) = keys.current.encrypt(&[]) {
                        send(sock, &ct).await;
                    }
                    rep.rekeys.fetch_add(1, Ordering::Relaxed);
                    rep.log("chei reinnoite");
                }
                Err(e) => eprintln!("raspuns de rekey invalid: {e}"),
            }
        }
        Ok(Packet::Data { receiver, .. }) => {
            let session = if receiver == keys.current.local_index() {
                &mut keys.current
            } else if let Some(prev) = keys.previous.as_mut().filter(|s| s.local_index() == receiver) {
                prev
            } else {
                return;
            };
            match session.decrypt(pkt) {
                Ok(pt) if pt.is_empty() => {} // keepalive de la server
                Ok(pt) => {
                    rep.rx.fetch_add(pt.len() as u64, Ordering::Relaxed);
                    if let Err(e) = tun.send(&pt).await {
                        eprintln!("scriere pe TUN esuata: {e}");
                    }
                }
                Err(e) => eprintln!("pachet respins: {e}"),
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_errors_explained() {
        let denied = io::Error::from(ErrorKind::PermissionDenied);
        let hint = tun_error_hint(&denied);
        assert!(hint.contains("administrator") || hint.contains("CAP_NET_ADMIN"));

        let other = io::Error::other("ceva neasteptat");
        assert!(tun_error_hint(&other).contains("ceva neasteptat"));

        #[cfg(windows)]
        {
            let missing = io::Error::from_raw_os_error(126);
            assert!(tun_error_hint(&missing).contains("wintun.net"));
            let denied = io::Error::from_raw_os_error(5);
            assert!(tun_error_hint(&denied).contains("administrator"));
            // ca in tun-rs: codul e doar in eroarea interioara (BUG-011)
            let wrapped = io::Error::other(Wrapped(io::Error::from_raw_os_error(126)));
            assert!(tun_error_hint(&wrapped).contains("wintun.net"));
        }
    }

    #[cfg(windows)]
    #[derive(Debug)]
    struct Wrapped(io::Error);

    #[cfg(windows)]
    impl std::fmt::Display for Wrapped {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "LoadLibraryExW failed")
        }
    }

    #[cfg(windows)]
    impl std::error::Error for Wrapped {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }
}
