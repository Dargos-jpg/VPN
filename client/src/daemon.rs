// daemon-ul clientului: tine tunelul (ruleaza ca admin/root) si primeste comenzi de la
// interfata grafica (care ruleaza fara privilegii) pe un canal local - separarea privilegiilor
//
// windows: named pipe \\.\pipe\vpn-totp; DACL explicit: SYSTEM + Administratori control total,
//          utilizatorii logati interactiv citire/scriere, clientii de pe retea respinsi
// linux:   unix socket (implicit /run/vpn-totp.sock), permisiuni 660, grup optional (--group)
//
// cine are acces la canal poate: conecta (doar cu un cod TOTP valid), deconecta, vedea starea.
// nu poate obtine cheia statica, secretul de lant sau cheile de sesiune - nu exista mesaj pentru asta

use std::sync::Arc;

use anyhow::Result;
use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader},
    sync::{broadcast, mpsc, Mutex},
};
use tokio_util::sync::CancellationToken;
use vpn_control::{read_msg, valid_code, write_msg, Event, Request, State};

use crate::{
    config::Config,
    engine::{self, Identity, Reporter},
};

struct Daemon {
    cfg: Config,
    id: Identity,
    rep: Reporter,
    codes_tx: mpsc::Sender<String>,
    codes_rx: Mutex<mpsc::Receiver<String>>,
    // Some = motorul ruleaza (conectat sau in curs); token-ul il opreste
    engine: std::sync::Mutex<Option<CancellationToken>>,
}

pub async fn serve(cfg: Config, endpoint: String, group: Option<String>) -> Result<()> {
    let id = Identity::from_config(&cfg)?;
    let rep = Reporter::new(&cfg);
    let (codes_tx, codes_rx) = mpsc::channel(4);
    let d = Arc::new(Daemon {
        cfg,
        id,
        rep,
        codes_tx,
        codes_rx: Mutex::new(codes_rx),
        engine: std::sync::Mutex::new(None),
    });

    let shutdown = CancellationToken::new();
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            crate::shutdown_signal().await;
            shutdown.cancel();
        });
    }

    eprintln!("daemon: astept comenzi pe {endpoint}");
    let r = listen(&d, &endpoint, group.as_deref(), &shutdown).await;

    // oprire: tunelul se inchide curat (rutele de full tunnel sterse) inainte de iesire
    let token = d.engine.lock().unwrap().clone();
    if let Some(t) = token {
        t.cancel();
        for _ in 0..50 {
            if d.engine.lock().unwrap().is_none() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    eprintln!("daemon: oprit");
    r
}

#[cfg(not(windows))]
async fn listen(d: &Arc<Daemon>, endpoint: &str, group: Option<&str>, shutdown: &CancellationToken) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;

    // un socket ramas de la o rulare anterioara oprita brutal
    let _ = std::fs::remove_file(endpoint);
    let listener = UnixListener::bind(endpoint)?;
    std::fs::set_permissions(endpoint, std::fs::Permissions::from_mode(0o660))?;
    if let Some(g) = group {
        std::os::unix::fs::chown(endpoint, None, Some(lookup_gid(g)?))?;
    }

    loop {
        tokio::select! {
            r = listener.accept() => {
                let (stream, _) = r?;
                tokio::spawn(handle_conn(stream, d.clone()));
            }
            _ = shutdown.cancelled() => break,
        }
    }
    let _ = std::fs::remove_file(endpoint);
    Ok(())
}

#[cfg(not(windows))]
fn lookup_gid(name: &str) -> Result<u32> {
    let groups = std::fs::read_to_string("/etc/group")?;
    groups
        .lines()
        .find_map(|l| {
            let mut f = l.split(':');
            (f.next() == Some(name)).then(|| f.nth(1)?.parse().ok())?
        })
        .ok_or_else(|| anyhow::anyhow!("grupul {name} nu exista"))
}

#[cfg(windows)]
async fn listen(d: &Arc<Daemon>, endpoint: &str, _group: Option<&str>, shutdown: &CancellationToken) -> Result<()> {
    let mut server = pipe::create(endpoint, true)?;
    loop {
        tokio::select! {
            r = server.connect() => {
                r?;
                // instanta conectata merge la handler, pentru urmatorul client se creeaza alta
                let conn = std::mem::replace(&mut server, pipe::create(endpoint, false)?);
                tokio::spawn(handle_conn(conn, d.clone()));
            }
            _ = shutdown.cancelled() => break,
        }
    }
    Ok(())
}

#[cfg(windows)]
mod pipe {
    use std::{ffi::c_void, io, ptr};

    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
    };

    // P = DACL protejat (nu mosteneste); SY = SYSTEM, BA = Administratori: control total (GA);
    // IU = utilizatori logati interactiv: citire + scriere (GRGW). nimeni altcineva
    const SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

    pub fn create(name: &str, first: bool) -> io::Result<NamedPipeServer> {
        let sddl: Vec<u16> = SDDL.encode_utf16().chain(Some(0)).collect();
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: sddl e terminat cu 0, sd primeste un descriptor alocat de sistem
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        // SAFETY: sa e valid pe durata apelului; kernelul copiaza descriptorul in obiectul pipe
        let r = unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(name, &mut sa as *mut _ as *mut c_void)
        };
        // SAFETY: sd a fost alocat de ConvertStringSecurityDescriptorToSecurityDescriptorW
        unsafe { LocalFree(sd) };
        r
    }
}

async fn handle_conn<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(stream: S, d: Arc<Daemon>) {
    let (rd, mut wr) = tokio::io::split(stream);
    let mut rd = BufReader::new(rd);

    // un singur writer pe conexiune: evenimentele si raspunsurile ajung pe acelasi canal
    let (out_tx, mut out_rx) = mpsc::channel::<Event>(64);
    let writer = tokio::spawn(async move {
        while let Some(ev) = out_rx.recv().await {
            if write_msg(&mut wr, &ev).await.is_err() {
                break;
            }
        }
    });
    let forwarder = {
        let mut sub = d.rep.subscribe();
        let out_tx = out_tx.clone();
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(ev) => {
                        if out_tx.send(ev).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        })
    };

    let _ = out_tx.send(Event::Status(d.rep.snapshot())).await;
    while let Ok(Some(req)) = read_msg::<_, Request>(&mut rd).await {
        handle_request(req, &d, &out_tx).await;
    }
    forwarder.abort();
    writer.abort();
}

async fn handle_request(req: Request, d: &Arc<Daemon>, out: &mpsc::Sender<Event>) {
    let reply = |message: &str| Event::Error {
        message: message.to_string(),
    };
    match req {
        Request::Status => {
            let _ = out.send(Event::Status(d.rep.snapshot())).await;
        }
        Request::Connect { code } => {
            if !valid_code(&code) {
                let _ = out.send(reply("codul trebuie sa aiba exact 6 cifre")).await;
                return;
            }
            let mut engine = d.engine.lock().unwrap();
            if engine.is_none() {
                let token = CancellationToken::new();
                *engine = Some(token.clone());
                d.rep.set_state(State::Connecting, None);
                tokio::spawn(run_engine(d.clone(), token, code));
            } else if d.rep.state() == State::NeedCode {
                let _ = d.codes_tx.try_send(code);
            } else {
                let msg = if d.rep.state() == State::Connected {
                    "deja conectat"
                } else {
                    "conectare in curs"
                };
                let _ = out.try_send(reply(msg));
            }
        }
        Request::Disconnect => {
            let token = d.engine.lock().unwrap().clone();
            match token {
                Some(t) => t.cancel(),
                None => {
                    let _ = out.send(reply("nu e conectat")).await;
                }
            }
        }
    }
}

async fn run_engine(d: Arc<Daemon>, token: CancellationToken, code: String) {
    let mut codes = d.codes_rx.lock().await;
    // coduri trimise cand nu erau cerute nu trebuie folosite mai tarziu
    while codes.try_recv().is_ok() {}
    if let Err(e) = engine::run(&d.cfg, &d.id, &mut codes, &d.rep, &token, Some(code)).await {
        d.rep.error(format!("{e:#}"));
    }
    d.rep.set_state(State::Disconnected, None);
    *d.engine.lock().unwrap() = None;
}
