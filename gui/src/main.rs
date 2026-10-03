// interfata grafica a clientului VPN
//
// ruleaza ca user obisnuit. nu creeaza interfete de retea, nu citeste client.toml si nu vede
// nicio cheie: trimite comenzi (connect cu cod TOTP, disconnect, status) catre
// `vpn-client daemon` pe canalul local si afiseaza evenimentele primite (vpn-control)
//
// daca daemon-ul nu ruleaza, interfata arata "daemon indisponibil" si reincearca la 2s

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::{
    io::{AsyncWriteExt, BufReader, WriteHalf},
    sync::Mutex,
};
use vpn_control::{read_msg, valid_code, write_msg, Duplex, Event, Request, Status, DEFAULT_ENDPOINT};

const RETRY: Duration = Duration::from_secs(2);

#[derive(Default)]
struct Daemon {
    // jumatatea de scriere a conexiunii cu daemon-ul, None cat timp daemon-ul nu e disponibil
    writer: Mutex<Option<WriteHalf<Box<dyn Duplex>>>>,
    // ultima stare cunoscuta: pagina o cere la incarcare, ca sa nu depinda de ordinea in care
    // pornesc conexiunea cu daemon-ul si ascultarea evenimentelor in JavaScript (BUG-009)
    last: std::sync::Mutex<Snapshot>,
}

#[derive(Serialize, Clone, Default)]
struct Snapshot {
    online: bool,
    endpoint: String,
    status: Option<Status>,
}

#[derive(Serialize, Clone)]
struct Availability {
    online: bool,
    endpoint: String,
}

async fn send(state: &State<'_, Daemon>, req: Request) -> Result<(), String> {
    let mut guard = state.writer.lock().await;
    let w = guard.as_mut().ok_or("daemon-ul nu ruleaza")?;
    write_msg(w, &req).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn connect(code: String, state: State<'_, Daemon>) -> Result<(), String> {
    let code = code.trim().to_string();
    // verificat si aici pentru un mesaj imediat; daemon-ul verifica oricum
    if !valid_code(&code) {
        return Err("codul trebuie sa aiba exact 6 cifre".into());
    }
    send(&state, Request::Connect { code }).await
}

#[tauri::command]
async fn disconnect(state: State<'_, Daemon>) -> Result<(), String> {
    send(&state, Request::Disconnect).await
}

#[tauri::command]
async fn refresh(state: State<'_, Daemon>) -> Result<(), String> {
    send(&state, Request::Status).await
}

#[tauri::command]
fn current(state: State<'_, Daemon>) -> Snapshot {
    state.last.lock().unwrap().clone()
}

fn remember(app: &AppHandle, online: bool, status: Option<Status>, endpoint: &str) {
    *app.state::<Daemon>().last.lock().unwrap() = Snapshot {
        online,
        endpoint: endpoint.to_string(),
        status,
    };
}

// conexiunea cu daemon-ul: evenimentele lui sunt trimise ferestrei ca "vpn-event",
// disponibilitatea ca "daemon"; la pierdere se reconecteaza
async fn daemon_loop(app: AppHandle) {
    let endpoint = std::env::var("VPN_CONTROL_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.into());
    let availability = |online| Availability {
        online,
        endpoint: endpoint.clone(),
    };
    loop {
        match vpn_control::connect(&endpoint).await {
            Ok(stream) => {
                let (rd, wr) = tokio::io::split(stream);
                *app.state::<Daemon>().writer.lock().await = Some(wr);
                remember(&app, true, None, &endpoint);
                let _ = app.emit("daemon", availability(true));

                let mut rd = BufReader::new(rd);
                while let Ok(Some(ev)) = read_msg::<_, Event>(&mut rd).await {
                    if let Event::Status(s) = &ev {
                        remember(&app, true, Some(s.clone()), &endpoint);
                    }
                    let _ = app.emit("vpn-event", ev);
                }

                if let Some(mut w) = app.state::<Daemon>().writer.lock().await.take() {
                    let _ = w.shutdown().await;
                }
                remember(&app, false, None, &endpoint);
                let _ = app.emit("daemon", availability(false));
            }
            Err(_) => {
                remember(&app, false, None, &endpoint);
                let _ = app.emit("daemon", availability(false));
            }
        }
        tokio::time::sleep(RETRY).await;
    }
}

fn main() {
    tauri::Builder::default()
        .manage(Daemon::default())
        .invoke_handler(tauri::generate_handler![connect, disconnect, refresh, current])
        .setup(|app| {
            tauri::async_runtime::spawn(daemon_loop(app.handle().clone()));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("nu pot porni interfata");
}
