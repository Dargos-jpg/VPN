// protocolul local dintre interfata (fara privilegii) si daemon-ul clientului (admin/root)
//
// - un mesaj JSON pe linie, max MAX_LINE bytes
// - canal: named pipe pe windows, unix socket pe linux; doar local, cu permisiuni restranse
// - interfata nu vede niciodata cheile: trimite doar codul TOTP si comenzi, primeste starea
//
// cereri (interfata -> daemon): connect {code}, disconnect, status
// evenimente (daemon -> interfata): status {...} la fiecare schimbare + periodic, error {message}, log {message}

use std::io;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_LINE: usize = 64 * 1024;

#[cfg(windows)]
pub const DEFAULT_ENDPOINT: &str = r"\\.\pipe\vpn-totp";
#[cfg(not(windows))]
pub const DEFAULT_ENDPOINT: &str = "/run/vpn-totp.sock";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    // la prima conectare sau cand starea e need_code
    Connect { code: String },
    Disconnect,
    Status,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum State {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    // tunelul a fost activ, sesiunea s-a pierdut: interfata TUN ramane, se asteapta cod nou
    NeedCode,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Status {
    pub state: State,
    pub server: String,
    pub mode: String,
    pub transport: String,
    pub tunnel_address: String,
    // de cand e conectat (secunde), doar in starea connected
    pub connected_secs: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub rekeys: u64,
    // de ce s-a pierdut sesiunea, in need_code
    pub reason: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Status(Status),
    Error { message: String },
    Log { message: String },
}

pub fn valid_code(code: &str) -> bool {
    code.len() == 6 && code.chars().all(|c| c.is_ascii_digit())
}

pub async fn write_msg<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let mut line = serde_json::to_vec(msg).map_err(io::Error::other)?;
    line.push(b'\n');
    w.write_all(&line).await?;
    w.flush().await
}

// None = celalalt capat a inchis conexiunea
pub async fn read_msg<R: AsyncBufRead + Unpin, T: DeserializeOwned>(r: &mut R) -> io::Result<Option<T>> {
    let mut line = String::new();
    let n = (&mut *r).take(MAX_LINE as u64).read_line(&mut line).await?;
    if n == 0 {
        return Ok(None);
    }
    if !line.ends_with('\n') {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "mesaj prea lung"));
    }
    serde_json::from_str(&line)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

// conectare la daemon din interfata sau din `vpn-client ctl`
pub async fn connect(endpoint: &str) -> io::Result<Box<dyn Duplex>> {
    #[cfg(windows)]
    {
        let pipe = tokio::net::windows::named_pipe::ClientOptions::new().open(endpoint)?;
        Ok(Box::new(pipe))
    }
    #[cfg(not(windows))]
    {
        let s = tokio::net::UnixStream::connect(endpoint).await?;
        Ok(Box::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[test]
    fn wire_format() {
        let r = Request::Connect { code: "123456".into() };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"cmd":"connect","code":"123456"}"#
        );
        assert_eq!(
            serde_json::to_string(&Request::Disconnect).unwrap(),
            r#"{"cmd":"disconnect"}"#
        );
        let e = Event::Error { message: "x".into() };
        assert_eq!(serde_json::to_string(&e).unwrap(), r#"{"type":"error","message":"x"}"#);
        let s = serde_json::to_string(&Event::Status(Status::default())).unwrap();
        assert!(s.starts_with(r#"{"type":"status","state":"disconnected""#));
    }

    #[test]
    fn code_format() {
        assert!(valid_code("012345"));
        assert!(!valid_code("12345"));
        assert!(!valid_code("12345a"));
        assert!(!valid_code("1234567"));
    }

    #[tokio::test]
    async fn roundtrip_and_limits() {
        let mut buf = Vec::new();
        write_msg(&mut buf, &Request::Status).await.unwrap();
        write_msg(&mut buf, &Request::Connect { code: "000000".into() })
            .await
            .unwrap();
        let mut r = BufReader::new(&buf[..]);
        assert_eq!(read_msg::<_, Request>(&mut r).await.unwrap(), Some(Request::Status));
        assert_eq!(
            read_msg::<_, Request>(&mut r).await.unwrap(),
            Some(Request::Connect { code: "000000".into() })
        );
        assert_eq!(read_msg::<_, Request>(&mut r).await.unwrap(), None);

        // linie fara sfarsit mai lunga decat limita => eroare, nu memorie nelimitata
        let long = vec![b'a'; MAX_LINE + 10];
        let mut r = BufReader::new(&long[..]);
        assert!(read_msg::<_, Request>(&mut r).await.is_err());
        // JSON invalid => eroare
        let mut r = BufReader::new(&b"{nu e json}\n"[..]);
        assert!(read_msg::<_, Request>(&mut r).await.is_err());
    }
}
