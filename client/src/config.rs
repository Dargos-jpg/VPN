// configuratia clientului (client.toml)

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use vpn_proto::session::{KEY_MAX_AGE, REKEY_AFTER_TIME};

use crate::transport;

#[derive(Deserialize)]
pub struct Config {
    pub server: SocketAddr,
    pub private_key: String,
    pub public_key: String,
    pub server_public_key: String,

    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    pub tunnel_address: Ipv4Addr,
    #[serde(default = "default_prefix")]
    pub tun_prefix: u8,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    // retele extra din spatele serverului, ex "192.168.1.0/24"
    #[serde(default)]
    pub routes: Vec<String>,
    // keepalive trimis daca nu s-a trimis nimic atat timp; tine deschisa maparea NAT
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u64,
    // fara niciun pachet de la server atat timp => sesiune pierduta
    #[serde(default = "default_dead_peer")]
    pub dead_peer_secs: u64,
    // dupa atat timp clientul schimba cheile (trebuie sa ramana loc de reincercari pana la KEY_MAX_AGE)
    #[serde(default = "default_rekey")]
    pub rekey_secs: u64,
    #[serde(default)]
    pub mode: Mode,
    // "udp" (implicit) sau "tcp" pentru retele care blocheaza UDP
    #[serde(default)]
    pub transport: transport::Kind,
    // DNS folosit prin tunel in full tunnel, ex ["1.1.1.1"]
    #[serde(default)]
    pub dns: Vec<Ipv4Addr>,
    // calea catre wintun.dll, doar pe windows
    #[allow(dead_code)]
    pub wintun_dll: Option<String>,
}

#[derive(Deserialize, Default, PartialEq, Clone, Copy, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Split,
    Full,
}

fn default_tun_name() -> String {
    "vpn0".into()
}
fn default_prefix() -> u8 {
    24
}
fn default_mtu() -> u16 {
    1420
}
fn default_keepalive() -> u64 {
    25
}
// serverul raspunde la fiecare keepalive, deci 90s = ~3 raspunsuri pierdute
fn default_dead_peer() -> u64 {
    90
}
fn default_rekey() -> u64 {
    REKEY_AFTER_TIME.as_secs()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("nu pot citi {}", path.display()))?;
        let cfg: Config = toml::from_str(&text)?;
        // rekey-ul trebuie sa aiba timp de cateva reincercari inainte sa expire cheile
        if Duration::from_secs(cfg.rekey_secs) + Duration::from_secs(30) > KEY_MAX_AGE {
            bail!("rekey_secs trebuie sa fie cel mult {}", KEY_MAX_AGE.as_secs() - 30);
        }
        Ok(cfg)
    }
}
