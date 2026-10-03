// rute pentru full tunnel: tot traficul prin TUN, cu exceptia pachetelor catre serverul VPN
//
// - 0.0.0.0/1 + 128.0.0.0/1 prin TUN: mai specifice decat ruta default, deci castiga fara
//   s-o stearga - la iesire reteaua laptopului ramane exact cum era (ca wg-quick / OpenVPN def1)
// - ruta /32 catre serverul VPN prin gateway-ul original, altfel pachetele criptate ale
//   tunelului ar intra in propriul tunel (bucla de rutare)
// - ::/1 + 8000::/1 prin TUN: tunelul e doar IPv4 si clientul arunca IPv6, deci IPv6 e blocat
//   in loc sa iasa pe langa VPN (IPv6 leak)
// - DNS prin tunel, altfel interogarile pleaca la DNS-ul retelei locale (DNS leak)
//
// tot ce se adauga se sterge in Drop (ctrl+c, eroare, deconectare normala). rutele prin TUN
// dispar oricum odata cu interfata; ruta catre server trebuie stearsa explicit

use std::{net::Ipv4Addr, process::Command};

use anyhow::{bail, Context, Result};

// cum se ajunge la serverul VPN inainte de full tunnel
struct Path {
    gateway: Option<Ipv4Addr>,
    dev: String,
}

pub struct FullTunnel {
    // comenzi rulate la iesire, in ordine inversa
    cleanup: Vec<Vec<String>>,
}

impl Drop for FullTunnel {
    fn drop(&mut self) {
        for cmd in self.cleanup.iter().rev() {
            let _ = run(cmd);
        }
    }
}

fn run<S: AsRef<str>>(cmd: &[S]) -> Result<String> {
    let args: Vec<&str> = cmd.iter().map(|s| s.as_ref()).collect();
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .with_context(|| format!("nu pot rula {}", args[0]))?;
    if !out.status.success() {
        bail!(
            "`{}` a esuat: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn owned(cmd: &[&str]) -> Vec<String> {
    cmd.iter().map(|s| s.to_string()).collect()
}

// linux: "1.2.3.4 via 192.168.1.1 dev wlan0 src ..." sau "192.168.100.1 dev veth0 src ..."
#[cfg(not(windows))]
fn path_to(server: Ipv4Addr) -> Result<Path> {
    let out = run(&["ip", "-4", "route", "get", &server.to_string()])?;
    parse_ip_route_get(&out).with_context(|| format!("nu inteleg ruta catre server: {out}"))
}

#[cfg_attr(windows, allow(dead_code))]
fn parse_ip_route_get(out: &str) -> Option<Path> {
    let words: Vec<&str> = out.split_whitespace().collect();
    let after = |key: &str| words.iter().position(|w| *w == key).and_then(|i| words.get(i + 1));
    Some(Path {
        gateway: after("via").and_then(|g| g.parse().ok()),
        dev: after("dev")?.to_string(),
    })
}

// windows: next hop si indexul interfetei din Find-NetRoute ("0.0.0.0" = direct conectat)
#[cfg(windows)]
fn path_to(server: Ipv4Addr) -> Result<Path> {
    let script = format!(
        "$r = Find-NetRoute -RemoteIPAddress {server} | Where-Object {{ $_.NextHop }} | Select-Object -First 1; \"$($r.NextHop) $($r.InterfaceIndex)\""
    );
    let out = run(&["powershell", "-NoProfile", "-Command", &script])?;
    let mut parts = out.split_whitespace();
    let gateway: Ipv4Addr = parts.next().context("Find-NetRoute fara rezultat")?.parse()?;
    let dev = parts.next().context("Find-NetRoute fara interfata")?.to_string();
    Ok(Path {
        gateway: (!gateway.is_unspecified()).then_some(gateway),
        dev,
    })
}

#[cfg(not(windows))]
fn host_route_cmds(server: Ipv4Addr, path: &Path) -> (Vec<String>, Vec<String>) {
    let dst = format!("{server}/32");
    let mut add = owned(&["ip", "-4", "route", "add", &dst]);
    if let Some(gw) = path.gateway {
        add.extend(owned(&["via", &gw.to_string()]));
    }
    add.extend(owned(&["dev", &path.dev]));
    (add, owned(&["ip", "-4", "route", "del", &dst]))
}

#[cfg(windows)]
fn host_route_cmds(server: Ipv4Addr, path: &Path) -> (Vec<String>, Vec<String>) {
    let gw = path.gateway.unwrap_or(Ipv4Addr::UNSPECIFIED).to_string();
    let srv = server.to_string();
    (
        owned(&[
            "route",
            "add",
            &srv,
            "mask",
            "255.255.255.255",
            &gw,
            "if",
            &path.dev,
            "metric",
            "1",
        ]),
        owned(&["route", "delete", &srv]),
    )
}

#[cfg(not(windows))]
fn tun_route_cmd(cidr: &str, dev: &str) -> Vec<String> {
    let family = if cidr.contains(':') { "-6" } else { "-4" };
    owned(&["ip", family, "route", "add", cidr, "dev", dev])
}

#[cfg(windows)]
fn tun_route_cmd(cidr: &str, dev: &str) -> Vec<String> {
    let family = if cidr.contains(':') { "ipv6" } else { "ipv4" };
    owned(&[
        "netsh",
        "interface",
        family,
        "add",
        "route",
        &format!("prefix={cidr}"),
        &format!("interface={dev}"),
        "store=active",
    ])
}

// linux: systemd-resolved, DNS-ul tunelului devine cel folosit pentru orice domeniu (~.)
#[cfg(not(windows))]
fn set_dns(dev: &str, dns: &[Ipv4Addr], cleanup: &mut Vec<Vec<String>>) {
    if dns.is_empty() {
        return;
    }
    let mut cmd = owned(&["resolvectl", "dns", dev]);
    cmd.extend(dns.iter().map(|d| d.to_string()));
    match run(&cmd).and_then(|_| run(&["resolvectl", "domain", dev, "~."])) {
        Ok(_) => cleanup.push(owned(&["resolvectl", "revert", dev])),
        Err(e) => eprintln!("atentie: DNS neconfigurat prin tunel ({e}), interogarile pot iesi pe langa VPN"),
    }
}

pub fn setup(server: Ipv4Addr, dev: &str, dns: &[Ipv4Addr]) -> Result<FullTunnel> {
    let mut ft = FullTunnel { cleanup: Vec::new() };

    // 1. ruta catre server pe drumul vechi, inainte ca tot traficul sa fie mutat in tunel
    let path = path_to(server)?;
    let (add, del) = host_route_cmds(server, &path);
    run(&add)?;
    ft.cleanup.push(del);

    // 2. tot IPv4 prin tunel
    for cidr in ["0.0.0.0/1", "128.0.0.0/1"] {
        run(&tun_route_cmd(cidr, dev))?;
    }

    // 3. IPv6 in tunel = aruncat de client; daca IPv6 lipseste pe masina, nu e nimic de blocat
    for cidr in ["::/1", "8000::/1"] {
        if let Err(e) = run(&tun_route_cmd(cidr, dev)) {
            eprintln!("atentie: nu pot bloca IPv6 prin tunel ({e})");
            break;
        }
    }

    // 4. DNS (pe windows se seteaza direct pe interfata, in main)
    #[cfg(not(windows))]
    set_dns(dev, dns, &mut ft.cleanup);
    #[cfg(windows)]
    let _ = dns;

    Ok(ft)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_route_with_gateway() {
        let p = parse_ip_route_get("1.2.3.4 via 192.168.1.1 dev wlan0 src 192.168.1.20 uid 1000\n    cache\n").unwrap();
        assert_eq!(p.gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(p.dev, "wlan0");
    }

    #[test]
    fn parse_route_on_link() {
        let p = parse_ip_route_get("192.168.100.1 dev veth-cli src 192.168.100.2 uid 0\n    cache\n").unwrap();
        assert_eq!(p.gateway, None);
        assert_eq!(p.dev, "veth-cli");
    }

    #[test]
    fn parse_route_garbage() {
        assert!(parse_ip_route_get("RTNETLINK answers: Network is unreachable").is_none());
    }
}
