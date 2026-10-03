# deploy pe VM (OCI, proiectul oci-terraform-ansible)

serverul VPN inlocuieste placeholder-ul nginx de pe `app-server`. modificarile din `oci-terraform-ansible` (sectiunile 3 si 4) sunt aplicate in acel repo; snippet-urile raman aici ca referinta. comentariile lor sunt in engleza, ca restul acelui proiect.

## ce trebuie stiut despre VM

- `VM.Standard.A1.Flex` = **ARM (aarch64)**, Ubuntu 22.04 => binarul trebuie compilat pentru aarch64
- glibc pe Ubuntu 22.04 e mai veche decat pe masina de build => binar **static (musl)**, altfel nu porneste
- rolul `hardening` porneste UFW cu deny pe tot ce intra => portul VPN trebuie deschis si in UFW, nu doar in security list
- reteaua VCN e 10.0.0.0/16, tunelul 10.8.0.0/24 - nu se suprapun

## 1. binarele (in acest repo)

varianta A, local in WSL:
```
rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl
cargo install cargo-zigbuild        # + zig de pe https://ziglang.org/download
scripts/build-release.sh            # => dist/vpn-server-aarch64, dist/vpn-client-x86_64, SHA256SUMS
```

varianta B, din CI: GitHub -> Actions -> ultimul run -> artefactul `vpn-linux-musl` (acelasi continut ca `dist/`).

verificat: serverul aarch64 rulat prin `qemu-aarch64` trece tot `scripts/netns-test.sh` cu clientul x86_64 nativ.

## 2. chei, TOTP, config (o singura data, in afara oricarui repo)

```
mkdir -p ~/vpn-secrets && chmod 700 ~/vpn-secrets
dist/vpn-server-x86_64 keygen > ~/vpn-secrets/server.keys
dist/vpn-client-x86_64 keygen > ~/vpn-secrets/client.keys
dist/vpn-server-x86_64 enroll --account laptop      # scanezi QR-ul cu telefonul
```

`~/vpn-secrets/server.toml` (chmod 600) - dupa `server.example.toml`, cu:
```toml
listen = "0.0.0.0:51900"
tun_address = "10.8.0.1"
client_tunnel_ip = "10.8.0.2"
```

`client.toml` pe laptop - dupa `client.example.toml`, cu `server = "<app_server_ip>:51900"` (din `terraform output vpn_endpoint`).

secretele nu intra in niciun repo. ansible le copiaza direct din `~/vpn-secrets` pe VM. optional: `ansible-vault encrypt ~/vpn-secrets/server.toml`.

## 3. terraform (in oci-terraform-ansible)

### `modules/network/main.tf` - regula UDP in security list

in `resource "oci_core_security_list" "main"`, langa celelalte `ingress_security_rules`:
```hcl
  # vpn-totp tunnel - open to everyone on purpose: the laptop roams between networks,
  # and the server never replies to unauthenticated packets (mac1 + TOTP in the handshake),
  # so the port still looks closed to scanners
  ingress_security_rules {
    source   = "0.0.0.0/0"
    protocol = "17" # UDP
    udp_options {
      min = 51900
      max = 51900
    }
  }
```

regulile pentru 80 si 443 pot fi scoase: fara nginx nu mai asculta nimic acolo (suprafata de atac mai mica).

### `outputs.tf`

```hcl
output "vpn_endpoint" {
  value = "${module.compute.public_ips[0]}:51900"
}
```

## 4. ansible (in oci-terraform-ansible)

### rol nou `ansible/roles/vpn-server/`

`defaults/main.yml`:
```yaml
---
vpn_port: 51900
# the VPN repo as seen from WSL
vpn_repo_dir: /mnt/e/proiecte/VPN
# static musl build, picked by the server architecture (A1.Flex = aarch64)
vpn_server_binary: "{{ vpn_repo_dir }}/dist/vpn-server-{{ 'aarch64' if ansible_architecture == 'aarch64' else 'x86_64' }}"
# private key + TOTP secret, kept outside every repo
vpn_server_config: "{{ lookup('env', 'HOME') }}/vpn-secrets/server.toml"
```

`tasks/main.yml`:
```yaml
---
- name: Create the vpn-totp system user
  user:
    name: vpn-totp
    system: true
    shell: /usr/sbin/nologin
    create_home: false

- name: Install the vpn-server binary
  copy:
    src: "{{ vpn_server_binary }}"
    dest: /usr/local/bin/vpn-server
    owner: root
    group: root
    mode: "0755"
  notify: restart vpn-server

- name: Create the config directory (only the service user can read it)
  file:
    path: /etc/vpn-totp
    state: directory
    owner: vpn-totp
    group: vpn-totp
    mode: "0700"

# the server refuses to start if this file is readable by anyone else
- name: Install the server config (private key + TOTP secret)
  copy:
    src: "{{ vpn_server_config }}"
    dest: /etc/vpn-totp/server.toml
    owner: vpn-totp
    group: vpn-totp
    mode: "0600"
  no_log: true
  notify: restart vpn-server

- name: Install the hardened systemd unit (non-root, CAP_NET_ADMIN only)
  copy:
    src: "{{ vpn_repo_dir }}/deploy/vpn-server.service"
    dest: /etc/systemd/system/vpn-server.service
    owner: root
    group: root
    mode: "0644"
  notify: restart vpn-server

- name: Allow the VPN port through UFW
  ufw:
    rule: allow
    port: "{{ vpn_port | string }}"
    proto: udp

- name: Make sure vpn-server is running and enabled
  systemd:
    name: vpn-server
    state: started
    enabled: true
    daemon_reload: true
```

`handlers/main.yml`:
```yaml
---
- name: restart vpn-server
  systemd:
    name: vpn-server
    state: restarted
    daemon_reload: true
```

### `ansible/site.yml`

play-ul pentru `app_server` - nginx/docker inlocuite cu vpn-server:
```yaml
- name: Deploy the VPN server
  hosts: app_server
  become: true
  roles:
    - vpn-server
```

### `ansible/roles/hardening/tasks/main.yml`

task-ul "Allow HTTP/HTTPS through UFW on the app server" poate fi scos (nu mai e nginx). rolurile `docker` si `app-deploy` raman in repo, doar nu mai sunt folosite de `app_server`.

## 4b. full tunnel (optional)

ca un client cu `mode = "full"` sa iasa pe internet prin server, serverul are nevoie de forwarding + NAT. in rolul ansible (aplicat deja in oci-terraform-ansible):
```yaml
# ansible/roles/vpn-server/defaults/main.yml, sau -e vpn_full_tunnel=true
vpn_full_tunnel: true
```
=> `net/ipv4/ip_forward=1` in `/etc/ufw/sysctl.conf`, masquerade pentru 10.8.0.0/24 in `/etc/ufw/before.rules` (pe interfata default a VM-ului), `ufw route allow in on vpn0 out on <iface>`.

pe o masina fara UFW: `sudo deploy/full-tunnel-nat.sh <iface>` (nftables).

## 4c. transport TCP (optional)

pentru retele care blocheaza UDP:
- `listen_tcp = "0.0.0.0:51900"` in `~/vpn-secrets/server.toml`
- rolul ansible: `vpn_tcp: true` (deschide 51900/tcp in UFW)
- security list (`modules/network/main.tf`), o regula noua langa cea UDP:
  ```hcl
  # optional TCP fallback for the VPN (networks that block UDP); visible to port scans
  ingress_security_rules {
    source   = "0.0.0.0/0"
    protocol = "6" # TCP
    tcp_options {
      min = 51900
      max = 51900
    }
  }
  ```
- client: `transport = "tcp"`

## 5. verificare dupa deploy

pe VM (`ssh ubuntu@<ip>`):
```
sudo systemctl status vpn-server
sudo journalctl -u vpn-server -n 20          # "ascult pe 0.0.0.0:51900, tunel vpn0 = 10.8.0.1/24"
sudo systemd-analyze security vpn-server     # asteptat ~1.7 OK
ip addr show vpn0
```

de pe laptop, cel mai simplu din WSL (clientul linux):
```
sudo dist/vpn-client-x86_64 connect --config client.toml     # cere codul de pe telefon
ping 10.8.0.1
```

## probleme posibile

- **imaginile Ubuntu de la Oracle vin cu reguli iptables proprii** (`/etc/iptables/rules.v4`, cu un REJECT la final pe INPUT), separate de UFW. daca security list-ul si UFW sunt corecte si tot nu ajunge nimic: `sudo iptables -L INPUT -n --line-numbers` pe VM. daca exista un `REJECT ... icmp-host-prohibited` inaintea regulilor UFW, portul trebuie permis si acolo (afecteaza la fel si porturile 80/443 de acum)
- **clientul nu primeste raspuns**: serverul tace la orice nu e autentificat, deci "niciun raspuns" poate insemna si firewall, si cod TOTP gresit, si chei gresite. pe VM, `journalctl -u vpn-server` arata daca pachetul a ajuns ("handshake respins" = a ajuns dar codul/cheile nu se potrivesc; nimic = blocat inainte)
- **ceasul**: laptopul si VM-ul trebuie sa fie la sub 2 minute (Ubuntu are `systemd-timesyncd` activ implicit; verificare: `timedatectl`)
