# vpn-totp

[![ci](https://github.com/Dargos-jpg/VPN/actions/workflows/ci.yml/badge.svg)](https://github.com/Dargos-jpg/VPN/actions/workflows/ci.yml)

Tunel VPN scris de la zero in Rust, la care conectarea cere pe langa cheile statice si un cod TOTP (2FA). Codul vine din orice aplicatie de autentificare standard (Google Authenticator, Authy etc.), fara cont si fara vreo legatura intre telefon si server.

## Cum functioneaza

- handshake `Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s` (crate-ul `snow`)
- clientul are cheia publica a serverului fixata, serverul o are pe a clientului
- codul TOTP (RFC 6238) e transformat prin HKDF intr-un PSK amestecat in primul mesaj al handshake-ului
- cod gresit sau expirat => handshake-ul pica criptografic si serverul nu raspunde nimic
- date: ChaCha20-Poly1305 cu counter explicit si fereastra anti-replay de 64 pachete
- rekey automat la 2 minute fara cod (psk din lantul sesiunii), cod TOTP nou la 12h
- mac1 + limita de rata in fata handshake-ului (protectie DoS)
- split tunnel (implicit) sau full tunnel; transport UDP (implicit) sau TCP
- client in doua procese: daemon privilegiat + interfata grafica fara privilegii

Documentatie:
- [NOTES.md](NOTES.md) - design si decizii
- [CHANGELOG.md](CHANGELOG.md) - istoricul modificarilor
- [BUGS.md](BUGS.md) - buguri gasite si cum au fost rezolvate
- [THREAT_MODEL.md](THREAT_MODEL.md) - ce protejeaza, impotriva cui, ce ramane neacoperit
- [DEPLOY.md](DEPLOY.md) - deploy pe VM-ul ARM din OCI (binare statice, terraform, ansible, verificare)

## Structura

```
proto/    protocolul: totp, psk, mac1, handshake, framing, sesiune, anti-replay (fara I/O)
control/  protocolul local dintre interfata grafica si daemon-ul clientului
server/   vpn-server: UDP (+ TCP optional), TUN, rate limiting
client/   vpn-client: connect (terminal), daemon, ctl; split/full tunnel, rekey
gui/      interfata grafica (Tauri 2), workspace separat
scripts/  teste cap-coada (netns, systemd), fuzzing, binare de release
fuzz/     tinte de fuzzing (cargo-fuzz)
deploy/   serviciu systemd, instalare, NAT pentru full tunnel
```

## Build si teste

```
cargo build --release
cargo test
```

## Rulare din terminal

```
# 1. chei
cargo run -p vpn-server -- keygen
cargo run -p vpn-client -- keygen

# 2. enrollment TOTP - scaneaza QR-ul cu aplicatia de autentificare
cargo run -p vpn-server -- enroll --account laptop

# 3. completeaza server.toml si client.toml dupa fisierele *.example.toml (chmod 600)

# 4. pornire (serverul pe linux ca root sau prin systemd, clientul ca admin)
sudo ./target/debug/vpn-server run --config server.toml
./target/debug/vpn-client connect --config client.toml

# 5. test
ping 10.8.0.1
```

Clientul cere codul de 6 cifre de pe telefon, face handshake-ul, abia apoi creeaza interfata TUN. In split tunnel traficul catre 10.8.0.0/24 trece prin tunel, restul merge direct; cu `mode = "full"` trece tot.

Pe Windows clientul are nevoie de `wintun.dll` (de pe https://www.wintun.net, varianta amd64) langa executabil sau in directorul curent.

## Interfata grafica

```
# ca administrator (tine tunelul):
vpn-client daemon --config client.toml

# ca user obisnuit:
cd gui && cargo run --release
```

Test rapid pe windows, cu serverul in WSL (genereaza chei de test, porneste daemon-ul cu UAC si interfata, afiseaza codul TOTP in locul telefonului):

```
scripts\windows-dev.ps1 start
scripts\windows-dev.ps1 code
scripts\windows-dev.ps1 stop
```

Interfata nu are drepturi de admin si nu vede cheile: trimite codul TOTP si comenzi daemon-ului pe un canal local (named pipe pe Windows, unix socket pe Linux) si afiseaza starea. Acelasi canal din linia de comanda:

```
vpn-client ctl status
vpn-client ctl connect 123456
vpn-client ctl disconnect
vpn-client ctl watch
```

## Teste cap-coada pe linux

```
cargo build
sudo scripts/netns-test.sh target/debug     # tunelul complet, 14 grupuri de verificari
sudo scripts/systemd-test.sh target/debug   # serverul ca serviciu fara root
```

`netns-test.sh` porneste serverul, clientul si un "internet" simulat in network namespace-uri separate si verifica: permisiuni config, cod TOTP gresit respins fara raspuns, ping in ambele sensuri, MTU, anti-spoofing, doar IPv4 prin tunel, confidentialitate pe cablu, rekey fara pierderi, keepalive, reconectare dupa restart de server, timeout pe server, protectie DoS, full tunnel + NAT, transport TCP cu UDP blocat, daemon + ctl. Nu are nevoie de VM-uri, merge si in WSL.

## Instalare pe server (systemd, fara root)

```
cargo build --release
sudo deploy/install.sh target/release/vpn-server server.toml
```

Serverul ruleaza ca user `vpn-totp`, doar cu `CAP_NET_ADMIN`, intr-un sandbox systemd (scor `systemd-analyze security` 1.7). Pentru VM-urile ARM din OCI: [DEPLOY.md](DEPLOY.md).

## Fuzzing

```
rustup toolchain install nightly && cargo install cargo-fuzz   # o singura data
scripts/fuzz.sh 60                                             # fiecare tinta 60s
```

Doar pe linux. Tintele si ce verifica fiecare sunt in NOTES.md.

## Stadiu

- [x] TOTP, derivare PSK, handshake Noise, sesiune criptata, anti-replay
- [x] interfata TUN, split tunnel si full tunnel (rute, DNS, IPv6 blocat, NAT pe server)
- [x] expirare sesiune, keepalive, reconectare cu cod TOTP nou, rekey automat fara TOTP
- [x] protectie DoS la handshake (mac1 + limita de rata)
- [x] transport TCP optional
- [x] daemon + interfata grafica cu separarea privilegiilor
- [x] serviciu systemd fara root, binare statice aarch64/x86_64
- [x] CI (GitHub Actions), fuzzing, threat model
- [ ] tunel complet testat pe windows (wintun + daemon ca administrator)
- [ ] deploy pe VM (terraform + ansible pregatite, pasi in DEPLOY.md)
- [ ] multi-client, LDAP, Vault
