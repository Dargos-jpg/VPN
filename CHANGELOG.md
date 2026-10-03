# changelog

toate modificarile, cele mai noi sus. fiecare intrare: ce s-a schimbat, unde, de ce.
bugurile si rezolvarile lor sunt separat in [BUGS.md](BUGS.md), deciziile de design in [NOTES.md](NOTES.md).

format intrare:

```
## AAAA-LL-ZZ - titlu scurt
- ce: ...
- unde: fisiere
- de ce: ...
```

---

## 2026-10-03 - documentatia publica separata de notele personale
- ce: notele de invatare si detaliile despre mediul de lucru propriu (hardware, cai locale) scoase din repo (`.gitignore`: `/LEARNING.md`, `/private/`); BUG-005 pastrat doar cu partea tehnica; formulari despre fluxul de lucru personal scoase din CHANGELOG si DEPLOY
- de ce: repo-ul public contine doar aplicatia si documentatia ei tehnica

## 2026-10-03 - mesaje de eroare clare pentru TUN, mediu de test pe windows
- ce:
  - `tun_error_hint` (client/src/engine.rs): erorile la crearea TUN traduse in ce are de facut userul - wintun.dll lipsa (cu link si cale), dll pentru alta arhitectura, drepturi de administrator (windows) / root sau CAP_NET_ADMIN (linux); parcurge tot lantul de erori (BUG-011); teste unitare
  - `scripts/windows-dev.ps1 start|code|stop`: server de dezvoltare in WSL, daemon ca administrator (UAC), interfata ca user normal, cod TOTP curent
  - `scripts/dev-wsl-server.sh`: serverul de dezvoltare (vpndev0, 10.9.0.0/24, port 51902, chei noi la fiecare start); scrie `dev/client.toml` + `dev/secret` (gitignored)
  - `scripts/totp.py`: codul TOTP curent dintr-un secret, in locul telefonului la teste
- verificare: daemon pe windows fara wintun.dll + handshake real cu serverul din WSL => mesajul nou cu wintun.net. pasul cu UAC din `windows-dev.ps1 start` netestat automat (cere confirmare interactiva)

## 2026-10-03 - interfata grafica (Tauri 2)
- ce:
  - `gui/` (workspace separat): aplicatie Tauri 2 care ruleaza ca user obisnuit si vorbeste doar cu `vpn-client daemon` pe canalul local (vpn-control); comenzi `connect` (cod TOTP), `disconnect`, `refresh`, `current`
  - pagina in HTML/CSS/JS simplu (`gui/ui`), fara npm; tema luminoasa/intunecata dupa sistem; stari: daemon indisponibil, deconectat, conectare, conectat (timp, trafic, rekey-uri), cod necesar dupa o sesiune pierduta (cu motivul)
  - securitate: CSP strict fara inline, capabilitati Tauri doar `core:default` + comenzile aplicatiei
  - iconita generata de `gui/icons/make_icon.py` (fara biblioteci externe)
  - CI: job `gui` (clippy pe windows)
  - fix BUG-009 (cursa la pornire) si BUG-010 (atributul hidden anulat de CSS)
- unde: `gui/`, `.gitignore`, `.github/workflows/ci.yml`, NOTES, THREAT_MODEL, README, BUGS
- testat pe windows (fara drepturi de admin): server in WSL, daemon + interfata pe windows ca user normal; codul TOTP tastat in interfata -> named pipe (DACL) -> daemon -> handshake reusit cu serverul ("sesiune noua") -> crearea TUN esueaza cum era de asteptat (fara wintun.dll / admin) si eroarea apare in interfata
- netestat: tunelul complet pe windows (cere `wintun.dll` + daemon pornit ca administrator)

## 2026-10-03 - daemon, ctl si protocolul de control local (baza pentru interfata grafica)
- ce:
  - crate nou `control/` (vpn-control): cereri `connect/disconnect/status`, evenimente `status/error/log`, JSON pe linie (max 64 KB), endpoint implicit (named pipe / unix socket), conectare client; 3 teste
  - client refactorizat: `config.rs` (configuratia), `engine.rs` (logica tunelului, condusa printr-un canal de coduri + `Reporter` cu stare si evenimente), `daemon.rs` (serverul canalului local), `main.rs` (comenzi)
  - `vpn-client daemon`: tunelul ca serviciu, condus de interfata/ctl; named pipe cu DACL explicit pe windows, unix socket 660 + grup optional pe linux; oprire curata la SIGTERM/ctrl+c
  - `vpn-client ctl status|connect <cod>|disconnect|watch`
  - `vpn-client connect` (terminal) foloseste acelasi motor, mesajele afisate raman aceleasi
  - fix BUG-008 (daemon blocat dupa un cod gresit)
  - netns-test testul 14: permisiuni socket, user fara drepturi respins, cod gresit, conectare, statistici, need_code dupa restart server, reconectare, deconectare, curatare
- unde: `control/`, `client/src/{config,engine,daemon,main}.rs`, `client/Cargo.toml` (windows-sys pentru DACL), `Cargo.toml`, `scripts/netns-test.sh`, NOTES, THREAT_MODEL, BUGS
- de ce: separarea privilegiilor - interfata grafica ruleaza fara drepturi de admin, doar daemon-ul are acces la retea si la chei
- rezultat: netns-test 14/14 (testele 1-13 neschimbate dupa refactorizare), clippy curat pe windows (inclusiv codul cu named pipe si SDDL)

## 2026-10-03 - transport TCP optional
- ce:
  - `proto`: `packet::frame` (`[lungime u16][pachet]`) + test
  - server: `listen_tcp` optional; `server/src/tcp.rs` - task per conexiune, max 64, primul pachet msg1 cu mac1 valid in 10s, 120s inactivitate; `Link::{Udp, Tcp}` in loc de adresa UDP, raspunsurile pleaca pe acelasi transport, `try_send` pe coada TCP
  - client: `transport = "udp" | "tcp"`; `client/src/transport.rs` - pe TCP citire/scriere in task-uri separate (recv sigur la anulare in select!); transport redeschis la reconectare
  - tokio: feature-uri `sync`, `io-util`
  - oci-terraform-ansible, rolul `vpn-server`: `vpn_tcp` (implicit false) => UFW 51900/tcp
  - netns-test testul 13: UDP blocat cu nftables, conectare + ping + rekey peste TCP, conexiune cu date aleatoare inchisa
- unde: `proto/src/packet.rs`, `server/src/{main,tcp}.rs`, `client/src/{main,transport}.rs`, `Cargo.toml`, `*.example.toml`, `scripts/netns-test.sh`, NOTES, THREAT_MODEL, DEPLOY, README
- de ce: unele retele (firme, hoteluri) blocheaza UDP; UDP ramane implicit (invizibilitate la scanare, fara TCP meltdown)
- rezultat: netns-test 13/13, clippy curat, 45 teste unitare/integrare

## 2026-10-03 - full tunnel
- ce:
  - client: `mode = "full"` + `dns = [...]`; `client/src/routes.rs` - rute 0/1 + 128/1 prin TUN, ruta /32 catre server pe gateway-ul original (linux `ip route get`, windows `Find-NetRoute`), ::/1 + 8000::/1 in TUN (IPv6 blocat), DNS prin tunel (resolvectl / DNS + metrica pe interfata windows), totul sters in Drop; 3 teste unitare pentru parsarea rutei
  - client + server: SIGTERM tratat ca ctrl+c (iesire curata la `kill` / `systemctl stop`)
  - `deploy/full-tunnel-nat.sh`: forwarding + masquerade cu nftables, forward permis doar vpn0 -> iesire + raspunsuri
  - oci-terraform-ansible, rolul `vpn-server`: `vpn_full_tunnel` (implicit false) - ip_forward, NAT in before.rules, `ufw route allow`; handler `reload ufw`
  - netns-test testul 12: namespace "internet" accesibil doar prin tunel + NAT
  - CI: nftables instalat in jobul de tunel
- unde: `client/src/{main,routes}.rs`, `server/src/main.rs`, `deploy/full-tunnel-nat.sh`, `scripts/netns-test.sh`, `client.example.toml`, `.github/workflows/ci.yml`, NOTES, THREAT_MODEL, DEPLOY, README; in celalalt repo `ansible/roles/vpn-server/`
- rezultat: netns-test 12/12, clippy curat pe windows (inclusiv codul specific windows), ansible syntax-check ok
- netestat: rutele si DNS-ul pe windows (compileaza, dar nu au rulat)

## 2026-10-03 - modificari aplicate in oci-terraform-ansible
- ce (in repo-ul oci-terraform-ansible):
  - `modules/network/main.tf`: regula UDP 51900 in security list; regulile 80/443 scoase (nginx inlocuit)
  - `outputs.tf`: `vpn_endpoint`
  - `ansible/roles/vpn-server/` (defaults, tasks, handlers): user `vpn-totp`, binar aarch64 din `dist/`, config din `~/vpn-secrets` (600, no_log), unit-ul din `deploy/`, UFW 51900/udp, serviciu activat
  - `ansible/site.yml`: play-ul app_server foloseste `vpn-server` in loc de docker + app-deploy
  - `ansible/roles/hardening/tasks/main.yml`: scos UFW 80/443 pentru app_server
  - README + NOTES din acel repo actualizate
- verificare: `terraform validate` ok, `ansible-playbook --syntax-check` ok, fara CRLF. `terraform fmt` semnaleaza alinieri vechi in alte fisiere (nu atinse)
- ramas: rularea efectiva cand exista VM-urile

## 2026-10-03 - pregatire deploy: binare statice ARM, DEPLOY.md
- ce:
  - `scripts/build-release.sh`: binare statice musl pentru aarch64 (VM-urile A1.Flex din OCI) si x86_64, cu `cargo-zigbuild`; `dist/` + SHA256SUMS
  - CI: job `release-bins`, binarele descarcabile ca artefact `vpn-linux-musl`
  - DEPLOY.md: pasii completi - binare, chei/TOTP/config in afara repo-urilor, modificarile pentru oci-terraform-ansible (regula UDP in security list, output `vpn_endpoint`, rol ansible `vpn-server`, site.yml, UFW), verificare, probleme posibile (iptables-ul din imaginile Oracle)
- unde: `scripts/build-release.sh`, `.github/workflows/ci.yml`, `.gitignore` (dist/), DEPLOY.md, README.md
- de ce: VM-urile sunt ARM cu Ubuntu 22.04 (glibc mai veche decat masina de build) => un binar compilat normal nu ar porni
- verificare: serverul aarch64 rulat prin `qemu-aarch64` in WSL trece tot `scripts/netns-test.sh` (11/11) cu clientul x86_64 nativ
- modificarile din oci-terraform-ansible NU sunt facute aici - se aplica separat in acel repo

## 2026-10-02 - protectie DoS la handshake: mac1 + limita de rata
- ce:
  - `proto/src/mac.rs`: mac1 = BLAKE2s cu cheie (din cheia publica a serverului) peste msg1, 16 bytes la final; compatibil RFC 7693 (verificat cu hashlib din python)
  - format init: `[1][000][sender][noise][mac1 16]`; `Responder::check_mac1` (fara DH), `accept_chained` verifica mac1 primul (`Error::BadMac`)
  - `server/src/ratelimit.rs`: token bucket per IP (2/s, rafala 5) si global (20/s, rafala 50), max 10000 IP-uri urmarite; 4 teste unitare
  - server: mac1 -> limita de rata -> DH; respingerile raportate agregat la 10s
  - fuzz: tinta noua `handshake_accept_mac` (mac1 valid peste input, ca sa ajunga in codul de DH)
  - netns-test testul 11: 300 de msg1 false, doar 5 ajung la DH
- unde: `proto/src/{mac,packet,handshake,error,lib}.rs`, `proto/tests/handshake.rs` (2 teste), `server/src/{main,ratelimit}.rs`, `fuzz/`, `scripts/netns-test.sh`, NOTES, THREAT_MODEL, README
- de ce: fiecare msg1 fals costa serverul pana la 8 DH; un flood putea ocupa procesorul
- rezultat: 37 teste proto + 4 server, netns-test 11/11, systemd-test ok, fuzz 6 tinte fara probleme; respingerea inputurilor aleatoare ~60x mai rapida

## 2026-10-02 - hardening pentru deploy: systemd fara root, permisiuni config
- ce:
  - `deploy/vpn-server.service`: user `vpn-totp`, doar `CAP_NET_ADMIN`, sandbox systemd (fisiere read-only, doar /dev/net/tun, familii de socket si syscall-uri restranse)
  - `deploy/install.sh`: user de sistem, binar in /usr/local/bin, config in /etc/vpn-totp (600), serviciu activat
  - serverul refuza un config accesibil altor useri (unix)
  - `scripts/systemd-test.sh`: instaleaza serviciul, verifica user, capabilitati efective, permisiuni, TUN si tunelul cap-coada, apoi dezinstaleaza tot
  - `scripts/netns-test.sh` testul 0: config 644 refuzat
- unde: `deploy/`, `server/src/main.rs`, `scripts/`, NOTES, THREAT_MODEL, README
- de ce: serverul primeste pachete de la oricine; un bug exploatabil nu trebuie sa insemne root pe VM
- rezultat (WSL): toate verificarile trec, `systemd-analyze security` = 1.7 OK (un serviciu fara hardening are ~9.6 UNSAFE)
- CI: joburi noi `systemd` (scripts/systemd-test.sh) si `fuzz` (30s pe tinta, inputurile care produc crash urcate ca artefact)

## 2026-10-02 - rekey automat fara TOTP
- ce:
  - secret de lant de 32 bytes trimis criptat in payload-ul msg2 la fiecare handshake
  - `Initiator::start_rekey` / `Responder::accept_chained`: handshake IKpsk1 cu psk derivat din secretul de lant (salt separat de cel TOTP); serverul incearca intai rekey-ul pe lantul sesiunii curente, apoi ferestrele TOTP
  - `Session`: doua ceasuri - varsta cheilor (`REKEY_AFTER_TIME` 120s, `KEY_MAX_AGE` 180s) si varsta autentificarii TOTP (`AUTH_MAX_AGE` 12h, mostenita peste rekey-uri); inlocuieste `REJECT_AFTER_TIME`
  - client: rekey la `rekey_secs` (implicit 120), reincercat la 5s, sesiunea anterioara pastrata pentru pachetele pe drum, keepalive de confirmare pe cheile noi
  - server: sesiunea curenta + anterioara, alegere dupa indexul din pachet; trimite pe cheile vechi pana primeste primul pachet pe cele noi
- unde: `proto/src/{psk,session,handshake}.rs`, `proto/tests/handshake.rs` (8 teste noi), `server/src/main.rs`, `client/src/main.rs`, `client.example.toml`, `scripts/netns-test.sh` (testul 7), `fuzz/` (handshake_accept incearca si calea de rekey), NOTES, THREAT_MODEL, README
- de ce: inainte aceleasi chei traiau 12h; acum forward secrecy la 2 minute, fara sa ceara cod TOTP userului
- rezultat: 34 teste proto, netns-test 10/10 (2 rekey-uri in timpul unui ping continuu, 0% pierderi), clippy curat

## 2026-10-02 - threat model
- ce: THREAT_MODEL.md - bunuri, presupuneri, atacatori, amenintari grupate (confidentialitate, autentificare, replay, abuz din tunel, disponibilitate, secrete), fiecare cu masura si testul/bugul care o acopera; riscuri ramase; ce NU acoperim
- de ce: documentul de referinta pentru orice decizie de securitate si pentru cine evalueaza proiectul

## 2026-10-02 - fuzzing
- ce: workspace separat `fuzz/` (cargo-fuzz, nightly) cu 5 tinte: `packet_parse`, `handshake_accept`, `handshake_tamper`, `session_decrypt`, `data_tamper`; `scripts/fuzz.sh` le ruleaza pe rand (build separat de rulare, loguri langa build)
- unde: `fuzz/`, `scripts/fuzz.sh`, `Cargo.toml` (exclude fuzz), NOTES, README- de ce: tot codul care primeste bytes din retea trebuie sa reziste la input arbitrar; doua tinte verifica proprietati de securitate (orice bit modificat => respins)
- nota: prima rulare a raportat 3 "crash-uri" fara artefacte - de fapt erori de compilare pentru ca `proto` era modificat in paralel. de aici build-ul separat in `fuzz.sh`

## 2026-10-02 - CI pe GitHub Actions + formatare standard
- ce: workflow cu 4 joburi paralele: fmt/clippy/teste pe linux, build/teste pe windows, testul cap-coada al tunelului (netns, sudo), `cargo audit` (si programat saptamanal). cod reformatat cu `cargo fmt`
- unde: `.github/workflows/ci.yml`, `rustfmt.toml` (max_width 120), toate fisierele .rs (doar formatare, fara schimbari de logica), NOTES.md, README.md
- de ce: orice regresie e prinsa automat la push; inainte totul depindea de rulat manual
- verificare locala: fmt --check ok, clippy -D warnings ok, 26/26 teste, cargo audit 0 vulnerabilitati (1 avertisment unmaintained, detalii in NOTES)

## 2026-09-29 - expirare sesiune, keepalive bidirectional, reconectare
- ce:
  - `Session` tine minte cand a fost creata, ultimul pachet autentificat primit si ultimul trimis. dupa `REJECT_AFTER_TIME` (12h) refuza sa cripteze/decripteze (`Error::Expired`) => cod TOTP nou
  - doar pachetele care trec de AEAD actualizeaza "ultimul pachet primit" - un atacator nu poate tine artificial o sesiune in viata
  - server: raspunde la fiecare keepalive; sterge sesiunea dupa `session_idle_secs` (180s) fara trafic sau la expirare
  - client: keepalive doar cand n-a trimis nimic `keepalive_secs` (25s); daca nu primeste nimic `dead_peer_secs` (90s) declara sesiunea pierduta, cere cod TOTP nou si reface handshake-ul fara sa inchida interfata TUN. la cod gresit reintreaba, ctrl+c iese oricand (inclusiv la prompt)
  - fix BUG-007 (ECONNREFUSED pe linux oprea clientul)
- unde: `proto/src/session.rs`, `proto/src/error.rs`, `proto/tests/handshake.rs` (2 teste noi), `server/src/main.rs`, `client/src/main.rs`, `scripts/netns-test.sh` (teste 7-9), `*.example.toml`, README, NOTES, BUGS
- de ce: pana acum o sesiune traia pana la restart; un server restartat lasa clientul blocat fara sa stie
- rezultat: unit/integration 26/26, netns-test 9/9 grupuri, clippy curat

## 2026-09-28 - test cap-coada al tunelului pe linux + fix BUG-006
- ce: script de test care porneste serverul si clientul in doua network namespace-uri legate cu veth si verifica: cod TOTP gresit (fara raspuns, fara TUN creat), ping in ambele sensuri, MTU 1420 fara fragmentare, anti-spoofing, doar IPv4 prin tunel, payload invizibil pe cablu (captura tcpdump). fix BUG-006 (IPv6 link-local trimis prin tunel)
- unde: `scripts/netns-test.sh` (nou), `client/src/main.rs`, `server/src/main.rs`, BUGS.md, README.md
- de ce: prima verificare cu trafic real; ruleaza in WSL, fara VM-uri
- rezultat: toate testele trec (WSL Ubuntu, kernel 6.18); unit/integration 24/24 pe windows si linux, clippy curat

## 2026-09-28 - mediu de test linux (WSL) reparat
- ce: filesystem-ul corupt al Ubuntu din WSL reparat (detalii in BUGS-005), instalat gcc (build-essential) si Rust in WSL
- unde: - (mediu de dezvoltare)
- de ce: serverul VPN are nevoie de TUN pe linux; WSL permite testarea tunelului fara VM-urile din cloud

## 2026-09-28 - interfata TUN + split tunnel
- ce: echo-ul text inlocuit cu tunel real de pachete IP. client si server trec pe tokio, bucla unica cu `select!` peste socket UDP, TUN, keepalive si ctrl+c
- unde:
  - `Cargo.toml` - dependinte noi `tokio`, `tun-rs` 2.8 (TUN pe linux, wintun pe windows)
  - `proto/src/ip.rs` - citire adresa sursa/destinatie din header IPv4/IPv6
  - `server/src/main.rs` - TUN 10.8.0.1/24; din retea: decriptare -> filtru anti-spoofing pe sursa -> TUN; din TUN: doar pachete catre ip-ul clientului -> criptare -> UDP. adresa peer-ului se actualizeaza doar dupa un pachet autentificat (roaming)
  - `client/src/main.rs` - TUN creat abia dupa handshake reusit; rute extra optionale (`ip route` / `netsh`); keepalive = pachet de date gol criptat la 25s
  - `server.example.toml`, `client.example.toml` - campuri noi pentru TUN
- de ce: pasul urmator dupa handshake - trafic real prin tunel. split tunnel vine gratis din prefixul interfetei (ruta 10.8.0.0/24 adaugata de OS)
- status: compileaza pe windows, clippy curat, teste 24/24. testat cu trafic real ulterior (vezi intrarea cu `netns-test.sh`)

## 2026-09-28 - fix BUG-004, limita de varsta pe timestamp-ul din handshake
- ce: `Responder::accept` respinge msg1 cu timestamp la mai mult de 120s de ceasul serverului (`Error::Stale`)
- unde: `proto/src/handshake.rs`, `proto/src/error.rs`, `proto/tests/handshake.rs` (teste noi + timestamp-uri realiste in cele vechi), BUGS.md, NOTES.md
- de ce: dupa restart serverul pierde `last_timestamp` si un msg1 capturat devenea reutilizabil
- teste: 12 unitare + 9 handshake, toate trec

## 2026-09-28 - repository git
- ce: git init, branch main, remote GitHub (privat). `.gitattributes` forteaza LF
- unde: .gitattributes
- de ce: istoric real al codului; LF ca sa nu apara diferente de line ending intre windows (dev) si linux (server)

## 2026-09-28 - toolchain instalat, prima compilare
- ce: instalat VS 2022 Build Tools (MSVC) + rustup (winget), toolchain stable-x86_64-pc-windows-msvc, cargo 1.98.1. `cargo test` trece din prima: 12 teste unitare + 7 teste handshake, fara erori de compilare
- unde: - (mediu de dezvoltare), Cargo.lock generat
- de ce: verificarea primei versiuni de cod
- nota: dupa instalare terminalul trebuie redeschis ca sa vada `~/.cargo/bin` in PATH

## 2026-09-28 - documentatie proiect
- ce: adaugat CHANGELOG.md (istoric modificari) si BUGS.md (buguri + rezolvari)
- unde: CHANGELOG.md, BUGS.md
- de ce: istoric complet al proiectului, separat de notele de design

## 2026-09-28 - schelet workspace + handshake + sesiune criptata
- ce: prima versiune de cod, necompilata inca (Rust neinstalat pe masina de dev)
- unde:
  - `Cargo.toml` - workspace cu 3 crate-uri, versiuni de dependinte centralizate
  - `proto/src/totp.rs` - TOTP RFC 6238 (HMAC-SHA1, 30s, 6 cifre), generare secret, base32, uri otpauth
  - `proto/src/psk.rs` - psk = HKDF-SHA256(cod, info = client_pub || server_pub)
  - `proto/src/keys.rs` - chei X25519, encode/decode base64, zeroize la drop
  - `proto/src/handshake.rs` - Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s, Initiator/Responder, timestamp in msg1
  - `proto/src/session.rs` - transport stateless, counter = nonce, limita REJECT_AFTER_MESSAGES
  - `proto/src/replay.rs` - fereastra anti-replay de 64 pachete
  - `proto/src/packet.rs` - framing init/resp/data, big endian
  - `proto/tests/handshake.rs` - teste cap-coada
  - `server/src/main.rs` - comenzi keygen, enroll (QR in terminal), run (UDP, echo)
  - `client/src/main.rs` - comenzi keygen, connect (cere codul TOTP, trimite linii criptate)
  - `server.example.toml`, `client.example.toml`, `.gitignore`, `README.md`, `NOTES.md`
- de ce: primul pas testabil fara VM-uri - handshake + date criptate pe localhost, inainte de TUN

## 2026-09-26 - design initial
- ce: stabilit conceptul, stack-ul, arhitectura handshake-ului si modul de tunelare (fara cod)
- de ce: detalii in NOTES.md; variantele respinse (SPA, NNpsk0) sunt in BUGS.md ca probleme de design
