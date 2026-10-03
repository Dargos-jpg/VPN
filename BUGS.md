# buguri si rezolvari

fiecare bug gasit, inclusiv cele de design prinse inainte de cod. cele mai noi sus.
id-urile nu se refolosesc. un bug inchis ramane in fisier.

format intrare:

```
## BUG-NNN - titlu scurt
- status: deschis / rezolvat (data) / nu se rezolva (motiv)
- tip: design / compilare / runtime / securitate / platforma
- simptom: ce se vedea / ce se putea intampla
- cauza: de ce se intampla
- rezolvare: ce s-a schimbat, in ce fisiere
- verificare: test sau pasi prin care s-a confirmat
```

---

## BUG-011 - mesajul "lipseste wintun.dll" nu aparea pentru eroarea reala
- status: rezolvat (2026-10-03)
- tip: runtime / windows (gasit de testul cap-coada cu scripts\windows-dev.ps1, imediat dupa ce mesajul a fost scris)
- simptom: in loc de explicatia cu wintun.net, userul vedea "nu pot crea interfata TUN: LoadLibraryExW failed"
- cauza: `tun-rs` impacheteaza eroarea windows intr-o alta eroare: textul exterior e "LoadLibraryExW failed", iar codul 126 (ERROR_MOD_NOT_FOUND) e doar in eroarea interioara (`source()`). verificarea se uita doar la eroarea exterioara. testul unitar scris initial construia direct o eroare cu codul 126, deci nu reproducea situatia reala
- rezolvare: `tun_error_hint` parcurge tot lantul `source()` si strange codurile de eroare; caz nou pentru 193 (dll pentru alta arhitectura); test unitar cu o eroare impachetata ca in tun-rs
- unde: `client/src/engine.rs`
- verificare: daemon pe windows fara wintun.dll + `ctl connect` => "lipseste wintun.dll: descarca-l de pe https://www.wintun.net ..."
- lectie: un test unitar care construieste singur eroarea "asteptata" poate trece fara sa reproduca forma reala a erorii - testul cap-coada a prins-o

## BUG-010 - formularul de cod vizibil desi interfata il ascundea
- status: rezolvat (2026-10-03)
- tip: interfata grafica (gasit la testul pe windows, din captura de ecran)
- simptom: cu daemon-ul oprit, formularul "Cod TOTP" ramanea vizibil (cu butonul dezactivat), desi JavaScript-ul ii punea atributul `hidden`
- cauza: regula CSS `form { display: flex }` are prioritate fata de stilul implicit al atributului `hidden` (`display: none`)
- rezolvare: `[hidden] { display: none !important; }` in `gui/ui/style.css`
- verificare: captura de ecran cu daemon-ul oprit - doar starea si detaliile, fara formular

## BUG-009 - interfata ramanea pe "Daemon indisponibil" cu daemon-ul pornit
- status: rezolvat (2026-10-03)
- tip: interfata grafica, conditie de cursa (gasit la testul pe windows)
- simptom: daemon-ul rula, `vpn-client ctl status` mergea pe acelasi named pipe, dar interfata afisa "Daemon indisponibil" si nicio informatie
- cauza: partea Rust a interfetei se conecta la daemon si trimitea evenimentele "daemon online" + starea initiala inainte ca pagina sa apuce sa inregistreze ascultatorii (`listen`) in JavaScript; evenimentele erau pierdute, iar daemon-ul trimite starea initiala o singura data
- rezolvare: partea Rust pastreaza ultima stare cunoscuta (online + status); pagina inregistreaza intai ascultatorii, apoi cere starea curenta cu comanda `current` - nu mai conteaza care porneste primul
- unde: `gui/src/main.rs`, `gui/ui/app.js`
- verificare: interfata pornita dupa daemon afiseaza imediat serverul, modul si transportul (captura de ecran)

## BUG-008 - daemon blocat in "conectare in curs" dupa un cod gresit
- status: rezolvat (2026-10-03)
- tip: runtime (gasit de test inainte de orice folosire reala)
- simptom: dupa `ctl connect <cod gresit>`, orice conectare noua raspundea "conectare in curs" si tunelul nu mai putea fi pornit fara restartul daemon-ului
- cauza: in modul daemon, la esecul primei conectari motorul raporta eroarea si ramanea pornit asteptand alt cod pe canal. starea vizibila era "disconnected", dar daemon-ul vedea motorul ca pornit si nu trimitea codul nou nici pe canal (asta se face doar in starea need_code), nici nu pornea alt ciclu
- rezolvare: prima conectare esuata intoarce eroare si opreste motorul in ambele moduri (terminal si daemon); daemon-ul raporteaza eroarea si porneste un ciclu nou la urmatoarea cerere. distinctia `Policy::{Cli, Daemon}` a disparut
- unde: `client/src/engine.rs`, `client/src/daemon.rs`, `client/src/main.rs`
- verificare: `scripts/netns-test.sh` testul 14 - cod gresit, apoi conectare cu codul corect

## BUG-007 - clientul se oprea cu eroare daca serverul era oprit momentan (linux)
- status: rezolvat (2026-09-29)
- tip: runtime / platforma
- simptom: (gasit la review, inainte sa apara in test) cu serverul oprit, primul pachet trimis de client produce un ICMP port unreachable; pe linux urmatorul `recv` pe socket-ul UDP conectat intoarce `ECONNREFUSED`, iar clientul trata asta ca eroare fatala si se inchidea
- cauza: in bucla clientului era tratat doar `ConnectionReset` (varianta de windows a aceleiasi situatii, BUG-003), nu si `ConnectionRefused`
- rezolvare: functia `transient()` in `client/src/main.rs` trateaza ambele ca temporare, atat in bucla de sesiune cat si in handshake. un server oprit e detectat acum prin timeout-ul de dead peer, nu prin eroare de socket
- verificare: `scripts/netns-test.sh` testul 8 - serverul e oprit si repornit, clientul ramane pornit si se reconecteaza

## BUG-006 - clientul trimitea IPv6 link-local prin tunel
- status: rezolvat (2026-09-28)
- tip: runtime
- simptom: in logul serverului, la fiecare conectare: `pachet din tunel cu sursa Some(fe80::...), aruncat`
- cauza: linux pune automat o adresa IPv6 link-local pe orice interfata noua si trimite pe ea router/neighbor solicitation. clientul cripta si trimitea tot ce citea de pe TUN, iar serverul (corect) arunca pachetele pentru ca sursa nu e `client_tunnel_ip`. nu e problema de securitate, dar e trafic criptat inutil si zgomot in log
- rezolvare: clientul trimite prin tunel doar pachete IPv4 (tunelul e doar IPv4 deocamdata). filtrul anti-spoofing din server ramane - el apara de un client modificat, cel din client doar evita traficul inutil. mesajul din log afiseaza acum adresa normal (`sursa 10.8.0.99 (asteptat 10.8.0.2)`), nu `Some(...)`
- unde: `client/src/main.rs`, `server/src/main.rs`
- verificare: `scripts/netns-test.sh` - testul 5 "doar IPv4 prin tunel"

## BUG-005 - filesystem corupt in WSL (Ubuntu), apt blocat
- status: rezolvat (2026-09-28)
- tip: mediu de dezvoltare (nu e bug in cod)
- simptom: `apt-get install build-essential` pica cu `dpkg: unrecoverable fatal error ... files list file for package 'apport' is missing final newline`; fara gcc, Rust nu poate linka pe linux, deci tunelul nu poate fi testat in WSL
- cauza: coruptie ext4 pe discul virtual al WSL (dmesg: `EXT4-fs warning ... ext4_dirblock_csum_verify ... run e2fsck`) dupa opriri bruste ale masinii gazda - VM-ul WSL moare cu scrieri neterminate. fisiere cu continut binar aleator in `/var/lib/dpkg/info` si fisiere instalate cu continut modificat
- rezolvare: backup, metadatele dpkg corupte mutate deoparte, `e2fsck -f -y -D` pe discul virtual (atasat cu `wsl --mount --bare` dintr-o distributie temporara), reinstalarea pachetelor cu fisiere modificate, apoi `build-essential`
- verificare: `dpkg --verify` = 0 fisiere modificate, `dpkg --audit` curat, fara erori ext4 in dmesg, `gcc` si `cargo` functionale in WSL
- lectie: o masina virtuala care pierde scrierile la o oprire brusca isi poate corupe sistemul de fisiere; un mediu de build nu e de incredere pana nu e verificat (`dpkg --verify`, `e2fsck`)

## BUG-004 - replay msg1 dupa restart server
- status: rezolvat (2026-09-28)
- tip: securitate
- simptom: dupa restart serverul uita ultimul timestamp acceptat, deci un msg1 capturat poate fi retrimis cat timp codul TOTP din el e inca valid (max ~90s)
- cauza: `Responder::last_timestamp` e doar in memorie (`proto/src/handshake.rs`)
- rezolvare: serverul respinge msg1 daca timestamp-ul difera cu mai mult de `MAX_CLOCK_DIFF_SECS` (120s) de ceasul lui, in trecut sau in viitor. eroare noua `Error::Stale`. varianta cu persistare pe disc respinsa - scrieri pe disc la fiecare handshake si tot ramane problema daca fisierul se pierde
- efect secundar: laptopul si serverul trebuie sa aiba ceasurile la mai putin de 2 min diferenta (NTP le tine la <1s in mod normal)
- verificare: `proto/tests/handshake.rs` - `replay_after_restart_rejected`, `future_timestamp_rejected`

## BUG-003 - recv_from pica pe Windows dupa ICMP port unreachable
- status: rezolvat preventiv (2026-09-28), neconfirmat la rulare
- tip: platforma
- simptom: pe Windows, daca un send_to ajunge la un port inchis, urmatorul recv_from intoarce WSAECONNRESET (10054). cu `?` bucla serverului s-ar opri
- cauza: comportament Winsock pe socket-uri UDP, nu apare pe Linux
- rezolvare: in bucla serverului erorile `ErrorKind::ConnectionReset` sunt ignorate (`server/src/main.rs`)
- verificare: de testat la prima rulare pe Windows: server pornit, client oprit brusc

## BUG-002 - NNpsk0 cu TOTP permite MITM prin brute force offline
- status: rezolvat (2026-09-26, in design, inainte de cod)
- tip: design / securitate
- simptom: un atacator on-path putea afla codul TOTP din primul mesaj si impersona serverul in aceeasi fereastra de 30s
- cauza: codul are ~20 biti. fara chei statice, tag-ul AEAD din msg1 depinde doar de psk si de cheia efemera publica, deci cele 10^6 coduri se verifica offline in milisecunde
- rezolvare: pattern schimbat in Noise_IKpsk1 - psk-ul intra dupa DH-urile es si ss, deci o incercare nu se poate verifica fara cheile statice private. cheia serverului e fixata in configul clientului (`proto/src/handshake.rs`, `proto/src/psk.rs`)
- verificare: `proto/tests/handshake.rs` - `unknown_client_key_rejected`, `wrong_server_key_rejected`

## BUG-001 - SPA separat de handshake permite MITM
- status: rezolvat (2026-09-26, in design, inainte de cod)
- tip: design / securitate
- simptom: un atacator on-path lasa pachetul SPA sa treaca, apoi intercepteaza handshake-ul care urmeaza
- cauza: SPA-ul autentifica doar un pachet, nu si sesiunea stabilita dupa el
- rezolvare: SPA eliminat, TOTP folosit ca psk direct in handshake-ul Noise, deci autentificarea si cheile de sesiune se stabilesc in aceeasi operatie
- verificare: `proto/tests/handshake.rs` - `wrong_code_rejected`
