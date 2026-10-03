# note de design

## de ce TOTP ca PSK si nu pachet separat (SPA)

prima varianta: un pachet SPA cu HMAC din TOTP, apoi handshake normal. problema: un atacator on-path lasa SPA-ul sa treaca si intercepteaza handshake-ul de dupa, care nu e legat de el. cu TOTP amestecat in handshake, autentificarea si cheile de sesiune sunt aceeasi operatie.

## de ce IK cu chei statice si nu NNpsk0

un cod de 6 cifre are 10^6 valori (~20 biti). cu un pattern fara chei statice (NNpsk0) primul mesaj contine un tag AEAD care depinde doar de psk si de cheia efemera publica. un atacator poate incerca toate cele 10^6 coduri offline in milisecunde, afla codul si face MITM in aceeasi fereastra de 30s.

in IKpsk1 psk-ul intra dupa DH-urile `es` si `ss`. ca sa verifici o incercare de cod iti trebuie una din cheile statice private. deci:
- cheia statica = ceva ce ai (fisierul de pe laptop)
- codul TOTP = al doilea factor (telefonul)
- pinning pe cheia serverului = nu exista MITM nici cu codul corect

psk1 (nu psk2): psk-ul e in msg1, deci serverul verifica TOTP-ul din primul pachet si poate tacea. cu psk2 ar intra abia in msg2 si serverul ar trebui sa raspunda ca sa afle daca codul e bun.

## derivare psk

```
conectare: psk = HKDF-SHA256(salt = "vpn-totp psk v1",       ikm = cod ascii,         info = client_pub || server_pub)
rekey:     psk = HKDF-SHA256(salt = "vpn-totp rekey psk v1", ikm = secret de lant 32B, info = client_pub || server_pub)
```

pasul de timp nu intra in ikm - laptopul nu stie ce pas a folosit telefonul, doar codul. legatura cu timpul e implicita, codul e functie de pas. serverul calculeaza codul pentru fiecare pas acceptat (curent, -1, +1) si incearca cate un handshake. nu se compara coduri direct, pica AEAD-ul.

salt-uri diferite = domain separation: un psk de rekey nu poate coincide niciodata cu unul de TOTP.

## rekey (schimbarea cheilor fara TOTP)

problema: cu aceleasi chei 12h, cine fura cheile de sesiune dintr-un moment decripteaza tot traficul acelei sesiuni. WireGuard schimba cheile la 2 min. dar TOTP cere omul, deci rekey-ul automat nu poate cere cod.

solutie - lant de secrete:
1. la fiecare handshake reusit serverul genereaza 32 bytes aleatori (secret de lant) si ii trimite in payload-ul msg2, criptat (dupa `ee`, `se`)
2. dupa `rekey_secs` (120s) clientul face un handshake nou, acelasi pattern IKpsk1, dar cu psk derivat din secretul de lant in loc de cod
3. serverul incearca intai psk-ul de rekey al sesiunii curente, apoi ferestrele TOTP
4. handshake-ul de rekey are DH-uri efemere noi => chei complet noi (forward secrecy la 2 min) si un secret de lant nou => lantul avanseaza, cel vechi nu mai e acceptat

proprietati:
- rekey cere cheia statica a clientului SI secretul de lant curent - deci doar cine a trecut de o autentificare TOTP (direct sau prin lant)
- momentul autentificarii TOTP (`auth_time`) se mosteneste peste rekey-uri: la 12h de la cod e nevoie de cod nou oricum
- cheile fiecarei sesiuni expira la 180s (`KEY_MAX_AGE`): daca rekey-ul esueaza ~60s (reincercat la 5s), sesiunea se pierde si clientul cere TOTP
- server restartat => nu mai are lantul => rekey respins => clientul ajunge la dead peer si cere TOTP

tranzitia fara pierderi:
- ambele parti pastreaza sesiunea anterioara pana ii expira cheile, ca sa decripteze pachetele inca pe drum; sesiunea se alege dupa `receiver` din pachet
- clientul trimite pe cheile noi imediat dupa msg2 (+ un keepalive ca confirmare)
- serverul trimite pe cheile vechi pana primeste primul pachet pe cele noi (confirmare ca clientul le are) - ca la WireGuard
- testat: ping continuu peste 2 rekey-uri, 0% pierderi (`scripts/netns-test.sh` testul 7)

ce NU rezolva: un atacator care fura cheia statica + secretul de lant curent (adica memoria clientului) poate continua lantul pana la 12h. dar cu memoria clientului are oricum totul

## anti-replay

- handshake: msg1 contine un timestamp (ns); serverul il cere strict mai mare decat ultimul acceptat. fara asta un msg1 capturat putea fi retrimis in fereastra TOTP si reseta sesiunea (sesiunea noua nu ar fi utilizabila de atacator, dar ar rupe-o pe cea reala)
- in plus timestamp-ul trebuie sa fie la max 120s de ceasul serverului - acopera cazul de restart, cand `last_timestamp` e pierdut (BUG-004)
- date: counter u64 = nonce, fereastra glisanta de 64. update-ul ferestrei se face doar dupa ce AEAD-ul trece
- limita de counter ca la WireGuard (2^64 - 2^13), dupa aia sesiunea refuza sa mai cripteze

## framing

big endian, 3 bytes rezervati dupa tip (aliniere + loc pentru flag-uri)

```
init: [1][000][sender u32][noise msg1][mac1 16] msg1 = 32 e + 48 s + 8 ts + 16 tag
resp: [2][000][sender u32][receiver u32][msg2]  msg2 = 32 e + 32 secret de lant + 16 tag
data: [3][000][receiver u32][counter u64][ct + tag 16]
```

## tunel

- TUN (nivel 3), `tun-rs`: pe linux /dev/net/tun, pe windows driverul wintun (wintun.dll separat, de pe wintun.net)
- server 10.8.0.1/24, client 10.8.0.2 (fix in config, un singur client)
- split tunnel implicit: OS-ul pune singur ruta pentru subreteaua interfetei; alte retele prin `routes` in client.toml
- MTU 1420, ca la WireGuard: 1500 - 40 (ipv6 exterior) - 8 (udp) - 16 (header data) - 16 (tag)
- anti-spoofing pe server: dupa decriptare, sursa pachetului interior trebuie sa fie `client_tunnel_ip` (echivalentul AllowedIPs din WireGuard)
- clientul trimite prin tunel doar IPv4 - OS-ul pune singur IPv6 link-local pe interfata si ar trimite solicitari inutile (BUG-006). IPv6 in tunel = extensie ulterioara
- keepalive: pachet de date cu payload gol, criptat normal. clientul il trimite doar daca n-a trimis nimic 25s, serverul raspunde la fiecare. tine deschisa maparea NAT, actualizeaza adresa clientului pe server si ii arata clientului ca serverul traieste

## full tunnel

`mode = "full"` in client.toml: tot traficul laptopului prin VPN.

client (`client/src/routes.rs`):
- `0.0.0.0/1` + `128.0.0.0/1` prin TUN: impreuna acopera tot IPv4 si sunt mai specifice decat ruta default, deci castiga fara s-o stearga. la iesire reteaua ramane cum era (acelasi truc ca wg-quick / OpenVPN `def1`)
- ruta `/32` catre IP-ul serverului pe drumul vechi (gateway-ul de dinainte, aflat cu `ip route get` / `Find-NetRoute`). fara ea, pachetele criptate ale tunelului ar fi trimise tot in tunel => bucla
- `::/1` + `8000::/1` prin TUN: tunelul e doar IPv4 si clientul arunca IPv6 => IPv6 blocat, nu scurs pe langa VPN
- DNS: pe linux `resolvectl dns vpn0 ...` + `resolvectl domain vpn0 ~.` (toate domeniile prin tunel); pe windows DNS pe interfata TUN + metrica 1
- totul se sterge in `Drop`; clientul trateaza si SIGTERM (nu doar ctrl+c), ca un `kill` / `systemctl stop` sa nu lase rute in urma

server: forwarding + NAT (masquerade 10.8.0.0/24 pe interfata de iesire). serverul ruleaza fara root, deci configurarea e in deploy:
- masini simple: `deploy/full-tunnel-nat.sh <iface>` (nftables: forward doar vpn0 -> iesire + raspunsurile, masquerade)
- VM-urile cu UFW: rolul ansible `vpn-server` cu `vpn_full_tunnel: true` (ip_forward in /etc/ufw/sysctl.conf, NAT in before.rules, `ufw route allow`)
- serverul accepta din tunel doar sursa 10.8.0.2 (anti-spoofing), iar spre client trimite doar pachete cu destinatia 10.8.0.2 - raspunsurile de pe internet ajung asa dupa NAT

limitari:
- fara kill switch: daca clientul e omorat brutal (SIGKILL, crash), interfata dispare si traficul revine pe drumul direct, necriptat
- windows: DNS-ul "smart multi-homed" poate trimite interogari si pe alte interfete; metrica 1 pe TUN reduce, nu elimina (o regula NRPT ar elimina)
- netestat inca pe windows (rutele si DNS-ul pe windows sunt scrise, nu verificate)

testat: `scripts/netns-test.sh` testul 12 - al treilea namespace simuleaza internetul, accesibil doar prin tunel + NAT; internetul vede adresa serverului; niciun ICMP in clar pe cablul clientului; rutele dispar la SIGTERM

## transport TCP (optional)

pentru retele care blocheaza UDP. `listen_tcp` in server.toml, `transport = "tcp"` in client.toml. UDP ramane implicit.

- framing: `[lungime u16 big endian][pachet]`, pachetul identic cu cel de pe UDP (`packet::frame`)
- server (`server/src/tcp.rs`): task per conexiune; pachetele ajung in bucla principala printr-un canal, impreuna cu canalul de raspuns. adresa clientului devine `Link::Udp` sau `Link::Tcp`, roaming-ul merge si intre ele
- aparari: max 64 conexiuni; primul pachet trebuie sa fie msg1 cu mac1 valid in 10s, altfel conexiunea e inchisa (nimeni nu tine socket-uri deschise fara cheia publica a serverului); 120s fara pachete => inchisa; coada de iesire limitata cu `try_send` - un client lent pierde pachete, nu blocheaza serverul
- client (`client/src/transport.rs`): citire si scriere in task-uri separate, legate prin canale. motivul: `recv()` e in `tokio::select!` si poate fi anulat oricand; un `read_exact` anulat la jumatatea unui pachet ar desincroniza framing-ul (cancel safety). cand TCP se inchide, `recv()` asteapta, iar dead peer + reconectarea deschid o conexiune noua

compromisuri (de ce nu e implicit):
- un port TCP deschis raspunde la SYN => serverul nu mai e invizibil la scanare pe acel port
- TCP peste TCP: pierderile pe drum declanseaza retransmisii atat in TCP-ul exterior cat si in conexiunile TCP din tunel, care se pot amplifica (TCP meltdown)

testat: `scripts/netns-test.sh` testul 13 - UDP blocat cu nftables pe server, conectare + ping + rekey peste TCP, conexiune cu date aleatoare inchisa imediat

## interfata grafica si separarea privilegiilor

```
 [vpn-gui]  user obisnuit             [vpn-client daemon]  admin / root
  Tauri (webview + Rust)    <-- canal local -->   engine.rs: TUN, rute, handshake, rekey
  - cod TOTP, butoane          JSON pe linie      - citeste client.toml (cheia statica)
  - afiseaza starea            (vpn-control)      - singurul cu drepturi de retea
```

de ce doua procese: crearea interfetei TUN si a rutelor cere admin/root. o interfata grafica intreaga rulata ca admin inseamna ca un bug in webview sau in JavaScript are drepturi de admin. separat, procesul privilegiat e mic si nu are interfata; cel cu interfata nu are privilegii. acelasi model ca WireGuard (manager service + UI) si Tailscale (tailscaled + UI)

canalul local (`control/`, crate `vpn-control`):
- cereri: `connect {code}`, `disconnect`, `status`; evenimente: `status {...}` (la fiecare schimbare + la 1s cand e conectat), `error`, `log`
- un mesaj JSON pe linie, max 64 KB (linie mai lunga => eroare, nu memorie nelimitata)
- **nu exista niciun mesaj care sa intoarca chei** - interfata vede doar starea si statistici
- windows: named pipe `\\.\pipe\vpn-totp`, DACL explicit `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)` (SYSTEM si Administratori control total, utilizatori logati interactiv citire/scriere, restul nimic), clientii de pe retea respinsi
- linux: unix socket `/run/vpn-totp.sock`, 660, grup optional `--group`
- cine are acces la canal poate conecta doar cu un cod TOTP valid, deconecta si vedea starea

motorul (`client/src/engine.rs`) e acelasi pentru `connect` (terminal) si `daemon`: primeste codurile pe un canal, raporteaza prin `Reporter` (stare + evenimente broadcast). `ctl` e un client al canalului din linia de comanda - folosit si de teste (`scripts/netns-test.sh` testul 14)

interfata (`gui/`, Tauri 2, workspace separat):
- HTML/CSS/JS simplu in `gui/ui`, fara npm/bundler; CSP strict (`script-src 'self'`, fara inline)
- capabilitati Tauri: doar `core:default` + comenzile aplicatiei (connect/disconnect/refresh) - fara acces la fisiere, shell, retea din JavaScript
- daca daemon-ul nu ruleaza: "Daemon indisponibil", reincearca la 2s
- `VPN_CONTROL_ENDPOINT` schimba canalul (pentru teste)

## ciclul de viata al sesiunii

```
            cod TOTP                      trafic / keepalive
 [client] ----------> handshake ok ---> [sesiune activa] <------+
                                          | | |  |              |
                                          | | |  +-- pachet ----+
                                          | | +-- 120s: rekey (fara cod) --> chei noi, aceeasi sesiune logica
                                          | |
       server tace 90s (dead peer) -------+ |
       rekey esuat, chei de 180s ------------+
       12h de la codul TOTP ----------------+
                                          |
                                          v
                             "sesiune pierduta" -> cere cod TOTP nou
                             -> handshake nou, TUN ramane pe loc
```

- server: sesiune stearsa dupa 180s fara pachete autentificate, la cheile expirate (client fara rekey) sau la 12h
- 12h = `AUTH_MAX_AGE`: userul se reautentifica cu 2FA macar o data pe zi de lucru, oricate rekey-uri ar fi fost
- "ultimul pachet primit" se actualizeaza doar dupa AEAD reusit - pachete falsificate nu tin sesiunea in viata
- timeout-urile sunt in config ca testul din `scripts/netns-test.sh` sa le poata scurta la secunde
- `proto` nu face I/O deloc - toata partea de retea si TUN e in binare, protocolul ramane testabil fara root

## CI si dependinte

- `.github/workflows/ci.yml`: fmt + clippy (`-D warnings`) + teste pe linux, build + teste pe windows, `scripts/netns-test.sh` cu sudo, `cargo audit` (si saptamanal, luni, ca sa prinda vulnerabilitati noi in dependinte neschimbate)
- `rustfmt.toml`: `max_width = 120`, ca formatarea standard sa nu rupa liniile scrise pana acum
- `cargo audit` (2026-10-02): 0 vulnerabilitati, 1 avertisment - `paste` (RUSTSEC-2024-0436) nu mai e intretinut. vine prin `tun-rs` -> `netlink-packet-core`, e proc-macro (ruleaza doar la compilare, nu ajunge in binar). lasat vizibil, de urmarit cand `tun-rs` isi actualizeaza dependintele

## protectie DoS la handshake

problema: fiecare msg1 costa serverul pana la 8 operatii DH (rekey + 3 ferestre TOTP, cate 2 DH). un flood de msg1 poate ocupa tot procesorul.

trei straturi, in ordinea costului:
1. **mac1** (`proto/src/mac.rs`), ca la WireGuard: ultimii 16 bytes ai msg1 = BLAKE2s cu cheie peste tot pachetul; cheia = BLAKE2s("vpn-totp mac1 v1" || cheia publica a serverului). nu e secret - orice client legitim o calculeaza - dar un scanner care nu stie cheia publica e respins cu un singur hash, fara DH. bonus: invizibilitate la scanare chiar si fara sa ajunga la DH
2. **limita de rata** (`server/src/ratelimit.rs`): token bucket per IP (2/s, rafala 5) si global (20/s, rafala 50). cea globala conteaza cand sursele sunt falsificate (UDP). tabela de IP-uri limitata la 10000 intrari ca un flood cu surse aleatoare sa nu umple memoria
3. abia apoi handshake-ul complet

respingerile nu se logheaza individual (un flood ar umple logul), ci un rezumat la 10s.

masurat (`scripts/netns-test.sh` testul 11): din 300 de msg1 false (200 fara mac1, 100 cu mac1 valid), doar 5 au ajuns la DH. in fuzzing, respingerea inputurilor aleatoare a crescut de la ~1.900/s la ~117.000/s.

ce NU rezolva: un atacator care stie cheia publica si falsifica adresa IP a clientului legitim ii poate consuma bucket-ul => clientul real e intarziat (nu compromis). WireGuard rezolva asta cu mac2 + cookie reply (dovada ca sursa poate primi pachete la adresa respectiva); aici e lasat ca extensie

## deploy pe server (hardening)

- `deploy/vpn-server.service`: user de sistem `vpn-totp`, fara root. singura capabilitate: `CAP_NET_ADMIN` (creare + configurare TUN). restul:
  - fisiere: `ProtectSystem=strict` (totul read-only), `ProtectHome`, `PrivateTmp`, config read-only
  - dispozitive: doar `/dev/net/tun`
  - retea: doar AF_INET/AF_INET6 (UDP), AF_NETLINK (configurare interfata), AF_UNIX (journald)
  - apeluri de sistem: `@system-service` minus `@privileged` si `@resources`
  - fara namespace-uri noi, fara memorie W+X, fara SUID, kernel tunables/modules/logs protejate
- `deploy/install.sh`: creeaza userul, pune binarul si configul (`/etc/vpn-totp/server.toml`, 600, al userului serviciului), activeaza serviciul
- serverul refuza sa porneasca daca configul e accesibil altor useri (ca ssh cu cheile private)
- verificat cu `scripts/systemd-test.sh` (instaleaza, verifica user/capabilitati/tunel, dezinstaleaza)
- de ce conteaza: serverul proceseaza pachete de la oricine din internet. daca are un bug exploatabil, atacatorul primeste doar ce are procesul - un user fara shell, care nu poate scrie nicaieri si nu poate face mai mult decat sa configureze interfete de retea

## fuzzing

- `fuzz/` (cargo-fuzz / libFuzzer, linux + nightly), rulat cu `scripts/fuzz.sh [secunde]`
- tinte:
  - `packet_parse` - parser + header IP: fara panic; orice pachet acceptat se re-encodeaza identic (format fara ambiguitati)
  - `handshake_accept` - msg1 arbitrar: fara panic si niciodata acceptat (nici ca TOTP, nici ca rekey). aproape tot e oprit de mac1
  - `handshake_accept_mac` - la fel, dar cu mac1 valid calculat peste input: ajunge in codul de DH/noise/timestamp (atacator care stie cheia publica)
  - `handshake_tamper` - msg1 valid cu biti modificati in partea criptografica: mereu respins
  - `session_decrypt` - pachet de date arbitrar: fara panic, niciodata acceptat
  - `data_tamper` - pachet de date valid cu orice bit modificat (header, counter, ciphertext, tag): mereu respins
- primele doua sunt "nu crapa", ultimele doua sunt proprietati de securitate verificate pe milioane de variante
- indexul `sender` din msg1 e acoperit de mac1, dar nu si de AEAD; mac1 poate fi recalculat de oricine stie cheia publica, deci tamper-ul porneste de la byte 8 - vezi THREAT_MODEL.md

## deschis / de decis

- **test pe windows cu drepturi de admin**: tunelul complet pe windows (wintun.dll + daemon pornit ca administrator); pana acum testat pe windows doar pana la handshake (vezi CHANGELOG, interfata grafica)
- **daemon ca serviciu windows**: acum `vpn-client daemon` se porneste manual ca administrator; un serviciu windows (SCM) ar porni la boot
- **kill switch** pentru full tunnel
- **cookie reply (mac2)**: protectie DoS completa cand atacatorul stie cheia publica si falsifica IP-ul clientului
- **multi-client**: responder-ul stie acum o singura cheie de client. cu mai multi, serverul trebuie sa afle cine e inainte sa stie ce secret TOTP sa foloseasca - `s` e decriptat inainte de psk in msg1, dar snow nu expune starea partiala
- port UDP: 51900 in exemple, de pus regula in security list-ul Terraform cand se face deploy
- TUN pe Windows cere wintun.dll, serverul ramane pe Linux
