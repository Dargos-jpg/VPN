# threat model

ce protejeaza VPN-ul, impotriva cui, cum, si ce ramane neacoperit.
fiecare masura trimite la locul din cod sau la bugul care a motivat-o.

## ce protejam

| bun | de ce conteaza |
|---|---|
| traficul din tunel | continutul si metadatele interne (adrese 10.8.0.x, porturi, protocoale) |
| accesul la reteaua din spatele serverului | split tunnel: resurse accesibile doar prin VPN |
| cheia statica privata a clientului | identitatea clientului (fisierul `client.toml`) |
| cheia statica privata a serverului + secretul TOTP | identitatea serverului si al doilea factor (`server.toml`) |
| disponibilitatea serverului | un singur proces, un singur client |

## presupuneri

- masina clientului si serverul nu sunt compromise in momentul folosirii (vezi "ce NU acoperim")
- telefonul cu aplicatia de autentificare e in posesia userului
- primitivele criptografice (X25519, ChaCha20-Poly1305, BLAKE2s, SHA-256, HMAC-SHA1) si implementarea lor din `snow` / RustCrypto sunt corecte
- ceasurile laptopului si serverului sunt la mai putin de 2 minute diferenta (NTP)
- cheia publica a serverului ajunge in `client.toml` pe un canal de incredere (copiata manual, nu luata de pe retea)

## atacatori

| atacator | poate | exemplu |
|---|---|---|
| pasiv pe retea | vede si inregistreaza tot traficul | Wi-Fi public, ISP |
| activ pe retea (MITM) | modifica, blocheaza, injecteaza, retrimite pachete | router compromis, ARP spoofing |
| scanner din internet | trimite pachete arbitrare la portul serverului | boti, shodan |
| cine a vazut un cod TOTP | stie codul curent | shoulder surfing, phishing in timp real |
| hot de laptop | are `client.toml` (cheia statica) | laptop furat |
| hot de telefon | genereaza coduri TOTP | telefon furat |
| client autentificat rau intentionat | are sesiune valida | laptop compromis dupa conectare |

## amenintari si masuri

### confidentialitate si integritate

| amenintare | masura | unde |
|---|---|---|
| citirea traficului de pe cablu | ChaCha20-Poly1305 pe fiecare pachet | `proto/src/session.rs`; testul 6 din netns-test |
| modificarea pachetelor pe drum | tag AEAD de 16 bytes, orice bit schimbat => respins | `data_tamper` (fuzz) |
| decriptarea ulterioara a traficului capturat dupa furtul cheilor statice | forward secrecy: chei efemere per sesiune (DH `ee`, `es`, `se`) | `proto/src/handshake.rs` |
| furtul cheilor de sesiune dintr-un moment => tot traficul sesiunii | rekey automat la 120s cu DH-uri efemere noi; cheile vechi expira la 180s | `rekey_without_totp`, testul 7 din netns-test |
| reutilizarea nonce-ului | nonce = counter strict crescator, limita `REJECT_AFTER_MESSAGES` | `session.rs` |

### autentificare

| amenintare | masura | unde |
|---|---|---|
| MITM pe handshake | chei statice fixate pe ambele parti (pattern IK) + psk din TOTP | BUG-001, BUG-002 |
| brute force offline pe cele 10^6 coduri TOTP | psk intra dupa DH-urile `es` si `ss` - o incercare nu se poate verifica fara cheile private | BUG-002, NOTES.md |
| conectare doar cu laptopul furat | lipseste codul TOTP | `wrong_code_rejected` |
| conectare doar cu telefonul furat / codul vazut | lipseste cheia statica a clientului | `unknown_client_key_rejected` |
| server fals | clientul accepta doar cheia serverului din config | `wrong_server_key_rejected` |
| rekey fara autentificare TOTP prealabila | psk de rekey din secretul de lant, primit doar criptat in msg2 dupa un handshake reusit | `rekey_without_server_session_rejected`, `rekey_by_other_client_key_rejected` |
| reutilizarea unui secret de lant vechi | secret nou la fiecare handshake, serverul accepta doar lantul sesiunii curente | `rekey_with_stale_chain_rejected` |
| sesiune prelungita la nesfarsit prin rekey | momentul autentificarii TOTP se mosteneste, limita de 12h ramane | `rekey_keeps_auth_time` |

### replay

| amenintare | masura | unde |
|---|---|---|
| retrimiterea unui msg1 capturat (resetare sesiune) | timestamp strict crescator in msg1 | `handshake_replay_rejected` |
| aceeasi retrimitere dupa restartul serverului | timestamp la max 120s de ceasul serverului | BUG-004 |
| retrimiterea pachetelor de date | fereastra glisanta de 64 pe counter, actualizata doar dupa AEAD | `proto/src/replay.rs` |

### full tunnel

| amenintare | masura | unde |
|---|---|---|
| bucla de rutare (pachetele tunelului intra in tunel) | ruta /32 catre server pe drumul original | testul 12 din netns-test |
| DNS leak (interogari la DNS-ul retelei locale) | DNS-ul tunelului pentru toate domeniile (`~.` pe linux, interfata TUN pe windows) | `client/src/routes.rs` |
| IPv6 leak (tunel doar IPv4) | `::/1` + `8000::/1` in TUN, clientul arunca IPv6 | `client/src/routes.rs`, BUG-006 |
| rute ramase dupa deconectare | stergere in Drop, tratare SIGTERM | testul 12 |
| serverul folosit ca releu deschis | forward doar din vpn0 cu sursa 10.8.0.0/24, doar raspunsuri inapoi | `deploy/full-tunnel-nat.sh`, rolul ansible |

### abuz din tunel

| amenintare | masura | unde |
|---|---|---|
| clientul injecteaza trafic cu alta adresa sursa | serverul accepta doar sursa `client_tunnel_ip` | testul 4 din netns-test |
| sesiune tinuta in viata artificial cu pachete false | doar pachetele care trec de AEAD reseteaza timer-ul | `only_authenticated_packets_count_as_alive` |

### descoperire si disponibilitate

| amenintare | masura | unde |
|---|---|---|
| scanare de porturi | serverul nu raspunde nimic la pachete neautentificate | testul 1 din netns-test |
| flood de msg1 de la cine nu stie cheia publica a serverului | mac1: respins cu un singur BLAKE2s, fara DH | testul 11 din netns-test, `mac1_checked_before_handshake` |
| flood de msg1 cu mac1 valid | limita de rata per IP (2/s) si globala (20/s) inainte de DH | testul 11, `server/src/ratelimit.rs` |
| flood cu surse IP aleatoare care umple memoria | tabela de rate limiting limitata la 10000 IP-uri | `tracked_ips_bounded` |
| crash prin pachete malformate | parser fara panic, verificat prin fuzzing | `fuzz/` |
| sesiune moarta care tine resurse | timeout de inactivitate (180s) si durata maxima (12h) | `server/src/main.rs` |
| conexiuni TCP tinute deschise fara date (slowloris) | max 64 conexiuni, primul pachet = msg1 cu mac1 valid in 10s, 120s inactivitate | `server/src/tcp.rs`, testul 13 |
| client TCP lent care blocheaza serverul | coada de iesire limitata, `try_send` (pachete aruncate, ca pe UDP) | `server/src/main.rs` (`Link::send`) |

### clientul local (daemon + interfata grafica)

| amenintare | masura | unde |
|---|---|---|
| bug in interfata grafica / webview => drepturi de admin | separarea privilegiilor: interfata ruleaza ca user obisnuit, doar daemon-ul are drepturi de retea | `client/src/daemon.rs`, `gui/` |
| alt user al masinii controleaza tunelul | canal local cu permisiuni: DACL pe named pipe (windows), socket 660 + grup (linux) | testul 14 (userul `nobody` respins) |
| conexiuni la canalul de control din retea | named pipe cu `reject_remote_clients`, unix socket doar local | `daemon.rs` |
| interfata (sau cine are acces la canal) obtine cheile | protocolul nu are niciun mesaj care sa intoarca chei sau secrete | `control/src/lib.rs` |
| mesaje uriase sau malformate pe canalul de control | max 64 KB pe linie, JSON invalid => conexiune inchisa | `read_msg`, teste in `control` |
| JavaScript injectat in interfata | CSP strict fara inline, capabilitati Tauri minime (fara fisiere/shell/retea) | `gui/tauri.conf.json`, `gui/capabilities/` |

### secrete pe disc si in memorie

| amenintare | masura | unde |
|---|---|---|
| chei ramase in memorie dupa folosire | `zeroize` pe chei, psk, secret TOTP, cod | `keys.rs`, `handshake.rs` |
| config cu secrete urcat in git | `server.toml`/`client.toml` in `.gitignore`, doar `*.example.toml` in repo | `.gitignore` |
| config cu secrete citibil de alti useri ai serverului | serverul refuza sa porneasca daca permisiunile nu sunt 600 | testul 0 din netns-test |

### compromiterea serverului printr-un bug

| amenintare | masura | unde |
|---|---|---|
| bug exploatabil in procesul serverului => control asupra masinii | serviciu systemd ca user `vpn-totp`, doar `CAP_NET_ADMIN`, sistem de fisiere read-only, syscall-uri filtrate; scor `systemd-analyze security` 1.7 | `deploy/vpn-server.service`, `scripts/systemd-test.sh` |

## riscuri ramase (de rezolvat)

| risc | impact | plan |
|---|---|---|
| atacator care stie cheia publica si falsifica IP-ul clientului legitim | ii consuma bucket-ul de rate limiting => conectarea clientului real e intarziata | mac2 + cookie reply ca la WireGuard |
| memoria clientului furata (cheie statica + secret de lant) | atacatorul poate continua lantul de rekey pana la 12h fara cod | acceptat - cu memoria clientului are oricum acces la tot |
| indexul `sender` din msg1 nu e autentificat criptografic (mac1 il acopera, dar cheia mac1 e publica) | un MITM il poate schimba si recalcula mac1 => handshake-ul pica la client (doar DoS, un MITM poate oricum bloca pachetele) | acceptat |
| clientul pe windows nu verifica permisiunile `client.toml` | cheia statica a clientului citibila de alti useri ai laptopului | ACL-uri windows, de vazut odata cu interfata grafica |

## ce NU acoperim

- **laptop sau server compromis in timpul folosirii** - malware cu acces la proces poate citi cheile din memorie sau traficul inainte de criptare. niciun VPN nu apara de asta
- **phishing in timp real cu cheia statica furata** - daca atacatorul are deja `client.toml` si obtine codul TOTP curent de la user, se poate conecta. TOTP nu leaga codul de un site/server anume (FIDO2 ar face-o)
- **secretul TOTP e simetric** - cine compromite serverul are si secretul, deci poate genera coduri. inerent TOTP
- **analiza de trafic** - dimensiunea si momentul pachetelor raman vizibile (fara padding / trafic de acoperire)
- **blocarea totala** - un atacator pe retea poate oricum bloca tot traficul (UDP si TCP)
- **invizibilitate pe TCP** - cu `listen_tcp` activ, portul TCP raspunde la conectare si apare la scanare (doar ca port deschis; fara cheia publica a serverului conexiunea e inchisa imediat)
- **IPv6 in tunel** - nesuportat; clientul nu trimite IPv6 prin tunel (BUG-006)
- **split tunnel** (implicit) - traficul in afara 10.8.0.0/24 si DNS-ul nu trec prin VPN, intentionat. in full tunnel trec, cu IPv6 blocat
- **kill switch** - daca clientul e omorat brutal, traficul revine pe drumul direct necriptat
- **DNS pe windows in full tunnel** - Windows poate trimite interogari si pe alte interfete (smart multi-homed name resolution); metrica mica pe TUN reduce riscul, nu il elimina
