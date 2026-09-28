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

## BUG-004 - replay msg1 dupa restart server
- status: deschis
- tip: securitate
- simptom: dupa restart serverul uita ultimul timestamp acceptat, deci un msg1 capturat poate fi retrimis cat timp codul TOTP din el e inca valid (max ~90s)
- cauza: `Responder::last_timestamp` e doar in memorie (`proto/src/handshake.rs`)
- rezolvare propusa: respins orice timestamp mai vechi de ~2 min fata de ceasul serverului, sau persistat pe disc
- verificare: -

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
