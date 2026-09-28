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
