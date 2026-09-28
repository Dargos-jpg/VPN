# vpn-totp

Tunel VPN scris de la zero in Rust, la care conectarea cere pe langa cheile statice si un cod TOTP (2FA). Codul vine din orice aplicatie de autentificare standard (Google Authenticator, Authy etc.), fara cont si fara vreo legatura intre telefon si server.

## Cum functioneaza

- handshake `Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s` (crate-ul `snow`)
- clientul are cheia publica a serverului fixata, serverul o are pe a clientului
- codul TOTP (RFC 6238) e transformat prin HKDF intr-un PSK amestecat in primul mesaj al handshake-ului
- cod gresit sau expirat => handshake-ul pica criptografic si serverul nu raspunde nimic
- date: ChaCha20-Poly1305 cu counter explicit si fereastra anti-replay de 64 pachete
- transport UDP

Documentatie:
- [NOTES.md](NOTES.md) - design si decizii
- [CHANGELOG.md](CHANGELOG.md) - istoricul modificarilor
- [BUGS.md](BUGS.md) - buguri gasite si cum au fost rezolvate

## Structura

```
proto/    protocolul comun: totp, psk, handshake, framing, sesiune, anti-replay
server/   binarul vpn-server
client/   binarul vpn-client
```

## Build si teste

```
cargo build --release
cargo test
```

## Rulare locala (ambele pe aceeasi masina)

```
# 1. chei
cargo run -p vpn-server -- keygen
cargo run -p vpn-client -- keygen

# 2. enrollment TOTP - scaneaza QR-ul cu aplicatia de autentificare
cargo run -p vpn-server -- enroll --account laptop

# 3. completeaza server.toml si client.toml dupa fisierele *.example.toml

# 4. pornire
cargo run -p vpn-server -- run --config server.toml
cargo run -p vpn-client -- connect --config client.toml
```

Clientul cere codul de 6 cifre de pe telefon, face handshake-ul, apoi fiecare linie scrisa e trimisa criptat si serverul o trimite inapoi.

## Stadiu

- [x] TOTP, derivare PSK, handshake, sesiune criptata, anti-replay
- [x] client/server UDP cu echo
- [ ] interfata TUN + split tunnel
- [ ] full tunnel
- [ ] transport TCP optional
- [ ] rekey
- [ ] multi-client, LDAP, Vault
