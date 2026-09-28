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
psk = HKDF-SHA256(salt = "vpn-totp psk v1", ikm = cod ascii, info = client_pub || server_pub)
```

pasul de timp nu intra in ikm - laptopul nu stie ce pas a folosit telefonul, doar codul. legatura cu timpul e implicita, codul e functie de pas. serverul calculeaza codul pentru fiecare pas acceptat (curent, -1, +1) si incearca cate un handshake. nu se compara coduri direct, pica AEAD-ul.

## anti-replay

- handshake: msg1 contine un timestamp (ns); serverul il cere strict mai mare decat ultimul acceptat. fara asta un msg1 capturat putea fi retrimis in fereastra TOTP si reseta sesiunea (sesiunea noua nu ar fi utilizabila de atacator, dar ar rupe-o pe cea reala)
- date: counter u64 = nonce, fereastra glisanta de 64. update-ul ferestrei se face doar dupa ce AEAD-ul trece
- limita de counter ca la WireGuard (2^64 - 2^13), dupa aia sesiunea refuza sa mai cripteze

## framing

big endian, 3 bytes rezervati dupa tip (aliniere + loc pentru flag-uri)

```
init: [1][000][sender u32][noise msg1]          msg1 = 32 e + 48 s + 8 ts + 16 tag
resp: [2][000][sender u32][receiver u32][msg2]  msg2 = 32 e + 16 tag
data: [3][000][receiver u32][counter u64][ct + tag 16]
```

## deschis / de decis

- **rekey**: TOTP cere interventia userului, deci rekey-ul automat (la ~2 min ca la WireGuard) nu poate cere cod nou. varianta probabila: un al doilea handshake fara psk TOTP (sau cu psk derivat din sesiunea curenta) pentru rekey, iar TOTP doar la conectarea initiala / dupa un timeout de sesiune mai lung (ex 8-12h)
- **restart server**: `last_timestamp` e doar in memorie. dupa restart un msg1 capturat e reutilizabil in fereastra TOTP ramasa. fix simplu: persistat pe disc sau respins orice ts mai vechi de ~2 min fata de ceasul serverului
- **DoS pe handshake**: fiecare msg1 costa pana la 3 x 2 DH pe server. WireGuard are mac1/cookie pentru asta, de vazut daca merita
- **multi-client**: responder-ul stie acum o singura cheie de client. cu mai multi, serverul trebuie sa afle cine e inainte sa stie ce secret TOTP sa foloseasca - `s` e decriptat inainte de psk in msg1, dar snow nu expune starea partiala
- subnet TUN: propus 10.8.0.0/24, neconfirmat
- port UDP: 51900 in exemple, de pus regula in security list-ul Terraform cand se face deploy
- TUN pe Windows cere wintun.dll, serverul ramane pe Linux
