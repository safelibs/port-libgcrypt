# gost-crypto

Pure-Rust реализация российских криптографических стандартов, совместимая с экосистемой [RustCrypto].

Pure-Rust implementation of Russian cryptographic standards, compatible with the [RustCrypto] ecosystem.

---

## Алгоритмы / Algorithms

| Алгоритм | Тип | Feature |
|----------|-----|---------|
| GOST 28147-89 ([RFC 5830]) | Блочный шифр, 64-бит блок, 256-бит ключ | всегда |
| GOST R 34.11-94 ([RFC 5831]) | Хэш 256-бит, параметры CryptoPro и Test | всегда |
| CMAC / OMAC | MAC поверх GOST 28147-89 | `mac` |
| GOST R 34.11-2012 Стрибог ([RFC 6986]) | Хэш 256 / 512-бит | `streebog` |
| Кузнечик GOST R 34.12-2015 ([RFC 7801]) | Блочный шифр, 128-бит блок, 256-бит ключ | `kuznyechik` |

- `no_std`
- Нет `unsafe` кода / No `unsafe` code
- Нет зависимостей времени выполнения / No runtime dependencies

---

## Cargo.toml

```toml
[dependencies]
gost-crypto = "0.2"

# Опционально / Optional:
gost-crypto = { version = "0.2", features = ["mac"] }
gost-crypto = { version = "0.2", features = ["streebog"] }
```

---

## Примеры / Examples

### GOST 28147-89 — шифрование блока / block encryption

```rust
use gost_crypto::{Gost28147, SBOX_CRYPTOPRO};

let key = [0x42u8; 32];
let cipher = Gost28147::with_sbox(&key, &SBOX_CRYPTOPRO);

let plaintext = [1u8, 2, 3, 4, 5, 6, 7, 8];
let ciphertext = cipher.encrypt_block_raw(&plaintext);
let recovered = cipher.decrypt_block_raw(&ciphertext);

assert_eq!(plaintext, recovered);
```

Для режимов CBC / CFB / OFB используйте внешние крейты из RustCrypto (`cbc`, `cfb-mode`, `ofb`) — `Gost28147` реализует `cipher::BlockCipherEncrypt + BlockCipherDecrypt + KeyInit`.

For CBC / CFB / OFB modes use RustCrypto mode crates (`cbc`, `cfb-mode`, `ofb`) — `Gost28147` implements `cipher::BlockCipherEncrypt + BlockCipherDecrypt + KeyInit`.

### GOST R 34.11-94 — хэш / hash

```rust
use gost_crypto::{Gost341194, SBOX_CRYPTOPRO};
use digest::Update;

let mut h = Gost341194::new_with_sbox(&SBOX_CRYPTOPRO);
h.update(b"hello");
let digest: [u8; 32] = h.finalize_bytes();
```

### CMAC (feature `mac`)

```rust
use gost_crypto::mac::Gost28147Mac;
use digest::Mac;

let mut mac = Gost28147Mac::new(&[0x42u8; 32].into());
mac.update(b"message");
let tag = mac.finalize().into_bytes();
```

### Kuznyechik (feature `kuznyechik`)

```toml
gost-crypto = { version = "0.2", features = ["kuznyechik"] }
```

```rust
use gost_crypto::kuznyechik::Kuznyechik;
use gost_crypto::kuznyechik::cipher::{KeyInit, BlockCipherEncrypt};

let key = [0x42u8; 32];
let c = Kuznyechik::new(&key.into());
let mut block = [0u8; 16];
c.encrypt_block((&mut block).into());
```

---

## Cipher Modes / Режимы шифрования

`Gost28147` implements standard `RustCrypto` traits, so any cipher v0.4-compatible mode crate works:

```toml
[dependencies]
gost-crypto = "0.2"
cbc = "0.1"
```

```rust
use gost_crypto::Gost28147;
use cbc::Encryptor;
use cipher::{KeyIvInit, BlockEncryptMut, block_padding::Pkcs7};

let enc = Encryptor::<Gost28147>::new(&key.into(), &iv.into());
let ct = enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext);
```

---

## S-боксы / S-boxes

Два встроенных параметра:

| Константа | Назначение |
|-----------|-----------|
| `SBOX_CRYPTOPRO` | КриптоПро CSP, RFC 4357 §11.2 |
| `SBOX_TEST` | RFC 5831 тестовые векторы |

`KeyInit::new` использует `SBOX_CRYPTOPRO`. Для другого S-бокса — `Gost28147::with_sbox`.

`KeyInit::new` defaults to `SBOX_CRYPTOPRO`. Use `Gost28147::with_sbox` for a custom S-box.

---

## Лицензия / License

[WTFPL](LICENSE)

[RustCrypto]: https://github.com/RustCrypto
[RFC 5830]: https://www.rfc-editor.org/rfc/rfc5830
[RFC 5831]: https://www.rfc-editor.org/rfc/rfc5831
[RFC 6986]: https://www.rfc-editor.org/rfc/rfc6986
[RFC 7801]: https://www.rfc-editor.org/rfc/rfc7801
